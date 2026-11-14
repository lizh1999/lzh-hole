//! Concrete public discovery state, independent of sockets, store and recovery.
//!
//! Service executes `StunSend` on the indicated retained data socket, supplies
//! fresh random transactions, and reports send failure. A bad reply never
//! consumes a pending transaction. Timers use monotonic milliseconds; signed
//! contact timestamps remain explicit UNIX milliseconds. Existing ntfy pacing
//! and `ExchangeTracker` still gate all public HTTP/signaling effects.

use crate::{
    VerifiedPayload,
    message::RequestId,
    nat_behavior::{MappingSample, NatProfile, classify_mapping},
    observation::{
        CandidateHint, CandidateScope, DiscoveryOrigin, DiscoveryUpdate, HintSource, ObservationId,
    },
    record::MAX_CANDIDATES,
    stun::{StunError, TRANSACTION_ID_LEN, build_binding_request, parse_binding_response_from},
};
use lzh_hole_types::{Endpoint, PeerRecordState};
use std::{collections::BTreeMap, net::SocketAddrV4};

pub const MAX_PUBLIC_TRANSPORTS: usize = 16;
pub const MAX_STUN_SERVERS: usize = 8;
pub const MAX_SOCKET_MAPPINGS: usize = 8;
pub const STUN_TIMEOUT_MS: u64 = 3_000;
pub const STUN_INTERVAL_MS: u64 = 5_000;
pub const STUN_MAPPING_TTL_MS: u64 = 120_000;
const REQUEST_RETRY_MS: u64 = 30_000;
const REQUEST_REFRESH_MS: u64 = 45 * 60_000;
const MAX_REQUEST_RETRY_MS: u64 = 30 * 60_000;

/// Opaque socket identity; the integrator maps its `TransportId.0` here.
pub type PublicTransportId = u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunSend {
    pub transport: PublicTransportId,
    pub server: SocketAddrV4,
    pub transaction: [u8; TRANSACTION_ID_LEN],
    pub packet: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicMapping {
    pub transport: PublicTransportId,
    pub endpoint: Endpoint,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingStun {
    transaction: [u8; TRANSACTION_ID_LEN],
    server: SocketAddrV4,
    expires_at_ms: u64,
}

#[derive(Debug)]
struct SocketDiscovery {
    servers: Vec<SocketAddrV4>,
    next_server: usize,
    pending: Option<PendingStun>,
    next_probe_ms: u64,
    mappings: BTreeMap<Endpoint, u64>,
    /// Newest mapping observed per STUN server, which is what makes
    /// endpoint-independent and endpoint-dependent mapping distinguishable.
    /// Bounded by the server list, which `add_transport` already caps.
    samples: BTreeMap<SocketAddrV4, MappingSample>,
    consecutive_timeouts: u32,
}

impl SocketDiscovery {
    fn expire(&mut self, now_ms: u64) {
        self.mappings.retain(|_, expiry| *expiry > now_ms);
        if self.pending.is_some_and(|p| p.expires_at_ms <= now_ms) {
            self.pending = None;
            self.consecutive_timeouts = self.consecutive_timeouts.saturating_add(1);
            self.next_probe_ms = now_ms.saturating_add(STUN_INTERVAL_MS);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingPublicRequest {
    pub id: RequestId,
    pub expires_at_ms: u64,
}

/// Cancel expired correlation before handling subsequent verified replies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicExpiry {
    pub updates: Vec<DiscoveryUpdate>,
    pub expired_request: Option<RequestId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicAcceptError<E> {
    Commit(E),
    Expired,
    Stale,
    Capacity,
}

#[derive(Debug)]
pub struct PublicDiscovery {
    sockets: BTreeMap<PublicTransportId, SocketDiscovery>,
    candidates: BTreeMap<Endpoint, CandidateHint>,
    highest_record_seq: Option<u64>,
    record_deadline_ms: u64,
    next_id: u64,
    pending_request: Option<PendingPublicRequest>,
    next_request_ms: u64,
    request_failures: u32,
    advertised_mappings: Vec<(PublicTransportId, Endpoint)>,
    advertised_flags: u8,
}

impl Default for PublicDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl PublicDiscovery {
    pub fn new() -> Self {
        Self {
            sockets: BTreeMap::new(),
            candidates: BTreeMap::new(),
            highest_record_seq: None,
            record_deadline_ms: 0,
            next_id: 1,
            pending_request: None,
            next_request_ms: 0,
            request_failures: 0,
            advertised_mappings: Vec::new(),
            advertised_flags: 0,
        }
    }

    /// Register once per retained socket generation.
    pub fn add_transport(
        &mut self,
        transport: PublicTransportId,
        servers: Vec<SocketAddrV4>,
        now_ms: u64,
    ) -> bool {
        if self.sockets.contains_key(&transport)
            || self.sockets.len() >= MAX_PUBLIC_TRANSPORTS
            || servers.len() > MAX_STUN_SERVERS
            || servers.iter().any(|s| s.port() == 0)
        {
            return false;
        }
        self.sockets.insert(
            transport,
            SocketDiscovery {
                servers,
                next_server: 0,
                pending: None,
                next_probe_ms: now_ms,
                mappings: BTreeMap::new(),
                samples: BTreeMap::new(),
                consecutive_timeouts: 0,
            },
        );
        true
    }

    pub fn remove_transport(&mut self, transport: PublicTransportId) {
        self.sockets.remove(&transport);
    }

    /// At most one effect per socket per interval; never initiates recovery.
    pub fn start_stun(
        &mut self,
        transport: PublicTransportId,
        transaction: [u8; TRANSACTION_ID_LEN],
        now_ms: u64,
    ) -> Result<Option<StunSend>, StunError> {
        let Some(socket) = self.sockets.get_mut(&transport) else {
            return Ok(None);
        };
        socket.expire(now_ms);
        if socket.pending.is_some() || now_ms < socket.next_probe_ms || socket.servers.is_empty() {
            return Ok(None);
        }
        let server = socket.servers[socket.next_server];
        let packet = build_binding_request(&transaction)?;
        socket.next_server = (socket.next_server + 1) % socket.servers.len();
        socket.pending = Some(PendingStun {
            transaction,
            server,
            expires_at_ms: now_ms.saturating_add(STUN_TIMEOUT_MS),
        });
        Ok(Some(StunSend {
            transport,
            server,
            transaction,
            packet,
        }))
    }

    /// Only the matching send failure can cancel a pending effect.
    pub fn stun_send_failed(
        &mut self,
        transport: PublicTransportId,
        transaction: [u8; TRANSACTION_ID_LEN],
        now_ms: u64,
    ) {
        if let Some(socket) = self.sockets.get_mut(&transport)
            && socket.pending.is_some_and(|p| p.transaction == transaction)
        {
            socket.pending = None;
            socket.next_probe_ms = now_ms.saturating_add(STUN_INTERVAL_MS);
        }
    }

    pub fn receive_stun(
        &mut self,
        transport: PublicTransportId,
        source: SocketAddrV4,
        packet: &[u8],
        now_ms: u64,
    ) -> Result<Option<PublicMapping>, StunError> {
        let Some(socket) = self.sockets.get_mut(&transport) else {
            return Ok(None);
        };
        socket.expire(now_ms);
        let Some(request) = socket.pending else {
            return Ok(None);
        };
        let response =
            parse_binding_response_from(packet, &request.transaction, request.server, source)?;
        let servers = socket
            .servers
            .iter()
            .map(|s| Endpoint::new(*s.ip(), s.port()))
            .collect::<Vec<_>>();
        crate::candidate::validate_publishable(&response.mapped, &servers)
            .map_err(StunError::InvalidMapping)?;
        socket.pending = None;
        socket.consecutive_timeouts = 0;
        socket.next_probe_ms = now_ms.saturating_add(STUN_INTERVAL_MS);
        let expires_at_ms = now_ms.saturating_add(STUN_MAPPING_TTL_MS);
        if !socket.mappings.contains_key(&response.mapped)
            && socket.mappings.len() >= MAX_SOCKET_MAPPINGS
            && let Some(oldest) = socket
                .mappings
                .iter()
                .min_by_key(|(_, expiry)| **expiry)
                .map(|(endpoint, _)| *endpoint)
        {
            socket.mappings.remove(&oldest);
        }
        socket.mappings.insert(response.mapped, expires_at_ms);
        // Record which destination produced which external port. This is the
        // only place endpoint-dependent mapping can be told apart from
        // endpoint-independent mapping, and it costs no extra packet: the
        // server rotation already queries several destinations in turn.
        socket.samples.insert(
            request.server,
            MappingSample {
                destination: *request.server.ip(),
                port: response.mapped.port,
                observed_at_ms: now_ms,
            },
        );
        Ok(Some(PublicMapping {
            transport,
            endpoint: response.mapped,
            expires_at_ms,
        }))
    }

    pub fn own_mappings(&self, now_ms: u64) -> Vec<PublicMapping> {
        self.sockets
            .iter()
            .flat_map(|(transport, socket)| {
                socket
                    .mappings
                    .iter()
                    .filter_map(move |(endpoint, expiry)| {
                        (*expiry > now_ms).then_some(PublicMapping {
                            transport: *transport,
                            endpoint: *endpoint,
                            expires_at_ms: *expiry,
                        })
                    })
            })
            .collect()
    }

    pub fn consecutive_timeouts(&self, transport: PublicTransportId) -> Option<u32> {
        self.sockets.get(&transport).map(|s| s.consecutive_timeouts)
    }

    /// Classify this socket's NAT mapping behaviour from the STUN servers it
    /// has already been queried against.
    ///
    /// Returns `Unknown` until at least two distinct server addresses have
    /// answered inside the coherence window, which is the honest answer when
    /// only one seed is configured. No extra socket and no extra packet is
    /// used: the existing server rotation supplies the samples.
    pub fn mapping_behavior(&self, transport: PublicTransportId) -> NatProfile {
        let Some(socket) = self.sockets.get(&transport) else {
            return NatProfile::unknown();
        };
        let samples: Vec<MappingSample> = socket.samples.values().copied().collect();
        classify_mapping(&samples)
    }

    /// Every socket's verdict, for diagnostics.
    pub fn mapping_behaviors(&self) -> Vec<(PublicTransportId, NatProfile)> {
        self.sockets
            .keys()
            .map(|transport| (*transport, self.mapping_behavior(*transport)))
            .collect()
    }

    /// Durably commit high-water state before releasing any candidate hints.
    /// Call immediately after verification on the same single writer.
    pub fn accept_verified<E>(
        &mut self,
        verified: &VerifiedPayload,
        now_unix_ms: u64,
        now_ms: u64,
        commit: impl FnOnce(&PeerRecordState) -> Result<(), E>,
    ) -> Result<Vec<DiscoveryUpdate>, PublicAcceptError<E>> {
        let record = &verified.validated.record;
        if record.expires_at_unix_ms <= now_unix_ms {
            return Err(PublicAcceptError::Expired);
        }
        if self
            .highest_record_seq
            .is_some_and(|seq| record.record_seq < seq)
        {
            return Err(PublicAcceptError::Stale);
        }
        let targets = &verified.validated.targets;
        let duplicate = self.highest_record_seq == Some(record.record_seq);
        let deadline = now_ms.saturating_add(record.expires_at_unix_ms - now_unix_ms);
        let deadline = if duplicate {
            deadline.min(self.record_deadline_ms)
        } else {
            deadline
        };
        if deadline <= now_ms {
            return Err(PublicAcceptError::Expired);
        }
        if targets.len() > MAX_CANDIDATES
            || self.next_id.checked_add(targets.len() as u64).is_none()
        {
            return Err(PublicAcceptError::Capacity);
        }
        if let Some(state) = verified.state_to_persist() {
            commit(state).map_err(PublicAcceptError::Commit)?;
        }
        let mut updates = Vec::new();
        self.candidates.retain(|endpoint, hint| {
            if targets.contains(endpoint) {
                true
            } else {
                updates.push(DiscoveryUpdate::Remove(hint.observation_id));
                false
            }
        });
        for endpoint in targets {
            let existing = self.candidates.get(endpoint);
            let id = existing.map(|h| h.observation_id).unwrap_or_else(|| {
                let id = ObservationId {
                    origin: DiscoveryOrigin::Public,
                    serial: self.next_id,
                };
                self.next_id += 1;
                id
            });
            let expires_at_ms = existing
                .filter(|_| duplicate)
                .map(|hint| deadline.min(hint.expires_at_ms))
                .unwrap_or(deadline);
            let hint = CandidateHint {
                remote: *endpoint,
                scope: CandidateScope::Public,
                observation_id: id,
                expires_at_ms,
                source: HintSource::VerifiedContactRecord,
            };
            self.candidates.insert(*endpoint, hint);
            updates.push(DiscoveryUpdate::Upsert(hint));
        }
        self.highest_record_seq = Some(record.record_seq);
        self.record_deadline_ms = deadline;
        Ok(updates)
    }

    pub fn expire(&mut self, now_ms: u64) -> PublicExpiry {
        for socket in self.sockets.values_mut() {
            socket.expire(now_ms);
        }
        let expired_request = self
            .pending_request
            .filter(|p| p.expires_at_ms <= now_ms)
            .map(|p| p.id);
        if expired_request.is_some() {
            self.fail_request(now_ms);
        }
        let mut updates = Vec::new();
        self.candidates.retain(|_, hint| {
            if hint.expires_at_ms <= now_ms {
                updates.push(DiscoveryUpdate::Remove(hint.observation_id));
                false
            } else {
                true
            }
        });
        PublicExpiry {
            updates,
            expired_request,
        }
    }

    /// Call after mapping or coordination flag changes. Identical refreshes do not
    /// accelerate requests. The caller cancels returned correlation, while ntfy
    /// retains its independent persisted pacing/HTTP budget.
    pub fn request_refresh_needed(&mut self, now_ms: u64, flags: u8) -> Option<RequestId> {
        let mappings = self
            .own_mappings(now_ms)
            .into_iter()
            .map(|m| (m.transport, m.endpoint))
            .collect::<Vec<_>>();
        if mappings == self.advertised_mappings && flags == self.advertised_flags {
            return None;
        }
        self.advertised_mappings = mappings;
        self.advertised_flags = flags;
        self.next_request_ms = self.next_request_ms.min(now_ms);
        self.pending_request.take().map(|pending| pending.id)
    }

    pub fn request_due(&self, now_ms: u64) -> bool {
        self.pending_request.is_none() && now_ms >= self.next_request_ms
    }

    pub fn request_started(
        &mut self,
        id: RequestId,
        expires_at_unix_ms: u64,
        now_unix_ms: u64,
        now_ms: u64,
    ) -> bool {
        if !self.request_due(now_ms) || expires_at_unix_ms <= now_unix_ms {
            return false;
        }
        self.pending_request = Some(PendingPublicRequest {
            id,
            expires_at_ms: now_ms.saturating_add(expires_at_unix_ms - now_unix_ms),
        });
        true
    }

    pub fn pending_request(&self) -> Option<PendingPublicRequest> {
        self.pending_request
    }

    pub fn request_failed(&mut self, id: RequestId, now_ms: u64) {
        if self.pending_request.is_some_and(|p| p.id == id) {
            self.fail_request(now_ms);
        }
    }

    pub fn request_queue_failed(&mut self, now_ms: u64) {
        if self.pending_request.is_none() {
            self.fail_request(now_ms);
        }
    }

    fn fail_request(&mut self, now_ms: u64) {
        self.pending_request = None;
        self.request_failures = self.request_failures.saturating_add(1).min(16);
        let delay = REQUEST_RETRY_MS
            .saturating_mul(1_u64 << (self.request_failures - 1).min(6))
            .min(MAX_REQUEST_RETRY_MS);
        self.next_request_ms = now_ms.saturating_add(delay);
    }

    pub fn request_matched(&mut self, id: RequestId, now_ms: u64) {
        if self.pending_request.is_some_and(|p| p.id == id) {
            self.pending_request = None;
            self.request_failures = 0;
            self.next_request_ms = now_ms.saturating_add(REQUEST_REFRESH_MS);
        }
    }
}

#[cfg(test)]
mod tests;
