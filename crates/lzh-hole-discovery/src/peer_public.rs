//! Per-relationship public coordination state, independent of sockets and store.
//!
//! Node-level STUN transactions, own public mappings and NAT mapping behaviour
//! live in [`crate::public`] and are shared by the whole node. Everything in
//! this file is scoped to exactly one relationship: the candidate hints derived
//! from that peer's verified contact records, its anti-rollback high-water mark,
//! and its own request pacing and de-duplication.
//!
//! Two `PeerPublic` values never share state, so one peer's record can never
//! move another peer's high-water mark, one peer's expiry can never remove
//! another peer's candidates, and one peer's request can never consume another
//! peer's coordination budget.
//!
//! Timers use monotonic milliseconds; signed contact timestamps remain explicit
//! UNIX milliseconds. Existing ntfy pacing and `ExchangeTracker` still gate all
//! public HTTP/signaling effects.

use crate::public::PublicTransportId;
use crate::{
    VerifiedPayload,
    message::RequestId,
    observation::{
        CandidateHint, CandidateScope, DiscoveryOrigin, DiscoveryUpdate, HintSource, ObservationId,
    },
    record::MAX_CANDIDATES,
};
use lzh_hole_types::{Endpoint, PeerRecordState};
use std::collections::BTreeMap;

const REQUEST_RETRY_MS: u64 = 30_000;
const REQUEST_REFRESH_MS: u64 = 45 * 60_000;
const MAX_REQUEST_RETRY_MS: u64 = 30 * 60_000;

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

/// One relationship's slice of public discovery.
#[derive(Debug)]
pub struct PeerPublic {
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

impl Default for PeerPublic {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerPublic {
    pub fn new() -> Self {
        Self {
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

    /// Expire this relationship's candidates and request correlation only.
    pub fn expire(&mut self, now_ms: u64) -> PublicExpiry {
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

    /// Call after this node's public mappings or this relationship's
    /// coordination flags change. Identical refreshes do not accelerate
    /// requests. The caller cancels the returned correlation, while ntfy
    /// retains its independent persisted pacing/HTTP budget.
    ///
    /// `mappings` is this node's current own public mapping set, which every
    /// relationship shares. It is passed in rather than read here because the
    /// node-level STUN state lives in [`crate::public`]; what is per
    /// relationship is only the memory of what this relationship last
    /// advertised, so a NAT rebinding refreshes every relationship exactly
    /// once and an unchanged node does not re-publish on every timer tick.
    pub fn request_refresh_needed(
        &mut self,
        now_ms: u64,
        mappings: &[(PublicTransportId, Endpoint)],
        flags: u8,
    ) -> Option<RequestId> {
        if mappings == self.advertised_mappings.as_slice() && flags == self.advertised_flags {
            return None;
        }
        self.advertised_mappings = mappings.to_vec();
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
