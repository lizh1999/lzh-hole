//! Node-level discovery I/O and per-relationship coordination handling.
//!
//! STUN, Bonjour browsing and Bonjour registration are node-level: they measure
//! and advertise this host, not any peer. Everything derived from a peer's
//! authenticated material is per relationship and is handed to exactly one
//! `PeerRuntime`:
//!
//! - a payload is verified against the relationship carried by the ntfy event
//!   it arrived on, never against a relationship guessed from its contents;
//! - a Bonjour observation is attributed by the pinned peer key in its TXT
//!   record, which is what makes "peer A's address is a candidate for A's
//!   engine only" true rather than aspirational;
//! - a durable sequence is reserved from that relationship's own stream.

use lzh_hole_discovery::{Delivery, ExchangeAction, MessageKind, PublicTransportId};

use super::peer::NodeFacts;
use super::status::component;
use super::*;

#[derive(Debug)]
pub(super) struct NtfyBlock {
    pub(super) detail: String,
    pub(super) not_before_unix_ms: u64,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum MdnsOperation {
    Browse(LanScope),
    Register(TransportId),
}

/// Give each retained transport a fresh representative before filling spare
/// wire slots with older distinct mappings. Self-filtering uses all mappings.
pub(super) fn publication_endpoints(
    mappings: Vec<lzh_hole_discovery::public::PublicMapping>,
) -> Vec<Endpoint> {
    let mut by_transport = BTreeMap::<u64, Vec<lzh_hole_discovery::public::PublicMapping>>::new();
    for mapping in mappings {
        by_transport
            .entry(mapping.transport)
            .or_default()
            .push(mapping);
    }
    for mappings in by_transport.values_mut() {
        // pop() returns newest first, with deterministic endpoint tie-breaking.
        mappings
            .sort_by_key(|mapping| (std::cmp::Reverse(mapping.expires_at_ms), mapping.endpoint));
        mappings.reverse();
    }
    let mut selected = Vec::new();
    loop {
        let before = selected.len();
        for mappings in by_transport.values_mut() {
            while let Some(mapping) = mappings.pop() {
                if !selected.contains(&mapping.endpoint) {
                    selected.push(mapping.endpoint);
                    break;
                }
            }
            if selected.len() == MAX_OWN_MAPPINGS {
                selected.sort();
                return selected;
            }
        }
        if selected.len() == before {
            selected.sort();
            return selected;
        }
    }
}

impl Daemon {
    /// Ask every relationship whether its advertised view went stale.
    ///
    /// The node's own public mappings are shared, so one NAT rebinding makes
    /// every relationship due exactly once; the per-relationship memory of what
    /// it last advertised is what keeps an idle timer tick from re-publishing.
    pub(super) fn refresh_public_requests(&mut self) {
        let now = self.monotonic_ms();
        let mappings = self
            .public
            .own_mappings(now)
            .into_iter()
            .map(|mapping| (mapping.transport as PublicTransportId, mapping.endpoint))
            .collect::<Vec<_>>();
        for id in self.peer_order.clone() {
            let flags = self.record_flags_for(id);
            let Some(peer) = self.peers.get_mut(&id) else {
                continue;
            };
            if let Some(request) = peer.public.request_refresh_needed(now, &mappings, flags) {
                peer.exchange.cancel_request(request);
            }
        }
    }

    pub(super) fn reset_mdns_scopes(&mut self) {
        self.mdns = None;
        self.mdns_operations.clear();
        let scopes = std::mem::take(&mut self.lan_scopes);
        let transports = self.candidate_transports();
        let mut updates = Vec::new();
        for scope in scopes.into_values() {
            updates.extend(
                self.lan
                    .revoke_interface(scope)
                    .into_iter()
                    .map(|update| (update.relationship_id, update.update)),
            );
        }
        self.apply_tagged_updates_with(updates, &transports);
        self.next_mdns_retry = Instant::now();
    }

    pub(super) fn ensure_mdns(&mut self) {
        if !self.network_enabled || !self.resolved.config.lan.enabled {
            if self.network_enabled {
                self.lan_status = component(
                    ComponentState::NotConfigured,
                    "LAN discovery disabled by configuration",
                    None,
                );
            }
            return;
        }
        if Instant::now() < self.next_mdns_retry {
            return;
        }
        let self_key = self.self_key();
        let client = self.mdns.get_or_insert_with(MdnsClient::new);
        let mut error = None;
        for scope in self.lan_scopes.values() {
            if self.mdns_operations.values().any(|operation| matches!(operation, MdnsOperation::Browse(existing) if existing == scope)) {
                continue;
            }
            match client.browse(scope.interface, "_lzh-hole._udp") {
                Ok(operation) => {
                    self.mdns_operations
                        .insert(operation, MdnsOperation::Browse(*scope));
                }
                Err(failure) => {
                    error = Some(failure.to_string());
                }
            }
        }
        for socket in self.transports.iter() {
            if self.mdns_operations.values().any(
                |operation| matches!(operation, MdnsOperation::Register(id) if *id == socket.id),
            ) {
                continue;
            }
            // One advertisement per bound socket, always naming this node's own
            // key. Which relationship an observer attributes it to is decided by
            // the observer's own pinned set, never by anything we transmit.
            let Ok(advertisement) = LanAdvertisement::new(self_key, endpoint(socket.local)) else {
                continue;
            };
            let instance = format!("lzh-{}-{}", &self_key.to_string()[..12], socket.id.0);
            match client.register(
                socket.interface_index,
                &instance,
                "_lzh-hole._udp",
                advertisement.port,
                &advertisement.txt,
            ) {
                Ok(operation) => {
                    self.mdns_operations
                        .insert(operation, MdnsOperation::Register(socket.id));
                }
                Err(failure) => {
                    error = Some(failure.to_string());
                }
            }
        }
        if let Some(error) = error {
            self.lan_status = component(
                ComponentState::Degraded,
                format!("Bonjour: {error}; established UDP path unchanged"),
                self.lan_status.last_success_unix_ms,
            );
        }
        if self.mdns_operations.is_empty() {
            self.mdns = None;
        }
        self.next_mdns_retry = Instant::now() + RECOVERY_RETRY;
    }

    pub(super) fn handle_mdns(&mut self, event: std::io::Result<MdnsEvent>) {
        let event = match event {
            Ok(event) => event,
            Err(error) => {
                self.reset_mdns_scopes();
                // Recreate scope epochs only during the bounded topology retry.
                self.next_interface_check = Instant::now() + RECOVERY_RETRY;
                self.next_mdns_retry = Instant::now() + RECOVERY_RETRY;
                self.lan_status = component(
                    ComponentState::Degraded,
                    format!("Bonjour stopped: {error}; UDP session retained"),
                    self.lan_status.last_success_unix_ms,
                );
                self.reproject_candidates();
                return;
            }
        };
        match event {
            MdnsEvent::Registered { operation, .. } => {
                if let Some(MdnsOperation::Register(id)) = self.mdns_operations.get(&operation)
                    && self.transports.get(*id).is_some()
                {
                    self.lan_status = component(
                        ComponentState::Healthy,
                        "Bonjour registration active; not peer health",
                        Some(now_unix_ms()),
                    );
                }
            }
            MdnsEvent::Upsert { operation, record } => {
                let Some(MdnsOperation::Browse(scope)) =
                    self.mdns_operations.get(&operation).copied()
                else {
                    return;
                };
                if self.lan_scopes.get(&record.key.interface_index) != Some(&scope) {
                    return;
                }
                let instance = record.key.name;
                let ttl = record
                    .srv_ttl
                    .unwrap_or(0)
                    .min(record.txt_ttl.unwrap_or(0))
                    .min(
                        record
                            .addresses
                            .iter()
                            .map(|address| address.ttl)
                            .min()
                            .unwrap_or(0),
                    );
                let ttl_ms = u64::from(ttl).saturating_mul(1000).saturating_sub(
                    record
                        .observed_at
                        .elapsed()
                        .as_millis()
                        .min(u128::from(u64::MAX)) as u64,
                );
                let addresses = record
                    .addresses
                    .into_iter()
                    .map(|address| address.address)
                    .filter(|address| {
                        !self
                            .transports
                            .iter()
                            .any(|socket| socket.local.ip() == address)
                    })
                    .collect();
                let observation = LanObservation {
                    instance: instance.clone(),
                    scope,
                    addresses,
                    port: record.port,
                    txt: record.txt,
                    ttl_ms,
                };
                // The relationship comes from the pinned key in the
                // advertisement's TXT record, resolved inside LanDiscovery. An
                // advertisement from a key we do not pin is refused there.
                let updates = match self.lan.observe(observation, self.monotonic_ms()) {
                    Ok(updates) => updates
                        .into_iter()
                        .map(|update| (update.relationship_id, update.update))
                        .collect::<Vec<_>>(),
                    Err(_) => {
                        self.record_drop("invalid_lan_observation", 1);
                        self.lan
                            .remove(&instance, scope)
                            .into_iter()
                            .map(|update| (update.relationship_id, update.update))
                            .collect::<Vec<_>>()
                    }
                };
                self.apply_tagged_updates(updates);
            }
            MdnsEvent::Remove { operation, key } => {
                let Some(MdnsOperation::Browse(scope)) =
                    self.mdns_operations.get(&operation).copied()
                else {
                    return;
                };
                if self.lan_scopes.get(&key.interface_index) == Some(&scope) {
                    let updates = self
                        .lan
                        .remove(&key.name, scope)
                        .into_iter()
                        .map(|update| (update.relationship_id, update.update))
                        .collect::<Vec<_>>();
                    self.apply_tagged_updates(updates);
                }
            }
            MdnsEvent::Error { operation, code } => {
                if let Some(MdnsOperation::Browse(scope)) = self.mdns_operations.remove(&operation)
                {
                    let updates = self
                        .lan
                        .revoke_interface(scope)
                        .into_iter()
                        .map(|update| (update.relationship_id, update.update))
                        .collect::<Vec<_>>();
                    self.apply_tagged_updates(updates);
                }
                self.lan_status = component(
                    ComponentState::Degraded,
                    format!("Bonjour operation failed ({code}); independent UDP session retained"),
                    self.lan_status.last_success_unix_ms,
                );
                if self.mdns_operations.is_empty() {
                    self.mdns = None;
                }
                self.next_mdns_retry = Instant::now() + RECOVERY_RETRY;
            }
        }
    }

    pub(super) async fn maybe_start_stun(&mut self) {
        if !self.network_enabled {
            return;
        }
        let ids = self
            .transports
            .iter()
            .map(|socket| socket.id)
            .collect::<Vec<_>>();
        for id in ids {
            let mut transaction = [0; TRANSACTION_ID_LEN];
            if getrandom::fill(&mut transaction).is_err() {
                self.record_drop("stun_randomness_failed", 1);
                continue;
            }
            let effect = match self
                .public
                .start_stun(id.0, transaction, self.monotonic_ms())
            {
                Ok(Some(effect)) => effect,
                Ok(None) => continue,
                Err(_) => {
                    self.record_drop("stun_encode_failed", 1);
                    continue;
                }
            };
            let Some(socket) = self.transports.get(id) else {
                continue;
            };
            match socket.socket.try_send_to(&effect.packet, effect.server) {
                Ok(written) if written == effect.packet.len() => {
                    self.bytes.udp_tx = self.bytes.udp_tx.saturating_add(written as u64);
                }
                _ => {
                    self.public
                        .stun_send_failed(id.0, transaction, self.monotonic_ms());
                    self.record_drop("stun_send_failed", 1);
                    self.stun_status = component(
                        ComponentState::Degraded,
                        "STUN send failed; data transports retained",
                        self.stun_status.last_success_unix_ms,
                    );
                }
            }
        }
    }

    pub(super) fn handle_stun(&mut self, id: TransportId, packet: &[u8], metadata: RecvMeta) {
        match self
            .public
            .receive_stun(id.0, metadata.source, packet, self.monotonic_ms())
        {
            Ok(Some(mapping)) => {
                self.stun_status = component(
                    ComponentState::Healthy,
                    format!(
                        "measured {} on transport {}; not peer health",
                        mapping.endpoint, id.0
                    ),
                    Some(now_unix_ms()),
                );
                self.refresh_public_requests();
            }
            Ok(None) => self.record_drop("unexpected_stun", 1),
            Err(_) => self.record_drop("bad_stun_response", 1),
        }
    }

    /// The single ntfy actor stopped. Every relationship loses coordination;
    /// none of them loses its UDP data path or its persisted pacing budget.
    pub(super) fn handle_ntfy_closed(&mut self) {
        self.ntfy_events = None;
        for peer in self.peers.values_mut() {
            peer.ntfy.subscribed = false;
            peer.ntfy.status = component(
                ComponentState::Failed,
                "ntfy actor stopped; UDP continues and the operation budget is not reset",
                peer.ntfy.status.last_success_unix_ms,
            );
        }
    }

    pub(super) async fn handle_ntfy(&mut self, event: NtfyEvent) {
        match event {
            NtfyEvent::Subscribed {
                relationship,
                cached_replay,
            } => {
                let Some(peer) = self.peers.get_mut(&relationship) else {
                    self.record_drop("unknown_relationship_event", 1);
                    return;
                };
                peer.ntfy.subscribed = true;
                peer.ntfy.clear_block();
                peer.ntfy.status = ComponentStatus {
                    state: ComponentState::Healthy,
                    detail: Some(format!(
                        "NDJSON subscribed (cached_replay={cached_replay}); this is not peer \
                         presence; requests remain paced and retain their signed expiry"
                    )),
                    last_success_unix_ms: Some(now_unix_ms()),
                    last_change_unix_ms: Some(now_unix_ms()),
                };
                // A reconnect does not invalidate an already published request.
                // Keep its correlation and original signed expiry instead of
                // burning another public operation and durable sequence.
                self.maybe_queue_request_for(relationship);
            }
            NtfyEvent::Received {
                relationship,
                payload,
                delivery,
                ntfy_id,
            } => {
                self.handle_signed_payload(relationship, payload, delivery, &ntfy_id)
                    .await
            }
            NtfyEvent::Published {
                relationship,
                kind,
                request_id,
            } => {
                let Some(peer) = self.peers.get_mut(&relationship) else {
                    self.record_drop("unknown_relationship_event", 1);
                    return;
                };
                peer.ntfy.clear_block();
                let now = now_unix_ms();
                if peer.ntfy.subscribed {
                    peer.ntfy.status.state = ComponentState::Healthy;
                    peer.ntfy.status.last_success_unix_ms = Some(now);
                    peer.ntfy.status.last_change_unix_ms = Some(now);
                }
                peer.ntfy.status.detail = Some(format!(
                    "ntfy HTTP 200 for {kind:?}/{request_id}; not peer receipt, presence or UDP health"
                ));
            }
            NtfyEvent::PublishFailed {
                relationship,
                kind,
                request_id,
                detail,
            } => {
                // Read the clock before taking the peer borrow: the peer is
                // borrowed mutably for the rest of this arm.
                let now = self.monotonic_ms();
                let Some(peer) = self.peers.get_mut(&relationship) else {
                    self.record_drop("unknown_relationship_event", 1);
                    return;
                };
                if kind == MessageKind::Request
                    && peer
                        .public
                        .pending_request()
                        .is_some_and(|pending| pending.id == request_id)
                {
                    peer.exchange.cancel_request(request_id);
                    peer.public.request_failed(request_id, now);
                }
                let status = peer.ntfy.degraded(format!(
                    "signed payload discarded without POST success: {detail}"
                ));
                peer.ntfy.status = status;
            }
            NtfyEvent::Error {
                relationship,
                operation,
                detail,
                retry_after,
            } => {
                let latest = format!("ntfy {operation}: {detail}; UDP state is independent");
                // A host-level failure is reported against every relationship;
                // an attributed one only against its own, so one relationship's
                // stream failure never marks another relationship degraded.
                let targets = match relationship {
                    Some(id) if self.peers.contains_key(&id) => vec![id],
                    Some(_) => {
                        self.record_drop("unknown_relationship_event", 1);
                        return;
                    }
                    None => self.peer_order.clone(),
                };
                for id in targets {
                    let Some(peer) = self.peers.get_mut(&id) else {
                        continue;
                    };
                    if let Some(delay) = retry_after {
                        peer.ntfy.note_retry_after(latest.clone(), delay);
                    }
                    let status = peer.ntfy.degraded(latest.clone());
                    peer.ntfy.status = status;
                    if operation == NtfyOperation::Subscribe {
                        peer.ntfy.subscribed = false;
                    }
                }
            }
        }
    }

    /// Verify one payload against exactly one relationship and use its candidates.
    pub(super) async fn handle_signed_payload(
        &mut self,
        relationship: RelationshipId,
        payload: SignedPayload,
        delivery: Delivery,
        ntfy_id: &str,
    ) {
        if !self.peers.contains_key(&relationship) {
            self.record_drop("unknown_relationship", 1);
            return;
        }
        let monotonic = self.monotonic_ms();
        let (stun_servers, forbidden_addresses) = self.node_fact_parts();
        let self_key = self.self_key();
        let boot_id = self.boot_id;
        let generation = self.generation;
        let flags = self.record_flags_for(relationship);
        let punch_offer_deadline = self.punch_offer_deadline_for(relationship);

        let facts = NodeFacts {
            ntfy_handle: self.ntfy_handle.as_ref(),
            engines: self.engines.as_ref(),
            state: &self.state,
            signing_key: &self.signing_key,
            public: &self.public,
            transports: &self.transports,
            boot_id,
            generation,
            self_key,
            stun_servers,
            forbidden_addresses,
            monotonic_ms: monotonic,
            flags,
            punch_offer_deadline,
        };
        let Some(peer) = self.peers.get_mut(&relationship) else {
            return;
        };
        let (updates, verified) = match facts.accept_payload(peer, &payload) {
            Ok(value) => value,
            Err(detail) => {
                peer.record_drop("invalid_peer_record", 1);
                peer.ntfy.write_detail(detail);
                return;
            }
        };
        peer.ntfy.write_detail(format!(
            "verified ntfy message {ntfy_id} as {delivery:?}; candidates only, not online evidence"
        ));
        let action = facts.apply_exchange(peer, &verified, delivery);

        let tagged = updates
            .into_iter()
            .map(|update| (relationship, update))
            .collect::<Vec<_>>();
        self.apply_tagged_updates(tagged);

        match action {
            ExchangeAction::ReplyOnce(request_id) => {
                let Some(peer) = self.peers.get_mut(&relationship) else {
                    return;
                };
                if peer.ntfy.waiting() {
                    let status = peer.ntfy.degraded(
                        "live request verified, but its reply is deferred until the persisted ntfy                          retry boundary; peer must use a fresh request"
                            .to_owned(),
                    );
                    peer.ntfy.status = status;
                    return;
                }
                let facts = NodeFacts {
                    ntfy_handle: self.ntfy_handle.as_ref(),
                    engines: self.engines.as_ref(),
                    state: &self.state,
                    signing_key: &self.signing_key,
                    public: &self.public,
                    transports: &self.transports,
                    boot_id,
                    generation,
                    self_key,
                    stun_servers: self
                        .resolved
                        .config
                        .stun_seeds
                        .iter()
                        .map(|server| endpoint(*server))
                        .collect(),
                    forbidden_addresses: self.forbidden_addresses(),
                    monotonic_ms: self.monotonic_ms(),
                    flags: self.record_flags_for(relationship),
                    punch_offer_deadline: self.punch_offer_deadline_for(relationship),
                };
                let Some(peer) = self.peers.get_mut(&relationship) else {
                    return;
                };
                if let Err(error) = facts.queue_payload(peer, MessageKind::Reply, request_id) {
                    peer.ntfy.write_detail(error);
                }
            }
            ExchangeAction::ReplyMatched(request_id) => {
                let monotonic = self.monotonic_ms();
                if let Some(peer) = self.peers.get_mut(&relationship) {
                    peer.public.request_matched(request_id, monotonic);
                }
            }
            ExchangeAction::Cached
            | ExchangeAction::DuplicateRequest
            | ExchangeAction::UnmatchedReply => {}
        }
    }

    /// Consider every relationship for a fresh coordination request.
    pub(super) fn maybe_queue_requests(&mut self) {
        if !self.network_enabled {
            return;
        }
        for id in self.peer_order.clone() {
            self.maybe_queue_request_for(id);
        }
    }

    /// Queue one relationship's request if it is actually due.
    ///
    /// Skipped while this peer's own engine is healthy: coordination exists to
    /// find a path, not to keep one alive.
    pub(super) fn maybe_queue_request_for(&mut self, relationship: RelationshipId) {
        if !self.network_enabled {
            return;
        }
        let monotonic = self.monotonic_ms();
        let now = now_unix_ms();
        if self.public.own_mappings(monotonic).is_empty() {
            return;
        }
        let (stun_servers, forbidden_addresses) = self.node_fact_parts();
        let self_key = self.self_key();
        let boot_id = self.boot_id;
        let generation = self.generation;
        let flags = self.record_flags_for(relationship);
        let punch_offer_deadline = self.punch_offer_deadline_for(relationship);

        let ready = {
            let Some(peer) = self.peers.get(&relationship) else {
                return;
            };
            let facts = NodeFacts {
                ntfy_handle: self.ntfy_handle.as_ref(),
                engines: self.engines.as_ref(),
                state: &self.state,
                signing_key: &self.signing_key,
                public: &self.public,
                transports: &self.transports,
                boot_id,
                generation,
                self_key,
                stun_servers: stun_servers.clone(),
                forbidden_addresses: forbidden_addresses.clone(),
                monotonic_ms: monotonic,
                flags,
                punch_offer_deadline,
            };
            peer.ntfy.subscribed
                && !peer.ntfy.waiting()
                && peer.public.request_due(monotonic)
                && !facts.peer_is_healthy(peer, now)
        };
        if !ready {
            return;
        }

        let request = match RequestId::random() {
            Ok(request) => request,
            Err(error) => {
                if let Some(peer) = self.peers.get_mut(&relationship) {
                    peer.ntfy.write_detail(error.to_string());
                }
                return;
            }
        };
        if let Some(peer) = self.peers.get_mut(&relationship)
            && let Err(error) = peer.exchange.register_request(request)
        {
            peer.ntfy.write_detail(error.to_string());
            peer.public.request_queue_failed(monotonic);
            return;
        }

        let facts = NodeFacts {
            ntfy_handle: self.ntfy_handle.as_ref(),
            engines: self.engines.as_ref(),
            state: &self.state,
            signing_key: &self.signing_key,
            public: &self.public,
            transports: &self.transports,
            boot_id,
            generation,
            self_key,
            stun_servers,
            forbidden_addresses,
            monotonic_ms: monotonic,
            flags,
            punch_offer_deadline,
        };
        let Some(peer) = self.peers.get_mut(&relationship) else {
            return;
        };
        match facts.queue_payload(peer, MessageKind::Request, request) {
            Ok(expires_at) => {
                peer.public
                    .request_started(request, expires_at, now, monotonic);
            }
            Err(error) => {
                peer.exchange.cancel_request(request);
                peer.public.request_queue_failed(monotonic);
                peer.ntfy.write_detail(error);
            }
        }
    }
}
