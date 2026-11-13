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
    pub(super) fn refresh_public_request(&mut self) {
        if let Some(id) = self.public.request_refresh_needed(self.monotonic_ms()) {
            self.exchange.cancel_request(id);
        }
    }

    pub(super) fn reset_mdns_scopes(&mut self) {
        self.mdns = None;
        self.mdns_operations.clear();
        let scopes = std::mem::take(&mut self.lan_scopes);
        let transports = self.candidate_transports();
        for scope in scopes.into_values() {
            for update in self.lan.revoke_interface(scope) {
                self.registry.apply(update, &transports);
            }
        }
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
            let Ok(advertisement) = LanAdvertisement::new(
                self.resolved.relationship.self_public_key,
                endpoint(socket.local),
            ) else {
                continue;
            };
            let instance = format!(
                "lzh-{}-{}",
                &self.resolved.relationship.self_public_key.to_string()[..12],
                socket.id.0
            );
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
                let updates = match self.lan.observe(observation, self.monotonic_ms()) {
                    Ok(updates) => updates,
                    Err(_) => {
                        self.record_drop("invalid_lan_observation", 1);
                        self.lan.remove(&instance, scope)
                    }
                };
                if !updates.is_empty() {
                    self.apply_discovery_updates(updates);
                }
            }
            MdnsEvent::Remove { operation, key } => {
                let Some(MdnsOperation::Browse(scope)) =
                    self.mdns_operations.get(&operation).copied()
                else {
                    return;
                };
                if self.lan_scopes.get(&key.interface_index) == Some(&scope) {
                    let updates = self.lan.remove(&key.name, scope);
                    if !updates.is_empty() {
                        self.apply_discovery_updates(updates);
                    }
                }
            }
            MdnsEvent::Error { operation, code } => {
                if let Some(MdnsOperation::Browse(scope)) = self.mdns_operations.remove(&operation)
                {
                    let updates = self.lan.revoke_interface(scope);
                    if !updates.is_empty() {
                        self.apply_discovery_updates(updates);
                    }
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
                self.refresh_public_request();
            }
            Ok(None) => self.record_drop("unexpected_stun", 1),
            Err(_) => self.record_drop("bad_stun_response", 1),
        }
    }

    pub(super) async fn handle_ntfy(&mut self, event: NtfyEvent) {
        match event {
            NtfyEvent::Subscribed { cached_replay } => {
                self.ntfy_subscribed = true;
                self.ntfy_block = None;
                self.ntfy_status = ComponentStatus {
                    state: ComponentState::Healthy,
                    detail: Some(format!(
                        "NDJSON subscribed (cached_replay={cached_replay}); this is not peer presence; requests remain paced and retain their signed expiry"
                    )),
                    last_success_unix_ms: Some(now_unix_ms()),
                    last_change_unix_ms: Some(now_unix_ms()),
                };
                // A reconnect does not invalidate an already published request.
                // Keep its correlation and original signed expiry instead of
                // burning another public operation and durable sequence.
                self.maybe_queue_request();
            }
            NtfyEvent::Received {
                payload,
                delivery,
                ntfy_id,
            } => {
                self.handle_signed_payload(payload, delivery, &ntfy_id)
                    .await
            }
            NtfyEvent::Published { kind, request_id } => {
                self.ntfy_block = None;
                let now = now_unix_ms();
                if self.ntfy_subscribed {
                    self.ntfy_status.state = ComponentState::Healthy;
                    self.ntfy_status.last_success_unix_ms = Some(now);
                    self.ntfy_status.last_change_unix_ms = Some(now);
                }
                self.ntfy_status.detail = Some(format!(
                    "ntfy HTTP 200 for {kind:?}/{request_id}; not peer receipt, presence or UDP health"
                ));
            }
            NtfyEvent::PublishFailed {
                kind,
                request_id,
                detail,
            } => {
                if kind == MessageKind::Request
                    && self
                        .public
                        .pending_request()
                        .is_some_and(|pending| pending.id == request_id)
                {
                    self.exchange.cancel_request(request_id);
                    self.public.request_failed(request_id, self.monotonic_ms());
                }
                self.ntfy_status = self.degraded_ntfy(format!(
                    "signed payload discarded without POST success: {detail}"
                ));
            }
            NtfyEvent::Error {
                operation,
                detail,
                retry_after,
            } => {
                let latest = format!("ntfy {operation}: {detail}; UDP state is independent");
                if let Some(delay) = retry_after.filter(|delay| !delay.is_zero()) {
                    let now = now_unix_ms();
                    let delay_ms = delay.as_millis().min(u64::MAX as u128) as u64;
                    let proposed = now.saturating_add(delay_ms);
                    let previous = self
                        .ntfy_block
                        .as_ref()
                        .filter(|block| block.not_before_unix_ms > now);
                    let not_before_unix_ms = previous
                        .map(|block| block.not_before_unix_ms.max(proposed))
                        .unwrap_or(proposed);
                    let detail = previous
                        .map(|block| block.detail.clone())
                        .unwrap_or(latest.clone());
                    self.ntfy_block = Some(NtfyBlock {
                        detail,
                        not_before_unix_ms,
                    });
                }
                self.ntfy_status = self.degraded_ntfy(latest);
                if operation == NtfyOperation::Subscribe {
                    self.ntfy_subscribed = false;
                }
            }
        }
    }

    fn degraded_ntfy(&self, latest: String) -> ComponentStatus {
        let now = now_unix_ms();
        if let Some(block) = self
            .ntfy_block
            .as_ref()
            .filter(|block| block.not_before_unix_ms > now)
        {
            let latest = if latest == block.detail {
                String::new()
            } else {
                format!("; latest: {latest}")
            };
            return component(
                ComponentState::Degraded,
                format!(
                    "{}{latest}; ntfy operations blocked until unix ms {}",
                    block.detail, block.not_before_unix_ms
                ),
                self.ntfy_status.last_success_unix_ms,
            );
        }
        component(
            ComponentState::Degraded,
            latest,
            self.ntfy_status.last_success_unix_ms,
        )
    }

    fn ntfy_waiting(&self) -> bool {
        self.ntfy_block
            .as_ref()
            .is_some_and(|block| block.not_before_unix_ms > now_unix_ms())
    }

    fn write_ntfy_detail(&mut self, detail: String) {
        if self.ntfy_waiting() {
            self.ntfy_status = self.degraded_ntfy(detail);
        } else {
            self.ntfy_status.detail = Some(detail);
        }
    }

    pub(super) async fn handle_signed_payload(
        &mut self,
        payload: SignedPayload,
        delivery: Delivery,
        ntfy_id: &str,
    ) {
        let now = now_unix_ms();
        let mut policy = PeerRecordPolicy::new(
            self.resolved.relationship.relationship_id,
            self.resolved.relationship.self_public_key,
            self.resolved.relationship.peer_public_key,
            now,
        );
        policy.stun_servers = self
            .resolved
            .config
            .stun_seeds
            .iter()
            .map(|address| endpoint(*address))
            .collect();
        policy.own_endpoints = self.own_endpoints(self.monotonic_ms());
        policy.forbidden_addresses = vec![self.resolved.self_vip, self.resolved.peer_vip];
        let verified = match payload.verify(&policy, self.peer_cache.state()) {
            Ok(verified) => verified,
            Err(error) => {
                self.record_drop("invalid_peer_record", 1);
                self.write_ntfy_detail(format!(
                    "signed payload rejected; not used as a candidate: {error}"
                ));
                return;
            }
        };
        let monotonic = self.monotonic_ms();
        let updates = match self
            .public
            .accept_verified(&verified, now, monotonic, |state| {
                self.peer_cache.commit(state)
            }) {
            Ok(updates) => updates,
            Err(error) => {
                self.record_drop("peer_highwater_write_failed", 1);
                self.write_ntfy_detail(format!("signed payload not used: {error:?}"));
                return;
            }
        };
        self.write_ntfy_detail(format!(
            "verified ntfy message {ntfy_id} as {delivery:?}; candidates only, not online evidence"
        ));
        self.apply_discovery_updates(updates);
        match self.exchange.on_verified(&verified, delivery) {
            ExchangeAction::ReplyOnce(request_id) => {
                if self.ntfy_waiting() {
                    self.ntfy_status = self.degraded_ntfy(
                        "live request verified, but its reply is deferred until the persisted ntfy retry boundary; peer must use a fresh request"
                            .to_owned(),
                    );
                } else if let Err(error) = self.queue_payload(MessageKind::Reply, request_id) {
                    self.write_ntfy_detail(error);
                }
            }
            ExchangeAction::ReplyMatched(request_id) => {
                self.public.request_matched(request_id, self.monotonic_ms());
            }
            ExchangeAction::Cached
            | ExchangeAction::DuplicateRequest
            | ExchangeAction::UnmatchedReply => {}
        }
    }

    pub(super) fn own_endpoints(&self, now_ms: u64) -> Vec<Endpoint> {
        let mut endpoints = self
            .public
            .own_mappings(now_ms)
            .into_iter()
            .map(|mapping| mapping.endpoint)
            .collect::<Vec<_>>();
        endpoints.extend(self.transports.iter().map(|socket| endpoint(socket.local)));
        endpoints.sort();
        endpoints.dedup();
        endpoints
    }

    pub(super) fn maybe_queue_request(&mut self) {
        if !self.network_enabled
            || !self.ntfy_subscribed
            || self.ntfy_waiting()
            || !self.public.request_due(self.monotonic_ms())
            || self.public.own_mappings(self.monotonic_ms()).is_empty()
            || self
                .engine
                .as_ref()
                .is_some_and(|engine| engine.snapshot(now_unix_ms()).currently_healthy)
        {
            return;
        }
        let id = match RequestId::random() {
            Ok(id) => id,
            Err(error) => {
                self.write_ntfy_detail(error.to_string());
                return;
            }
        };
        if let Err(error) = self.exchange.register_request(id) {
            self.write_ntfy_detail(error.to_string());
            self.public.request_queue_failed(self.monotonic_ms());
            return;
        }
        match self.queue_payload(MessageKind::Request, id) {
            Ok(expires_at) => {
                self.public
                    .request_started(id, expires_at, now_unix_ms(), self.monotonic_ms());
            }
            Err(error) => {
                self.exchange.cancel_request(id);
                self.public.request_queue_failed(self.monotonic_ms());
                self.write_ntfy_detail(error);
            }
        }
    }

    /// Build and queue a signed payload. Sequence persistence always precedes signing.
    pub(super) fn queue_payload(
        &mut self,
        kind: MessageKind,
        id: RequestId,
    ) -> Result<u64, String> {
        let now = now_unix_ms();
        let candidates = publication_endpoints(self.public.own_mappings(self.monotonic_ms()))
            .into_iter()
            .map(|endpoint| RecordCandidate {
                endpoint,
                source: CandidateSource::Stun,
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Err(
                "no fresh measured STUN mapping; refusing an empty contact record".to_owned(),
            );
        }
        let durable = self
            .state
            .load_sequence()
            .map_err(|error| error.to_string())?;
        let highest_peer = self.peer_cache.highest_seq().unwrap_or(0);
        let sequence = reserve_sequence(durable, highest_peer, now_unix_us())
            .map_err(|error| error.to_string())?;
        self.state
            .store_sequence(sequence)
            .map_err(|error| error.to_string())?;
        let expires_at = now.saturating_add(MAX_LIFETIME_MS);
        let record = ContactRecord {
            relationship_id: self.resolved.relationship.relationship_id,
            sender: self.resolved.relationship.self_public_key,
            receiver: self.resolved.relationship.peer_public_key,
            record_seq: sequence,
            issued_at_unix_ms: now,
            expires_at_unix_ms: expires_at,
            boot_id: self.boot_id,
            generation: self.generation,
            candidates,
        };
        // No publish queueing or signing happens before the durable reservation above.
        let payload = SignedPayload::sign(kind, id, &record, &self.signing_key)
            .map_err(|error| error.to_string())?;
        let handle = self
            .ntfy_handle
            .as_ref()
            .ok_or_else(|| "ntfy transport is not running".to_owned())?;
        handle
            .try_publish(payload)
            .map_err(|error| error.to_string())?;
        Ok(expires_at)
    }
}
