use super::status::component;
use super::*;

#[derive(Debug)]
pub(super) struct PendingRequest {
    pub(super) id: RequestId,
    pub(super) expires_at_unix_ms: u64,
}

#[derive(Debug)]
pub(super) struct NtfyBlock {
    pub(super) detail: String,
    pub(super) not_before_unix_ms: u64,
}

impl Daemon {
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
                        .pending_request
                        .as_ref()
                        .is_some_and(|pending| pending.id == request_id)
                {
                    self.exchange.cancel_request(request_id);
                    self.pending_request = None;
                    self.request_failures = self.request_failures.saturating_add(1).min(16);
                    self.next_request = Instant::now() + request_retry_delay(self.request_failures);
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
        policy.own_endpoints = self.own_endpoints(now);
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
        if let Some(state) = verified.state_to_persist()
            && let Err(error) = self.peer_cache.commit(state)
        {
            self.record_drop("peer_highwater_write_failed", 1);
            self.write_ntfy_detail(format!(
                "signed payload not used because its high-water commit failed: {error}"
            ));
            return;
        }
        self.write_ntfy_detail(format!(
            "verified ntfy message {ntfy_id} as {delivery:?}; candidates only, not online evidence"
        ));
        self.candidates = verified.validated.targets.clone();
        if let Some(engine) = &mut self.engine {
            engine.set_candidates(&self.candidates);
        }
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
                if self
                    .pending_request
                    .as_ref()
                    .is_some_and(|pending| pending.id == request_id)
                {
                    self.pending_request = None;
                    self.request_failures = 0;
                    self.next_request = Instant::now() + REQUEST_REFRESH;
                }
            }
            ExchangeAction::Cached
            | ExchangeAction::DuplicateRequest
            | ExchangeAction::UnmatchedReply => {}
        }
    }

    pub(super) fn own_endpoints(&self, now_ms: u64) -> Vec<Endpoint> {
        let mut endpoints = self.stun.own_mappings(now_ms);
        if let Some(socket) = &self.socket {
            endpoints.push(endpoint(socket.get_ref().local_addr()));
        }
        endpoints.sort();
        endpoints.dedup();
        endpoints
    }

    pub(super) fn maybe_queue_request(&mut self) {
        if !self.network_enabled
            || !self.ntfy_subscribed
            || self.ntfy_waiting()
            || self.pending_request.is_some()
            || Instant::now() < self.next_request
            || self.stun.own_mappings(now_unix_ms()).is_empty()
        {
            return;
        }
        if self
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
            self.next_request = Instant::now() + REQUEST_RETRY;
            return;
        }
        match self.queue_payload(MessageKind::Request, id) {
            Ok(expires_at) => {
                self.pending_request = Some(PendingRequest {
                    id,
                    expires_at_unix_ms: expires_at,
                });
            }
            Err(error) => {
                self.exchange.cancel_request(id);
                self.pending_request = None;
                self.next_request = Instant::now() + REQUEST_RETRY;
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
        let candidates = self
            .stun
            .own_mappings(now)
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
