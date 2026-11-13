use super::status::component;
use super::*;

#[derive(Debug)]
pub(super) struct StunState {
    pub(super) servers: Vec<SocketAddrV4>,
    pub(super) next_server: usize,
    pub(super) in_flight: Option<StunRequest>,
    pub(super) next_probe: Instant,
    pub(super) mappings: BTreeMap<Endpoint, u64>,
    pub(super) consecutive_timeouts: u32,
    pub(super) status: ComponentStatus,
}

#[derive(Debug)]
pub(super) struct StunRequest {
    pub(super) transaction: [u8; TRANSACTION_ID_LEN],
    pub(super) server: SocketAddrV4,
    pub(super) started_at: Instant,
}

impl StunState {
    pub(super) fn new(servers: Vec<SocketAddrV4>) -> Self {
        Self {
            servers,
            next_server: 0,
            in_flight: None,
            next_probe: Instant::now(),
            mappings: BTreeMap::new(),
            consecutive_timeouts: 0,
            status: ComponentStatus {
                state: ComponentState::Starting,
                detail: Some("no STUN mapping measured on this socket".to_owned()),
                ..ComponentStatus::default()
            },
        }
    }

    pub(super) fn own_mappings(&self, now_ms: u64) -> Vec<Endpoint> {
        self.mappings
            .iter()
            .filter(|(_, observed)| now_ms.saturating_sub(**observed) < STUN_MAPPING_TTL_MS)
            .map(|(endpoint, _)| *endpoint)
            .take(MAX_OWN_MAPPINGS)
            .collect()
    }
}

impl Daemon {
    pub(super) async fn maybe_start_stun(&mut self) {
        if !self.network_enabled || self.stun.servers.is_empty() {
            return;
        }
        if let Some(request) = &self.stun.in_flight {
            let started_at = request.started_at;
            let server = request.server;
            if started_at.elapsed() >= STUN_TIMEOUT {
                self.stun.in_flight = None;
                self.stun.next_probe = Instant::now() + STUN_INTERVAL;
                self.stun.consecutive_timeouts = self.stun.consecutive_timeouts.saturating_add(1);
                self.stun.status = component(
                    ComponentState::Degraded,
                    format!("STUN response from {server} timed out"),
                    self.stun.status.last_success_unix_ms,
                );
                if self.stun.consecutive_timeouts >= self.stun.servers.len() as u32 {
                    self.schedule_recovery("every STUN server timed out on this interface");
                }
            } else {
                return;
            }
        }
        if Instant::now() < self.stun.next_probe {
            return;
        }
        let Some(socket) = &self.socket else {
            return;
        };
        let server = self.stun.servers[self.stun.next_server % self.stun.servers.len()];
        self.stun.next_server = (self.stun.next_server + 1) % self.stun.servers.len();
        let mut transaction = [0u8; TRANSACTION_ID_LEN];
        if getrandom::fill(&mut transaction).is_err() {
            self.stun.status = component(
                ComponentState::Failed,
                "OS randomness unavailable for STUN transaction",
                self.stun.status.last_success_unix_ms,
            );
            self.stun.next_probe = Instant::now() + STUN_INTERVAL;
            return;
        }
        let request = match build_binding_request(&transaction) {
            Ok(request) => request,
            Err(error) => {
                self.stun.status = component(
                    ComponentState::Failed,
                    format!("STUN encode: {error}"),
                    self.stun.status.last_success_unix_ms,
                );
                return;
            }
        };
        match timeout(SOCKET_IO_TIMEOUT, socket.send_to(&request, server)).await {
            Ok(Ok(written)) if written == request.len() => {
                self.bytes.udp_tx = self.bytes.udp_tx.saturating_add(written as u64);
                self.stun.in_flight = Some(StunRequest {
                    transaction,
                    server,
                    started_at: Instant::now(),
                });
            }
            _ => {
                self.record_drop("stun_send_failed", 1);
                self.stun.next_probe = Instant::now() + STUN_INTERVAL;
                self.stun.status = component(
                    ComponentState::Degraded,
                    format!("STUN send to {server} failed"),
                    self.stun.status.last_success_unix_ms,
                );
                self.schedule_recovery("UDP send failed during STUN");
            }
        }
    }

    pub(super) fn handle_stun(&mut self, packet: &[u8], metadata: RecvMeta) {
        let Some(request) = self.stun.in_flight.take() else {
            self.record_drop("unexpected_stun", 1);
            return;
        };
        match parse_binding_response_from(
            packet,
            &request.transaction,
            request.server,
            metadata.source,
        ) {
            Ok(response) => {
                self.stun.consecutive_timeouts = 0;
                let servers = self
                    .resolved
                    .config
                    .stun_seeds
                    .iter()
                    .map(|address| endpoint(*address))
                    .collect::<Vec<_>>();
                if let Err(reason) = validate_publishable(&response.mapped, &servers) {
                    self.record_drop("invalid_stun_mapping", 1);
                    self.stun.status = component(
                        ComponentState::Degraded,
                        format!("STUN mapping refused: {reason}"),
                        self.stun.status.last_success_unix_ms,
                    );
                } else {
                    let now = now_unix_ms();
                    let new_mapping = !self.stun.mappings.contains_key(&response.mapped)
                        && self.stun.mappings.len() < MAX_OWN_MAPPINGS;
                    if self.stun.mappings.len() < MAX_OWN_MAPPINGS
                        || self.stun.mappings.contains_key(&response.mapped)
                    {
                        self.stun.mappings.insert(response.mapped, now);
                    }
                    if new_mapping {
                        if let Some(pending) = self.pending_request.take() {
                            self.exchange.cancel_request(pending.id);
                        }
                        self.next_request = Instant::now();
                    }
                    self.stun.status = ComponentStatus {
                        state: ComponentState::Healthy,
                        detail: Some(format!(
                            "measured {} on the retained data socket; not peer health",
                            response.mapped
                        )),
                        last_success_unix_ms: Some(now),
                        last_change_unix_ms: Some(now),
                    };
                }
            }
            Err(error) => {
                self.record_drop("bad_stun_response", 1);
                self.stun.status = component(
                    ComponentState::Degraded,
                    format!("STUN response rejected: {error}"),
                    self.stun.status.last_success_unix_ms,
                );
            }
        }
        self.stun.next_probe = Instant::now() + STUN_INTERVAL;
    }
}
