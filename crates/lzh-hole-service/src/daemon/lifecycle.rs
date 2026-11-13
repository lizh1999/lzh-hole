use super::status::component;
use super::stun::StunState;
use super::*;

impl Daemon {
    pub(super) async fn rebuild_network(&mut self, reason: &str) -> Result<(), String> {
        if !self.network_enabled {
            return Err("network is disabled by test-only component injection".to_owned());
        }
        if let Some(engine) = &mut self.engine {
            engine.close();
        }
        self.engine = None;
        self.socket = None; // Drop before rebinding the same fixed UDP port.
        self.stun = StunState::new(self.resolved.config.stun_seeds.clone());
        self.boot_id = BootId::random().map_err(|error| error.to_string())?;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| "generation exhausted".to_owned())?;
        if let Some(pending) = self.pending_request.take() {
            self.exchange.cancel_request(pending.id);
        }
        record_interface_failure(&mut self.interface_failures, &self.interface_name);
        match open_network(
            &self.resolved,
            &self.psk,
            self.boot_id,
            self.generation,
            &self.candidates,
            &mut self.interface_failures,
        ) {
            Ok(opened) => {
                self.interface_name = opened.interface_name;
                self.bind_ip = opened.bind_ip;
                self.socket = Some(opened.socket);
                self.engine = Some(opened.engine);
                self.next_recovery = None;
                self.next_interface_check = Instant::now() + INTERFACE_CHECK_INTERVAL;
                self.next_request = Instant::now();
                self.snapshot.session = component(
                    ComponentState::Starting,
                    format!("{reason}; new engine has no confirmed path"),
                    None,
                );
                Ok(())
            }
            Err(error) => {
                self.next_recovery = Some(Instant::now() + RECOVERY_RETRY);
                self.snapshot.session =
                    component(ComponentState::Failed, format!("{reason}: {error}"), None);
                Err(error.to_string())
            }
        }
    }

    pub(super) fn schedule_recovery(&mut self, reason: &str) {
        self.snapshot.session = component(
            ComponentState::Degraded,
            format!("{reason}; socket rebuild scheduled"),
            None,
        );
        if self.next_recovery.is_none() {
            self.next_recovery = Some(Instant::now() + RECOVERY_RETRY);
        }
    }

    pub(super) fn physical_interface_valid(&self) -> bool {
        if !self.network_enabled {
            return true;
        }
        let Ok(interfaces) = enumerate_interfaces() else {
            return false;
        };
        let Some(selected) = interfaces.iter().find(|interface| {
            interface.name == self.interface_name
                && interface.is_physical_candidate()
                && !interface.is_loopback
                && interface.ipv4.contains(&self.bind_ip)
        }) else {
            return false;
        };
        if self.resolved.config.interface.is_some() {
            return true;
        }
        let destinations = self
            .resolved
            .config
            .stun_seeds
            .iter()
            .map(|address| *address.ip())
            .collect::<Vec<_>>();
        interfaces_with_ipv4_route(&destinations)
            .is_ok_and(|routed| routed.contains(&selected.index))
    }

    pub(super) async fn shutdown(&mut self) {
        self.snapshot.daemon.state = DaemonState::Stopping;
        self.publish_snapshot();
        if let Some(handle) = &self.ntfy_handle {
            handle.cancel();
        }
        if let Some(engine) = &mut self.engine {
            engine.close();
        }
        self.socket = None;
        if let Some(tunnel) = self.tunnel.take() {
            if let Err(error) = tunnel.close() {
                self.tun_status = component(
                    ComponentState::Failed,
                    format!("utun/route cleanup failed: {error}"),
                    self.tun_status.last_success_unix_ms,
                );
                self.route_status = self.tun_status.clone();
            } else {
                self.tun_status.state = ComponentState::Stopped;
                self.route_status.state = ComponentState::Stopped;
            }
        }
        self.snapshot.daemon.state = DaemonState::Stopped;
        self.publish_snapshot();
    }
}

pub(super) struct OpenedNetwork {
    pub(super) socket: AsyncPhysicalSocket,
    pub(super) interface_name: String,
    pub(super) bind_ip: Ipv4Addr,
    pub(super) engine: PeerEngine,
}

pub(super) fn open_network(
    resolved: &ResolvedConfig,
    psk: &Secret32,
    boot_id: BootId,
    generation: u64,
    candidates: &[Endpoint],
    interface_failures: &mut BTreeMap<String, u64>,
) -> Result<OpenedNetwork, DaemonError> {
    let ordered = physical_interface_candidates(resolved, interface_failures)?;
    open_in_order(&ordered, interface_failures, |interface_name, bind_ip| {
        let socket = PhysicalSocket::open(interface_name, bind_ip, resolved.config.udp_port)
            .and_then(|socket| socket.into_async())
            .map_err(|error| error.to_string())?;
        let local = endpoint(socket.get_ref().local_addr());
        let stun_servers = resolved
            .config
            .stun_seeds
            .iter()
            .map(|address| endpoint(*address))
            .collect::<Vec<_>>();
        let handshake = HandshakeConfig {
            relationship_id: resolved.relationship.relationship_id,
            me: resolved.relationship.self_public_key,
            peer: resolved.relationship.peer_public_key,
            boot_id,
            generation,
        };
        let mut engine = PeerEngine::new(
            EngineConfig {
                handshake,
                self_vip: resolved.self_vip,
                peer_vip: resolved.peer_vip,
                candidate_policy: CandidatePolicy {
                    own_endpoints: vec![local],
                    forbidden_addresses: vec![resolved.self_vip, resolved.peer_vip],
                    stun_servers,
                    require_public_unicast: true,
                },
            },
            psk,
        )
        .map_err(|error| error.to_string())?;
        engine.set_candidates(candidates);
        Ok(OpenedNetwork {
            socket,
            interface_name: interface_name.to_owned(),
            bind_ip,
            engine,
        })
    })
    .map_err(DaemonError::Network)
}

fn record_interface_failure(failures: &mut BTreeMap<String, u64>, interface_name: &str) {
    let count = failures.entry(interface_name.to_owned()).or_default();
    *count = count.saturating_add(1);
}

pub(super) fn open_in_order<T>(
    candidates: &[(String, Ipv4Addr)],
    failures: &mut BTreeMap<String, u64>,
    mut open: impl FnMut(&str, Ipv4Addr) -> Result<T, String>,
) -> Result<T, String> {
    let mut errors = Vec::new();
    for (interface_name, bind_ip) in candidates {
        match open(interface_name, *bind_ip) {
            Ok(opened) => return Ok(opened),
            Err(error) => {
                record_interface_failure(failures, interface_name);
                errors.push(format!("{interface_name}/{bind_ip}: {error}"));
            }
        }
    }
    Err(format!(
        "every physical interface candidate failed: {}",
        errors.join("; ")
    ))
}

fn physical_interface_candidates(
    resolved: &ResolvedConfig,
    failures: &mut BTreeMap<String, u64>,
) -> Result<Vec<(String, Ipv4Addr)>, DaemonError> {
    let interfaces = enumerate_interfaces()
        .map_err(|error| DaemonError::Network(format!("enumerate interfaces: {error}")))?;
    failures.retain(|name, _| interfaces.iter().any(|interface| &interface.name == name));
    let routed = if resolved.config.interface.is_none() {
        let destinations = resolved
            .config
            .stun_seeds
            .iter()
            .map(|address| *address.ip())
            .collect::<Vec<_>>();
        interfaces_with_ipv4_route(&destinations)
            .map_err(|error| DaemonError::Network(format!("enumerate IPv4 routes: {error}")))?
    } else {
        std::collections::BTreeSet::new()
    };
    ordered_physical_interfaces_from(&interfaces, &routed, resolved, failures)
}

pub(super) fn ordered_physical_interfaces_from(
    interfaces: &[InterfaceInfo],
    routed: &std::collections::BTreeSet<u32>,
    resolved: &ResolvedConfig,
    failures: &BTreeMap<String, u64>,
) -> Result<Vec<(String, Ipv4Addr)>, DaemonError> {
    let config = &resolved.config;
    let mut candidates = match &config.interface {
        Some(name) => vec![
            interfaces
                .iter()
                .find(|interface| &interface.name == name)
                .ok_or_else(|| DaemonError::Network(format!("no interface named {name}")))?,
        ],
        None => {
            let mut candidates = interfaces
                .iter()
                .filter(|interface| {
                    interface.is_physical_candidate()
                        && !interface.is_loopback
                        && routed.contains(&interface.index)
                        && config.bind_ip.is_none_or(|ip| interface.ipv4.contains(&ip))
                })
                .collect::<Vec<_>>();
            candidates.sort_by_key(|interface| {
                (
                    failures.get(&interface.name).copied().unwrap_or(0),
                    interface.index,
                )
            });
            candidates
        }
    };
    if candidates.is_empty() {
        return Err(DaemonError::Network(
            "no usable physical interface with a same-interface STUN route".to_owned(),
        ));
    }
    candidates
        .drain(..)
        .map(|chosen| {
            if !chosen.is_physical_candidate() || chosen.is_loopback {
                return Err(DaemonError::Network(format!(
                    "{} is not an up physical IPv4 interface",
                    chosen.name
                )));
            }
            let bind_ip = match config.bind_ip {
                Some(ip) if !chosen.ipv4.contains(&ip) => {
                    return Err(DaemonError::Network(format!(
                        "bind_ip {ip} is not configured on {}",
                        chosen.name
                    )));
                }
                Some(ip) => ip,
                None => *chosen
                    .ipv4
                    .first()
                    .ok_or_else(|| DaemonError::Network(format!("{} has no IPv4", chosen.name)))?,
            };
            Ok((chosen.name.clone(), bind_ip))
        })
        .collect()
}
