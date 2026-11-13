use super::*;

impl Daemon {
    pub(super) fn refresh_network(&mut self) {
        if !self.network_enabled {
            return;
        }
        let snapshots = match enumerate_interface_prefixes() {
            Ok(snapshots) => snapshots,
            Err(error) => {
                self.snapshot.session.detail = Some(format!(
                    "interface snapshot unavailable: {error}; retained sockets unchanged"
                ));
                return;
            }
        };
        let interfaces = snapshots
            .iter()
            .map(|snapshot| snapshot.interface.clone())
            .collect::<Vec<_>>();
        self.interface_failures
            .retain(|name, _| interfaces.iter().any(|interface| &interface.name == name));
        let destinations = self
            .resolved
            .config
            .stun_seeds
            .iter()
            .map(|server| *server.ip())
            .collect::<Vec<_>>();
        let routed = interfaces_with_ipv4_route(&destinations).unwrap_or_default();
        let desired = ordered_physical_interfaces_from(
            &interfaces,
            &routed,
            &self.resolved,
            &self.interface_failures,
        )
        .unwrap_or_default();
        let old = self
            .transports
            .iter()
            .map(|socket| socket.id)
            .collect::<Vec<_>>();
        let retired = self
            .transports
            .iter()
            .filter(|socket| {
                !desired.iter().any(|(name, address)| {
                    name == &socket.interface && address == socket.local.ip()
                }) || !interfaces.iter().any(|interface| {
                    interface.index == socket.interface_index && interface.name == socket.interface
                })
            })
            .map(|socket| socket.id)
            .collect::<Vec<_>>();
        for id in retired {
            self.retire_transport(id);
        }
        for (name, address) in desired {
            match self
                .transports
                .open(&name, address, self.resolved.config.udp_port)
            {
                Ok(id) => {
                    self.public.add_transport(
                        id.0,
                        self.resolved.config.stun_seeds.clone(),
                        self.monotonic_ms(),
                    );
                }
                Err(error) => {
                    record_interface_failure(&mut self.interface_failures, &name);
                    self.snapshot.session.detail = Some(format!(
                        "physical socket {name}/{address}: {error}; other sockets retained"
                    ));
                }
            }
        }
        let current = self
            .transports
            .iter()
            .map(|socket| socket.id)
            .collect::<Vec<_>>();
        if snapshots != self.topology || old != current {
            self.reset_mdns_scopes();
        }
        self.topology = snapshots;
        for socket in self.transports.iter() {
            if !self.lan_scopes.contains_key(&socket.interface_index) {
                let generation = self.next_scope_generation;
                if let Some(next) = generation.checked_add(1) {
                    self.next_scope_generation = next;
                    self.lan_scopes.insert(
                        socket.interface_index,
                        LanScope {
                            interface: socket.interface_index,
                            generation,
                        },
                    );
                }
            }
        }
        let policies = self
            .transports
            .iter()
            .map(|socket| {
                let lan_subnets = if self.resolved.config.lan.enabled {
                    self.topology
                        .iter()
                        .find(|snapshot| snapshot.interface.index == socket.interface_index)
                        .map(|snapshot| {
                            snapshot
                                .ipv4_prefixes
                                .iter()
                                .filter(|prefix| &prefix.address == socket.local.ip())
                                .map(|prefix| LanSubnet {
                                    address: prefix.address,
                                    prefix_len: prefix.prefix_len,
                                })
                                .collect()
                        })
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                TransportPolicy {
                    transport: socket.id,
                    local_endpoint: endpoint(socket.local),
                    lan_subnets,
                }
            })
            .collect::<Vec<_>>();
        if let Some(engine) = &mut self.engine {
            engine.set_transports(&policies);
        }
        self.refresh_public_request();
        self.reproject_candidates();
        self.ensure_mdns();
    }

    pub(super) fn retire_transport(&mut self, id: TransportId) {
        let index = self.transports.get(id).map(|socket| socket.interface_index);
        if self.transports.remove(id) {
            self.public.remove_transport(id.0);
            if let Some(engine) = &mut self.engine {
                engine.remove_transport(id);
            }
            let scope_retired = index.is_some_and(|index| {
                !self
                    .transports
                    .iter()
                    .any(|socket| socket.interface_index == index)
            });
            let operations = self
                .mdns_operations
                .iter()
                .filter_map(|(operation, owner)| match owner {
                    MdnsOperation::Register(registered) if *registered == id => Some(*operation),
                    MdnsOperation::Browse(scope)
                        if scope_retired && Some(scope.interface) == index =>
                    {
                        Some(*operation)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            for operation in operations {
                if let Some(client) = &mut self.mdns {
                    client.cancel(operation);
                }
                self.mdns_operations.remove(&operation);
            }
            if scope_retired
                && let Some(scope) = index.and_then(|index| self.lan_scopes.remove(&index))
            {
                let transports = self.candidate_transports();
                for update in self.lan.revoke_interface(scope) {
                    self.registry.apply(update, &transports);
                }
            }
            self.paths
                .retain(|candidate| candidate.path.transport != id);
            if self.mdns_operations.is_empty() {
                self.mdns = None;
            }
            self.refresh_public_request();
            self.next_interface_check = Instant::now() + RECOVERY_RETRY;
        }
    }

    pub(super) fn candidate_transports(&self) -> Vec<CandidateTransport> {
        self.transports
            .iter()
            .map(|socket| CandidateTransport {
                id: socket.id,
                scope: self
                    .lan_scopes
                    .get(&socket.interface_index)
                    .copied()
                    .unwrap_or(LanScope {
                        interface: socket.interface_index,
                        generation: 0,
                    }),
                local: endpoint(socket.local),
            })
            .collect()
    }

    pub(super) fn reproject_candidates(&mut self) {
        let transports = self.candidate_transports();
        let mut public_routes = BTreeMap::new();
        self.paths = self
            .registry
            .project(&transports, self.monotonic_ms(), |transport, hint| {
                if hint.remote.ip == self.resolved.self_vip
                    || hint.remote.ip == self.resolved.peer_vip
                    || self
                        .transports
                        .iter()
                        .any(|socket| *socket.local.ip() == hint.remote.ip)
                {
                    return false;
                }
                match hint.scope {
                    CandidateScope::Lan(_) => self
                        .topology
                        .iter()
                        .find(|snapshot| snapshot.interface.index == transport.scope.interface)
                        .is_some_and(|snapshot| {
                            has_scoped_direct_route_from(
                                snapshot,
                                transport.local.ip,
                                hint.remote.ip,
                            )
                            .unwrap_or(false)
                        }),
                    CandidateScope::Public => public_routes
                        .entry(hint.remote.ip)
                        .or_insert_with(|| {
                            ipv4_route_sources(&self.topology, hint.remote.ip).unwrap_or_default()
                        })
                        .contains(&(transport.scope.interface, transport.local.ip)),
                }
            });
        if let Some(engine) = &mut self.engine {
            engine.set_paths(&self.paths);
        }
    }

    pub(super) fn apply_discovery_updates(&mut self, updates: Vec<DiscoveryUpdate>) {
        let transports = self.candidate_transports();
        for update in updates {
            self.registry.apply(update, &transports);
        }
        self.reproject_candidates();
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
        self.mdns = None;
        self.mdns_operations.clear();
        self.transports.clear();
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

pub(super) fn make_engine(
    resolved: &ResolvedConfig,
    psk: &Secret32,
    boot_id: BootId,
    generation: u64,
) -> Result<PeerEngine, DaemonError> {
    let mut engine = PeerEngine::new(
        EngineConfig {
            handshake: HandshakeConfig {
                relationship_id: resolved.relationship.relationship_id,
                me: resolved.relationship.self_public_key,
                peer: resolved.relationship.peer_public_key,
                boot_id,
                generation,
            },
            self_vip: resolved.self_vip,
            peer_vip: resolved.peer_vip,
            candidate_policy: CandidatePolicy {
                own_endpoints: Vec::new(),
                forbidden_addresses: vec![resolved.self_vip, resolved.peer_vip],
                stun_servers: resolved
                    .config
                    .stun_seeds
                    .iter()
                    .map(|server| endpoint(*server))
                    .collect(),
                require_public_unicast: true,
            },
        },
        psk,
    )?;
    engine.set_transports(&[]);
    Ok(engine)
}

fn record_interface_failure(failures: &mut BTreeMap<String, u64>, interface_name: &str) {
    let count = failures.entry(interface_name.to_owned()).or_default();
    *count = count.saturating_add(1);
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
        None => interfaces
            .iter()
            .filter(|interface| {
                interface.is_physical_candidate()
                    && !interface.is_loopback
                    && (config.lan.enabled || routed.contains(&interface.index))
                    && config.bind_ip.is_none_or(|ip| interface.ipv4.contains(&ip))
            })
            .collect(),
    };
    candidates.sort_by_key(|interface| {
        (
            !routed.contains(&interface.index),
            failures.get(&interface.name).copied().unwrap_or(0),
            interface.index,
        )
    });
    let mut endpoints = Vec::new();
    for chosen in candidates {
        if !chosen.is_physical_candidate() || chosen.is_loopback {
            return Err(DaemonError::Network(format!(
                "{} is not an up physical IPv4 interface",
                chosen.name
            )));
        }
        if let Some(ip) = config.bind_ip
            && !chosen.ipv4.contains(&ip)
        {
            return Err(DaemonError::Network(format!(
                "bind_ip {ip} is not configured on {}",
                chosen.name
            )));
        }
        for ip in &chosen.ipv4 {
            if config.bind_ip.is_some_and(|bound| bound != *ip)
                || *ip == resolved.self_vip
                || *ip == resolved.peer_vip
                || !matches!(
                    lzh_hole_discovery::candidate::classify(*ip),
                    None | Some(
                        lzh_hole_discovery::candidate::EndpointReject::Private
                            | lzh_hole_discovery::candidate::EndpointReject::Cgnat
                    )
                )
            {
                continue;
            }
            let candidate = (chosen.name.clone(), *ip);
            if !endpoints.contains(&candidate) {
                endpoints.push(candidate);
            }
        }
    }
    if endpoints.is_empty() {
        return Err(DaemonError::Network(
            "no permitted physical IPv4 bind address".to_owned(),
        ));
    }
    Ok(endpoints)
}
