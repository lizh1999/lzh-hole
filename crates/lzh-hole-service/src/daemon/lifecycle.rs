//! Physical socket ownership, per-relationship path projection and shutdown.
//!
//! Physical sockets, STUN measurements and Bonjour scopes are node-level: they
//! describe this host's own network, not any peer. What is per relationship is
//! the projected path set, because a path is only ever usable by the engine
//! that owns the relationship whose authenticated record or pinned-key
//! advertisement produced it.
//!
//! Every reprojection writes a path set for **every** relationship, including an
//! empty one. Skipping a relationship with no surviving candidates would leave
//! its engine holding paths that discovery has already withdrawn.

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
        let retired_any = !retired.is_empty();
        for id in retired {
            self.retire_transport(id);
        }
        // An interface disappearing invalidates every punch socket bound to it,
        // so the attempt is abandoned rather than left holding dead descriptors.
        if retired_any {
            self.stop_punch(now_unix_ms());
        }
        for (name, address) in desired {
            match self.transports.open(
                &mut self.transport_ids,
                &name,
                address,
                self.resolved.config.udp_port,
            ) {
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
        self.sync_engine_transports();
        self.refresh_public_requests();
        self.reproject_candidates();
        self.ensure_mdns();
    }

    /// Publish the current socket set to every peer engine.
    ///
    /// Physical sockets are a node-level resource, so one socket change is
    /// applied to every relationship at once. That can rebuild every session
    /// together, which is a deliberate availability trade: the alternative is
    /// per-engine policy divergence inside one node.
    pub(super) fn sync_engine_transports(&mut self) {
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
        if let Some(engines) = &mut self.engines {
            engines.set_transports(&policies);
        }
    }

    pub(super) fn retire_transport(&mut self, id: TransportId) {
        let index = self.transports.get(id).map(|socket| socket.interface_index);
        if self.transports.remove(id) {
            self.promoted_transports.remove(&id);
            if self
                .promoted_slot
                .as_ref()
                .is_some_and(|(_, _, slot)| *slot == id)
            {
                self.promoted_slot = None;
            }
            self.public.remove_transport(id.0);
            if let Some(engines) = &mut self.engines {
                for (_, engine) in engines.iter_mut() {
                    engine.remove_transport(id);
                }
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
                let updates = self
                    .lan
                    .revoke_interface(scope)
                    .into_iter()
                    .map(|update| (update.relationship_id, update.update))
                    .collect::<Vec<_>>();
                self.apply_tagged_updates_with(updates, &transports);
            }
            for paths in self.paths.values_mut() {
                paths.retain(|candidate| candidate.path.transport != id);
            }
            if self.mdns_operations.is_empty() {
                self.mdns = None;
            }
            self.refresh_public_requests();
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

    /// Reproject every relationship's paths from the current observation set.
    ///
    /// A relationship with no surviving candidate gets an explicitly empty path
    /// set. That is what actually withdraws a path from its engine; leaving the
    /// previous set in place would keep a withdrawn candidate usable.
    pub(super) fn reproject_candidates(&mut self) {
        let transports = self.candidate_transports();
        let self_vip = self.resolved.self_vip;
        let peer_vips = self
            .peers
            .values()
            .map(|peer| peer.peer_vip)
            .collect::<Vec<_>>();
        let bound: Vec<Ipv4Addr> = self
            .transports
            .iter()
            .map(|socket| *socket.local.ip())
            .collect();
        let mut public_routes = BTreeMap::new();
        let projected =
            self.registry
                .project(&transports, self.monotonic_ms(), |transport, hint| {
                    // No overlay address of this mesh is ever a physical target,
                    // whichever relationship the hint belongs to.
                    if hint.remote.ip == self_vip
                        || peer_vips.contains(&hint.remote.ip)
                        || bound.contains(&hint.remote.ip)
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
                                ipv4_route_sources(&self.topology, hint.remote.ip)
                                    .unwrap_or_default()
                            })
                            .contains(&(transport.scope.interface, transport.local.ip)),
                    }
                });

        self.paths = self
            .peer_order
            .iter()
            .map(|relationship| {
                (
                    *relationship,
                    projected.get(relationship).cloned().unwrap_or_default(),
                )
            })
            .collect();

        if let Some(engines) = &mut self.engines {
            for (relationship, paths) in &self.paths {
                if let Some(engine) = engines.get_mut(*relationship) {
                    engine.set_paths(paths);
                }
            }
        }
    }

    pub(super) fn apply_tagged_updates(&mut self, updates: Vec<(RelationshipId, DiscoveryUpdate)>) {
        let transports = self.candidate_transports();
        self.apply_tagged_updates_with(updates, &transports);
    }

    pub(super) fn apply_tagged_updates_with(
        &mut self,
        updates: Vec<(RelationshipId, DiscoveryUpdate)>,
        transports: &[CandidateTransport],
    ) {
        if updates.is_empty() {
            return;
        }
        for (relationship, update) in updates {
            // A hint is only ever recorded against the relationship that
            // authenticated it. An unknown relationship is refused rather than
            // attributed to an arbitrary peer.
            if !self.peers.contains_key(&relationship) {
                self.record_drop("unknown_relationship_update", 1);
                continue;
            }
            self.registry.apply(relationship, update, transports);
        }
        self.reproject_candidates();
    }

    pub(super) async fn shutdown(&mut self) {
        self.snapshot.daemon.state = DaemonState::Stopping;
        self.publish_snapshot();
        if let Some(handle) = &self.ntfy_handle {
            handle.cancel();
        }
        if let Some(engines) = &mut self.engines {
            engines.close();
        }
        self.stop_punch(now_unix_ms());
        self.mdns = None;
        self.mdns_operations.clear();
        self.transports.clear();
        self.promoted_transports.clear();
        self.promoted_slot = None;
        // Routes are removed before utun, by OverlayRoutes' own field order and
        // by its explicit close path.
        if let Some(overlay) = self.overlay.take() {
            let owned = overlay.peers().collect::<Vec<_>>();
            match overlay.close() {
                Ok(()) => {
                    self.tun_status.state = ComponentState::Stopped;
                    self.route_status.state = ComponentState::Stopped;
                    self.route_status.detail = Some(format!(
                        "removed every owned peer /32 route ({}) before closing utun",
                        owned
                            .iter()
                            .map(|peer| format!("{peer}/32"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                Err(error) => {
                    self.tun_status = component(
                        ComponentState::Failed,
                        format!("utun/route cleanup failed: {error}"),
                        self.tun_status.last_success_unix_ms,
                    );
                    self.route_status = self.tun_status.clone();
                }
            }
        }
        self.snapshot.daemon.state = DaemonState::Stopped;
        self.publish_snapshot();
    }
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
    // No overlay address of this mesh may be used as a physical bind address.
    let overlay: Vec<Ipv4Addr> = std::iter::once(resolved.self_vip)
        .chain(resolved.peers.iter().map(|peer| peer.peer_vip))
        .collect();
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
                || overlay.contains(ip)
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
