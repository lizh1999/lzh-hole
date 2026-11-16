//! Snapshot assembly: one honest observation per peer, plus node-level facts.
//!
//! Node-level fields that could be read as "the mesh is fine" are deliberately
//! aggregates computed by `lzh_hole_control`, not by this file: partial health
//! must never be reported as health, and an unmeasured peer must never be
//! silently folded into a healthy verdict. This module only supplies per-peer
//! observations and the genuinely node-scoped subsystems (utun, routes, STUN,
//! Bonjour, discovery accounting).
//!
//! A path and a candidate belong to exactly one peer, so the node-level
//! `current_path` and `candidates` are left empty rather than filled with an
//! arbitrary peer's values.

use lzh_hole_control::{
    CandidateStatus, CurrentPathStatus, DiscoveryOrigin, OverlayHealth, PeerStatus,
};
use lzh_hole_protocol::engine::EngineSnapshot;

use super::*;

impl Daemon {
    pub(super) fn record_drop(&mut self, reason: &str, count: u64) {
        let _ = self.io_drops.record(reason, count);
    }

    pub(super) fn publish_snapshot(&mut self) {
        let now = now_unix_ms();
        let snapshots = self
            .engines
            .as_ref()
            .map(|engines| engines.snapshots(now))
            .unwrap_or_default();
        for (relationship, snapshot) in &snapshots {
            if snapshot.currently_healthy
                && let Some(peer) = self.peers.get_mut(relationship)
            {
                peer.last_healthy_unix_ms = Some(now);
            }
        }

        self.snapshot.updated_unix_ms = now;
        self.snapshot.punch = self.node_punch_status();
        self.snapshot.stun = if !self.network_enabled {
            component(
                ComponentState::NotConfigured,
                "disabled by test-only component injection",
                None,
            )
        } else if self.public.own_mappings(self.monotonic_ms()).is_empty() {
            component(
                ComponentState::Degraded,
                "no fresh public mapping; independent LAN session may remain healthy",
                self.stun_status.last_success_unix_ms,
            )
        } else {
            self.stun_status.clone()
        };
        self.snapshot.lan = self.lan_status.clone();
        self.snapshot.ntfy = self.node_ntfy_status();
        self.snapshot.tun = self.tun_status.clone();
        self.snapshot.routes = self.route_status.clone();

        let counters = self.registry.counters;
        self.snapshot.discovery = lzh_hole_control::DiscoveryCounters {
            accepted_updates: counters.accepted_updates,
            rejected_updates: counters.rejected_updates,
            withdrawals: counters.withdrawals,
        };
        self.snapshot.bytes = self.bytes.clone();
        self.snapshot.drops = self.io_drops.clone();

        let peers = self.peer_statuses(&snapshots, now);
        // Recomputes session, overlay, current_path and candidates from the
        // peers. Must run last: it overwrites those four node-level fields.
        if !self.snapshot.set_peers(peers) {
            self.record_drop("snapshot_peer_list_refused", 1);
        }
        self.snapshot_tx_send();
    }

    pub(super) fn snapshot_tx_send(&mut self) {
        self.snapshot_tx.send_replace(self.snapshot.clone());
    }

    /// One status per pinned peer, in relationship-id order.
    fn peer_statuses(
        &mut self,
        snapshots: &[(RelationshipId, EngineSnapshot)],
        now: u64,
    ) -> Vec<PeerStatus> {
        let order = self.peer_order.clone();
        let mut out = Vec::with_capacity(order.len());
        for relationship_id in order {
            let engine = snapshots
                .iter()
                .find(|(id, _)| *id == relationship_id)
                .map(|(_, snapshot)| snapshot);
            let paths = self
                .paths
                .get(&relationship_id)
                .cloned()
                .unwrap_or_default();
            let punching = self.punch.as_ref().map(|attempt| attempt.relationship);
            let punch = self.peer_punch_status(relationship_id);
            let Some(peer) = self.peers.get_mut(&relationship_id) else {
                continue;
            };
            let role = format!("{:?}", peer.relationship.role).to_lowercase();
            let session = peer_session_status(peer, engine, now);
            let overlay = OverlayHealth {
                direct_reachable: engine.map(|snapshot| snapshot.direct_reachable),
                currently_healthy: engine.map(|snapshot| snapshot.currently_healthy),
                detail: Some(
                    "engine health is actual bilateral PONG evidence for this peer only; \
                     transparent TCP/UDP/ICMP and P0 have not been accepted by this daemon"
                        .to_owned(),
                ),
            };
            let current_path =
                engine
                    .and_then(|snapshot| snapshot.selected_path)
                    .and_then(|path| {
                        self.transports
                            .get(path.transport)
                            .map(|socket| CurrentPathStatus {
                                transport_id: path.transport.0,
                                interface: socket.interface.clone(),
                                local_endpoint: socket.local.to_string(),
                                remote_endpoint: path.remote.to_string(),
                                kind: if lzh_hole_discovery::candidate::is_private(path.remote.ip) {
                                    DiscoveryOrigin::Lan
                                } else {
                                    DiscoveryOrigin::Public
                                },
                            })
                    });
            let candidates = paths
                .iter()
                .map(|candidate| CandidateStatus {
                    origin: match candidate.kind {
                        lzh_hole_protocol::path::PathKind::Lan => DiscoveryOrigin::Lan,
                        lzh_hole_protocol::path::PathKind::Public => DiscoveryOrigin::Public,
                    },
                    transport_id: candidate.path.transport.0,
                    remote_endpoint: candidate.path.remote.to_string(),
                })
                .collect();
            let mut drops = peer.drops.clone();
            if let Some(snapshot) = engine {
                for (reason, count) in engine_drop_reasons(snapshot) {
                    let _ = drops.record(reason, count);
                }
            }
            let ntfy = peer.ntfy.status.clone();
            let bytes = peer.bytes.clone();
            let _ = punching;
            out.push(PeerStatus {
                relationship_id: relationship_id.to_hex(),
                peer_vip: peer.peer_vip.to_string(),
                peer_key: peer.peer_key.to_string(),
                role,
                session,
                overlay,
                ntfy,
                current_path,
                candidates,
                punch,
                bytes,
                drops,
            });
        }
        out
    }

    /// Node-level ntfy status: the worst of every relationship's view, with the
    /// reason visible. One relationship's Retry-After boundary must not be
    /// hidden by another relationship's healthy stream.
    fn node_ntfy_status(&self) -> ComponentStatus {
        if !self.network_enabled {
            return component(
                ComponentState::NotConfigured,
                "disabled by test-only component injection",
                None,
            );
        }
        let total = self.peers.len();
        let subscribed = self
            .peers
            .values()
            .filter(|peer| peer.ntfy.subscribed)
            .count();
        let blocked = self
            .peers
            .values()
            .filter(|peer| peer.ntfy.waiting())
            .count();
        let state = if total == 0 {
            ComponentState::NotConfigured
        } else if subscribed == total && blocked == 0 {
            ComponentState::Healthy
        } else if subscribed == 0 {
            ComponentState::Failed
        } else {
            ComponentState::Degraded
        };
        let last_success = self
            .peers
            .values()
            .filter_map(|peer| peer.ntfy.status.last_success_unix_ms)
            .max();
        component(
            state,
            format!(
                "one actor serves {total} relationship topics: {subscribed}/{total} subscribed, \
                 {blocked} blocked by a persisted retry boundary; per-relationship detail in peers[]"
            ),
            last_success,
        )
    }
}

fn peer_session_status(
    peer: &PeerRuntime,
    snapshot: Option<&EngineSnapshot>,
    now: u64,
) -> ComponentStatus {
    let Some(snapshot) = snapshot else {
        return component(
            ComponentState::Failed,
            "this peer's engine is unavailable; recovery is pending",
            peer.last_healthy_unix_ms,
        );
    };
    if snapshot.currently_healthy {
        ComponentStatus {
            state: ComponentState::Healthy,
            detail: Some(format!(
                "bilateral PONG health on {:?}",
                snapshot.selected_endpoint
            )),
            last_success_unix_ms: peer.last_healthy_unix_ms.or(Some(now)),
            last_change_unix_ms: Some(now),
        }
    } else if snapshot.session_id.is_some() {
        component(
            ComponentState::Starting,
            "session exists but return-path/bilateral PONG health is not confirmed",
            peer.last_healthy_unix_ms,
        )
    } else {
        component(
            ComponentState::Starting,
            format!(
                "no current session; {} verified candidates",
                snapshot.candidate_count
            ),
            peer.last_healthy_unix_ms,
        )
    }
}

fn engine_drop_reasons(snapshot: &EngineSnapshot) -> [(&'static str, u64); 10] {
    let counters = snapshot.counters;
    [
        ("udp_outbox_full", counters.udp_out_dropped),
        ("tun_inbox_full", counters.ipv4_in_dropped),
        ("malformed_frame", counters.malformed_frames),
        ("stale_frame", counters.stale_frames),
        ("bad_mac", counters.bad_mac),
        ("replay_rejected", counters.replay_rejected),
        ("wrong_endpoint", counters.wrong_endpoint),
        ("invalid_ipv4", counters.invalid_ipv4),
        ("control_rejected", counters.control_rejected),
        ("handshake_rejected", counters.handshake_rejected),
    ]
}

pub(super) fn component(
    state: ComponentState,
    detail: impl Into<String>,
    last_success_unix_ms: Option<u64>,
) -> ComponentStatus {
    ComponentStatus {
        state,
        detail: Some(detail.into()),
        last_success_unix_ms,
        last_change_unix_ms: Some(now_unix_ms()),
    }
}
