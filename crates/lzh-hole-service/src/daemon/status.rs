use super::*;

impl Daemon {
    pub(super) fn record_drop(&mut self, reason: &str, count: u64) {
        let _ = self.io_drops.record(reason, count);
    }

    pub(super) fn publish_snapshot(&mut self) {
        let now = now_unix_ms();
        let engine_snapshot = self.engine.as_ref().map(|engine| engine.snapshot(now));
        if engine_snapshot.is_some_and(|snapshot| snapshot.currently_healthy) {
            self.last_healthy_unix_ms = Some(now);
        }
        self.snapshot.updated_unix_ms = now;
        self.snapshot.stun = if !self.network_enabled {
            component(
                ComponentState::NotConfigured,
                "disabled by test-only component injection",
                None,
            )
        } else {
            self.stun.status.clone()
        };
        self.snapshot.ntfy = self.ntfy_status.clone();
        self.snapshot.tun = self.tun_status.clone();
        self.snapshot.routes = self.route_status.clone();
        self.snapshot.session = self.session_status(engine_snapshot, now);
        self.snapshot.overlay.direct_reachable = engine_snapshot.map(|s| s.direct_reachable);
        self.snapshot.overlay.currently_healthy = engine_snapshot.map(|s| s.currently_healthy);
        self.snapshot.overlay.detail = Some(
            "engine health is actual PONG evidence; transparent TCP/UDP/ICMP and P0 have not been accepted by this daemon"
                .to_owned(),
        );
        self.snapshot.bytes = self.bytes.clone();
        self.snapshot.drops = self.combined_drops(engine_snapshot);
        self.snapshot_tx_send();
    }

    pub(super) fn snapshot_tx_send(&mut self) {
        self.snapshot_tx.send_replace(self.snapshot.clone());
    }

    pub(super) fn session_status(
        &self,
        snapshot: Option<EngineSnapshot>,
        now: u64,
    ) -> ComponentStatus {
        let Some(snapshot) = snapshot else {
            return component(
                if !self.network_enabled {
                    ComponentState::NotConfigured
                } else {
                    ComponentState::Failed
                },
                if !self.network_enabled {
                    "network engine disabled by test-only component injection".to_owned()
                } else {
                    "network engine unavailable; recovery is pending".to_owned()
                },
                None,
            );
        };
        if snapshot.currently_healthy {
            ComponentStatus {
                state: ComponentState::Healthy,
                detail: Some(format!(
                    "bilateral PONG health on {:?}",
                    snapshot.selected_endpoint
                )),
                last_success_unix_ms: self.last_healthy_unix_ms.or(Some(now)),
                last_change_unix_ms: Some(now),
            }
        } else if snapshot.session_id.is_some() {
            component(
                ComponentState::Starting,
                "session exists but return-path/bilateral PONG health is not confirmed",
                self.last_healthy_unix_ms,
            )
        } else {
            component(
                ComponentState::Starting,
                format!(
                    "no current session; {} verified candidates",
                    snapshot.candidate_count
                ),
                self.last_healthy_unix_ms,
            )
        }
    }

    pub(super) fn combined_drops(&self, snapshot: Option<EngineSnapshot>) -> DropCounters {
        let mut drops = self.io_drops.clone();
        if let Some(snapshot) = snapshot {
            let counters = snapshot.counters;
            for (reason, count) in [
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
            ] {
                let _ = drops.record(reason, count);
            }
        }
        drops
    }
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
