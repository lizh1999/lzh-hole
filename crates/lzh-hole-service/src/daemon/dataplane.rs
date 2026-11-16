//! Inbound and outbound dataplane over one `PeerSet` and one utun.
//!
//! Routing is by relationship on the way in and by destination address on the
//! way out. Both directions fail closed here, before any engine is reached: an
//! unknown relationship or an unowned destination is refused by this layer, and
//! only the engine that owns the relationship ever authenticates, replays or
//! admits a frame.
//!
//! Counters are attributed to the peer that actually produced or consumed the
//! traffic. Bytes this layer refused itself are node-level, because no peer owns
//! a datagram that never reached an engine.

use lzh_hole_protocol::engine::SendError;
use lzh_hole_protocol::mesh::{Inbound, MeshSendError};

use super::status::component;
use super::*;

impl Daemon {
    /// Attribute one drop to a peer, or to the node when no peer owns it.
    fn drop_for(&mut self, relationship: Option<RelationshipId>, reason: &str, count: u64) {
        match relationship.and_then(|id| self.peers.get_mut(&id)) {
            Some(peer) => peer.record_drop(reason, count),
            None => self.record_drop(reason, count),
        }
    }

    pub(super) async fn handle_udp(&mut self, event: TransportDatagram) {
        let id = event.transport;
        let (result, buffer) = (event.result, event.buffer);
        let Some(socket) = self.transports.get(id) else {
            self.record_drop("no_socket", 1);
            return;
        };
        let (size, metadata) = match result {
            Ok(value) => value,
            Err(error) => {
                self.record_drop("udp_recv_failed", 1);
                self.snapshot.session.detail = Some(format!(
                    "transport {} receive failed: {error}; other transports retained",
                    id.0
                ));
                self.retire_transport(id);
                return;
            }
        };
        self.bytes.udp_rx = self.bytes.udp_rx.saturating_add(size as u64);
        if metadata
            .ifindex
            .is_some_and(|index| index != socket.interface_index)
        {
            self.record_drop("wrong_interface", 1);
            return;
        }
        if metadata.dest.is_some_and(|dest| dest != *socket.local.ip()) {
            self.record_drop("wrong_destination", 1);
            return;
        }
        let packet = &buffer[..size];
        if looks_like_stun(packet) {
            self.handle_stun(id, packet, metadata);
            return;
        }
        let Some(engines) = &mut self.engines else {
            self.record_drop("engine_unavailable", 1);
            return;
        };
        // Only the fixed header is read to choose an engine. That is a strictly
        // weaker check than the one the owning engine performs, so this can
        // never reject a frame the engine would have admitted, and a datagram
        // aimed at a relationship this node does not hold never perturbs any
        // other peer's replay or session state.
        match engines.dispatch(id, endpoint(metadata.source), packet, now_unix_ms()) {
            Inbound::Delivered(relationship) => {
                if let Some(peer) = self.peers.get_mut(&relationship) {
                    peer.bytes.udp_rx = peer.bytes.udp_rx.saturating_add(size as u64);
                }
            }
            Inbound::UnknownRelationship(_) => self.record_drop("unknown_relationship", 1),
            Inbound::Malformed => self.record_drop("malformed_frame", 1),
        }
    }

    pub(super) async fn handle_tun(&mut self, event: TunEvent) {
        let (result, buffer) = (event.result, event.buffer);
        let size = match result {
            Ok(size) => size,
            Err(error) => {
                self.record_drop("tun_read_failed", 1);
                self.tun_status = component(
                    ComponentState::Failed,
                    format!("utun read failed: {error}"),
                    self.tun_status.last_success_unix_ms,
                );
                return;
            }
        };
        self.bytes.tun_rx = self.bytes.tun_rx.saturating_add(size as u64);
        let packet = &buffer[..size];
        let Some(engines) = &mut self.engines else {
            self.record_drop("engine_unavailable", 1);
            return;
        };
        match engines.send_ipv4(packet, now_unix_ms()) {
            Ok(relationship) => {
                if let Some(peer) = self.peers.get_mut(&relationship) {
                    peer.bytes.tun_rx = peer.bytes.tun_rx.saturating_add(size as u64);
                }
            }
            Err(error) => {
                // A destination no peer owns, or a buffer that is not a
                // readable IPv4 header, is refused here and never reaches an
                // engine. Everything else is the owning engine's own verdict.
                let (relationship, reason) = match error {
                    MeshSendError::NoPeerForDestination(_) => (None, "unroutable"),
                    MeshSendError::Malformed => (None, "invalid_local_ipv4"),
                    MeshSendError::Peer(send) => (None, send_reason(send)),
                };
                self.drop_for(relationship, reason, 1);
            }
        }
    }

    pub(super) async fn drain_engine(&mut self) {
        loop {
            let next = match &mut self.engines {
                Some(engines) => engines.next_udp_frame(),
                None => None,
            };
            let Some((relationship, frame)) = next else {
                break;
            };
            let Some(socket) = self.transports.get(frame.transport) else {
                self.drop_for(Some(relationship), "no_socket", 1);
                continue;
            };
            let target = socket_addr(frame.target);
            match socket.socket.try_send_to(&frame.bytes, target) {
                Ok(written) if written == frame.bytes.len() => {
                    self.bytes.udp_tx = self.bytes.udp_tx.saturating_add(written as u64);
                    if let Some(peer) = self.peers.get_mut(&relationship) {
                        peer.bytes.udp_tx = peer.bytes.udp_tx.saturating_add(written as u64);
                    }
                }
                _ => {
                    self.drop_for(Some(relationship), "udp_send_failed", 1);
                    // A per-destination send failure is not evidence that every
                    // other path/socket disappeared. Topology refresh and
                    // authenticated health independently decide recovery.
                }
            }
        }
        loop {
            let next = match &mut self.engines {
                Some(engines) => engines.next_ipv4_packet(),
                None => None,
            };
            let Some((relationship, packet)) = next else {
                break;
            };
            let Some(tunnel) = self.tunnel() else {
                self.drop_for(Some(relationship), "tun_not_configured", 1);
                continue;
            };
            match timeout(SOCKET_IO_TIMEOUT, tunnel.send_ipv4(&packet)).await {
                Ok(Ok(())) => {
                    self.bytes.tun_tx = self.bytes.tun_tx.saturating_add(packet.len() as u64);
                    if let Some(peer) = self.peers.get_mut(&relationship) {
                        peer.bytes.tun_tx = peer.bytes.tun_tx.saturating_add(packet.len() as u64);
                    }
                }
                _ => {
                    self.drop_for(Some(relationship), "tun_write_failed", 1);
                    self.tun_status = component(
                        ComponentState::Degraded,
                        "utun write failed or timed out",
                        self.tun_status.last_success_unix_ms,
                    );
                }
            }
        }
    }
}

fn send_reason(error: SendError) -> &'static str {
    match error {
        SendError::NoActivePath => "no_active_path",
        SendError::OutboxFull => "udp_outbox_full",
        SendError::Closed => "engine_closed",
        SendError::SequenceExhausted => "sequence_exhausted",
        _ => "invalid_local_ipv4",
    }
}
