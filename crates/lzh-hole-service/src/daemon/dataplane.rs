use super::status::component;
use super::*;

impl Daemon {
    pub(super) async fn handle_udp(&mut self, event: UdpEvent) {
        let (result, buffer) = (event.result, event.buffer);
        let Some(socket) = &self.socket else {
            self.record_drop("no_socket", 1);
            return;
        };
        let (size, metadata) = match result {
            Ok(value) => value,
            Err(error) => {
                self.record_drop("udp_recv_failed", 1);
                self.schedule_recovery(&format!("UDP receive failed: {error}"));
                return;
            }
        };
        if metadata
            .ifindex
            .is_some_and(|index| index != socket.get_ref().bound_ifindex())
        {
            self.record_drop("wrong_interface", 1);
            return;
        }
        if metadata
            .dest
            .is_some_and(|dest| dest != *socket.get_ref().local_addr().ip())
        {
            self.record_drop("wrong_destination", 1);
            return;
        }
        self.bytes.udp_rx = self.bytes.udp_rx.saturating_add(size as u64);
        let packet = &buffer[..size];
        if looks_like_stun(packet) {
            self.handle_stun(packet, metadata);
            return;
        }
        if let Some(engine) = &mut self.engine {
            engine.handle_datagram(endpoint(metadata.source), packet, now_unix_ms());
        } else {
            self.record_drop("engine_unavailable", 1);
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
        if let Some(engine) = &mut self.engine {
            if let Err(error) = engine.send_ipv4(&buffer[..size], now_unix_ms()) {
                let reason = match error {
                    lzh_hole_protocol::engine::SendError::NoActivePath => "no_active_path",
                    lzh_hole_protocol::engine::SendError::OutboxFull => "udp_outbox_full",
                    lzh_hole_protocol::engine::SendError::Closed => "engine_closed",
                    lzh_hole_protocol::engine::SendError::SequenceExhausted => "sequence_exhausted",
                    _ => "invalid_local_ipv4",
                };
                self.record_drop(reason, 1);
            }
        } else {
            self.record_drop("engine_unavailable", 1);
        }
    }

    pub(super) async fn drain_engine(&mut self) {
        loop {
            let frame = match &mut self.engine {
                Some(engine) => engine.next_udp_frame(),
                None => None,
            };
            let Some(frame) = frame else {
                break;
            };
            let Some(socket) = &self.socket else {
                self.record_drop("no_socket", 1);
                continue;
            };
            let target = socket_addr(frame.target);
            match timeout(SOCKET_IO_TIMEOUT, socket.send_to(&frame.bytes, target)).await {
                Ok(Ok(written)) if written == frame.bytes.len() => {
                    self.bytes.udp_tx = self.bytes.udp_tx.saturating_add(written as u64);
                }
                _ => {
                    self.record_drop("udp_send_failed", 1);
                    self.schedule_recovery("UDP engine-frame send failed");
                }
            }
        }
        loop {
            let packet = match &mut self.engine {
                Some(engine) => engine.next_ipv4_packet(),
                None => None,
            };
            let Some(packet) = packet else {
                break;
            };
            let Some(tunnel) = &self.tunnel else {
                self.record_drop("tun_not_configured", 1);
                continue;
            };
            match timeout(SOCKET_IO_TIMEOUT, tunnel.send_ipv4(&packet)).await {
                Ok(Ok(())) => {
                    self.bytes.tun_tx = self.bytes.tun_tx.saturating_add(packet.len() as u64);
                }
                _ => {
                    self.record_drop("tun_write_failed", 1);
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
