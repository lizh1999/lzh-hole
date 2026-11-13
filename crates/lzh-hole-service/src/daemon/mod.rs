//! Resident wiring: bounded physical transports, discovery, PeerEngine and utun.
//!
//! Public-network operation is explicit by invoking `daemon`. utun creation and
//! its owned peer /32 route additionally require `--allow-tun`. The offline
//! control mode is a truthful control-plane-only mode, not an overlay test.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use lzh_hole_discovery::candidate::{CandidateSource, Endpoint};
use lzh_hole_discovery::peer_record::{PeerRecordPolicy, PeerRecordReject};
use lzh_hole_discovery::record::{
    ContactRecord, MAX_LIFETIME_MS, RecordCandidate, reserve_sequence,
};
use lzh_hole_discovery::stun::{TRANSACTION_ID_LEN, looks_like_stun};
use lzh_hole_discovery::{
    CandidateScope, DiscoveryUpdate, LanAdvertisement, LanDiscovery, LanObservation, LanScope,
    PublicDiscovery,
};
use lzh_hole_net::interface::{
    InterfaceInfo, InterfacePrefixes, enumerate_interface_prefixes, has_scoped_direct_route_from,
    interfaces_with_ipv4_route, ipv4_route_sources,
};
use lzh_hole_net::mdns::{MdnsClient, MdnsEvent, OperationId};
use lzh_hole_net::socket::RecvMeta;
use lzh_hole_net::tun::{TunConfig, Tunnel, TunnelError};
use lzh_hole_protocol::engine::{
    CandidatePolicy, EngineBuildError, EngineConfig, EngineSnapshot, PeerEngine,
};
use lzh_hole_protocol::handshake::HandshakeConfig;
use lzh_hole_protocol::path::{LanSubnet, PathCandidate, TransportPolicy};
use lzh_hole_store::{FileLock, HighWaterError, PeerRecordCache};
use lzh_hole_types::{BootId, DiscoveryPublicKey, Secret32, TransportId};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, interval_at, timeout};

use crate::config::{ConfigError, ResolvedConfig, ServiceConfig};
use lzh_hole_control::{
    ByteCounters, COMMAND_CHANNEL_CAPACITY, ComponentState, ComponentStatus, ControlConfig,
    ControlError, ControlResponse, ControlServer, DaemonState, DropCounters, ServiceCommand,
    ServiceSnapshot,
};
use lzh_hole_discovery::{
    Delivery, ExchangeAction, ExchangeTracker, MessageKind, NtfyConfig, NtfyError, NtfyEvent,
    NtfyHandle, NtfyOperation, NtfyPacingLoad, NtfyPacingStore, NtfyTransport, PayloadError,
    RequestId, SignedPayload, topic_for_relationship,
};
use lzh_hole_store::{PairingError, StateDir, read_private_bytes, write_private_bytes};

const ENGINE_TICK: Duration = Duration::from_millis(250);
mod candidates;
mod dataplane;
mod discovery;
mod lifecycle;
mod status;
mod transport;

use candidates::{CandidateRegistry, CandidateTransport};
use discovery::{MdnsOperation, NtfyBlock};
use status::component;
use transport::{TransportDatagram, TransportSet};

const SOCKET_IO_TIMEOUT: Duration = Duration::from_secs(5);
const RECOVERY_RETRY: Duration = Duration::from_secs(5);
const INTERFACE_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const MAX_OWN_MAPPINGS: usize = 8;
const NTFY_CHANNEL_CAPACITY: usize = 16;

/// Daemon setup or runtime failure. Network errors are normally handled inside
/// the event loop and reported in status rather than terminating the process.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    /// Configuration/pairing load failure.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Pairing state failure.
    #[error(transparent)]
    Pairing(#[from] PairingError),
    /// Control socket failure.
    #[error(transparent)]
    Control(#[from] ControlError),
    /// ntfy setup failure.
    #[error(transparent)]
    Ntfy(#[from] NtfyError),
    /// Signed payload construction failure.
    #[error(transparent)]
    Payload(#[from] PayloadError),
    /// Peer-record policy failure.
    #[error(transparent)]
    PeerRecord(#[from] PeerRecordReject),
    /// Durable peer high-water failure.
    #[error(transparent)]
    HighWater(#[from] HighWaterError),
    /// Engine construction failure.
    #[error(transparent)]
    Engine(#[from] EngineBuildError),
    /// Explicitly requested utun setup failure.
    #[error(transparent)]
    Tunnel(#[from] TunnelError),
    /// Tokio runtime creation failure.
    #[error("Tokio runtime: {0}")]
    Runtime(std::io::Error),
    /// Physical interface/socket setup failure.
    #[error("physical network setup: {0}")]
    Network(String),
    /// Persistent state or sequence failure.
    #[error("daemon state: {0}")]
    State(String),
}

/// Run the resident service to shutdown. This function itself never grants
/// privileges; `allow_tun` is the explicit operator opt-in for privileged utun.
pub fn run(config_path: PathBuf, allow_tun: bool) -> Result<ExitCode, DaemonError> {
    let resolved = ServiceConfig::load_resolved(&config_path)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(DaemonError::Runtime)?;
    runtime.block_on(async {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        run_async(
            resolved,
            allow_tun,
            RuntimeComponents::production(),
            shutdown_rx,
        )
        .await
    })?;
    Ok(ExitCode::SUCCESS)
}

/// Execute one doctor request without loading the daemon configuration.
pub fn doctor(socket: &Path) -> Result<ControlResponse, DaemonError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(DaemonError::Runtime)?;
    Ok(runtime.block_on(lzh_hole_control::doctor(socket))?)
}

#[derive(Debug)]
struct FileNtfyPacingStore {
    path: PathBuf,
}

impl NtfyPacingStore for FileNtfyPacingStore {
    fn load(&mut self) -> Result<NtfyPacingLoad, String> {
        if self.path.exists() {
            return read_private_bytes(&self.path, 64 * 1024)
                .map(NtfyPacingLoad::Snapshot)
                .map_err(|error| error.to_string());
        }
        Ok(NtfyPacingLoad::Missing)
    }

    fn save(&mut self, snapshot: &[u8]) -> Result<(), String> {
        write_private_bytes(&self.path, snapshot).map_err(|error| error.to_string())
    }
}

#[derive(Debug, Clone, Copy)]
struct RuntimeComponents {
    network: bool,
}

impl RuntimeComponents {
    const fn production() -> Self {
        Self { network: true }
    }

    #[cfg(test)]
    const fn offline_for_test() -> Self {
        Self { network: false }
    }
}

async fn run_async(
    resolved: ResolvedConfig,
    allow_tun: bool,
    components: RuntimeComponents,
    external_shutdown: watch::Receiver<bool>,
) -> Result<(), DaemonError> {
    let started = now_unix_ms();
    let initial = ServiceSnapshot::starting(std::process::id(), started);
    let (snapshots, _snapshot_rx) = watch::channel(initial);
    let (command_tx, command_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
    let control_config = ControlConfig::new(
        resolved.config.control_socket.clone(),
        resolved.config.management_uid,
    )?;
    let control = ControlServer::bind(&control_config, command_tx)?;
    let mut daemon = Daemon::new(resolved, allow_tun, components, snapshots)?;

    let (ntfy_events, ntfy_handle, ntfy_task) = if components.network {
        let mut ntfy = NtfyConfig::new(
            &daemon.resolved.config.ntfy.base_url,
            &daemon.resolved.config.ntfy.topic,
        )?;
        if let Some(ip) = daemon.resolved.config.ntfy.resolve_ip {
            ntfy = ntfy.with_resolve_ip(ip)?;
        }
        let ntfy = ntfy.with_cached_replay(true);
        let pacing = FileNtfyPacingStore {
            path: daemon.state.file("ntfy-pacing.json"),
        };
        let (transport, handle, events) = NtfyTransport::channel_with_pacing_store(
            ntfy,
            NTFY_CHANNEL_CAPACITY,
            Box::new(pacing),
        )?;
        let task = tokio::spawn(transport.run());
        (Some(events), Some(handle), Some(task))
    } else {
        (None, None, None)
    };
    daemon.ntfy_events = ntfy_events;
    daemon.ntfy_handle = ntfy_handle;
    daemon.ntfy_task = ntfy_task;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let control_task = tokio::spawn(control.serve(shutdown_rx.clone()));
    daemon.snapshot.mark_daemon_running(now_unix_ms());
    daemon.publish_snapshot();
    let run_result = daemon.event_loop(command_rx, external_shutdown).await;
    daemon.shutdown().await;
    let _ = shutdown_tx.send(true);
    if let Some(task) = daemon.ntfy_task.take() {
        let _ = timeout(Duration::from_secs(5), task).await;
    }
    control_task
        .await
        .map_err(|error| DaemonError::State(format!("control task: {error}")))??;
    run_result
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

fn now_unix_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_micros().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

fn endpoint(addr: SocketAddrV4) -> Endpoint {
    Endpoint::new(*addr.ip(), addr.port())
}

fn socket_addr(endpoint: Endpoint) -> SocketAddrV4 {
    SocketAddrV4::new(endpoint.ip, endpoint.port)
}

struct Daemon {
    resolved: ResolvedConfig,
    state: StateDir,
    signing_key: SigningKey,
    _publisher_lock: FileLock,
    peer_cache: PeerRecordCache,
    exchange: ExchangeTracker,
    network_enabled: bool,
    transports: TransportSet,
    interface_failures: BTreeMap<String, u64>,
    engine: Option<PeerEngine>,
    registry: CandidateRegistry,
    paths: Vec<PathCandidate>,
    topology: Vec<InterfacePrefixes>,
    lan_scopes: BTreeMap<u32, LanScope>,
    next_scope_generation: u64,
    clock: Instant,
    public: PublicDiscovery,
    lan: LanDiscovery,
    mdns: Option<MdnsClient>,
    mdns_operations: BTreeMap<OperationId, MdnsOperation>,
    next_mdns_retry: Instant,
    lan_status: ComponentStatus,
    stun_status: ComponentStatus,
    boot_id: BootId,
    generation: u64,
    tunnel: Option<Tunnel>,
    tun_status: ComponentStatus,
    route_status: ComponentStatus,
    ntfy_status: ComponentStatus,
    ntfy_events: Option<mpsc::Receiver<NtfyEvent>>,
    ntfy_handle: Option<NtfyHandle>,
    ntfy_task: Option<JoinHandle<Result<(), NtfyError>>>,
    ntfy_subscribed: bool,
    ntfy_block: Option<NtfyBlock>,
    next_interface_check: Instant,
    bytes: ByteCounters,
    io_drops: DropCounters,
    last_healthy_unix_ms: Option<u64>,
    snapshot: ServiceSnapshot,
    snapshot_tx: watch::Sender<ServiceSnapshot>,
}

impl Daemon {
    fn new(
        resolved: ResolvedConfig,
        allow_tun: bool,
        components: RuntimeComponents,
        snapshot_tx: watch::Sender<ServiceSnapshot>,
    ) -> Result<Self, DaemonError> {
        let network_enabled = components.network;
        let expected_topic = topic_for_relationship(&resolved.relationship.relationship_id);
        if resolved.config.ntfy.topic != expected_topic {
            return Err(DaemonError::State(format!(
                "ntfy.topic must be {expected_topic} for this finalized relationship"
            )));
        }
        let state = StateDir::open(&resolved.config.state_dir)?;
        let signing_key = state.load_signing_key()?;
        let actual_key = DiscoveryPublicKey::from_bytes(signing_key.verifying_key().to_bytes());
        if actual_key != resolved.relationship.self_public_key {
            return Err(DaemonError::State(
                "identity seed does not match the finalized relationship".to_owned(),
            ));
        }
        let psk = state.load_psk()?;
        let publisher_lock = state.lock_publisher()?;
        let peer_cache = PeerRecordCache::load(&state.file("peer-record.json"))?;
        let boot_id = BootId::random().map_err(|error| DaemonError::State(error.to_string()))?;
        let generation = 1;
        let engine = if network_enabled {
            Some(lifecycle::make_engine(
                &resolved, &psk, boot_id, generation,
            )?)
        } else {
            None
        };
        let lan = LanDiscovery::new(resolved.relationship.peer_public_key);

        let (tunnel, tun_status, route_status) = if allow_tun {
            let tunnel = Tunnel::create(
                TunConfig::new(resolved.self_vip, resolved.peer_vip).with_mtu(resolved.config.mtu),
            )?;
            let tun_status = ComponentStatus {
                state: ComponentState::Healthy,
                detail: Some(format!(
                    "actual {} if_index={} mtu={}",
                    tunnel.name(),
                    tunnel.if_index(),
                    resolved.config.mtu
                )),
                last_success_unix_ms: Some(now_unix_ms()),
                last_change_unix_ms: Some(now_unix_ms()),
            };
            let (peer_route, prefix_len) = resolved.peer_host_route();
            let route_status = ComponentStatus {
                state: ComponentState::Healthy,
                detail: Some(format!(
                    "Tunnel owns only peer {peer_route}/{prefix_len}; no additional route installed"
                )),
                last_success_unix_ms: Some(now_unix_ms()),
                last_change_unix_ms: Some(now_unix_ms()),
            };
            (Some(tunnel), tun_status, route_status)
        } else {
            let detail = if !network_enabled {
                "disabled by test-only component injection".to_owned()
            } else {
                "not created; pass --allow-tun for the explicit privileged operation".to_owned()
            };
            (
                None,
                ComponentStatus {
                    state: ComponentState::NotConfigured,
                    detail: Some(detail.clone()),
                    ..ComponentStatus::default()
                },
                ComponentStatus {
                    state: ComponentState::NotConfigured,
                    detail: Some(detail),
                    ..ComponentStatus::default()
                },
            )
        };
        let ntfy_status = if !network_enabled {
            ComponentStatus {
                state: ComponentState::NotConfigured,
                detail: Some("disabled by test-only component injection".to_owned()),
                ..ComponentStatus::default()
            }
        } else {
            ComponentStatus {
                state: ComponentState::Starting,
                detail: Some("ntfy transport created; not subscribed yet".to_owned()),
                ..ComponentStatus::default()
            }
        };
        let mut snapshot = snapshot_tx.borrow().clone();
        snapshot.ntfy = ntfy_status.clone();
        snapshot.tun = tun_status.clone();
        snapshot.routes = route_status.clone();
        snapshot_tx.send_replace(snapshot.clone());
        let now = Instant::now();
        let mut daemon = Self {
            resolved,
            state,
            signing_key,
            _publisher_lock: publisher_lock,
            peer_cache,
            exchange: ExchangeTracker::default(),
            network_enabled,
            transports: TransportSet::default(),
            interface_failures: BTreeMap::new(),
            engine,
            registry: CandidateRegistry::default(),
            paths: Vec::new(),
            topology: Vec::new(),
            lan_scopes: BTreeMap::new(),
            next_scope_generation: 1,
            clock: now,
            public: PublicDiscovery::new(),
            lan,
            mdns: None,
            mdns_operations: BTreeMap::new(),
            next_mdns_retry: now,
            lan_status: component(ComponentState::Starting, "no Bonjour observation yet", None),
            stun_status: component(ComponentState::Starting, "no public mapping measured", None),
            boot_id,
            generation,
            tunnel,
            tun_status,
            route_status,
            ntfy_status,
            ntfy_events: None,
            ntfy_handle: None,
            ntfy_task: None,
            ntfy_subscribed: false,
            ntfy_block: None,
            next_interface_check: now + INTERFACE_CHECK_INTERVAL,
            bytes: ByteCounters::default(),
            io_drops: DropCounters::default(),
            last_healthy_unix_ms: None,
            snapshot,
            snapshot_tx,
        };
        if network_enabled {
            daemon.refresh_network();
        } else {
            daemon.lan_status = component(
                ComponentState::NotConfigured,
                "disabled by test-only component injection",
                None,
            );
        }
        Ok(daemon)
    }

    async fn event_loop(
        &mut self,
        mut commands: mpsc::Receiver<ServiceCommand>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), DaemonError> {
        let mut ticker = interval_at(Instant::now() + ENGINE_TICK, ENGINE_TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|error| DaemonError::Network(format!("SIGTERM handler: {error}")))?;
        self.housekeeping().await;
        loop {
            self.publish_snapshot();
            if *shutdown.borrow() {
                return Ok(());
            }
            let event = tokio::select! {
                _ = ticker.tick() => LoopEvent::Tick,
                command = commands.recv() => LoopEvent::Command(command),
                ntfy = next_ntfy(&mut self.ntfy_events) => LoopEvent::Ntfy(ntfy),
                udp = self.transports.recv() => LoopEvent::Udp(udp),
                mdns = next_mdns(&mut self.mdns) => LoopEvent::Mdns(mdns),
                tun = recv_tun(self.tunnel.as_ref(), self.resolved.config.mtu) => LoopEvent::Tun(tun),
                _ = tokio::signal::ctrl_c() => LoopEvent::Stop,
                _ = sigterm.recv() => LoopEvent::Stop,
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { LoopEvent::Stop } else { LoopEvent::Tick }
                }
            };
            match event {
                LoopEvent::Tick => self.housekeeping().await,
                LoopEvent::Stop => return Ok(()),
                LoopEvent::Command(None) => return Ok(()),
                LoopEvent::Command(Some(command)) => self.handle_command(command).await,
                LoopEvent::Ntfy(None) => {
                    self.ntfy_events = None;
                    self.ntfy_subscribed = false;
                    self.ntfy_status = component(
                        ComponentState::Failed,
                        "ntfy actor stopped; UDP continues and the operation budget is not reset",
                        None,
                    );
                }
                LoopEvent::Ntfy(Some(event)) => self.handle_ntfy(event).await,
                LoopEvent::Udp(udp) => self.handle_udp(udp).await,
                LoopEvent::Mdns(event) => self.handle_mdns(event),
                LoopEvent::Tun(tun) => self.handle_tun(tun).await,
            }
            self.drain_engine().await;
        }
    }

    async fn housekeeping(&mut self) {
        let now_ms = now_unix_ms();
        if let Some(engine) = &mut self.engine {
            engine.tick(now_ms);
        }
        let now = self.monotonic_ms();
        let expired = self.public.expire(now);
        if let Some(id) = expired.expired_request {
            self.exchange.cancel_request(id);
        }
        let mut updates = expired.updates;
        updates.extend(self.lan.expire(now));
        if !updates.is_empty() {
            self.apply_discovery_updates(updates);
        }
        self.registry.expire(now);
        self.refresh_public_request();
        if self.network_enabled && Instant::now() >= self.next_interface_check {
            self.next_interface_check = Instant::now() + INTERFACE_CHECK_INTERVAL;
            self.refresh_network();
        }
        self.ensure_mdns();
        self.maybe_start_stun().await;
        self.maybe_queue_request();
    }

    async fn handle_command(&mut self, command: ServiceCommand) {
        match command {
            ServiceCommand::Doctor { reply } => {
                self.publish_snapshot();
                let _ = reply.send(Ok(self.snapshot.clone()));
            }
        }
    }

    fn monotonic_ms(&self) -> u64 {
        self.clock.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }
}

enum LoopEvent {
    Tick,
    Stop,
    Command(Option<ServiceCommand>),
    Ntfy(Option<NtfyEvent>),
    Udp(TransportDatagram),
    Mdns(std::io::Result<MdnsEvent>),
    Tun(TunEvent),
}

struct TunEvent {
    result: std::io::Result<usize>,
    buffer: Vec<u8>,
}

async fn next_mdns(mdns: &mut Option<MdnsClient>) -> std::io::Result<MdnsEvent> {
    match mdns {
        Some(mdns) => mdns.recv().await,
        None => std::future::pending().await,
    }
}

async fn recv_tun(tunnel: Option<&Tunnel>, mtu: u16) -> TunEvent {
    let Some(tunnel) = tunnel else {
        std::future::pending::<()>().await;
        unreachable!();
    };
    let mut buffer = vec![0u8; usize::from(mtu)];
    let result = tunnel.recv_ipv4(&mut buffer).await;
    TunEvent { result, buffer }
}

async fn next_ntfy(events: &mut Option<mpsc::Receiver<NtfyEvent>>) -> Option<NtfyEvent> {
    match events {
        Some(events) => events.recv().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests;
