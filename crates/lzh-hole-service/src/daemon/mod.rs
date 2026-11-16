//! Resident wiring: bounded physical transports, per-relationship discovery,
//! one `PeerSet` and one utun.
//!
//! Public-network operation is explicit by invoking `daemon`. utun creation and
//! its owned peer /32 routes additionally require `--allow-tun`. The offline
//! control mode is a truthful control-plane-only mode, not an overlay test.
//!
//! A node holds one identity, one overlay address and one set of physical
//! sockets however many peers it has. Everything else is per relationship: the
//! engine, the coordination topic, the durable sequence stream, the anti-rollback
//! cache, the request correlation and the candidate set. Nothing is pooled
//! across peers, so admitting a peer cannot weaken the peers already present.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use lzh_hole_discovery::candidate::Endpoint;
use lzh_hole_discovery::peer_record::PeerRecordReject;
use lzh_hole_discovery::stun::{TRANSACTION_ID_LEN, looks_like_stun};
use lzh_hole_discovery::{
    CandidateScope, DiscoveryUpdate, GatewayDnsConfig, GatewayDnsResolver, LanAdvertisement,
    LanDiscovery, LanObservation, LanScope, NtfyConfig as NtfyTransportConfig, NtfyError,
    NtfyEvent, NtfyHandle, NtfyOperation, NtfyPacingLoad, NtfyPacingStore, NtfyResolver,
    NtfyTransport, PayloadError, PublicDiscovery, RequestId, SignedPayload, topic_for_relationship,
};
use lzh_hole_net::interface::{
    InterfaceInfo, InterfacePrefixes, enumerate_interface_prefixes, has_scoped_direct_route_from,
    interfaces_with_ipv4_route, ipv4_route_sources,
};
use lzh_hole_net::mdns::{MdnsClient, MdnsEvent, OperationId};
use lzh_hole_net::overlay::OverlayRoutes;
use lzh_hole_net::socket::RecvMeta;
use lzh_hole_net::tun::{TunConfig, Tunnel, TunnelError};
use lzh_hole_protocol::engine::{CandidatePolicy, EngineBuildError, EngineConfig};
use lzh_hole_protocol::handshake::HandshakeConfig;
use lzh_hole_protocol::mesh::{PeerSet, PeerSetError};
use lzh_hole_protocol::path::{LanSubnet, PathCandidate, TransportPolicy};
use lzh_hole_protocol::punch::PUNCH_BURST;
use lzh_hole_store::{FileLock, HighWaterError};
use lzh_hole_types::{BootId, DiscoveryPublicKey, RelationshipId, TransportId};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, interval_at, timeout};

use crate::config::{ConfigError, ResolvedConfig, ServiceConfig};
use lzh_hole_control::{
    ByteCounters, COMMAND_CHANNEL_CAPACITY, ComponentState, ComponentStatus, ControlConfig,
    ControlError, ControlResponse, ControlServer, DaemonState, DropCounters, PunchStatus,
    ServiceCommand, ServiceSnapshot,
};
use lzh_hole_store::{PairingError, StateDir, read_private_bytes, write_private_bytes};

const ENGINE_TICK: Duration = Duration::from_millis(250);
mod candidates;
mod dataplane;
mod discovery;
mod lifecycle;
mod peer;
mod punch;
mod status;
mod transport;

use candidates::{CandidateRegistry, CandidateTransport};
use discovery::{MdnsOperation, publication_endpoints};
use peer::{PeerNtfy, PeerRuntime};
use punch::{PunchAttempt, PunchDatagram, PunchPeerState, PunchSockets, TokenBucket};
use status::component;
use transport::{TransportDatagram, TransportIds, TransportSet};

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
    /// A relationship could not join the mesh.
    #[error("peer set refused relationship {relationship}: {source}")]
    PeerSet {
        /// The relationship that was refused.
        relationship: String,
        /// Why it was refused.
        source: PeerSetError,
    },
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

    // One actor for one host, serving every relationship's topic. Serving eight
    // relationships with eight actors would multiply the per-host operation
    // interval and the rolling daily budget by eight against the same host.
    let (ntfy_events, ntfy_handle, ntfy_task) = if components.network {
        let topics = daemon
            .peers
            .keys()
            .map(|id| (*id, topic_for_relationship(id)))
            .collect::<BTreeMap<_, _>>();
        let mut ntfy = NtfyTransportConfig::multi(&daemon.resolved.config.ntfy.base_url, &topics)?;
        // The ntfy hostname is resolved over a socket pinned to the selected
        // physical interface, against that interface own default gateway. A
        // host resolver that hands out Fake-IP addresses therefore cannot
        // decide where a coordination operation goes.
        ntfy = ntfy.with_resolver(NtfyResolver::new(GatewayDnsResolver::new(
            GatewayDnsConfig {
                interface: daemon.resolved.config.interface.clone(),
                bind_ip: daemon.resolved.config.bind_ip,
                server: daemon.resolved.config.ntfy.dns_server,
            },
        )));
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
    network_enabled: bool,
    transports: TransportSet,
    /// One identifier space for the data plane and the punch pool alike.
    transport_ids: TransportIds,

    /// Every pinned peer, in relationship-id order. Fixed for the process
    /// lifetime: a peer is admitted by configuration and pairing, not at runtime.
    peers: BTreeMap<RelationshipId, PeerRuntime>,
    /// The same ids as a stable vector, so event-loop polling never has to
    /// allocate an order on every wakeup.
    peer_order: Vec<RelationshipId>,
    /// One independently authenticated engine per relationship.
    engines: Option<PeerSet>,

    /// Node-level STUN state, shared by every relationship.
    public: PublicDiscovery,
    /// Bonjour, pinned to every peer key at once.
    lan: LanDiscovery,
    /// Discovery hints, attributed to the relationship that produced them.
    registry: CandidateRegistry,
    /// Projected paths per relationship.
    paths: BTreeMap<RelationshipId, Vec<PathCandidate>>,

    punch_sockets: PunchSockets,
    punch_bucket: TokenBucket,
    /// At most one hole-punch attempt runs at a time across the whole mesh.
    ///
    /// Punch sockets are a node-level descriptor budget, and a scan is only
    /// meaningful against one peer's NAT at a time. Peers that also want a punch
    /// wait their turn; `peer_punch_status` reports that wait truthfully rather
    /// than claiming an attempt is running.
    punch: Option<PunchAttempt>,
    /// Per-relationship punch backoff, last failure and current queue reason.
    ///
    /// Isolated per relationship so a peer that keeps failing never delays
    /// another peer's attempt, and so a relationship's bookkeeping disappears
    /// with the relationship itself.
    punch_states: BTreeMap<RelationshipId, PunchPeerState>,
    punch_send_failures: u32,
    /// A punch slot whose socket already joined the data plane.
    promoted_slot: Option<(RelationshipId, u16, TransportId)>,
    /// Promoted sockets get a bounded handshake grace period, then must own a path.
    promoted_transports: BTreeMap<TransportId, (RelationshipId, u64)>,

    interface_failures: BTreeMap<String, u64>,
    topology: Vec<InterfacePrefixes>,
    lan_scopes: BTreeMap<u32, LanScope>,
    next_scope_generation: u64,
    clock: Instant,
    mdns: Option<MdnsClient>,
    mdns_operations: BTreeMap<OperationId, MdnsOperation>,
    next_mdns_retry: Instant,
    lan_status: ComponentStatus,
    stun_status: ComponentStatus,
    boot_id: BootId,
    generation: u64,
    /// One utun plus one owned /32 per peer. Absent unless `--allow-tun`.
    overlay: Option<OverlayRoutes>,
    tun_status: ComponentStatus,
    route_status: ComponentStatus,
    /// One ntfy actor for the whole node.
    ntfy_events: Option<mpsc::Receiver<NtfyEvent>>,
    ntfy_handle: Option<NtfyHandle>,
    ntfy_task: Option<JoinHandle<Result<(), NtfyError>>>,
    next_interface_check: Instant,
    bytes: ByteCounters,
    io_drops: DropCounters,
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
        let state = StateDir::open(&resolved.config.state_dir)?;
        let signing_key = state.load_signing_key()?;
        let actual_key = DiscoveryPublicKey::from_bytes(signing_key.verifying_key().to_bytes());
        for peer in &resolved.peers {
            if peer.relationship.self_public_key != actual_key {
                return Err(DaemonError::State(format!(
                    "identity seed does not match finalized relationship {}",
                    peer.relationship_id().to_hex()
                )));
            }
        }
        let publisher_lock = state.lock_publisher()?;
        let boot_id = BootId::random().map_err(|error| DaemonError::State(error.to_string()))?;
        let generation = 1;

        // Every overlay address in the mesh is never a physical candidate
        // target, for this node's engines and for every peer's record.
        let forbidden_addresses = std::iter::once(resolved.self_vip)
            .chain(resolved.peers.iter().map(|peer| peer.peer_vip))
            .collect::<Vec<_>>();
        let stun_servers = resolved
            .config
            .stun_seeds
            .iter()
            .map(|server| endpoint(*server))
            .collect::<Vec<_>>();

        let mut engines = if network_enabled {
            let mut set = PeerSet::new(resolved.self_vip, actual_key);
            for peer in &resolved.peers {
                let psk = state.load_psk(peer.relationship_id())?;
                let config = EngineConfig {
                    handshake: HandshakeConfig {
                        relationship_id: peer.relationship_id(),
                        me: actual_key,
                        peer: peer.peer_key(),
                        boot_id,
                        generation,
                    },
                    self_vip: resolved.self_vip,
                    peer_vip: peer.peer_vip,
                    candidate_policy: CandidatePolicy {
                        own_endpoints: Vec::new(),
                        forbidden_addresses: forbidden_addresses.clone(),
                        stun_servers: stun_servers.clone(),
                        require_public_unicast: true,
                    },
                };
                set.insert(config, &psk)
                    .map_err(|source| DaemonError::PeerSet {
                        relationship: peer.relationship_id().to_hex(),
                        source,
                    })?;
            }
            Some(set)
        } else {
            None
        };
        let _ = &mut engines;

        let ntfy_detail = if network_enabled {
            "one actor created for every relationship topic; not subscribed yet"
        } else {
            "disabled by test-only component injection"
        };
        let mut peers = BTreeMap::new();
        for peer in &resolved.peers {
            let ntfy = if network_enabled {
                PeerNtfy::starting(ntfy_detail)
            } else {
                PeerNtfy::not_configured(ntfy_detail)
            };
            let runtime = PeerRuntime::new(&state, peer.relationship.clone(), peer.peer_vip, ntfy)?;
            peers.insert(peer.relationship_id(), runtime);
        }
        let peer_order = peers.keys().copied().collect::<Vec<_>>();

        let lan = LanDiscovery::new(
            resolved
                .peers
                .iter()
                .map(|peer| (peer.peer_key(), peer.relationship_id()))
                .collect(),
        );

        let (overlay, tun_status, route_status) = if allow_tun {
            let routes = resolved
                .peers
                .iter()
                .map(|peer| peer.peer_vip)
                .collect::<Vec<_>>();
            let overlay = OverlayRoutes::create(
                TunConfig::new(resolved.self_vip).with_mtu(resolved.config.mtu),
                &routes,
            )?;
            let tun_status = ComponentStatus {
                state: ComponentState::Healthy,
                detail: Some(format!(
                    "actual {} if_index={} mtu={}",
                    overlay.tunnel().name(),
                    overlay.tunnel().if_index(),
                    resolved.config.mtu
                )),
                last_success_unix_ms: Some(now_unix_ms()),
                last_change_unix_ms: Some(now_unix_ms()),
            };
            let route_status = ComponentStatus {
                state: ComponentState::Healthy,
                detail: Some(format!(
                    "tunnel owns exactly {} peer /32 routes and nothing else: {}",
                    routes.len(),
                    routes
                        .iter()
                        .map(|peer| format!("{peer}/32"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
                last_success_unix_ms: Some(now_unix_ms()),
                last_change_unix_ms: Some(now_unix_ms()),
            };
            (Some(overlay), tun_status, route_status)
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

        let mut snapshot = snapshot_tx.borrow().clone();
        snapshot.tun = tun_status.clone();
        snapshot.routes = route_status.clone();
        snapshot_tx.send_replace(snapshot.clone());
        let now = Instant::now();
        // One punch bookkeeping entry per configured peer, created up front so
        // status reporting never has to distinguish "no attempt yet" from
        // "this relationship is unknown".
        let punch_states: BTreeMap<RelationshipId, PunchPeerState> = peer_order
            .iter()
            .map(|id| (*id, PunchPeerState::default()))
            .collect();
        let mut daemon = Self {
            resolved,
            state,
            signing_key,
            _publisher_lock: publisher_lock,
            network_enabled,
            transports: TransportSet::default(),
            transport_ids: TransportIds::default(),
            peers,
            peer_order,
            engines,
            public: PublicDiscovery::new(),
            lan,
            registry: CandidateRegistry::default(),
            paths: BTreeMap::new(),
            punch_sockets: PunchSockets::default(),
            punch_bucket: TokenBucket::new(PUNCH_BURST, PUNCH_BURST, 0),
            punch: None,
            punch_states,
            punch_send_failures: 0,
            promoted_slot: None,
            promoted_transports: BTreeMap::new(),
            interface_failures: BTreeMap::new(),
            topology: Vec::new(),
            lan_scopes: BTreeMap::new(),
            next_scope_generation: 1,
            clock: now,
            mdns: None,
            mdns_operations: BTreeMap::new(),
            next_mdns_retry: now,
            lan_status: component(ComponentState::Starting, "no Bonjour observation yet", None),
            stun_status: component(ComponentState::Starting, "no public mapping measured", None),
            boot_id,
            generation,
            overlay,
            tun_status,
            route_status,
            ntfy_events: None,
            ntfy_handle: None,
            ntfy_task: None,
            next_interface_check: now + INTERFACE_CHECK_INTERVAL,
            bytes: ByteCounters::default(),
            io_drops: DropCounters::default(),
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

    /// The utun carrying every owned peer route, if one was created.
    fn tunnel(&self) -> Option<&Tunnel> {
        self.overlay.as_ref().map(OverlayRoutes::tunnel)
    }

    /// Every overlay address in the mesh: ours and every peer's.
    ///
    /// No engine and no peer record may ever name one of these as a physical
    /// candidate target, whichever relationship it belongs to.
    fn forbidden_addresses(&self) -> Vec<Ipv4Addr> {
        std::iter::once(self.resolved.self_vip)
            .chain(self.peers.values().map(|peer| peer.peer_vip))
            .collect()
    }

    /// The parts of `NodeFacts` that must be computed before any peer is
    /// borrowed mutably.
    ///
    /// `NodeFacts` itself is assembled at each call site from individual field
    /// references rather than through a `&self` method, because a method would
    /// borrow the whole daemon and make `self.peers.get_mut(..)` illegal in the
    /// same scope. Field-level borrows of `state`, `signing_key`, `public`,
    /// `transports` and `ntfy_handle` are disjoint from `peers`.
    fn node_fact_parts(&self) -> (Vec<Endpoint>, Vec<Ipv4Addr>) {
        (
            self.resolved
                .config
                .stun_seeds
                .iter()
                .map(|server| endpoint(*server))
                .collect(),
            self.forbidden_addresses(),
        )
    }

    fn self_key(&self) -> DiscoveryPublicKey {
        self.resolved
            .peers
            .first()
            .map(|peer| peer.relationship.self_public_key)
            .unwrap_or_else(|| {
                DiscoveryPublicKey::from_bytes(self.signing_key.verifying_key().to_bytes())
            })
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
                punch = self.punch_sockets.recv() => LoopEvent::Punch(punch),
                mdns = next_mdns(&mut self.mdns) => LoopEvent::Mdns(mdns),
                tun = recv_tun(
                    self.overlay.as_ref().map(OverlayRoutes::tunnel),
                    self.resolved.config.mtu,
                ) => LoopEvent::Tun(tun),
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
                LoopEvent::Ntfy(None) => self.handle_ntfy_closed(),
                LoopEvent::Ntfy(Some(event)) => self.handle_ntfy(event).await,
                LoopEvent::Udp(udp) => self.handle_udp(udp).await,
                LoopEvent::Punch(punch) => {
                    let now_ms = now_unix_ms();
                    self.handle_punch_udp(punch, now_ms);
                }
                LoopEvent::Mdns(event) => self.handle_mdns(event),
                LoopEvent::Tun(tun) => self.handle_tun(tun).await,
            }
            self.drain_engine().await;
            let now_ms = now_unix_ms();
            self.drain_punch(now_ms).await;
        }
    }

    async fn housekeeping(&mut self) {
        let now_ms = now_unix_ms();
        if let Some(engines) = &mut self.engines {
            engines.tick(now_ms);
        }
        // A punch never starts while a path is healthy; `maybe_start_punch`
        // enforces that and records why it declined.
        self.maybe_start_punch(now_ms);
        self.drive_punch(now_ms);
        let now = self.monotonic_ms();
        self.public.expire_sockets(now);
        let mut updates = Vec::new();
        for (relationship, peer) in &mut self.peers {
            let expiry = peer.public.expire(now);
            if let Some(id) = expiry.expired_request {
                peer.exchange.cancel_request(id);
            }
            updates.extend(
                expiry
                    .updates
                    .into_iter()
                    .map(|update| (*relationship, update)),
            );
        }
        updates.extend(
            self.lan
                .expire(now)
                .into_iter()
                .map(|update| (update.relationship_id, update.update)),
        );
        self.apply_tagged_updates(updates);
        self.registry.expire(now);
        self.refresh_public_requests();
        if self.network_enabled && Instant::now() >= self.next_interface_check {
            self.next_interface_check = Instant::now() + INTERFACE_CHECK_INTERVAL;
            self.refresh_network();
        }
        self.ensure_mdns();
        self.maybe_start_stun().await;
        self.maybe_queue_requests();
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
    Punch(PunchDatagram),
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
