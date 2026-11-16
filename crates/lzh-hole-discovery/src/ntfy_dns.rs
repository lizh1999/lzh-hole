//! ntfy hostname resolution that never reads the host resolver.
//!
//! The transport asks this resolver instead of the system one. A system
//! resolver that has been pointed at a Fake-IP proxy hands out 198.18.0.0/15
//! addresses whose reachability depends on that proxy being up, and no amount
//! of retrying makes such an answer real. Asking the selected physical
//! interface own default gateway, from a socket pinned to that interface,
//! keeps the question and the answer on the same path the data plane uses.
//!
//! Nothing here decides whether an answer may be connected to. That policy
//! lives in the transport, so it applies to every injected resolver equally.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use lzh_hole_net::dns::{self, DNS_PORT, DnsError};
use lzh_hole_net::interface::{
    InterfacePrefixes, Ipv4Prefix, default_gateway_ipv4, enumerate_interface_prefixes,
};

/// Bound on one whole resolution, including every DNS attempt.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(15);

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Where the ntfy hostname may be resolved from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewayDnsConfig {
    /// Physical interface to pin the DNS socket to. None selects one.
    pub interface: Option<String>,
    /// Source address to bind. None selects one on the chosen interface.
    pub bind_ip: Option<Ipv4Addr>,
    /// Resolver to ask. None uses the chosen interface default gateway.
    pub server: Option<SocketAddrV4>,
}

/// One resolved source and server triple for a single lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryPlan {
    /// Interface the DNS socket is pinned to.
    pub interface: String,
    /// Source address the DNS socket binds.
    pub bind_ip: Ipv4Addr,
    /// Server that will be asked.
    pub server: SocketAddrV4,
}

/// Why one ntfy hostname could not be resolved.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// No physical IPv4 interface is usable for a DNS query.
    #[error("no physical IPv4 interface is usable for a DNS query")]
    NoInterface,
    /// The requested interface is unknown, or is not a usable physical one.
    #[error("{0:?} is not a usable physical IPv4 interface")]
    UnknownInterface(String),
    /// No source address shares a link with the server that must be asked.
    #[error("{interface} has no IPv4 source address on the same link as {server}")]
    NoSource {
        /// Interface that was chosen.
        interface: String,
        /// Server that must be reachable from it.
        server: Ipv4Addr,
    },
    /// Interfaces or routes could not be read.
    #[error("cannot read interfaces or routes: {0}")]
    Platform(#[from] std::io::Error),
    /// The lookup did not finish inside its bound.
    #[error("DNS lookup did not finish within 15 seconds")]
    Timeout,
    /// The lookup itself failed.
    #[error("DNS lookup failed: {0}")]
    Query(#[from] DnsError),
}

/// A reqwest resolver backed by an interface-bound gateway DNS query.
#[derive(Debug, Clone)]
pub struct GatewayDnsResolver {
    config: GatewayDnsConfig,
}

impl GatewayDnsConfig {
    /// Ask one explicit resolver instead of the interface default gateway.
    pub fn with_server(mut self, server: Ipv4Addr) -> Self {
        self.server = Some(SocketAddrV4::new(server, DNS_PORT));
        self
    }
}

impl GatewayDnsResolver {
    /// Build a resolver from an explicit interface, source and server policy.
    pub fn new(config: GatewayDnsConfig) -> Self {
        Self { config }
    }

    /// The plan one lookup would use, without sending anything.
    pub fn plan(&self) -> Result<QueryPlan, ResolveError> {
        plan_query(&self.config)
    }
}

impl reqwest::dns::Resolve for GatewayDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let config = self.config.clone();
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addresses = resolve_host(&config, &host).await?;
            // Port zero lets the connector apply the scheme port, and an
            // explicit port in the URL still wins, exactly as reqwest documents.
            let addrs: reqwest::dns::Addrs =
                Box::new(addresses.into_iter().map(|ip| SocketAddr::from((ip, 0))));
            Ok::<reqwest::dns::Addrs, BoxError>(addrs)
        })
    }
}

async fn resolve_host(
    config: &GatewayDnsConfig,
    host: &str,
) -> Result<Vec<Ipv4Addr>, ResolveError> {
    let plan = plan_query(config)?;
    tokio::time::timeout(
        RESOLVE_TIMEOUT,
        dns::query_a(&plan.interface, plan.bind_ip, plan.server, host),
    )
    .await
    .map_err(|_| ResolveError::Timeout)?
    .map_err(ResolveError::Query)
}

fn plan_query(config: &GatewayDnsConfig) -> Result<QueryPlan, ResolveError> {
    let snapshots = enumerate_interface_prefixes()?;
    let candidates = candidate_interfaces(&snapshots, config.interface.as_deref())?;
    let mut last: Option<ResolveError> = None;
    for snapshot in candidates {
        match plan_for(snapshot, config) {
            Ok(plan) => return Ok(plan),
            // An adapter with a routable address but no gateway, or whose
            // aliases cannot reach the server, is simply not this host way
            // out. Keep looking instead of failing the whole lookup.
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or(ResolveError::NoInterface))
}

fn plan_for(
    snapshot: &InterfacePrefixes,
    config: &GatewayDnsConfig,
) -> Result<QueryPlan, ResolveError> {
    let (server_ip, server_port) = match config.server {
        Some(server) => (*server.ip(), server.port()),
        None => (default_gateway_ipv4(&snapshot.interface.name)?, DNS_PORT),
    };
    let bind_ip = choose_source(snapshot, server_ip, config.bind_ip)?;
    Ok(QueryPlan {
        interface: snapshot.interface.name.clone(),
        bind_ip,
        server: SocketAddrV4::new(server_ip, server_port),
    })
}

/// The interfaces a DNS socket may be pinned to, in kernel snapshot order.
///
/// A named interface must be a real, up, non-tunnel IPv4 adapter. Without a
/// name every such adapter becomes a candidate and the first one that can
/// actually reach a resolver wins, which keeps the choice deterministic
/// rather than dependent on route iteration order.
///
/// Adapters that only carry a link-local address, such as the peer-to-peer
/// Wi-Fi interfaces macOS keeps up, are excluded outright: a DNS query needs
/// a routable source address, and those adapters never have a gateway.
fn candidate_interfaces<'a>(
    snapshots: &'a [InterfacePrefixes],
    requested: Option<&str>,
) -> Result<Vec<&'a InterfacePrefixes>, ResolveError> {
    fn usable(snapshot: &InterfacePrefixes) -> bool {
        let interface = &snapshot.interface;
        interface.is_physical_candidate()
            && !interface.is_loopback
            && interface.index != 0
            && !snapshot.ipv4_prefixes.is_empty()
            && interface
                .ipv4
                .iter()
                .any(|address| !address.is_link_local() && !address.is_loopback())
    }
    match requested {
        Some(name) => snapshots
            .iter()
            .find(|snapshot| snapshot.interface.name == name)
            .filter(|snapshot| usable(snapshot))
            .map(|snapshot| vec![snapshot])
            .ok_or_else(|| ResolveError::UnknownInterface(name.to_owned())),
        None => Ok(snapshots
            .iter()
            .filter(|snapshot| usable(snapshot))
            .collect()),
    }
}

/// Pick the source address that can actually reach the server.
///
/// The server must sit inside one of the source own prefixes. A second,
/// unrelated alias on the same adapter is not a licence to send from an
/// address whose link cannot reach the server at all.
fn choose_source(
    snapshot: &InterfacePrefixes,
    server: Ipv4Addr,
    bind_ip: Option<Ipv4Addr>,
) -> Result<Ipv4Addr, ResolveError> {
    let on_link = |address: Ipv4Addr| {
        snapshot
            .ipv4_prefixes
            .iter()
            .any(|prefix: &Ipv4Prefix| prefix.address == address && prefix.contains(server))
    };
    let refuse = || ResolveError::NoSource {
        interface: snapshot.interface.name.clone(),
        server,
    };
    match bind_ip {
        Some(address) if on_link(address) => Ok(address),
        Some(_) => Err(refuse()),
        None => snapshot
            .interface
            .ipv4
            .iter()
            .copied()
            .find(|address| on_link(*address))
            .ok_or_else(refuse),
    }
}

#[cfg(test)]
mod tests;
