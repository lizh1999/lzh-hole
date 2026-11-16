//! ntfy hostname resolution that never reads the host resolver.
//!
//! The transport asks this resolver instead of the system one. A system
//! resolver that has been pointed at a Fake-IP proxy hands out 198.18.0.0/15
//! addresses whose reachability depends on that proxy being up, and no amount
//! of retrying makes such an answer real. Asking a resolver from a socket
//! pinned to the selected physical interface keeps the question and the answer
//! on the same path the data plane uses.
//!
//! Which resolver is asked is a chain, not a guess. A configured server is
//! authoritative. Otherwise each interface contributes the resolvers its own
//! DHCP lease offers and then its own default gateway, and every server that
//! does not answer hands over to the next one inside one bounded resolution.
//! A gateway that does not run a resolver is an ordinary network.
//!
//! Nothing here decides whether an answer may be connected to. That policy
//! lives in the transport, so it applies to every injected resolver equally.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use lzh_hole_net::dhcp::dhcp_dns_servers;
use lzh_hole_net::dns::{self, DNS_PORT, DnsError, DnsOptions};
use lzh_hole_net::interface::{
    InterfacePrefixes, Ipv4Prefix, default_gateway_ipv4, enumerate_interface_prefixes,
    ipv4_route_sources,
};
use tokio::time::Instant;

/// Bound on one whole resolution, including every server that is tried.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(15);
/// Transmissions attempted against one server before moving on to the next.
pub const PLAN_ATTEMPTS: usize = 2;
/// Wait for a single transmission.
pub const PLAN_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(1_500);
/// Bound on one server, so a silent server cannot eat the whole resolution.
pub const PLAN_TIMEOUT: Duration = Duration::from_secs(4);
/// Most servers one interface may contribute to one resolution.
pub const MAX_PLAN_SERVERS: usize = 4;

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
    /// No source address on this interface has a route to the server.
    #[error("{interface} has no IPv4 source address that can reach {server}")]
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

    /// Every plan one lookup may try, in the order it would try them.
    ///
    /// Nothing is sent: this only reads interfaces, routes and DHCP leases.
    pub fn plans(&self) -> Result<Vec<QueryPlan>, ResolveError> {
        plan_queries(&self.config)
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
    let plans = plan_queries(config)?;
    let deadline = Instant::now() + RESOLVE_TIMEOUT;
    let mut last: Option<ResolveError> = None;
    for plan in plans {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            if last.is_none() {
                last = Some(ResolveError::Timeout);
            }
            break;
        }
        let options = DnsOptions {
            attempts: PLAN_ATTEMPTS,
            attempt_timeout: PLAN_ATTEMPT_TIMEOUT,
        };
        let query = dns::query_a_with(&plan.interface, plan.bind_ip, plan.server, host, options);
        // A server that never answers must not consume the budget of the
        // servers behind it, so each one is bounded on its own as well.
        match tokio::time::timeout(remaining.min(PLAN_TIMEOUT), query).await {
            Ok(Ok(addresses)) => return Ok(addresses),
            Ok(Err(error)) => last = Some(ResolveError::Query(error)),
            Err(_) => last = Some(ResolveError::Timeout),
        }
    }
    Err(last.unwrap_or(ResolveError::NoInterface))
}

/// Every (interface, source, server) triple one lookup may use, in order.
///
/// A configured server is the only one that will be asked: it is an operator
/// decision, and silently asking something else instead would send the query
/// somewhere nobody chose. Without one, each candidate interface contributes
/// the resolvers its own DHCP lease offers, followed by its own default
/// gateway, because a gateway that does not run a resolver is an ordinary
/// network rather than a reason to give up.
fn plan_queries(config: &GatewayDnsConfig) -> Result<Vec<QueryPlan>, ResolveError> {
    let snapshots = enumerate_interface_prefixes()?;
    let candidates = candidate_interfaces(&snapshots, config.interface.as_deref())?;
    let mut plans: Vec<QueryPlan> = Vec::new();
    let mut last: Option<ResolveError> = None;
    for snapshot in candidates {
        let leased = dhcp_dns_servers(&snapshot.interface.name).unwrap_or_default();
        let gateway = default_gateway_ipv4(&snapshot.interface.name).ok();
        for server in servers_for(config, &leased, gateway) {
            match plan_for_server(snapshot, &snapshots, server, config.bind_ip) {
                Ok(plan) => {
                    if !plans.contains(&plan) {
                        plans.push(plan);
                    }
                }
                // An adapter whose aliases cannot reach the server is simply
                // not this host way out. Keep looking instead of failing the
                // whole lookup.
                Err(error) => last = Some(error),
            }
        }
    }
    if plans.is_empty() {
        return Err(last.unwrap_or(ResolveError::NoInterface));
    }
    Ok(plans)
}

/// The servers one interface contributes, most authoritative first.
fn servers_for(
    config: &GatewayDnsConfig,
    leased: &[Ipv4Addr],
    gateway: Option<Ipv4Addr>,
) -> Vec<SocketAddrV4> {
    if let Some(server) = config.server {
        return vec![server];
    }
    let mut servers: Vec<Ipv4Addr> = Vec::new();
    // The lease is what the network operator handed this interface, so it
    // outranks the guess that the gateway also runs a resolver.
    servers.extend_from_slice(leased);
    if let Some(gateway) = gateway
        && !servers.contains(&gateway)
    {
        servers.push(gateway);
    }
    servers.truncate(MAX_PLAN_SERVERS);
    servers
        .into_iter()
        .map(|server| SocketAddrV4::new(server, DNS_PORT))
        .collect()
}

fn plan_for_server(
    snapshot: &InterfacePrefixes,
    snapshots: &[InterfacePrefixes],
    server: SocketAddrV4,
    bind_ip: Option<Ipv4Addr>,
) -> Result<QueryPlan, ResolveError> {
    let sources = ipv4_route_sources(snapshots, *server.ip())?;
    let bind_ip = choose_source(snapshot, &sources, *server.ip(), bind_ip)?;
    Ok(QueryPlan {
        interface: snapshot.interface.name.clone(),
        bind_ip,
        server,
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
/// Reachability is the routing table answer, not a same-link guess: a resolver
/// on another subnet of the same network is reached through this interface own
/// route, and refusing it would make the documented dns_server escape hatch
/// unusable on exactly the networks that need it. A second, unrelated alias on
/// the same adapter is still not a licence to send from an address whose link
/// cannot reach the server at all.
fn choose_source(
    snapshot: &InterfacePrefixes,
    sources: &BTreeSet<(u32, Ipv4Addr)>,
    server: Ipv4Addr,
    bind_ip: Option<Ipv4Addr>,
) -> Result<Ipv4Addr, ResolveError> {
    let index = snapshot.interface.index;
    let usable = |address: Ipv4Addr| !address.is_loopback() && sources.contains(&(index, address));
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
        Some(address) if usable(address) => Ok(address),
        Some(_) => Err(refuse()),
        None => {
            // An address on the server own link is preferred, so an unrelated
            // alias that merely happens to have a route cannot win by accident.
            let mut linked: Vec<Ipv4Addr> = snapshot
                .interface
                .ipv4
                .iter()
                .copied()
                .filter(|address| usable(*address) && on_link(*address))
                .collect();
            let mut routed: Vec<Ipv4Addr> = snapshot
                .interface
                .ipv4
                .iter()
                .copied()
                .filter(|address| usable(*address) && !on_link(*address))
                .collect();
            linked.sort_unstable();
            routed.sort_unstable();
            linked.into_iter().chain(routed).next().ok_or_else(refuse)
        }
    }
}

#[cfg(test)]
mod tests;
