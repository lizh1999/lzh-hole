//! Ownership-scoped management of the single peer IPv4 `/32` route.
//!
//! A pre-existing host route is never adopted. After a successful add, cleanup
//! only deletes a listed route that still has the exact destination, local
//! gateway and utun interface installed by this guard. A replaced route is left
//! alone rather than risking deletion of somebody else's resource.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr};

use route_manager::{Route, RouteKind, RouteManager};

/// Failures while installing or cleaning up the peer host route.
#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    /// Invalid address or interface configuration.
    #[error("invalid peer host route: {0}")]
    InvalidConfig(&'static str),
    /// A route manager operation failed.
    #[error("peer host route operation failed: {0}")]
    Io(#[from] io::Error),
    /// An exact host route already existed and was not touched.
    #[error("peer host route {peer}/32 already exists: {route}")]
    Conflict {
        /// Peer whose route could not be installed.
        peer: Ipv4Addr,
        /// The conflicting route as reported by the kernel.
        route: String,
    },
    /// The route added by this task could not be identified unambiguously.
    #[error("could not verify owned peer host route {peer}/32: {detail}")]
    Verification {
        /// Peer whose route could not be verified.
        peer: Ipv4Addr,
        /// Verification failure detail.
        detail: &'static str,
    },
    /// The installed route disappeared or was replaced. No delete was issued.
    #[error("owned peer host route {0}/32 was removed or replaced; refusing cleanup")]
    Changed(Ipv4Addr),
}

trait RouteBackend {
    fn list(&mut self) -> io::Result<Vec<Route>>;
    fn add(&mut self, route: &Route) -> io::Result<()>;
    fn delete(&mut self, route: &Route) -> io::Result<()>;
}

struct SystemRoutes {
    manager: RouteManager,
}

impl SystemRoutes {
    fn new() -> io::Result<Self> {
        Ok(Self {
            manager: RouteManager::new()?,
        })
    }
}

impl RouteBackend for SystemRoutes {
    fn list(&mut self) -> io::Result<Vec<Route>> {
        self.manager.list()
    }

    fn add(&mut self, route: &Route) -> io::Result<()> {
        self.manager.add(route)
    }

    fn delete(&mut self, route: &Route) -> io::Result<()> {
        self.manager.delete(route)
    }
}

/// RAII owner of one peer `/32` route.
///
/// Keep this guard alive for as long as the route is needed. `Drop` makes a
/// best-effort cleanup; [`PeerHostRoute::close`] reports cleanup errors.
pub struct PeerHostRoute {
    inner: RouteGuard<SystemRoutes>,
}

impl PeerHostRoute {
    /// Install `peer/32` via `local` on the specified utun interface.
    ///
    /// Any pre-existing route for the same `/32`, including an identical one,
    /// is a conflict rather than something this task may adopt and later delete.
    pub fn install(
        local: Ipv4Addr,
        peer: Ipv4Addr,
        if_index: u32,
        if_name: &str,
    ) -> Result<Self, RouteError> {
        validate_config(local, peer, if_index, if_name)?;
        let route = host_route(local, peer, if_index, if_name);
        route.check()?;
        let backend = SystemRoutes::new()?;
        Ok(Self {
            inner: RouteGuard::install(backend, route, local, peer)?,
        })
    }

    /// Peer virtual IPv4 address owned by this route guard.
    pub fn peer(&self) -> Ipv4Addr {
        self.inner.peer
    }

    /// Remove the owned route, reporting any failure or external replacement.
    pub fn close(self) -> Result<(), RouteError> {
        self.inner.close()
    }
}

impl fmt::Debug for PeerHostRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerHostRoute")
            .field("route", &self.inner.route.to_string())
            .field("owned", &self.inner.owned)
            .finish()
    }
}

struct RouteGuard<B: RouteBackend> {
    backend: B,
    route: Route,
    local: Ipv4Addr,
    peer: Ipv4Addr,
    owned: bool,
}

impl<B: RouteBackend> RouteGuard<B> {
    fn install(
        mut backend: B,
        route: Route,
        local: Ipv4Addr,
        peer: Ipv4Addr,
    ) -> Result<Self, RouteError> {
        let existing = backend.list()?;
        if let Some(conflict) = existing.iter().find(|route| is_peer_prefix(route, peer)) {
            return Err(RouteError::Conflict {
                peer,
                route: conflict.to_string(),
            });
        }

        backend.add(&route)?;
        let listed = backend.list()?;
        let matches = listed
            .iter()
            .filter(|candidate| is_owned_route(candidate, local, peer, route.if_index()))
            .count();
        if matches != 1 {
            // Do not issue a prefix-only delete here: without an exact listed
            // match we cannot prove that the current route is still ours.
            return Err(RouteError::Verification {
                peer,
                detail: if matches == 0 {
                    "added route was not visible with its expected gateway and interface"
                } else {
                    "multiple matching routes make ownership ambiguous"
                },
            });
        }

        Ok(Self {
            backend,
            route,
            local,
            peer,
            owned: true,
        })
    }

    fn cleanup(&mut self) -> Result<(), RouteError> {
        if !self.owned {
            return Ok(());
        }
        let listed = self.backend.list()?;
        let matching: Vec<Route> = listed
            .iter()
            .filter(|candidate| {
                is_owned_route(candidate, self.local, self.peer, self.route.if_index())
            })
            .cloned()
            .collect();

        match matching.len() {
            0 => {
                self.owned = false;
                if listed.iter().any(|route| is_peer_prefix(route, self.peer)) {
                    Err(RouteError::Changed(self.peer))
                } else {
                    // Somebody already removed our route. There is no resource
                    // left for this guard to clean up.
                    Ok(())
                }
            }
            1 => {
                // Delete the route object returned by list, not a fresh object
                // with only a destination prefix.
                self.backend.delete(&matching[0])?;
                self.owned = false;
                Ok(())
            }
            _ => Err(RouteError::Verification {
                peer: self.peer,
                detail: "multiple matching routes make cleanup ambiguous",
            }),
        }
    }

    fn close(mut self) -> Result<(), RouteError> {
        self.cleanup()
    }
}

impl<B: RouteBackend> Drop for RouteGuard<B> {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn validate_config(
    local: Ipv4Addr,
    peer: Ipv4Addr,
    if_index: u32,
    if_name: &str,
) -> Result<(), RouteError> {
    if local == peer {
        return Err(RouteError::InvalidConfig(
            "local and peer addresses must differ",
        ));
    }
    if local.is_unspecified() || peer.is_unspecified() {
        return Err(RouteError::InvalidConfig(
            "local and peer addresses must not be unspecified",
        ));
    }
    if local.is_multicast() || peer.is_multicast() {
        return Err(RouteError::InvalidConfig(
            "local and peer addresses must not be multicast",
        ));
    }
    if local.is_broadcast() || peer.is_broadcast() {
        return Err(RouteError::InvalidConfig(
            "local and peer addresses must not be broadcast",
        ));
    }
    if if_index == 0 {
        return Err(RouteError::InvalidConfig(
            "interface index must not be zero",
        ));
    }
    if !if_name.starts_with("utun") {
        return Err(RouteError::InvalidConfig(
            "peer host route requires a utun interface",
        ));
    }
    Ok(())
}

fn host_route(local: Ipv4Addr, peer: Ipv4Addr, if_index: u32, if_name: &str) -> Route {
    Route::new(IpAddr::V4(peer), 32)
        .with_gateway(IpAddr::V4(local))
        .with_if_index(if_index)
        .with_if_name(if_name.to_owned())
}

fn is_peer_prefix(route: &Route, peer: Ipv4Addr) -> bool {
    route.destination() == IpAddr::V4(peer) && route.prefix() == 32
}

fn is_owned_route(route: &Route, local: Ipv4Addr, peer: Ipv4Addr, if_index: Option<u32>) -> bool {
    is_peer_prefix(route, peer)
        && route.gateway() == Some(IpAddr::V4(local))
        && route.if_index() == if_index
        && route.kind() == RouteKind::Unicast
        && !route.if_scope()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Default)]
    struct MockState {
        routes: Vec<Route>,
        added: Vec<Route>,
        deleted: Vec<Route>,
        hide_added: bool,
    }

    #[derive(Clone, Default)]
    struct MockBackend(Rc<RefCell<MockState>>);

    impl RouteBackend for MockBackend {
        fn list(&mut self) -> io::Result<Vec<Route>> {
            Ok(self.0.borrow().routes.clone())
        }

        fn add(&mut self, route: &Route) -> io::Result<()> {
            let mut state = self.0.borrow_mut();
            state.added.push(route.clone());
            if !state.hide_added {
                state.routes.push(route.clone());
            }
            Ok(())
        }

        fn delete(&mut self, route: &Route) -> io::Result<()> {
            let mut state = self.0.borrow_mut();
            state.deleted.push(route.clone());
            state.routes.retain(|candidate| candidate != route);
            Ok(())
        }
    }

    fn local() -> Ipv4Addr {
        Ipv4Addr::new(10, 66, 0, 1)
    }

    fn peer() -> Ipv4Addr {
        Ipv4Addr::new(10, 66, 0, 2)
    }

    fn route() -> Route {
        host_route(local(), peer(), 42, "utun42")
    }

    fn install_error(result: Result<RouteGuard<MockBackend>, RouteError>) -> RouteError {
        match result {
            Ok(_) => panic!("route installation unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    #[test]
    fn broad_routes_do_not_block_a_more_specific_peer_route() {
        let backend = MockBackend::default();
        backend.0.borrow_mut().routes = vec![
            Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            Route::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
        ];
        let guard = RouteGuard::install(backend.clone(), route(), local(), peer()).unwrap();
        assert_eq!(backend.0.borrow().added.len(), 1);
        assert_eq!(backend.0.borrow().added[0].prefix(), 32);
        guard.close().unwrap();
        assert_eq!(backend.0.borrow().deleted.len(), 1);
        assert_eq!(backend.0.borrow().routes.len(), 2);
    }

    #[test]
    fn a_preexisting_identical_host_route_is_never_adopted() {
        let backend = MockBackend::default();
        backend.0.borrow_mut().routes.push(route());
        let error = install_error(RouteGuard::install(
            backend.clone(),
            route(),
            local(),
            peer(),
        ));
        assert!(matches!(error, RouteError::Conflict { .. }));
        assert!(backend.0.borrow().added.is_empty());
        assert!(backend.0.borrow().deleted.is_empty());
        assert_eq!(backend.0.borrow().routes, vec![route()]);
    }

    #[test]
    fn drop_deletes_only_the_route_installed_by_this_guard() {
        let backend = MockBackend::default();
        let foreign = Route::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 32);
        backend.0.borrow_mut().routes.push(foreign.clone());
        {
            let _guard = RouteGuard::install(backend.clone(), route(), local(), peer()).unwrap();
        }
        let state = backend.0.borrow();
        assert_eq!(state.deleted, vec![route()]);
        assert_eq!(state.routes, vec![foreign]);
    }

    #[test]
    fn an_externally_replaced_route_is_not_deleted() {
        let backend = MockBackend::default();
        let guard = RouteGuard::install(backend.clone(), route(), local(), peer()).unwrap();
        let replacement = Route::new(IpAddr::V4(peer()), 32)
            .with_gateway(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254)))
            .with_if_index(7);
        backend.0.borrow_mut().routes = vec![replacement.clone()];

        let error = guard.close().unwrap_err();
        assert!(matches!(error, RouteError::Changed(_)));
        let state = backend.0.borrow();
        assert!(state.deleted.is_empty());
        assert_eq!(state.routes, vec![replacement]);
    }

    #[test]
    fn an_unverifiable_add_is_not_cleaned_up_by_prefix() {
        let backend = MockBackend::default();
        backend.0.borrow_mut().hide_added = true;
        let error = install_error(RouteGuard::install(
            backend.clone(),
            route(),
            local(),
            peer(),
        ));
        assert!(matches!(error, RouteError::Verification { .. }));
        assert!(backend.0.borrow().deleted.is_empty());
    }

    #[test]
    fn route_configuration_is_ipv4_host_only_and_utun_scoped() {
        let route = route();
        assert_eq!(route.destination(), IpAddr::V4(peer()));
        assert_eq!(route.prefix(), 32);
        assert_eq!(route.gateway(), Some(IpAddr::V4(local())));
        assert_eq!(route.if_index(), Some(42));
        assert_eq!(route.kind(), RouteKind::Unicast);
        assert!(!route.if_scope());
        assert!(matches!(
            validate_config(local(), local(), 42, "utun42"),
            Err(RouteError::InvalidConfig(_))
        ));
        assert!(matches!(
            validate_config(local(), peer(), 42, "en0"),
            Err(RouteError::InvalidConfig(_))
        ));
    }
}
