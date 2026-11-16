//! One utun plus every peer `/32` host route this node owns through it.
//!
//! A mesh node has a single overlay address and one independent relationship
//! per peer, so it needs exactly one utun and up to [`MAX_OVERLAY_ROUTES`]
//! separate `/32` host routes. This module owns that set as one unit:
//!
//! * Only `/32` host routes are ever installed, exactly one per peer, and
//!   never a prefix or default route. The route shape itself is built and
//!   verified by [`crate::route`], which stays the single owner of that rule.
//! * A pre-existing route for the same `/32`, even an identical one, is a
//!   [`RouteError::Conflict`]. Nothing is ever adopted and later deleted.
//! * A failed [`OverlayRoutes::create`] leaves no partial mesh: every route
//!   installed by that call is removed and utun is closed before the error is
//!   returned.
//! * A failed [`OverlayRoutes::install`] leaves every already-owned route in
//!   place, because the new route is only inserted after it exists.
//! * Routes are always removed while utun still exists, both in
//!   [`OverlayRoutes::close`] and on drop.

use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;

use crate::route::{PeerHostRoute, RouteError};
use crate::tun::{TunConfig, Tunnel, TunnelError};

/// Maximum number of peer `/32` routes one node may own through its utun.
///
/// The bound keeps a misbehaving or hostile peer set from growing the routing
/// table without limit.
pub const MAX_OVERLAY_ROUTES: usize = 8;

mod sealed {
    /// Prevents downstream crates from substituting the overlay's tunnel or
    /// route owner, which would bypass the conflict, ownership and
    /// utun-scoping checks in [`crate::route`].
    pub trait Sealed {}
}

/// One owned peer `/32` host route.
///
/// Implemented by [`PeerHostRoute`]; sealed, so the overlay can never be
/// pointed at a route owner with weaker guarantees.
pub trait OwnedPeerRoute: sealed::Sealed + fmt::Debug + Sized {
    /// Remove the owned route, reporting any failure or external replacement.
    fn close(self) -> Result<(), RouteError>;
}

impl sealed::Sealed for PeerHostRoute {}

impl OwnedPeerRoute for PeerHostRoute {
    fn close(self) -> Result<(), RouteError> {
        PeerHostRoute::close(self)
    }
}

/// The utun carrying a set of overlay routes.
///
/// Implemented by [`Tunnel`]; sealed for the same reason as
/// [`OwnedPeerRoute`]. The generic parameter exists so this crate's unit
/// tests can drive the overlay bookkeeping without a privileged utun or a
/// real routing table.
pub trait OverlayTunnel: sealed::Sealed + Sized {
    /// Route guard type produced by [`OverlayTunnel::install_peer_route`].
    type Route: OwnedPeerRoute;

    /// Create and configure the utun.
    fn create(config: TunConfig) -> Result<Self, TunnelError>;

    /// Install exactly one owned `/32` host route to `peer`.
    fn install_peer_route(&self, peer: Ipv4Addr) -> Result<Self::Route, RouteError>;
}

impl sealed::Sealed for Tunnel {}

impl OverlayTunnel for Tunnel {
    type Route = PeerHostRoute;

    fn create(config: TunConfig) -> Result<Self, TunnelError> {
        Tunnel::create(config)
    }

    fn install_peer_route(&self, peer: Ipv4Addr) -> Result<Self::Route, RouteError> {
        Tunnel::install_peer_route(self, peer)
    }
}

/// One utun plus every peer `/32` host route this node owns through it.
///
/// Field declaration order is load-bearing: `routes` is declared before
/// `tunnel`, so on drop every route is removed while utun still exists.
/// Removing a route after its interface is gone is exactly the situation
/// `route.rs` refuses to guess about. Do not reorder these fields.
pub struct OverlayRoutes<T: OverlayTunnel = Tunnel> {
    routes: BTreeMap<Ipv4Addr, T::Route>,
    tunnel: T,
}

impl<T: OverlayTunnel> OverlayRoutes<T> {
    /// Install one peer route into `routes`, refusing duplicates and keeping
    /// the map untouched when installation fails.
    fn install_into(
        routes: &mut BTreeMap<Ipv4Addr, T::Route>,
        tunnel: &T,
        peer: Ipv4Addr,
    ) -> Result<(), RouteError> {
        if let Some(existing) = routes.get(&peer) {
            return Err(RouteError::Conflict {
                peer,
                route: format!("{existing:?}"),
            });
        }
        if routes.len() >= MAX_OVERLAY_ROUTES {
            return Err(RouteError::InvalidConfig(
                "overlay already owns the maximum number of peer routes",
            ));
        }
        // The route is only recorded once it actually exists, so a failed
        // install can never drop or disturb an already-owned route.
        let route = tunnel.install_peer_route(peer)?;
        routes.insert(peer, route);
        Ok(())
    }

    fn create_inner(config: TunConfig, peers: &[Ipv4Addr]) -> Result<Self, TunnelError> {
        if peers.len() > MAX_OVERLAY_ROUTES {
            return Err(TunnelError::InvalidConfig(
                "initial peer count exceeds the maximum number of overlay routes",
            ));
        }

        let tunnel = T::create(config)?;
        let mut routes: BTreeMap<Ipv4Addr, T::Route> = BTreeMap::new();
        for peer in peers {
            if let Err(error) = Self::install_into(&mut routes, &tunnel, *peer) {
                // Roll back everything this call installed, routes first, then
                // utun, so a partial mesh is never left behind. Cleanup errors
                // are deliberately not reported: the install failure is the
                // actionable one, and each guard's `Drop` already retried.
                for (_peer, route) in routes {
                    let _ = route.close();
                }
                drop(tunnel);
                return Err(TunnelError::Route(error));
            }
        }

        Ok(Self { routes, tunnel })
    }

    fn install_inner(&mut self, peer: Ipv4Addr) -> Result<(), RouteError> {
        Self::install_into(&mut self.routes, &self.tunnel, peer)
    }

    fn remove_inner(&mut self, peer: Ipv4Addr) -> Result<(), RouteError> {
        match self.routes.remove(&peer) {
            Some(route) => route.close(),
            None => Ok(()),
        }
    }

    fn peers_inner(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.routes.keys().copied()
    }

    fn contains_inner(&self, peer: Ipv4Addr) -> bool {
        self.routes.contains_key(&peer)
    }

    fn close_inner(self) -> Result<(), RouteError> {
        // Destructure so the routes are consumed by the loop below and utun is
        // dropped explicitly afterwards, independent of local drop order.
        let Self { routes, tunnel } = self;
        let mut first_error = None;
        for (_peer, route) in routes {
            if let Err(error) = route.close() {
                first_error.get_or_insert(error);
            }
        }
        drop(tunnel);
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn tunnel_inner(&self) -> &T {
        &self.tunnel
    }
}

impl OverlayRoutes {
    /// Create utun and install one `/32` per initial peer.
    ///
    /// If any initial peer's route fails, every route already installed by
    /// this call is removed and utun is closed before the error is returned,
    /// so a partial mesh is never left behind.
    pub fn create(config: TunConfig, peers: &[Ipv4Addr]) -> Result<Self, TunnelError> {
        Self::create_inner(config, peers)
    }

    /// The utun carrying these routes.
    pub fn tunnel(&self) -> &Tunnel {
        self.tunnel_inner()
    }

    /// Install one more peer `/32`.
    ///
    /// Refuses a peer that already has a route here, and leaves every existing
    /// route untouched when the new one cannot be installed.
    pub fn install(&mut self, peer: Ipv4Addr) -> Result<(), RouteError> {
        self.install_inner(peer)
    }

    /// Remove one peer `/32`, reporting any failure or external replacement.
    /// Removing a peer that has no route here is not an error.
    pub fn remove(&mut self, peer: Ipv4Addr) -> Result<(), RouteError> {
        self.remove_inner(peer)
    }

    /// Every peer address currently routed, in address order.
    pub fn peers(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.peers_inner()
    }

    /// Whether a peer currently has a route.
    pub fn contains(&self, peer: Ipv4Addr) -> bool {
        self.contains_inner(peer)
    }

    /// Remove every owned route and close utun, reporting the first failure.
    ///
    /// Every route is attempted even if an earlier one fails, so one stuck
    /// route cannot strand the rest.
    pub fn close(self) -> Result<(), RouteError> {
        self.close_inner()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeSet;

    const IF_NAME: &str = "utun42";

    #[derive(Debug, Default)]
    struct MockState {
        /// Peers with a route currently in the fake routing table.
        present: BTreeSet<Ipv4Addr>,
        /// Peers whose installation must fail as a pre-existing conflict.
        conflicts: BTreeSet<Ipv4Addr>,
        /// Peers whose cleanup must report an external replacement.
        replaced: BTreeSet<Ipv4Addr>,
        /// Every install attempt, as `(local, peer)`.
        installs: Vec<(Ipv4Addr, Ipv4Addr)>,
        /// Every cleanup attempt, in order.
        closed: Vec<Ipv4Addr>,
        /// Whether utun still existed at each cleanup attempt.
        closed_while_utun_alive: Vec<bool>,
        tunnel_created: usize,
        tunnel_drops: usize,
        tunnel_alive: bool,
        fail_tunnel: bool,
    }

    thread_local! {
        static STATE: RefCell<MockState> = RefCell::new(MockState::default());
    }

    fn with_state<R>(f: impl FnOnce(&mut MockState) -> R) -> R {
        STATE.with(|state| f(&mut state.borrow_mut()))
    }

    fn reset() {
        with_state(|state| *state = MockState::default());
    }

    /// Stand-in for `PeerHostRoute`. It models the parts of `route.rs` the
    /// overlay depends on: an install either yields an owned guard or fails
    /// without touching the table, and cleanup reports an external
    /// replacement instead of deleting somebody else's route.
    #[derive(Debug)]
    struct MockRoute {
        peer: Ipv4Addr,
        settled: Cell<bool>,
    }

    impl MockRoute {
        fn cleanup(&self) -> Result<(), RouteError> {
            if self.settled.get() {
                return Ok(());
            }
            self.settled.set(true);
            with_state(|state| {
                state.closed.push(self.peer);
                state.closed_while_utun_alive.push(state.tunnel_alive);
                if state.replaced.contains(&self.peer) {
                    return Err(RouteError::Changed(self.peer));
                }
                state.present.remove(&self.peer);
                Ok(())
            })
        }
    }

    impl sealed::Sealed for MockRoute {}

    impl OwnedPeerRoute for MockRoute {
        fn close(self) -> Result<(), RouteError> {
            self.cleanup()
        }
    }

    impl Drop for MockRoute {
        fn drop(&mut self) {
            let _ = self.cleanup();
        }
    }

    /// Stand-in for `Tunnel`. Creating a real utun is privileged, so this
    /// double exercises the overlay's own bookkeeping only.
    #[derive(Debug)]
    struct MockTunnel {
        config: TunConfig,
    }

    impl sealed::Sealed for MockTunnel {}

    impl OverlayTunnel for MockTunnel {
        type Route = MockRoute;

        fn create(config: TunConfig) -> Result<Self, TunnelError> {
            config.validate()?;
            with_state(|state| {
                if state.fail_tunnel {
                    return Err(TunnelError::DeviceVerification(
                        "mock utun creation refused".to_owned(),
                    ));
                }
                state.tunnel_created += 1;
                state.tunnel_alive = true;
                Ok(())
            })?;
            Ok(Self { config })
        }

        fn install_peer_route(&self, peer: Ipv4Addr) -> Result<Self::Route, RouteError> {
            with_state(|state| {
                state.installs.push((self.config.local(), peer));
                if state.conflicts.contains(&peer) || state.present.contains(&peer) {
                    return Err(RouteError::Conflict {
                        peer,
                        route: format!("{peer}/32 via {IF_NAME}"),
                    });
                }
                state.present.insert(peer);
                Ok(MockRoute {
                    peer,
                    settled: Cell::new(false),
                })
            })
        }
    }

    impl Drop for MockTunnel {
        fn drop(&mut self) {
            with_state(|state| {
                state.tunnel_alive = false;
                state.tunnel_drops += 1;
            });
        }
    }

    type MockOverlay = OverlayRoutes<MockTunnel>;

    fn local() -> Ipv4Addr {
        Ipv4Addr::new(100, 64, 0, 1)
    }

    fn peer(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(100, 64, 0, n)
    }

    fn config() -> TunConfig {
        TunConfig::new(local())
    }

    fn create(peers: &[Ipv4Addr]) -> Result<MockOverlay, TunnelError> {
        MockOverlay::create_inner(config(), peers)
    }

    fn expect_error(result: Result<MockOverlay, TunnelError>) -> TunnelError {
        match result {
            Ok(_) => panic!("overlay creation unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    #[test]
    fn three_peer_routes_coexist_in_address_order() {
        reset();
        let overlay = create(&[peer(9), peer(3), peer(7)]).unwrap();

        assert_eq!(
            overlay.peers_inner().collect::<Vec<_>>(),
            vec![peer(3), peer(7), peer(9)]
        );
        for candidate in [peer(3), peer(7), peer(9)] {
            assert!(overlay.contains_inner(candidate));
        }
        assert!(!overlay.contains_inner(peer(4)));

        // Exactly one install per peer, each for a distinct peer address: no
        // prefix route, no default route, no extra destination.
        let installs = with_state(|state| state.installs.clone());
        assert_eq!(
            installs,
            vec![(local(), peer(9)), (local(), peer(3)), (local(), peer(7))]
        );
        assert!(!installs.iter().any(|(_local, peer)| peer.is_unspecified()));
        with_state(|state| {
            assert_eq!(state.present.len(), 3);
            assert!(state.closed.is_empty());
        });
    }

    #[test]
    fn failed_create_rolls_back_routes_and_utun() {
        reset();
        with_state(|state| {
            state.conflicts.insert(peer(5));
        });

        let error = expect_error(create(&[peer(4), peer(5), peer(6)]));
        assert!(matches!(
            error,
            TunnelError::Route(RouteError::Conflict { .. })
        ));

        with_state(|state| {
            // The first peer's route was removed again, the conflicting peer
            // was never installed, and utun was closed.
            assert!(state.present.is_empty());
            assert_eq!(state.closed, vec![peer(4)]);
            assert!(state.closed_while_utun_alive.iter().all(|alive| *alive));
            assert_eq!(state.tunnel_created, 1);
            assert_eq!(state.tunnel_drops, 1);
            assert!(!state.tunnel_alive);
        });
    }

    #[test]
    fn failed_install_leaves_existing_routes_untouched() {
        reset();
        let mut overlay = create(&[peer(4), peer(5)]).unwrap();
        with_state(|state| {
            state.conflicts.insert(peer(6));
        });

        let error = overlay.install_inner(peer(6)).unwrap_err();
        assert!(matches!(error, RouteError::Conflict { .. }));

        assert_eq!(
            overlay.peers_inner().collect::<Vec<_>>(),
            vec![peer(4), peer(5)]
        );
        with_state(|state| {
            assert_eq!(state.present, BTreeSet::from([peer(4), peer(5)]));
            assert!(state.closed.is_empty());
            assert_eq!(state.tunnel_drops, 0);
        });
    }

    #[test]
    fn duplicate_install_is_refused_without_touching_the_owned_route() {
        reset();
        let mut overlay = create(&[peer(4)]).unwrap();

        let error = overlay.install_inner(peer(4)).unwrap_err();
        assert!(matches!(
            error,
            RouteError::Conflict { peer: conflicting, .. } if conflicting == peer(4)
        ));

        assert!(overlay.contains_inner(peer(4)));
        with_state(|state| {
            // The second install was never attempted and the owned route was
            // never closed.
            assert_eq!(state.installs, vec![(local(), peer(4))]);
            assert_eq!(state.present, BTreeSet::from([peer(4)]));
            assert!(state.closed.is_empty());
        });
    }

    #[test]
    fn remove_is_idempotent_and_scoped() {
        reset();
        let mut overlay = create(&[peer(4), peer(5), peer(6)]).unwrap();

        overlay.remove_inner(peer(8)).unwrap();
        assert_eq!(
            overlay.peers_inner().collect::<Vec<_>>(),
            vec![peer(4), peer(5), peer(6)]
        );
        with_state(|state| assert!(state.closed.is_empty()));

        overlay.remove_inner(peer(5)).unwrap();
        assert!(!overlay.contains_inner(peer(5)));
        assert_eq!(
            overlay.peers_inner().collect::<Vec<_>>(),
            vec![peer(4), peer(6)]
        );
        with_state(|state| {
            assert_eq!(state.closed, vec![peer(5)]);
            assert_eq!(state.present, BTreeSet::from([peer(4), peer(6)]));
            assert!(state.closed_while_utun_alive.iter().all(|alive| *alive));
        });

        // Removing it again is still not an error.
        overlay.remove_inner(peer(5)).unwrap();
    }

    #[test]
    fn close_removes_every_route_even_when_one_was_replaced() {
        reset();
        let overlay = create(&[peer(4), peer(5), peer(6)]).unwrap();
        with_state(|state| {
            state.replaced.insert(peer(5));
            // An external replacement means the guard refuses to delete it.
            state.present.insert(peer(5));
        });

        let error = overlay.close_inner().unwrap_err();
        assert!(matches!(error, RouteError::Changed(replaced) if replaced == peer(5)));

        with_state(|state| {
            // Every route was attempted, in address order, and the two healthy
            // ones were actually removed.
            assert_eq!(state.closed, vec![peer(4), peer(5), peer(6)]);
            assert!(state.closed_while_utun_alive.iter().all(|alive| *alive));
            assert_eq!(state.present, BTreeSet::from([peer(5)]));
            assert_eq!(state.tunnel_drops, 1);
            assert!(!state.tunnel_alive);
        });
    }

    #[test]
    fn drop_removes_routes_before_utun() {
        reset();
        {
            let _overlay = create(&[peer(4), peer(5)]).unwrap();
        }
        with_state(|state| {
            assert_eq!(state.closed, vec![peer(4), peer(5)]);
            // Field declaration order, not convention: every route was cleaned
            // up while utun still existed.
            assert_eq!(state.closed_while_utun_alive, vec![true, true]);
            assert_eq!(state.tunnel_drops, 1);
            assert!(state.present.is_empty());
        });
    }

    #[test]
    fn route_count_is_bounded() {
        reset();
        let full: Vec<Ipv4Addr> = (2..=9u8).map(peer).collect();
        assert_eq!(full.len(), MAX_OVERLAY_ROUTES);
        let mut overlay = create(&full).unwrap();
        assert_eq!(overlay.peers_inner().count(), MAX_OVERLAY_ROUTES);

        let error = overlay.install_inner(peer(10)).unwrap_err();
        assert!(matches!(error, RouteError::InvalidConfig(_)));
        assert_eq!(overlay.peers_inner().count(), MAX_OVERLAY_ROUTES);
        with_state(|state| {
            assert_eq!(state.present.len(), MAX_OVERLAY_ROUTES);
            assert!(state.closed.is_empty());
        });

        reset();
        let too_many: Vec<Ipv4Addr> = (2..=10u8).map(peer).collect();
        assert!(too_many.len() > MAX_OVERLAY_ROUTES);
        let error = expect_error(create(&too_many));
        assert!(matches!(error, TunnelError::InvalidConfig(_)));
        with_state(|state| {
            // Rejected before utun existed: no route, no interface.
            assert!(state.installs.is_empty());
            assert!(state.present.is_empty());
            assert_eq!(state.tunnel_created, 0);
            assert_eq!(state.tunnel_drops, 0);
        });
    }

    #[test]
    fn create_installs_nothing_when_utun_creation_fails() {
        reset();
        with_state(|state| state.fail_tunnel = true);

        let error = expect_error(create(&[peer(4)]));
        assert!(matches!(error, TunnelError::DeviceVerification(_)));
        with_state(|state| {
            assert!(state.installs.is_empty());
            assert!(state.present.is_empty());
            assert!(state.closed.is_empty());
        });
    }

    #[test]
    fn create_rejects_an_invalid_local_address_before_touching_anything() {
        reset();
        let error = expect_error(MockOverlay::create_inner(
            TunConfig::new(Ipv4Addr::UNSPECIFIED),
            &[peer(4)],
        ));
        assert!(matches!(error, TunnelError::InvalidConfig(_)));
        with_state(|state| {
            assert!(state.installs.is_empty());
            assert_eq!(state.tunnel_created, 0);
        });
    }
}
