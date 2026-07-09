//! Network-change watcher. Polls the OS's chosen primary outbound
//! IPs every few seconds and, when they change, renegotiates ICE on
//! every active peer in this network — `restart_ice()` *plus* a fresh
//! offer, so both ends re-gather on the new interface and reconnect in
//! place (see `engine::renegotiate_ice`), rather than a bare local
//! re-gather the peer never hears about.
//!
//! Why this exists
//! ---------------
//! Without it, WebRTC only notices a network change when its
//! consent-freshness timer expires — ~30 s of silently sending
//! packets into the void after the user closes their laptop lid
//! and reopens on a different WiFi, or VPN comes up, or the
//! mesh interface changes IP for any other reason. The user
//! sees a connected peer status that quietly turns into
//! "reconnecting" half a minute later.
//!
//! By detecting the IP change in seconds and pre-emptively kicking
//! `restart_ice()` on every active peer, recovery starts
//! immediately and usually completes before the user notices.
//!
//! How we sample
//! -------------
//! Two complementary reads per poll:
//!
//! - **Primary source probes** — the well-known "bind a UDP socket and
//!   connect" trick: `connect()` on a UDP socket sends nothing, it just
//!   sets the default destination so `local_addr()` returns the source IP
//!   the OS picked. Probed toward the mesh's *own* STUN host when one is
//!   configured (the interface that routes to this mesh's relays is the
//!   one that matters, especially multi-homed), falling back to the
//!   public resolvers (8.8.8.8:53 / Google's v6) otherwise.
//! - **The full local address set** (via `if-addrs`), fingerprinted — v4
//!   addresses and v6 /64 prefixes, loopback/link-local excluded. This is
//!   what sees a change on a box with *no default route at all* (an
//!   internet-isolated LAN fleet: both probes read `None` forever) or on
//!   the interface the default route doesn't cover.
//!
//! Change detection is `last != current`, so any transition counts,
//! including up→down and down→up.
//!
//! Cost is one UDP socket bind + connect per poll, on the order of
//! microseconds. It runs on the shared state-watch tick (see
//! `STATE_WATCH_INTERVAL_MS` in `scheduler.rs`) rather than its own
//! interval — one periodic pass covers network-change detection alongside
//! the per-peer state confirmation.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tracing::{debug, info};

use crate::events::{DiagEntry, DiagLevel, MeshEvent};

use super::ice_watchdog;
use super::scheduler::NETWORK_CHANGE_RESTART_COOLDOWN_MS;
use super::state::NetworkState;

/// Snapshot of the OS's chosen primary outbound IPs **plus a fingerprint of
/// the whole usable local address set**. Compared by value — any transition
/// (v4 changes, v6 disappears, an interface gains or loses an address)
/// triggers the change handler.
///
/// The default-route probes alone were blind in exactly the deployments the
/// hosted-services story sells: an internet-isolated LAN fleet has no
/// default route, so both probes read `None` forever and no change ever
/// fired; a multi-homed box (mesh on one interface, internet on another)
/// had its mesh-side changes invisible and its internet-side flips firing
/// spurious restarts. The local-set fingerprint catches every interface
/// change; the probes still say which addresses are *primary*.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkSnapshot {
    pub v4: Option<Ipv4Addr>,
    pub v6: Option<Ipv6Addr>,
    /// Order-insensitive hash of the usable local addresses — v4 addresses
    /// plus v6 **/64 prefixes** (a privacy-extension rotation mints a new
    /// suffix inside the same prefix on a schedule; hashing full v6
    /// addresses would fire a pointless restart every rotation). Loopback
    /// and link-local are out, matching what ICE gathers.
    pub local_set: u64,
    /// How many addresses fed the fingerprint — the "is anything up at all"
    /// half of the offline verdict (a LAN-only box has no primary outbound
    /// IPs but is emphatically not offline).
    pub local_count: usize,
}

impl NetworkSnapshot {
    /// `probe` — the mesh's own signaling/STUN host when one is configured,
    /// so the primary-source question is asked toward the host that
    /// actually matters for this mesh; `None` falls back to the public
    /// resolvers, exactly the old behaviour.
    pub async fn sample(probe: Option<SocketAddr>) -> Self {
        let (v4, v6) = match probe {
            Some(addr @ SocketAddr::V4(_)) => (
                probe_source(addr)
                    .await
                    .or(primary_v4().await.map(IpAddr::V4)),
                primary_v6().await.map(IpAddr::V6),
            ),
            Some(addr @ SocketAddr::V6(_)) => (
                primary_v4().await.map(IpAddr::V4),
                probe_source(addr)
                    .await
                    .or(primary_v6().await.map(IpAddr::V6)),
            ),
            None => (
                primary_v4().await.map(IpAddr::V4),
                primary_v6().await.map(IpAddr::V6),
            ),
        };
        let v4 = match v4 {
            Some(IpAddr::V4(a)) => Some(a),
            _ => None,
        };
        let v6 = match v6 {
            Some(IpAddr::V6(a)) => Some(a),
            _ => None,
        };
        let (local_set, local_count) = local_fingerprint();
        Self {
            v4,
            v6,
            local_set,
            local_count,
        }
    }

    /// Fully offline: no primary outbound source *and* no usable local
    /// address at all. The second clause is what keeps an internet-isolated
    /// LAN fleet (both probes `None` by construction) from reading as
    /// offline and gating ICE recovery off.
    pub fn offline(&self) -> bool {
        self.v4.is_none() && self.v6.is_none() && self.local_count == 0
    }
}

async fn primary_v4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.connect("8.8.8.8:53").await.ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    }
}

async fn primary_v6() -> Option<Ipv6Addr> {
    let socket = UdpSocket::bind("[::]:0").await.ok()?;
    // Google's public v6 DNS — no packets sent, just a destination
    // hint for the OS's local-address selection.
    socket.connect("[2001:4860:4860::8888]:53").await.ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(_) => None,
        IpAddr::V6(v6) => Some(v6),
    }
}

/// Which local source the OS picks toward `addr` — the same connect-a-UDP-
/// socket trick as the public probes, aimed at the mesh's own server.
async fn probe_source(addr: SocketAddr) -> Option<IpAddr> {
    let bind = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await.ok()?;
    socket.connect(addr).await.ok()?;
    Some(socket.local_addr().ok()?.ip())
}

/// The mesh's own probe target: its first configured STUN server's
/// host:port, resolved through the OS resolver (bounded — a dead resolver
/// must not stall the tick). `None` on a mesh with no STUN configured or a
/// name that doesn't resolve; the sampler then falls back to the public
/// probes, exactly the old behaviour. Pointing the probe at the mesh's own
/// server is what makes the "primary source" answer meaningful on a
/// multi-homed box: the interface that routes to *this mesh's* relays is
/// the one whose changes matter here.
async fn resolve_probe(state: &Arc<NetworkState>) -> Option<SocketAddr> {
    let url = {
        let cfg = state.config.read();
        cfg.stun_servers
            .iter()
            .flat_map(|s| s.urls.iter())
            .next()
            .cloned()
    }?;
    let bare = url
        .strip_prefix("stun://")
        .or_else(|| url.strip_prefix("stun:"))
        .unwrap_or(&url);
    let bare = bare.split('?').next().unwrap_or(bare);
    let target = if bare.contains(':') {
        bare.to_string()
    } else {
        format!("{bare}:3478")
    };
    tokio::time::timeout(Duration::from_secs(2), tokio::net::lookup_host(target))
        .await
        .ok()?
        .ok()?
        .next()
}

/// Hash of the usable local address set (+ its size): v4 addresses and v6
/// /64 prefixes, loopback/link-local excluded — the same class of addresses
/// ICE gathers (see `transport::webrtc::is_link_local_ip`).
fn local_fingerprint() -> (u64, usize) {
    use std::hash::{Hash, Hasher};
    let mut keys: Vec<String> = if_addrs::get_if_addrs()
        .map(|ifs| {
            ifs.into_iter()
                .filter(|i| !i.is_loopback())
                .filter_map(|i| match i.addr.ip() {
                    ip if crate::transport::webrtc::is_link_local_ip(&ip) => None,
                    IpAddr::V4(v4) => Some(v4.to_string()),
                    // /64 prefix only: privacy-extension suffixes rotate on
                    // a schedule inside a stable prefix.
                    IpAddr::V6(v6) => {
                        let s = v6.segments();
                        Some(format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3]))
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    keys.sort();
    keys.dedup();
    let count = keys.len();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    keys.hash(&mut h);
    (h.finish(), count)
}

/// Holds the last observed snapshot. Lives inside the driver loop
/// so we don't need a Mutex — single owner.
pub struct NetworkWatch {
    /// `None` until the first poll: that poll adopts its snapshot silently
    /// (no change event), so daemon startup doesn't kick a useless ICE
    /// restart — and the adopted baseline is already probed toward the
    /// mesh's own server, so the probe switching over from the public
    /// fallback can't read as a change either.
    last: Option<NetworkSnapshot>,
    /// When we last fired a change-triggered ICE-restart fan-out. Used
    /// to coalesce the burst of primary-IP flips a Wi-Fi→cellular
    /// handoff produces into a single restart (see
    /// `NETWORK_CHANGE_RESTART_COOLDOWN_MS`).
    last_restart_at: Option<Instant>,
    /// The mesh's own probe target (its first configured STUN host),
    /// resolved lazily and re-resolved on a slow TTL — never per tick.
    probe: Option<SocketAddr>,
    probe_checked_at: Option<Instant>,
}

impl NetworkWatch {
    /// Build an empty watcher; the first `poll` seeds the baseline (see
    /// [`NetworkWatch::last`]).
    pub async fn new() -> Self {
        Self {
            last: None,
            last_restart_at: None,
            probe: None,
            probe_checked_at: None,
        }
    }

    /// Sample, compare, and fire the change handler if the primary
    /// outbound IPs moved — but at most once per
    /// `NETWORK_CHANGE_RESTART_COOLDOWN_MS`. We always adopt the new
    /// snapshot so further moves are still detected; we just don't pile
    /// a second restart onto the first one's in-flight gather while the
    /// network is still settling. Leading-edge: the first change in a
    /// burst fires immediately (responsive), the rest coalesce.
    pub async fn poll(&mut self, state: &Arc<NetworkState>) {
        // Keep the probe target fresh on a slow TTL: the config's STUN host
        // can change, DNS can move — but a lookup per tick would be waste.
        const PROBE_TTL: Duration = Duration::from_secs(300);
        if self
            .probe_checked_at
            .is_none_or(|t| t.elapsed() >= PROBE_TTL)
        {
            self.probe_checked_at = Some(Instant::now());
            self.probe = resolve_probe(state).await;
        }
        let current = NetworkSnapshot::sample(self.probe).await;
        let Some(last) = &self.last else {
            // First poll: adopt the baseline silently (see `last`).
            self.last = Some(current);
            return;
        };
        if &current == last {
            return;
        }
        let prev = self.last.replace(current.clone()).expect("checked above");

        // A change where the primary outbound IPs held (while we still have a
        // primary) is benign secondary-interface churn — adopt the new
        // fingerprint (done above) and stop, rather than churn every peer's ICE
        // for an address nothing connects through. See
        // [`is_benign_secondary_churn`].
        if is_benign_secondary_churn(&prev, &current) {
            debug!(
                network = %state.network_id,
                v4 = ?current.v4, v6 = ?current.v6,
                "local address set changed but primary outbound IPs held — \
                 benign secondary-interface churn, not renegotiating"
            );
            return;
        }

        let now = Instant::now();

        // The offline edges are never coalesced. Going fully offline
        // latches the hold flag; the interface *returning* must force the
        // full relay-redial + ICE-restart fan-out (and clear the flag) —
        // that's the load-bearing recovery step the macOS-wake / network-
        // handoff path depends on. The cooldown exists only to fold the
        // burst of primary-IP flips a single Wi-Fi↔cellular handoff
        // produces (v4 swaps, then v6 appears) into one restart — i.e.
        // online→online churn.
        //
        // Coalescing the return-from-offline was a bug seen in the field:
        // the going-offline event armed the cooldown, so the return a
        // second or two later got swallowed — no redial (the relay sat on
        // its dead socket grinding through backoff for ~20 s), no ICE
        // restart, and the offline flag never cleared (leaving in-place
        // recovery gated off), forcing every handoff down the slow drop-
        // and-rebuild path.
        let now_offline = current.offline();
        let is_offline_edge = now_offline || state.is_offline();
        if cooldown_coalesces(is_offline_edge, self.last_restart_at, now) {
            debug!(
                network = %state.network_id,
                prev_v4 = ?prev.v4, next_v4 = ?current.v4,
                prev_v6 = ?prev.v6, next_v6 = ?current.v6,
                "network changed again within restart cooldown — coalescing"
            );
            return;
        }
        // Only an actual restart fan-out arms the cooldown. Latching the
        // offline flag must NOT consume the slot, or the return that
        // follows it a moment later would be coalesced — the bug above.
        if !now_offline {
            self.last_restart_at = Some(now);
        }
        on_network_change(state, &prev, &current).await;
    }
}

/// Whether a snapshot transition is **benign secondary-interface churn** — the
/// primary outbound IPs held *and* we still have a primary, so only the
/// local-address fingerprint moved. That happens constantly from things no mesh
/// peer connects through: a Windows Teredo/ISATAP tunnel address rotating its
/// embedded prefix, a container/VPN adapter coming and going, a v6 temporary
/// address minted in a fresh prefix. Renegotiating ICE on every peer for it is
/// pure harm — it churns live sessions (data channels close, peers drop
/// `IceFailed`), and on a just-dialed CEC customer it kills the connection
/// before the approve handshake can complete.
///
/// A box with **no primary at all** (an internet-isolated LAN — both probes read
/// `None`) returns `false`: there a fingerprint change is the only
/// address-change signal it has, so it must still fire. A genuine primary move
/// (Wi-Fi↔cellular, the mesh interface changing) changes `v4`/`v6` and returns
/// `false` too.
fn is_benign_secondary_churn(prev: &NetworkSnapshot, current: &NetworkSnapshot) -> bool {
    let primary_held = current.v4 == prev.v4 && current.v6 == prev.v6;
    let have_primary = current.v4.is_some() || current.v6.is_some();
    primary_held && have_primary
}

/// Whether a network change should be coalesced (skipped) under the
/// restart cooldown. Offline edges — going down, or returning from down —
/// are never coalesced; only an online→online primary-IP flip within
/// [`NETWORK_CHANGE_RESTART_COOLDOWN_MS`] of the last restart is.
fn cooldown_coalesces(
    is_offline_edge: bool,
    last_restart_at: Option<Instant>,
    now: Instant,
) -> bool {
    if is_offline_edge {
        return false;
    }
    last_restart_at
        .map(|t| now.duration_since(t) < Duration::from_millis(NETWORK_CHANGE_RESTART_COOLDOWN_MS))
        .unwrap_or(false)
}

async fn on_network_change(
    state: &Arc<NetworkState>,
    prev: &NetworkSnapshot,
    current: &NetworkSnapshot,
) {
    // Going fully offline (no v4 *and* no v6) is the first half of a
    // macOS wake: the interface drops for a second or two before it
    // comes back. Firing the relay redial + ICE restart fan-out now is
    // worse than useless — `restart_ice()` can't bind a socket on a
    // down interface (the `Network is unreachable` wall in the logs),
    // and every doomed attempt burns a 15 s checking-timeout. So we just
    // latch the offline flag (which gates `renegotiate_ice` and the
    // checking-timeout watchdog) and wait. The *next* change — the
    // interface returning — is an offline→online edge that runs the full
    // handler below and restarts everything cleanly on the new route.
    let now_offline = current.offline();
    let was_offline = state.set_offline(now_offline);
    if now_offline {
        info!(
            prev_v4 = ?prev.v4,
            prev_v6 = ?prev.v6,
            "primary outbound IP lost — network down, holding ICE restarts until it returns"
        );
        state.emit(MeshEvent::Diag(DiagEntry {
            ts: crate::engine::state::now_unix_ms(),
            network_id: state.network_id.clone(),
            level: DiagLevel::Info,
            category: "network".to_string(),
            message: "Lost the primary network interface; holding ICE restarts until it returns."
                .to_string(),
            detail: serde_json::json!({
                "prev": { "v4": prev.v4.map(|v| v.to_string()), "v6": prev.v6.map(|v| v.to_string()) },
            }),
        }));
        return;
    }
    if was_offline {
        debug!(network = %state.network_id, "primary outbound IP returned — resuming ICE restarts");
    }

    info!(
        prev_v4 = ?prev.v4,
        next_v4 = ?current.v4,
        prev_v6 = ?prev.v6,
        next_v6 = ?current.v6,
        "primary outbound IP changed — renegotiating ICE on all active peers"
    );

    state.emit(MeshEvent::Diag(DiagEntry {
        ts: crate::engine::state::now_unix_ms(),
        network_id: state.network_id.clone(),
        level: DiagLevel::Info,
        category: "network".to_string(),
        message: "Primary network interface changed; renegotiating ICE with every active peer."
            .to_string(),
        detail: serde_json::json!({
            "prev": { "v4": prev.v4.map(|v| v.to_string()), "v6": prev.v6.map(|v| v.to_string()) },
            "next": { "v4": current.v4.map(|v| v.to_string()), "v6": current.v6.map(|v| v.to_string()) },
        }),
    }));

    // Redial the relays, then renegotiate ICE with every peer once a fresh
    // relay session lands. Shared with the manual reconnect controls (see
    // [`redial_then_fan_out`]).
    redial_then_fan_out(state).await;
}

/// Redial the relay sockets, then renegotiate ICE with every active peer —
/// driven by the relay-connected signal so the offers don't race the redial
/// into a still-reconnecting socket. Shared by the automatic network-change
/// handler and the manual [`reconnect_all_in_place`].
///
/// Redialing the relays first is the half that was missing — and why
/// renegotiation alone never fixed a handoff. When the primary interface
/// moves, every relay WebSocket was bound to the old route and is now a
/// zombie: the TCP connection wasn't torn down (no FIN/RST crossed the dead
/// path), so our side still thinks it's open and the kernel won't notice for
/// *minutes*. Until those sockets redial we are deaf and mute on signaling —
/// the renegotiation offer and the ICE candidates get published to nowhere
/// (they ride an ephemeral Nostr kind, forwarded to current subscribers or
/// dropped, never stored), which is exactly the "0 remote candidates arrived"
/// stall. `request_relay_reconnect` bumps the generation every relay task
/// watches, so they drop the zombie and reconnect at once. Same fix the wake
/// path uses for the identical post-suspend zombie (see `engine::wake::on_wake`).
///
/// The fan-out is then *driven by* that reconnect rather than raced against
/// it: we subscribe to the relay-connected signal before asking for the
/// redial and renegotiate the instant a fresh relay session lands. Reactive,
/// not timed — if signaling never returns there is nothing to offer into
/// anyway, and the moment it does, this fires.
async fn redial_then_fan_out(state: &Arc<NetworkState>) {
    let mut connected_rx = state.relay_connected_rx();
    if let Some(rx) = connected_rx.as_mut() {
        rx.borrow_and_update();
    }
    let redialing = state.request_relay_reconnect();
    if redialing {
        debug!(network = %state.network_id, "forcing relay reconnect before ICE fan-out");
    }

    // With a driver attached, hand the fan-out to a task that wakes on the
    // relay-connected signal. Without one (tests / the in-process broker) or
    // if the redial didn't take, fan out inline as before.
    if redialing {
        if let Some(mut rx) = connected_rx {
            let state = state.clone();
            tokio::spawn(async move {
                // Wakes when a relay establishes a fresh session; errs only if
                // the driver shut down (nothing left to renegotiate).
                if rx.changed().await.is_ok() {
                    debug!(
                        network = %state.network_id,
                        "relay reconnected — renegotiating"
                    );
                    fan_out_restart(&state).await;
                }
            });
            return;
        }
    }

    fan_out_restart(state).await;
}

/// Manually triggered in-place reconnect for a whole network — the
/// non-destructive twin of a leave-then-rejoin. Redials signaling and
/// renegotiates ICE with every active peer *without* leaving the room or
/// tearing any session down, so peers never see a `Leave` and no app-level
/// state (capabilities, routes, presence caches) is dropped. This is what the
/// GUI's global "refresh / reconnect" control drives: the same recovery the
/// network-change watcher runs automatically on an interface flip, on demand.
/// See [`on_network_change`].
pub(crate) async fn reconnect_all_in_place(state: &Arc<NetworkState>) {
    // A redial / ICE restart can't bind a socket while the interface is down;
    // the network-watch returning edge drives recovery there. Don't fight it.
    if state.is_offline() {
        debug!(
            network = %state.network_id,
            "reconnect requested while offline — deferring to network-watch"
        );
        return;
    }
    state.emit(MeshEvent::Diag(DiagEntry {
        ts: crate::engine::state::now_unix_ms(),
        network_id: state.network_id.clone(),
        level: DiagLevel::Info,
        category: "network".to_string(),
        message: "Reconnecting: redialing signaling and renegotiating ICE with every peer."
            .to_string(),
        detail: serde_json::json!({ "manual": true }),
    }));
    redial_then_fan_out(state).await;
}

/// Manually triggered in-place reconnect for a *single* peer — the per-node
/// twin of [`reconnect_all_in_place`], for AllMyStuff's per-node refresh. ICE-
/// restarts the one session in place (no teardown) and re-seeds discovery so a
/// peer we'd already lost rebuilds on the next announce round-trip. Scoped to
/// the one peer: it does **not** redial the shared relay sockets the way the
/// whole-network reconnect does, so refreshing one node never churns signaling
/// for the others.
pub(crate) async fn reconnect_peer_in_place(state: &Arc<NetworkState>, device_id: &str) {
    if state.is_offline() {
        debug!(
            network = %state.network_id,
            peer = %device_id,
            "peer reconnect requested while offline — deferring to network-watch"
        );
        return;
    }
    state.emit(MeshEvent::Diag(DiagEntry {
        ts: crate::engine::state::now_unix_ms(),
        network_id: state.network_id.clone(),
        level: DiagLevel::Info,
        category: "network".to_string(),
        message: format!("Reconnecting peer {device_id} in place."),
        detail: serde_json::json!({ "manual": true, "peer": device_id }),
    }));
    // Force past a stale `Connected` — a manual refresh is the user telling us
    // the link is quiet despite what ICE reports, the same reason the
    // network-change watcher passes `force = true`. A no-op if we hold no
    // session for the peer.
    super::renegotiate_ice(state, device_id, true, "manual-reconnect").await;
    // If we'd lost the peer entirely, nudge discovery (and flush any owed
    // offer) so it rebuilds rather than waiting for its own announce schedule.
    super::try_reoffer(state, device_id).await;
    super::maybe_reactive_announce(state);
}

/// Renegotiate ICE with every active peer and re-seed discovery. Split out so
/// the network-change handler can run it either inline or reactively, once a
/// relay is confirmed back (see [`on_network_change`]).
async fn fan_out_restart(state: &Arc<NetworkState>) {
    ice_watchdog::force_ice_restart_all(state).await;
    // Re-offer every peer we owe an offer to (offerer-role peers dropped on
    // the way down). A fresh relay session after a handoff is exactly when a
    // dropped peer's offer can finally cross — flush them all at once here,
    // event-driven, rather than waiting for each intent's backoff on the
    // tick. `try_reoffer` no-ops for any that already rebuilt.
    for device_id in state.flush_reconnect_intents() {
        super::try_reoffer(state, &device_id).await;
    }
    // Re-seed discovery as well: peers we lost while off-network (or that were
    // torn down by the data-channel-open watchdog) rediscover on the next
    // announce round-trip instead of waiting for their own schedule — so
    // rejoining a network the peer is on reconnects in about a second.
    // Rate-limited through the shared guard so this can't add relay load on
    // top of the restart fan-out.
    super::maybe_reactive_announce(state);
    debug!(network = %state.network_id, "ICE restart fan-out complete");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_equality_compares_every_field() {
        let a = NetworkSnapshot {
            v4: Some(Ipv4Addr::new(192, 168, 1, 5)),
            v6: None,
            ..Default::default()
        };
        let b = NetworkSnapshot {
            v4: Some(Ipv4Addr::new(192, 168, 1, 5)),
            v6: None,
            ..Default::default()
        };
        assert_eq!(a, b);

        let c = NetworkSnapshot {
            v4: Some(Ipv4Addr::new(192, 168, 1, 6)),
            v6: None,
            ..Default::default()
        };
        assert_ne!(a, c);

        let d = NetworkSnapshot {
            v4: Some(Ipv4Addr::new(192, 168, 1, 5)),
            v6: Some(Ipv6Addr::LOCALHOST),
            ..Default::default()
        };
        assert_ne!(a, d);

        // An interface change with identical primaries still reads as a
        // change — the whole point of the local-set fingerprint (the
        // default-route probes are blind off the default route).
        let e = NetworkSnapshot {
            local_set: 7,
            local_count: 2,
            ..a.clone()
        };
        assert_ne!(a, e);
    }

    #[test]
    fn lan_only_is_not_offline() {
        // No default route (both primary probes None) but interfaces up:
        // the exact shape of an internet-isolated LAN fleet. Reading this
        // as "offline" used to gate ICE recovery off on the deployments
        // that need it most.
        let lan_only = NetworkSnapshot {
            v4: None,
            v6: None,
            local_set: 42,
            local_count: 1,
        };
        assert!(!lan_only.offline());
        // Genuinely nothing up: offline.
        let dark = NetworkSnapshot {
            v4: None,
            v6: None,
            local_set: 0,
            local_count: 0,
        };
        assert!(dark.offline());
    }

    #[test]
    fn fingerprint_only_change_with_a_held_primary_is_benign() {
        // Primary v4 held, v6 held (None) — only the local-address fingerprint
        // moved. This is the storm from the field: a tunnel/virtual address
        // rotating fires "IP changed" every few seconds and renegotiates the
        // whole mesh, dropping live peers. Must read as benign.
        let prev = NetworkSnapshot {
            v4: Some(Ipv4Addr::new(192, 168, 88, 15)),
            v6: None,
            local_set: 100,
            local_count: 3,
        };
        let current = NetworkSnapshot {
            local_set: 200,
            local_count: 3,
            ..prev.clone()
        };
        assert_ne!(prev, current, "the fingerprint genuinely differs");
        assert!(
            is_benign_secondary_churn(&prev, &current),
            "a fingerprint-only change with the primary held must not renegotiate"
        );
    }

    #[test]
    fn real_and_lan_only_changes_are_not_benign() {
        // A genuine primary move (Wi-Fi↔cellular, mesh interface changing) fires.
        let prev = NetworkSnapshot {
            v4: Some(Ipv4Addr::new(192, 168, 88, 15)),
            v6: None,
            local_set: 100,
            local_count: 3,
        };
        let primary_moved = NetworkSnapshot {
            v4: Some(Ipv4Addr::new(10, 0, 0, 9)),
            ..prev.clone()
        };
        assert!(!is_benign_secondary_churn(&prev, &primary_moved));

        // v6 appearing is a real change too.
        let v6_appeared = NetworkSnapshot {
            v6: Some(Ipv6Addr::LOCALHOST),
            ..prev.clone()
        };
        assert!(!is_benign_secondary_churn(&prev, &v6_appeared));

        // Internet-isolated LAN: no primary at all — a fingerprint change is
        // the ONLY address-change signal it has, so it must still fire.
        let lan_prev = NetworkSnapshot {
            v4: None,
            v6: None,
            local_set: 100,
            local_count: 1,
        };
        let lan_next = NetworkSnapshot {
            local_set: 200,
            ..lan_prev.clone()
        };
        assert_ne!(lan_prev, lan_next);
        assert!(
            !is_benign_secondary_churn(&lan_prev, &lan_next),
            "with no primary, a fingerprint change is the only signal — must fire"
        );
    }

    #[test]
    fn offline_edges_bypass_the_restart_cooldown() {
        let now = Instant::now();
        // An online→online flip a moment after a restart coalesces…
        assert!(cooldown_coalesces(false, Some(now), now));
        // …but an offline edge (going down, or the interface returning)
        // never does, even squarely inside the cooldown window. This is
        // the fix: the return-from-offline must always run the full
        // redial + restart handler.
        assert!(!cooldown_coalesces(true, Some(now), now));
    }

    #[test]
    fn online_flip_coalesces_only_within_the_window() {
        let base = Instant::now();
        let within = base + Duration::from_millis(NETWORK_CHANGE_RESTART_COOLDOWN_MS / 2);
        let after = base + Duration::from_millis(NETWORK_CHANGE_RESTART_COOLDOWN_MS + 1);
        assert!(
            cooldown_coalesces(false, Some(base), within),
            "a flip inside the window coalesces onto the in-flight restart"
        );
        assert!(
            !cooldown_coalesces(false, Some(base), after),
            "a flip after the window fires its own restart"
        );
        assert!(
            !cooldown_coalesces(false, None, base),
            "the first-ever change always fires"
        );
    }
}
