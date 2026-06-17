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
//! No new dependencies — we use the well-known "bind a UDP socket
//! and connect to a public address" trick to ask the OS which
//! local IP it would use for outbound traffic. `connect()` on a
//! UDP socket doesn't actually send anything; it just sets the
//! default destination so `local_addr()` returns the source IP
//! the OS picked. We do this once for v4 (8.8.8.8:53) and once
//! for v6 (Google's public v6 resolver). Either or both may be
//! `None` (no v6 connectivity, no v4, offline entirely) — change
//! detection is `last != current`, so any transition counts,
//! including up→down and down→up.
//!
//! Cost is one UDP socket bind + connect per poll, on the order of
//! microseconds. It runs on the shared state-watch tick (see
//! `STATE_WATCH_INTERVAL_MS` in `scheduler.rs`) rather than its own
//! interval — one periodic pass covers network-change detection alongside
//! the per-peer state confirmation.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tracing::{debug, info};

use crate::events::{DiagEntry, DiagLevel, MeshEvent};

use super::ice_watchdog;
use super::scheduler::NETWORK_CHANGE_RESTART_COOLDOWN_MS;
use super::state::NetworkState;

/// Snapshot of the OS's chosen primary outbound IPs. Compared by
/// value — any transition (v4 changes, v4 appears, v6 disappears,
/// etc.) triggers the change handler.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkSnapshot {
    pub v4: Option<Ipv4Addr>,
    pub v6: Option<Ipv6Addr>,
}

impl NetworkSnapshot {
    pub async fn sample() -> Self {
        let v4 = primary_v4().await;
        let v6 = primary_v6().await;
        Self { v4, v6 }
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

/// Holds the last observed snapshot. Lives inside the driver loop
/// so we don't need a Mutex — single owner.
pub struct NetworkWatch {
    last: NetworkSnapshot,
    /// When we last fired a change-triggered ICE-restart fan-out. Used
    /// to coalesce the burst of primary-IP flips a Wi-Fi→cellular
    /// handoff produces into a single restart (see
    /// `NETWORK_CHANGE_RESTART_COOLDOWN_MS`).
    last_restart_at: Option<Instant>,
}

impl NetworkWatch {
    /// Build a watcher pre-seeded with the current snapshot. The
    /// first `poll` after construction won't fire a change event
    /// unless the network actually moves between init and that
    /// poll — desirable so daemon startup doesn't kick a useless
    /// ICE restart.
    pub async fn new() -> Self {
        Self {
            last: NetworkSnapshot::sample().await,
            last_restart_at: None,
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
        let current = NetworkSnapshot::sample().await;
        if current == self.last {
            return;
        }
        let prev = std::mem::replace(&mut self.last, current.clone());
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
        let now_offline = current.v4.is_none() && current.v6.is_none();
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
    let now_offline = current.v4.is_none() && current.v6.is_none();
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

    // FIRST, redial the relays. This is the half that was missing — and
    // why renegotiation alone never fixed the handoff. When the primary
    // interface moves, every relay WebSocket was bound to the old route
    // and is now a zombie: the TCP connection wasn't torn down (no
    // FIN/RST crossed the dead path), so our side still thinks it's open
    // and the kernel won't notice for *minutes*. Until those sockets
    // redial we are deaf and mute on signaling — the renegotiation offer
    // and the ICE candidates below get published to nowhere (they ride an
    // ephemeral Nostr kind, so they're forwarded to current subscribers
    // or dropped, never stored), which is exactly the "0 remote
    // candidates arrived" stall. `request_relay_reconnect` bumps the
    // generation every relay task watches, so they drop the zombie and
    // reconnect on the new interface at once. Same fix the wake path uses
    // for the identical post-suspend zombie (see `engine::wake::on_wake`).
    //
    // The fan-out is then *driven by* that reconnect rather than raced
    // against it: an offer published while the relays are still redialing
    // reaches nobody (the stall above), so we subscribe to the relay-connected
    // signal before asking for the redial and renegotiate the instant a fresh
    // relay session lands. Reactive, not timed — if signaling never returns
    // there is nothing to offer into anyway, and the moment it does, this
    // fires. (The data-channel-open watchdog remains the only teardown clock.)
    let mut connected_rx = state.relay_connected_rx();
    if let Some(rx) = connected_rx.as_mut() {
        rx.borrow_and_update();
    }
    let redialing = state.request_relay_reconnect();
    if redialing {
        debug!(network = %state.network_id, "network change — forcing relay reconnect");
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
                        "relay reconnected after network change — renegotiating"
                    );
                    fan_out_restart(&state).await;
                }
            });
            return;
        }
    }

    fan_out_restart(state).await;
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
    fn snapshot_equality_compares_v4_and_v6() {
        let a = NetworkSnapshot {
            v4: Some(Ipv4Addr::new(192, 168, 1, 5)),
            v6: None,
        };
        let b = NetworkSnapshot {
            v4: Some(Ipv4Addr::new(192, 168, 1, 5)),
            v6: None,
        };
        assert_eq!(a, b);

        let c = NetworkSnapshot {
            v4: Some(Ipv4Addr::new(192, 168, 1, 6)),
            v6: None,
        };
        assert_ne!(a, c);

        let d = NetworkSnapshot {
            v4: Some(Ipv4Addr::new(192, 168, 1, 5)),
            v6: Some(Ipv6Addr::LOCALHOST),
        };
        assert_ne!(a, d);
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
