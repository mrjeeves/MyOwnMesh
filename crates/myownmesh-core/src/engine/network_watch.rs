//! Network-change watcher. Polls the OS's chosen primary outbound
//! IPs every few seconds and, when they change, forces an ICE
//! restart on every active peer in this network.
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
//! Cost is one UDP socket bind + connect per poll, on the order
//! of microseconds. Frequency is tuned to be responsive without
//! being noisy; see `NETWORK_WATCH_POLL_MS` in `scheduler.rs`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tracing::{debug, info};

use crate::events::{DiagEntry, DiagLevel, MeshEvent};

use super::ice_watchdog;
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
        }
    }

    /// Sample, compare, and fire the change handler if the
    /// primary outbound IPs moved.
    pub async fn poll(&mut self, state: &Arc<NetworkState>) {
        let current = NetworkSnapshot::sample().await;
        if current == self.last {
            return;
        }
        let prev = std::mem::replace(&mut self.last, current.clone());
        on_network_change(state, &prev, &current).await;
    }
}

async fn on_network_change(
    state: &Arc<NetworkState>,
    prev: &NetworkSnapshot,
    current: &NetworkSnapshot,
) {
    info!(
        prev_v4 = ?prev.v4,
        next_v4 = ?current.v4,
        prev_v6 = ?prev.v6,
        next_v6 = ?current.v6,
        "primary outbound IP changed — forcing ICE restart on all active peers"
    );

    state.emit(MeshEvent::Diag(DiagEntry {
        network_id: state.network_id.clone(),
        level: DiagLevel::Info,
        category: "network".to_string(),
        message: "Primary network interface changed; restarting ICE on every active peer."
            .to_string(),
        detail: serde_json::json!({
            "prev": { "v4": prev.v4.map(|v| v.to_string()), "v6": prev.v6.map(|v| v.to_string()) },
            "next": { "v4": current.v4.map(|v| v.to_string()), "v6": current.v6.map(|v| v.to_string()) },
        }),
    }));

    ice_watchdog::force_ice_restart_all(state).await;
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
}
