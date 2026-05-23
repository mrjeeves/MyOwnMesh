//! Tier 2.5 — per-peer ICE watchdog. Fires at
//! `ICE_DISCONNECTED_RESTART_MS` after a peer's ICE state goes
//! `disconnected` — earlier than the underlying WebRTC stack's
//! own consent-freshness timer would notice a stale network.
//!
//! Side-effect of beating the upstream timer: a recovered
//! connection sees `connected` again from inside our
//! `restart_ice()` call, so we never tear down the data channel
//! on a brief LAN blip.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, warn};
use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState;

use super::connection::PeerStatus;
use super::ladder::ConnectionTier;
use super::scheduler::{ICE_DISCONNECTED_RESTART_MS, ICE_RESTART_RECOVERY_MS};
use super::state::NetworkState;

/// Periodic poll — checks every active peer's ICE state and
/// triggers `restart_ice()` for any past the disconnected
/// threshold. Cheap to call on every tick: it's an O(N) scan
/// over the peers map with no per-peer locks held across awaits.
pub async fn poll_all(state: &Arc<NetworkState>) {
    let now = Instant::now();
    let candidates: Vec<String> = state
        .peers
        .iter()
        .filter_map(|e| {
            let data = e.value().state.read();
            if !matches!(data.status, PeerStatus::Active | PeerStatus::Shelved) {
                return None;
            }
            let since = data.ice_disconnected_since?;
            if now.saturating_duration_since(since).as_millis() as u64
                >= ICE_DISCONNECTED_RESTART_MS
            {
                Some(e.key().clone())
            } else {
                None
            }
        })
        .collect();

    for peer_id in candidates {
        try_restart_ice(state, &peer_id).await;
    }
}

/// Tier 3 — `pc.restart_ice()` then wait the recovery grace.
async fn try_restart_ice(state: &Arc<NetworkState>, device_id: &str) {
    let session = {
        let Some(peer) = state.peers.get(device_id) else {
            return;
        };
        let session = peer.session.lock().clone();
        session
    };
    let Some(session) = session else { return };

    // Skip if ICE has already recovered on its own.
    match session.ice_connection_state() {
        RTCIceConnectionState::Connected | RTCIceConnectionState::Completed => {
            if let Some(peer) = state.peers.get(device_id) {
                let mut data = peer.state.write();
                data.ice_disconnected_since = None;
                data.tier = ConnectionTier::Steady;
            }
            return;
        }
        _ => {}
    }

    debug!(peer = %device_id, "tier 2.5 → restart_ice()");
    if let Some(peer) = state.peers.get(device_id) {
        let mut data = peer.state.write();
        data.diag.ice_restarts += 1;
        data.tier = ConnectionTier::IceRestart {
            started: Instant::now(),
        };
    }
    if let Err(e) = session.restart_ice().await {
        warn!(peer = %device_id, "restart_ice failed: {e}");
    }

    // Schedule the recovery check. After `ICE_RESTART_RECOVERY_MS`
    // we either see ICE back to `connected` (the watchdog
    // resolves naturally via the engine's state-change handler)
    // or escalate to Tier 4.
    let state_clone = state.clone();
    let device_id = device_id.to_string();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(ICE_RESTART_RECOVERY_MS)).await;
        let still_failing = {
            let Some(peer) = state_clone.peers.get(&device_id) else {
                return;
            };
            let data = peer.state.read();
            !matches!(data.tier, ConnectionTier::Steady)
        };
        if still_failing {
            warn!(peer = %device_id, "ICE restart did not recover — escalating to Tier 4");
            super::ladder::escalate_to_rehandshake(&state_clone, &device_id).await;
        }
    });
}

/// Called directly from the ICE state-change handler when ICE
/// reports `Failed`. Skips the watchdog window — we know the
/// connection is gone.
pub async fn on_failed(state: &Arc<NetworkState>, device_id: &str) {
    warn!(peer = %device_id, "ICE failed — Tier 4 immediately");
    super::ladder::escalate_to_rehandshake(state, device_id).await;
}
