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
use crate::events::{DiagEntry, DiagLevel, MeshEvent};

/// After this many consecutive ICE failures with zero relay
/// candidates on both sides, surface the no-TURN diagnostic. Three
/// gives the connection a fair chance to recover on its own
/// (signaling races, transient network drops) before we tell the
/// user the topology won't ever work without TURN.
const NO_TURN_DIAG_AFTER_FAILURES: u32 = 3;

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
        state.log_diag_with(
            crate::events::DiagLevel::Warn,
            "ice",
            format!("restart_ice failed for {device_id}: {e}"),
            serde_json::json!({ "peer": device_id, "error": e.to_string() }),
        );
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
            state_clone.log_diag_with(
                crate::events::DiagLevel::Warn,
                "ice",
                format!("ICE restart did not recover for {device_id} — escalating to Tier 4"),
                serde_json::json!({ "peer": device_id }),
            );
            super::ladder::escalate_to_rehandshake(&state_clone, &device_id).await;
        }
    });
}

/// Called directly from the ICE state-change handler when ICE
/// reports `Failed`. Skips the watchdog window — we know the
/// connection is gone.
pub async fn on_failed(state: &Arc<NetworkState>, device_id: &str) {
    state.log_diag_with(
        crate::events::DiagLevel::Warn,
        "ice",
        format!("ICE failed for {device_id} — Tier 4 immediately"),
        serde_json::json!({ "peer": device_id }),
    );
    maybe_emit_no_turn_diag(state, device_id);
    super::ladder::escalate_to_rehandshake(state, device_id).await;
}

/// Inspect the peer's candidate stats after an ICE failure and, if
/// neither side ever produced a relay candidate, surface a
/// human-readable diagnostic pointing at the missing TURN config.
/// Throttled: the `no_turn_diag_emitted` flag stops us re-emitting
/// once per ladder cycle. Reset by the engine's Active transition.
fn maybe_emit_no_turn_diag(state: &Arc<NetworkState>, device_id: &str) {
    let snapshot = {
        let Some(peer) = state.peers.get(device_id) else {
            return;
        };
        let mut data = peer.state.write();
        data.ice_failed_count = data.ice_failed_count.saturating_add(1);
        if data.no_turn_diag_emitted {
            return;
        }
        // Need enough consecutive failures to rule out transient
        // signaling glitches. With zero relay candidates on either
        // side, no amount of retrying will fix the symmetric-NAT
        // case — surface that now.
        if data.ice_failed_count < NO_TURN_DIAG_AFTER_FAILURES {
            return;
        }
        let local_relay = data.diag.local_candidates.relay;
        let remote_relay = data.diag.remote_candidates.relay;
        if local_relay > 0 || remote_relay > 0 {
            return;
        }
        data.no_turn_diag_emitted = true;
        (
            data.ice_failed_count,
            data.diag.local_candidates.host,
            data.diag.local_candidates.server_reflexive,
            data.diag.remote_candidates.host,
            data.diag.remote_candidates.server_reflexive,
        )
    };
    let (failures, local_host, local_srflx, remote_host, remote_srflx) = snapshot;
    let message = format!(
        "ICE failed {failures} times for peer {device_id} with zero relay (TURN) candidates \
         on either side. Direct connectivity isn't reaching this peer — add a TURN server to \
         this network's settings so the engine can fall back to a relay."
    );
    warn!(
        peer = %device_id,
        failures,
        local_host,
        local_srflx,
        remote_host,
        remote_srflx,
        "no TURN configured and ICE keeps failing"
    );
    state.emit(MeshEvent::Diag(DiagEntry {
        network_id: state.network_id.clone(),
        level: DiagLevel::Warn,
        category: "ice".to_string(),
        message,
        detail: serde_json::json!({
            "peer": device_id,
            "failures": failures,
            "local_candidates": {
                "host": local_host,
                "server_reflexive": local_srflx,
                "relay": 0,
            },
            "remote_candidates": {
                "host": remote_host,
                "server_reflexive": remote_srflx,
                "relay": 0,
            },
            "hint": "add_turn_server",
        }),
    }));
}

/// Force an ICE restart on every active or shelved peer, ignoring
/// the "already connected" short-circuit. Used by the network-change
/// watcher: when the OS reports the primary outbound IP just
/// changed, every existing connection's local candidates are stale
/// and ICE won't notice until its 30 s consent-freshness timer
/// expires. Pre-empting that timer here gets us reconnected within
/// seconds instead of half a minute.
pub async fn force_ice_restart_all(state: &Arc<NetworkState>) {
    let candidates: Vec<String> = state
        .peers
        .iter()
        .filter_map(|e| {
            let data = e.value().state.read();
            matches!(data.status, PeerStatus::Active | PeerStatus::Shelved).then(|| e.key().clone())
        })
        .collect();

    for peer_id in candidates {
        force_one(state, &peer_id).await;
    }
}

async fn force_one(state: &Arc<NetworkState>, device_id: &str) {
    // Bind the cloned `Option<Arc<PeerSession>>` to a named local
    // before the inner block returns so the MutexGuard temporary
    // from `.lock()` drops before the `peer` Ref does. Without
    // this, Rust 2021's trailing-expression scoping keeps the
    // guard alive across the outer borrow checker boundary and
    // fails E0597. Matches the pattern used by `try_restart_ice`
    // above.
    let session = {
        let Some(peer) = state.peers.get(device_id) else {
            return;
        };
        let session = peer.session.lock().clone();
        session
    };
    let Some(session) = session else { return };

    debug!(peer = %device_id, "network change — forcing ICE restart");
    if let Some(peer) = state.peers.get(device_id) {
        let mut data = peer.state.write();
        data.diag.ice_restarts += 1;
        data.tier = ConnectionTier::IceRestart {
            started: Instant::now(),
        };
    }
    if let Err(e) = session.restart_ice().await {
        warn!(peer = %device_id, "force restart_ice failed: {e}");
    }
}
