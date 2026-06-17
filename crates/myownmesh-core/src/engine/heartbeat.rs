//! Periodic ping / pong on every active peer. The Tier 4
//! re-handshake fires when a peer's last_recv_at gap exceeds
//! `HEARTBEAT_TIMEOUT_MS + WAKE_DETECTION_THRESHOLD_MS`.

use std::sync::Arc;
use std::time::Instant;

use tracing::trace;

use crate::protocol::keepalive::{PingMessage, PongMessage};
use crate::protocol::MeshMessage;

use super::connection::PeerStatus;
use super::scheduler::{HEARTBEAT_TIMEOUT_MS, WAKE_DETECTION_THRESHOLD_MS};
use super::state::NetworkState;

/// Periodic engine tick — fired by the driver every
/// `HEARTBEAT_INTERVAL_MS`. Sends a ping to every active peer and
/// triggers Tier 4 for peers past `HEARTBEAT_TIMEOUT_MS`.
pub async fn tick(state: &Arc<NetworkState>) {
    let now = Instant::now();
    let to_ping: Vec<String> = state
        .peers
        .iter()
        .filter(|e| {
            matches!(
                e.value().state.read().status,
                PeerStatus::Active | PeerStatus::Shelved
            )
        })
        .map(|e| e.key().clone())
        .collect();
    for peer_id in &to_ping {
        send_ping(state, peer_id).await;
    }

    // Check for silent peers past the heartbeat timeout. Surface
    // Tier 4 for any that exceed the (timeout + wake threshold)
    // combined window — the wake-threshold buffer prevents a
    // long-paused tokio runtime from immediately re-handshaking
    // every peer the moment it resumes.
    let stale_cutoff_ms = HEARTBEAT_TIMEOUT_MS + WAKE_DETECTION_THRESHOLD_MS;
    let stale: Vec<String> = state
        .peers
        .iter()
        .filter_map(|e| {
            let data = e.value().state.read();
            if !matches!(data.status, PeerStatus::Active | PeerStatus::Shelved) {
                return None;
            }
            let elapsed = data
                .last_recv_at
                .map(|t| now.duration_since(t).as_millis() as u64);
            match elapsed {
                Some(ms) if ms > stale_cutoff_ms => Some(e.key().clone()),
                _ => None,
            }
        })
        .collect();
    // Silence past the ping/pong window means the *transport* is dead, not
    // that app state went stale: a live channel keeps `last_recv_at` fresh
    // via the heartbeat pong every interval, so anything past this
    // threshold has stopped carrying frames regardless of what ICE reports.
    // Re-handshaking `hello` over a dead channel can't work — it lands in
    // the void (observed: three "Connected"-on-TURN peers stuck at
    // Handshaking for minutes after a network change). Rebuild instead and
    // let discovery re-establish a fresh connection.
    if !stale.is_empty() {
        for peer_id in &stale {
            state.log_diag_with(
                crate::events::DiagLevel::Warn,
                "heartbeat",
                format!("peer silent past heartbeat timeout — rebuilding: {peer_id}"),
                serde_json::json!({ "peer": peer_id }),
            );
            super::drop_peer(state, peer_id, crate::events::DropReason::HeartbeatTimeout).await;
        }
        // Re-seed discovery so the rebuilt peers rediscover promptly rather
        // than waiting for their next scheduled announce. Rate-limited, so
        // a wave of timeouts collapses into one publish.
        super::maybe_reactive_announce(state);
    }
}

pub(super) async fn send_ping(state: &Arc<NetworkState>, device_id: &str) {
    let t = monotonic_ms();
    if let Some(peer) = state.peers.get(device_id) {
        let mut data = peer.state.write();
        data.last_ping_sent_at = Some(Instant::now());
        data.last_ping_t = Some(t);
    }
    if let Err(e) =
        super::send_to_peer(state, device_id, &MeshMessage::Ping(PingMessage { t })).await
    {
        trace!(peer = %device_id, "ping send failed (peer probably gone): {e}");
    }
}

pub async fn on_ping(state: &Arc<NetworkState>, device_id: &str, ping: PingMessage) {
    // Echo back unchanged so the sender can compute RTT against
    // its own clock.
    if let Err(e) = super::send_to_peer(
        state,
        device_id,
        &MeshMessage::Pong(PongMessage { t: ping.t }),
    )
    .await
    {
        trace!(peer = %device_id, "pong send failed: {e}");
    }
}

pub async fn on_pong(state: &Arc<NetworkState>, device_id: &str, pong: PongMessage) {
    let now = monotonic_ms();
    if let Some(peer) = state.peers.get(device_id) {
        let mut data = peer.state.write();
        if data.last_ping_t == Some(pong.t) {
            let rtt = (now - pong.t).max(0) as u32;
            data.rtt_ms = Some(rtt);
        }
    }
}

fn monotonic_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
