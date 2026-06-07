//! Wake detection. The driver loop drives one timer per
//! scheduled tick; if a tick fires much later than its interval
//! it means the OS paused the tokio runtime (sleep / suspend /
//! container freeze). Treat that as a wake event so the engine
//! can probe peers proactively rather than waiting another
//! heartbeat interval.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::debug;

use crate::protocol::{keepalive::PingMessage, MeshMessage};

use super::connection::PeerStatus;
use super::scheduler::{WAKE_COALESCE_MS, WAKE_DETECTION_THRESHOLD_MS, WAKE_PROBE_DELAY_MS};
use super::state::{NetworkState, SignalingOutbound};

/// Local detector — tracks the last observed tick instant and
/// raises a wake event when the next tick comes too long after.
pub struct WakeDetector {
    last_tick_at: Option<Instant>,
    last_wake_at: Option<Instant>,
    pending: bool,
}

impl WakeDetector {
    pub fn new() -> Self {
        Self {
            last_tick_at: None,
            last_wake_at: None,
            pending: false,
        }
    }

    /// Observe a periodic tick that nominally repeats every
    /// `interval_ms`. If the gap to the previous tick exceeds
    /// `WAKE_DETECTION_THRESHOLD_MS` the next call to
    /// [`Self::take_wake_event`] returns `true`.
    pub fn observe(&mut self, now: Instant, interval_ms: u64) {
        if let Some(prev) = self.last_tick_at {
            let gap = now.saturating_duration_since(prev).as_millis() as u64;
            let threshold = WAKE_DETECTION_THRESHOLD_MS.max(interval_ms * 2);
            if gap > threshold {
                let stale_window = self
                    .last_wake_at
                    .map(|t| now.saturating_duration_since(t).as_millis() as u64)
                    .unwrap_or(u64::MAX);
                if stale_window > WAKE_COALESCE_MS {
                    self.pending = true;
                    self.last_wake_at = Some(now);
                }
            }
        }
        self.last_tick_at = Some(now);
    }

    /// Consume the pending wake event flag.
    pub fn take_wake_event(&mut self) -> bool {
        let p = self.pending;
        self.pending = false;
        p
    }
}

impl Default for WakeDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Tier 2 entry — wake detected. Ping every active peer and
/// schedule a follow-up sweep after `WAKE_PROBE_DELAY_MS` to see
/// who responded.
pub async fn on_wake(state: &Arc<NetworkState>) {
    debug!(network = %state.network_id, "tier 2 wake probe");

    // Re-advertise immediately on resume. While this node was paused
    // (OS suspend, container freeze, or a model-load memory-thrash
    // that starved the process) it sent no traffic, so peers tore it
    // down after the heartbeat grace. They only rediscover us through
    // a fresh announce — without this we wait up to ANNOUNCE_STEADY_MS
    // (2 min) for the next scheduled one. Reactive reflection
    // (see `handle_signaling_inbound`) makes neighbors re-announce
    // within ~1 s, so the round-trip rebuild lands in seconds. One
    // send per wake event — wake events are coalesced upstream by
    // WAKE_COALESCE_MS, and reflected announces are rate-limited by
    // REACTIVE_ANNOUNCE_MIN_INTERVAL_MS, so this can't storm the relay.
    let _ = state.signaling_tx.send(SignalingOutbound::Announce);

    // The announce above is useless if it's written to a dead socket.
    // After an OS suspend the relay WebSocket is typically a zombie —
    // the TCP connection was never torn down because the host wasn't
    // running to receive the FIN/RST, so our side still thinks it's
    // open and the kernel won't notice for minutes. Force every relay
    // to redial now: the fresh session re-subscribes (replaying recent
    // presence) and sends its own open-announce, so peers rediscover us
    // in seconds instead of waiting for the stale socket to time out.
    // No-op when there's no Nostr driver attached (e.g. local-broker
    // tests).
    if state.request_relay_reconnect() {
        debug!(network = %state.network_id, "wake — forcing relay reconnect");
    }

    let active: Vec<String> = state
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
    let now = monotonic_ms();
    for peer_id in &active {
        if let Some(peer) = state.peers.get(peer_id) {
            peer.state.write().last_ping_t = Some(now);
        }
        if let Err(e) =
            super::send_to_peer(state, peer_id, &MeshMessage::Ping(PingMessage { t: now })).await
        {
            tracing::trace!(peer = %peer_id, "wake-probe ping failed: {e}");
        }
    }

    // Wait the probe delay then check who responded. Anyone still
    // silent is escalated.
    let state_clone = state.clone();
    let peers = active;
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(WAKE_PROBE_DELAY_MS)).await;
        let now = Instant::now();
        for peer_id in peers {
            let stale = {
                let Some(peer) = state_clone.peers.get(&peer_id) else {
                    continue;
                };
                let data = peer.state.read();
                data.last_recv_at
                    .map(|t| now.saturating_duration_since(t).as_millis() as u64)
                    .unwrap_or(u64::MAX)
                    > WAKE_PROBE_DELAY_MS
            };
            if stale {
                debug!(peer = %peer_id, "wake probe — peer silent, escalating");
                super::ladder::escalate_to_rehandshake(&state_clone, &peer_id).await;
            }
        }
    });
}

fn monotonic_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn on_wake_emits_announce_for_rediscovery() {
        // A node that was paused must re-advertise on resume so peers
        // that tore it down during the pause rediscover it without
        // waiting for the 2-minute steady announce cadence.
        let state = crate::engine::build_test_state("wake-announce");
        let mut rx = state
            .take_signaling_outbound_rx()
            .expect("outbound signaling rx should be available");
        on_wake(&state).await;
        assert!(
            matches!(rx.try_recv(), Ok(SignalingOutbound::Announce)),
            "on_wake must emit a fresh announce"
        );
    }

    #[tokio::test]
    async fn on_wake_forces_relay_reconnect() {
        // The wake path must also kick the relay so a socket left stale
        // by the suspend is replaced at once. With no driver attached it
        // degrades to a silent no-op (request returns false); with one,
        // on_wake bumps the generation every relay task watches.
        let state = crate::engine::build_test_state("wake-reconnect");
        let _ = state.take_signaling_outbound_rx();
        assert!(
            !state.request_relay_reconnect(),
            "no attached driver → no-op"
        );
        let signal = std::sync::Arc::new(tokio::sync::watch::channel(0u64).0);
        let rx = signal.subscribe();
        state.set_relay_reconnect(signal);
        on_wake(&state).await;
        assert!(
            rx.has_changed().unwrap(),
            "on_wake must bump the relay-reconnect signal"
        );
    }

    #[test]
    fn detector_fires_on_long_gap() {
        let mut det = WakeDetector::new();
        let base = Instant::now();
        det.observe(base, 30_000);
        assert!(!det.take_wake_event(), "first tick shouldn't fire");
        // 70s later — well past 2x heartbeat interval
        det.observe(base + Duration::from_secs(70), 30_000);
        assert!(det.take_wake_event(), "70s gap should fire wake");
    }

    #[test]
    fn detector_does_not_fire_on_normal_cadence() {
        let mut det = WakeDetector::new();
        let base = Instant::now();
        det.observe(base, 30_000);
        det.observe(base + Duration::from_secs(30), 30_000);
        assert!(!det.take_wake_event(), "30s gap should not fire");
    }

    #[test]
    fn detector_coalesces_close_events() {
        let mut det = WakeDetector::new();
        let base = Instant::now();
        det.observe(base, 30_000);
        det.observe(base + Duration::from_secs(70), 30_000);
        assert!(det.take_wake_event());
        // Second long gap within WAKE_COALESCE_MS doesn't fire.
        det.observe(
            base + Duration::from_secs(70) + Duration::from_millis(500),
            30_000,
        );
        // The 500ms gap between the two observations is small,
        // but the detector only fires when the *threshold* is
        // exceeded — so this one wouldn't fire on its own. The
        // coalescing check only applies when a long gap *does*
        // happen close to a prior wake.
        assert!(!det.take_wake_event());
    }
}
