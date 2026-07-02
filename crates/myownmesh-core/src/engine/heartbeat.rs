//! Periodic ping / pong on every active peer. A peer whose
//! `last_recv_at` gap exceeds
//! `HEARTBEAT_TIMEOUT_MS + WAKE_DETECTION_THRESHOLD_MS` is treated as
//! a dead transport and dropped for rebuild (see [`tick`]).

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
/// drops + rebuilds any peer silent past `HEARTBEAT_TIMEOUT_MS`.
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

    // Fold this tick's per-peer clock-skew estimates into the network
    // verdict (passive — built entirely from pings peers already sent us).
    watch_clock_skew(state);

    // Check for silent peers past the heartbeat timeout. Drop + rebuild
    // any that exceed the (timeout + wake threshold) combined window —
    // the wake-threshold buffer prevents a long-paused tokio runtime
    // from immediately tearing down every peer the moment it resumes.
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
    // A free clock-skew sample: `ping.t` is the sender's wall clock at
    // send (see `PingMessage::t`), so after correcting for transit time
    // (half our measured RTT to this peer) the difference to our own wall
    // clock is how far the two clocks disagree. Median over a small window
    // rides out one-off delivery stalls. Entirely passive — the ping was
    // coming anyway.
    if ping.t > 0 {
        let now = monotonic_ms();
        if let Some(peer) = state.peers.get(device_id) {
            let mut data = peer.state.write();
            let half_rtt = i64::from(data.rtt_ms.unwrap_or(0)) / 2;
            let sample = ping.t + half_rtt - now;
            data.clock_skew_samples.push(sample);
            if data.clock_skew_samples.len() > SKEW_WINDOW {
                data.clock_skew_samples.remove(0);
            }
            data.clock_skew_ms = median(&data.clock_skew_samples);
        }
    }
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

// ---- passive clock-skew watch ------------------------------------------
//
// Wall-clock disagreement is a quiet wrecker on this mesh: member-log
// entries converge last-writer-wins on wall-clock stamps (a skewed clock can
// strand a device evicted), custody TOTP accepts a ±30 s step, and presence
// replay windows read against local time. Every inbound heartbeat ping
// already carries the sender's wall clock, so each connected peer gives us a
// free skew measurement — enough to warn "*this* machine's clock is off"
// without a single extra call to any node.

/// Per-peer sample window: 5 pings ≈ 2½ minutes of history — enough to
/// median out a one-off delivery stall, short enough to converge quickly
/// after an NTP step or a suspend/resume.
pub(super) const SKEW_WINDOW: usize = 5;
/// |skew| at which a peer counts as disagreeing with our clock (10 s: far
/// beyond NTP jitter or RTT noise, well under TOTP/LWW damage territory).
pub const SKEW_WARN_MS: i64 = 10_000;
/// |skew| the network estimate must fall back under before a raised warning
/// clears — hysteresis so the diag doesn't flap at the threshold.
pub const SKEW_CLEAR_MS: i64 = 5_000;
/// Consecutive over-threshold ticks (30 s apart) before warning — a slow
/// double-check, not a single-glitch alarm.
pub const SKEW_WARN_TICKS: u8 = 3;

/// Median of `samples` (odd length), or the **smaller-magnitude** middle
/// (even length). The conservative even-case pick is deliberate: read as a
/// network verdict it means a *strict majority* of peers must agree we're
/// off before the estimate crosses the threshold — with two peers split
/// [0 s, 60 s], the verdict is 0 (it's that peer's clock that's wrong, and
/// its own daemon will notice against *its* peers).
pub(super) fn median(samples: &[i64]) -> Option<i64> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let n = sorted.len();
    if n % 2 == 1 {
        return Some(sorted[n / 2]);
    }
    let (a, b) = (sorted[n / 2 - 1], sorted[n / 2]);
    Some(if a.abs() <= b.abs() { a } else { b })
}

/// What a [`ClockSkewWatch::observe`] tick concluded, when it concluded
/// anything: raise the warning, or stand down a raised one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkewVerdict {
    /// Our clock has disagreed with the network past
    /// [`SKEW_WARN_MS`] for [`SKEW_WARN_TICKS`] consecutive ticks.
    Warn { skew_ms: i64, peers: usize },
    /// A raised warning cleared — the estimate fell back under
    /// [`SKEW_CLEAR_MS`].
    Clear { skew_ms: i64 },
}

/// The latched state machine behind the clock-skew diagnostic: warn once
/// after sustained disagreement, clear once when it resolves, never flap.
/// Pure (no clock, no I/O) so the transitions are unit-testable.
#[derive(Debug, Default)]
pub struct ClockSkewWatch {
    over_ticks: u8,
    warned: bool,
}

impl ClockSkewWatch {
    /// Feed one tick's network estimate (the conservative median of the
    /// per-peer skews, over `peers` measurable peers). `None` estimate =
    /// nothing measurable this tick: the streak resets but a raised
    /// warning stays raised (no peers is no evidence the clock healed).
    pub fn observe(&mut self, estimate: Option<i64>, peers: usize) -> Option<SkewVerdict> {
        let Some(skew_ms) = estimate else {
            self.over_ticks = 0;
            return None;
        };
        if skew_ms.abs() >= SKEW_WARN_MS {
            self.over_ticks = self.over_ticks.saturating_add(1);
            if self.over_ticks >= SKEW_WARN_TICKS && !self.warned {
                self.warned = true;
                return Some(SkewVerdict::Warn { skew_ms, peers });
            }
        } else {
            self.over_ticks = 0;
            if self.warned && skew_ms.abs() <= SKEW_CLEAR_MS {
                self.warned = false;
                return Some(SkewVerdict::Clear { skew_ms });
            }
        }
        None
    }
}

/// Evaluate this tick's network clock-skew estimate and emit the diag on a
/// verdict. Called from [`tick`]; split out so the shape stays readable.
fn watch_clock_skew(state: &Arc<NetworkState>) {
    let skews: Vec<i64> = state
        .peers
        .iter()
        .filter(|e| {
            matches!(
                e.value().state.read().status,
                PeerStatus::Active | PeerStatus::Shelved
            )
        })
        .filter_map(|e| e.value().state.read().clock_skew_ms)
        .collect();
    let estimate = median(&skews);
    let verdict = state.clock_skew_watch.lock().observe(estimate, skews.len());
    match verdict {
        Some(SkewVerdict::Warn { skew_ms, peers }) => {
            let secs = skew_ms.abs() as f64 / 1000.0;
            let direction = if skew_ms > 0 { "behind" } else { "ahead of" };
            let msg = if peers >= 2 {
                format!(
                    "this device's clock is ~{secs:.0}s {direction} the rest of the network \
                     ({peers} peers agree) — fleet roster updates, TOTP custody codes and \
                     cross-device timestamps can misbehave; sync this machine's clock (NTP)"
                )
            } else {
                format!(
                    "this device's clock and its only reachable peer's disagree by ~{secs:.0}s \
                     — one of the two is wrong; sync both machines' clocks (NTP)"
                )
            };
            state.log_diag_with(
                crate::events::DiagLevel::Warn,
                "clock",
                msg,
                serde_json::json!({ "skew_ms": skew_ms, "peers": peers }),
            );
        }
        Some(SkewVerdict::Clear { skew_ms }) => {
            state.log_diag_with(
                crate::events::DiagLevel::Info,
                "clock",
                "this device's clock is back in sync with the network".to_string(),
                serde_json::json!({ "skew_ms": skew_ms }),
            );
        }
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_is_conservative_on_even_splits() {
        // Odd: plain median.
        assert_eq!(median(&[60_000, 0, 100]), Some(100));
        // Even: the smaller-magnitude middle — a 2-peer split where only one
        // peer disagrees must NOT read as "our clock is off".
        assert_eq!(median(&[0, 60_000]), Some(0));
        assert_eq!(median(&[-60_000, -50]), Some(-50));
        // Even, both middles genuinely off: still reports off.
        assert_eq!(median(&[58_000, 60_000]), Some(58_000));
        assert_eq!(median(&[]), None);
    }

    #[test]
    fn skew_watch_warns_after_sustained_disagreement_and_latches() {
        let mut w = ClockSkewWatch::default();
        // Two over-threshold ticks: still quiet (a glitch, not a verdict).
        assert_eq!(w.observe(Some(30_000), 3), None);
        assert_eq!(w.observe(Some(31_000), 3), None);
        // Third consecutive: warn once…
        assert_eq!(
            w.observe(Some(29_000), 3),
            Some(SkewVerdict::Warn {
                skew_ms: 29_000,
                peers: 3
            })
        );
        // …and only once (latched, no per-tick spam).
        assert_eq!(w.observe(Some(29_500), 3), None);
        // Dropping under warn but above clear: hysteresis holds the latch.
        assert_eq!(w.observe(Some(7_000), 3), None);
        // Under the clear floor: stand down exactly once.
        assert_eq!(
            w.observe(Some(1_000), 3),
            Some(SkewVerdict::Clear { skew_ms: 1_000 })
        );
        assert_eq!(w.observe(Some(900), 3), None);
    }

    #[test]
    fn skew_watch_streak_resets_on_a_good_tick_or_no_peers() {
        let mut w = ClockSkewWatch::default();
        assert_eq!(w.observe(Some(30_000), 2), None);
        assert_eq!(w.observe(Some(30_000), 2), None);
        // A healthy tick in between resets the streak…
        assert_eq!(w.observe(Some(0), 2), None);
        assert_eq!(w.observe(Some(30_000), 2), None);
        assert_eq!(w.observe(Some(30_000), 2), None);
        // …as does a tick with nothing measurable — and no peers is never
        // evidence the clock healed, so a raised warning would stay raised.
        assert_eq!(w.observe(None, 0), None);
        assert_eq!(w.observe(Some(30_000), 2), None);
        assert_eq!(w.observe(Some(30_000), 2), None);
        assert!(matches!(
            w.observe(Some(30_000), 2),
            Some(SkewVerdict::Warn { .. })
        ));
    }
}
