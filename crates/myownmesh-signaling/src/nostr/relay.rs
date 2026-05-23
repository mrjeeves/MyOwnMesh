//! Per-relay WebSocket lifecycle. One `Relay` task per configured URL;
//! the room layer multiplexes signaling messages across the active
//! relays.
//!
//! Reconnect behavior bakes in the upstream-Trystero fixes from
//! [`crate::upstream`]:
//!
//! - **Subscription replay (item 1):** outgoing `["REQ", subId, …]` /
//!   `["CLOSE", subId]` are tracked per socket. On every `onopen`
//!   after the first, all active REQ messages are replayed under
//!   the anti-flood schedule [`crate::upstream::RESUBSCRIBE_BACKOFF_MS`].
//!
//! - **State-transition logging (item 5):** the relay emits structured
//!   diag entries only on lifecycle transitions and stuck thresholds.
//!   Per-EVENT logs are suppressed by default.
//!
//! v1 here ships the supporting types and constants; the concrete
//! tokio_tungstenite driver lands when the transport layer in
//! `myownmesh-core::transport` is wired up.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::upstream::{BACKOFF_RESET_AFTER_MS, RESUBSCRIBE_BACKOFF_MS};

/// Tracks the active Nostr REQ subscriptions on a single WebSocket
/// and replays them on reconnect with anti-flood backoff. See
/// `myownmesh-signaling::upstream` item 1.
///
/// Threading: this struct is intended to live inside the relay's
/// per-socket task; no external synchronization needed.
#[derive(Debug, Default)]
pub struct SubscriptionReplay {
    /// Active subscription frames keyed by Nostr subscription id.
    /// Stored verbatim so we can re-send the exact bytes the peer
    /// originally subscribed with.
    active: HashMap<String, String>,
    /// Reconnect attempts since last full reset.
    attempt: usize,
    /// Wall-clock instant of the last replay we executed.
    last_replay_at: Option<Instant>,
    /// True once the socket has had at least one successful open —
    /// the first open isn't a "reconnect" and doesn't replay.
    has_opened_once: bool,
}

impl SubscriptionReplay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inspect an outgoing wire frame and update the tracked
    /// subscription set. Returns the frame untouched — call sites
    /// pass the result to the actual socket. Non-JSON frames pass
    /// through silently.
    pub fn observe_send<'a>(&mut self, frame: &'a str) -> &'a str {
        if frame.starts_with('[') {
            if let Ok(parsed) = serde_json::from_str::<Vec<serde_json::Value>>(frame) {
                if let (Some(tag), Some(sub_id)) = (
                    parsed.first().and_then(|v| v.as_str()),
                    parsed.get(1).and_then(|v| v.as_str()),
                ) {
                    match tag {
                        "REQ" => {
                            self.active.insert(sub_id.to_string(), frame.to_string());
                        }
                        "CLOSE" => {
                            self.active.remove(sub_id);
                        }
                        _ => {}
                    }
                }
            }
        }
        frame
    }

    /// Mark the socket as freshly open. Returns the subscription
    /// frames to replay (zero on the first open) and the next-eligible
    /// delay before *another* replay may run. Caller schedules the
    /// send and the delay according to its own timer.
    pub fn on_open(&mut self) -> ReplayDecision {
        if !self.has_opened_once {
            self.has_opened_once = true;
            return ReplayDecision::nothing();
        }
        // If we've been quiet past the reset threshold, the next
        // replay starts from index 0 again. Otherwise the index
        // climbs each time so a flapping socket caps at the longest
        // backoff.
        if let Some(last) = self.last_replay_at {
            if last.elapsed() > Duration::from_millis(BACKOFF_RESET_AFTER_MS) {
                self.attempt = 0;
            }
        }
        let idx = self.attempt.min(RESUBSCRIBE_BACKOFF_MS.len() - 1);
        let delay_ms = RESUBSCRIBE_BACKOFF_MS[idx];

        if self.active.is_empty() {
            return ReplayDecision::nothing();
        }

        // Decide whether to replay immediately or wait the remainder
        // of the backoff. The first reconnect (attempt == 0) replays
        // immediately so a clean blip recovers fast.
        let now = Instant::now();
        let must_wait = match self.last_replay_at {
            None => Duration::ZERO,
            Some(last) => Duration::from_millis(delay_ms).saturating_sub(now - last),
        };

        let frames: Vec<String> = self.active.values().cloned().collect();
        self.attempt += 1;
        ReplayDecision {
            frames,
            wait: must_wait,
            attempt: self.attempt,
            next_eligible_in: Duration::from_millis(delay_ms),
        }
    }

    /// Called by the relay task after it actually sends a replay.
    /// Updates the `last_replay_at` watermark used by future backoff
    /// decisions.
    pub fn record_replay(&mut self) {
        self.last_replay_at = Some(Instant::now());
    }

    /// Active REQ count — surfaced in diag logs.
    pub fn active_count(&self) -> usize {
        self.active.len()
    }
}

/// Returned by [`SubscriptionReplay::on_open`]. Empty `frames` means
/// "nothing to replay right now"; non-empty means "send these,
/// possibly after `wait`".
#[derive(Debug, Clone)]
pub struct ReplayDecision {
    pub frames: Vec<String>,
    /// How long to wait before sending. Zero = send now.
    pub wait: Duration,
    pub attempt: usize,
    /// After this replay lands, the soonest a future replay may
    /// run. Logged for observability.
    pub next_eligible_in: Duration,
}

impl ReplayDecision {
    fn nothing() -> Self {
        Self {
            frames: Vec::new(),
            wait: Duration::ZERO,
            attempt: 0,
            next_eligible_in: Duration::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_send_tracks_req_and_close() {
        let mut r = SubscriptionReplay::new();
        r.observe_send(r#"["REQ","sub1",{"kinds":[1]}]"#);
        r.observe_send(r#"["REQ","sub2",{"kinds":[2]}]"#);
        assert_eq!(r.active_count(), 2);
        r.observe_send(r#"["CLOSE","sub1"]"#);
        assert_eq!(r.active_count(), 1);
    }

    #[test]
    fn observe_send_ignores_event_frames() {
        let mut r = SubscriptionReplay::new();
        r.observe_send(r#"["EVENT",{"id":"abc"}]"#);
        assert_eq!(r.active_count(), 0);
    }

    #[test]
    fn observe_send_ignores_non_json() {
        let mut r = SubscriptionReplay::new();
        r.observe_send("not json");
        r.observe_send("");
        assert_eq!(r.active_count(), 0);
    }

    #[test]
    fn first_open_does_not_replay() {
        let mut r = SubscriptionReplay::new();
        r.observe_send(r#"["REQ","sub1",{}]"#);
        let dec = r.on_open();
        assert!(dec.frames.is_empty());
    }

    #[test]
    fn second_open_replays_active_subs() {
        let mut r = SubscriptionReplay::new();
        r.observe_send(r#"["REQ","sub1",{}]"#);
        let _ = r.on_open(); // first
        let dec = r.on_open(); // second
        assert_eq!(dec.frames.len(), 1);
        assert_eq!(dec.attempt, 1);
    }

    #[test]
    fn open_with_no_subs_replays_nothing() {
        let mut r = SubscriptionReplay::new();
        let _ = r.on_open();
        let dec = r.on_open();
        assert!(dec.frames.is_empty());
    }
}
