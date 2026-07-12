//! Acknowledged channel delivery — the engine's queue-until-delivered
//! contract for application frames.
//!
//! The plain send path ([`super::send_to_peer`]) is best-effort by
//! design: "send now or error". Every embedder that needed more built
//! its own retransmit loop on top (a 2 s connect-request beat, presence
//! re-beacons, re-assert-on-reconnect phases). This module is that
//! contract, built once where the connection state actually lives:
//!
//! * **Enqueue any time.** A send to a peer whose link isn't up yet —
//!   or that just dropped — parks in the per-peer outbox instead of
//!   erroring.
//! * **Flush on link-up.** The moment a peer goes ACTIVE the outbox
//!   drains in order. A session rebuild marks in-flight entries unsent,
//!   so they retransmit on the next ACTIVE — the entry, not the caller,
//!   survives the reconnect.
//! * **Exactly-once delivery.** Frames ride a `(stream, seq)` pair;
//!   the receiver drops seqs at or below its high-water mark and acks
//!   cumulatively, so a retransmit can't double-deliver. `stream` is
//!   minted per outbox lifetime, so a daemon restart (fresh seq=1) is
//!   distinguishable from a replay.
//! * **Bounded.** Outboxes cap at [`OUTBOX_CAP`] entries and every
//!   entry carries a TTL ([`DEFAULT_TTL_MS`] unless the caller picks);
//!   expiry resolves the caller's wait with an error instead of
//!   pretending.
//!
//! Peers that don't advertise [`Feature::RELIABLE_CHANNELS`] get the
//! best available degradation: entries still queue until the link is
//! up, then ride a plain `channel` frame — the caller's wait resolves
//! on successful *send* rather than acknowledged *delivery*.
//!
//! Everything here runs on the engine driver task (via the command
//! queue and the state-watch tick), so outbox mutation is serial; the
//! mutexes only guard against snapshot readers.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::oneshot;
use tracing::{debug, trace, warn};

use crate::error::{Error, Result};
use crate::protocol::{features, MeshMessage};

use super::connection::PeerStatus;
use super::state::NetworkState;

/// Default time an entry may wait for acknowledged delivery before its
/// caller is told the truth. Long enough to ride out a reconnect (ICE
/// rebuild lands well inside it), short enough that "the peer is gone"
/// isn't discovered minutes later.
pub const DEFAULT_TTL_MS: u64 = 60_000;

/// Per-peer outbox ceiling. A caller that outruns delivery this far is
/// backpressured with an error instead of growing memory unboundedly.
pub const OUTBOX_CAP: usize = 256;

/// One queued frame awaiting acknowledged delivery.
struct Pending {
    seq: u64,
    channel: String,
    payload: serde_json::Value,
    /// When the entry lapses; expiry resolves `reply` with an error.
    expires_at: Instant,
    /// Whether the frame is on the wire for the *current* session.
    /// Reset to `false` on session rebuild so the retransmit happens.
    sent: bool,
    /// The caller's wait, resolved on ack (or send, for a fallback
    /// peer), TTL expiry, or terminal peer failure.
    reply: Option<oneshot::Sender<Result<()>>>,
}

/// The per-peer send side: one stream id for this outbox's lifetime and
/// the in-order queue of pending entries.
pub(crate) struct Outbox {
    stream: u64,
    next_seq: u64,
    entries: VecDeque<Pending>,
}

impl Outbox {
    fn new() -> Self {
        use rand::Rng;
        Self {
            // Random per outbox lifetime — a daemon restart mints a new
            // stream, which is what lets the receiver treat "seq went
            // backwards" as a reset instead of a replay.
            stream: rand::thread_rng().gen::<u64>() | 1,
            next_seq: 0,
            entries: VecDeque::new(),
        }
    }

    /// Entries currently queued (sent-but-unacked included).
    pub(crate) fn depth(&self) -> usize {
        self.entries.len()
    }
}

/// Receiver-side high-water mark for one peer's inbound stream.
#[derive(Clone, Copy, Default)]
pub(crate) struct InboundMark {
    stream: u64,
    last_seq: u64,
}

/// Queue a frame for acknowledged delivery to `peer`, then try to flush
/// immediately (a no-op if the link isn't up — the ACTIVE transition
/// and the state-watch tick pick it up later).
pub(crate) async fn enqueue(
    state: &Arc<NetworkState>,
    peer: &str,
    channel: &str,
    payload: serde_json::Value,
    ttl_ms: Option<u64>,
    reply: oneshot::Sender<Result<()>>,
) {
    {
        let mut out = state.reliable_out.lock();
        let outbox = out.entry(peer.to_string()).or_insert_with(Outbox::new);
        if outbox.entries.len() >= OUTBOX_CAP {
            drop(out);
            let _ = reply.send(Err(Error::Transport(format!(
                "reliable outbox for {peer} is full ({OUTBOX_CAP} frames pending)"
            ))));
            return;
        }
        outbox.next_seq += 1;
        let seq = outbox.next_seq;
        let ttl = Duration::from_millis(ttl_ms.unwrap_or(DEFAULT_TTL_MS));
        outbox.entries.push_back(Pending {
            seq,
            channel: channel.to_string(),
            payload,
            expires_at: Instant::now() + ttl,
            sent: false,
            reply: Some(reply),
        });
    }
    flush_peer(state, peer).await;
}

/// Whether `peer`'s link can carry frames right now, and whether it
/// speaks the acked contract. `None` = not sendable yet.
fn link_ready(state: &Arc<NetworkState>, peer: &str) -> Option<bool> {
    let entry = state.peers.get(peer)?;
    let data = entry.state.read();
    let up = matches!(data.status, PeerStatus::Active | PeerStatus::Shelved)
        && data.data_channel_open;
    if !up {
        return None;
    }
    Some(features::peer_supports(
        &data.features,
        features::Feature::RELIABLE_CHANNELS,
    ))
}

/// Drain `peer`'s unsent entries onto the wire, in order. Safe to call
/// any time; does nothing when the link is down. Called on the ACTIVE
/// transition, after each enqueue, on inbound acks, and from the
/// state-watch tick.
pub(crate) async fn flush_peer(state: &Arc<NetworkState>, peer: &str) {
    let Some(acked_peer) = link_ready(state, peer) else {
        return;
    };

    // Collect what needs sending without holding the lock across awaits.
    let (stream, to_send): (u64, Vec<(u64, String, serde_json::Value)>) = {
        let mut out = state.reliable_out.lock();
        let Some(outbox) = out.get_mut(peer) else {
            return;
        };
        let stream = outbox.stream;
        let batch: Vec<_> = outbox
            .entries
            .iter()
            .filter(|p| !p.sent)
            .map(|p| (p.seq, p.channel.clone(), p.payload.clone()))
            .collect();
        (stream, batch)
    };
    if to_send.is_empty() {
        return;
    }

    for (seq, channel, payload) in to_send {
        let msg = if acked_peer {
            MeshMessage::ChannelSeq {
                stream,
                seq,
                channel: channel.clone(),
                payload: payload.clone(),
            }
        } else {
            // Fallback peer: plain frame, no ack coming. The entry
            // resolves on send success below.
            MeshMessage::Channel {
                channel: channel.clone(),
                payload: payload.clone(),
            }
        };
        match super::send_to_peer(state, peer, &msg).await {
            Ok(()) => {
                let mut out = state.reliable_out.lock();
                let Some(outbox) = out.get_mut(peer) else { return };
                if acked_peer {
                    if let Some(p) = outbox.entries.iter_mut().find(|p| p.seq == seq) {
                        p.sent = true;
                    }
                } else {
                    // Best-effort degradation: sent == delivered as far
                    // as we can ever know for this peer.
                    if let Some(pos) = outbox.entries.iter().position(|p| p.seq == seq) {
                        if let Some(reply) = outbox.entries.remove(pos).and_then(|p| p.reply) {
                            let _ = reply.send(Ok(()));
                        }
                    }
                }
            }
            Err(e) => {
                // Link wobbled mid-flush — leave the entry unsent; the
                // tick or the next ACTIVE retries. In-order delivery
                // means we stop rather than skip ahead.
                trace!(peer = %super::short_peer(peer), "reliable flush paused: {e}");
                break;
            }
        }
    }
}

/// Inbound `channel_seq`: deliver exactly once, ack cumulatively.
pub(crate) async fn on_channel_seq(
    state: &Arc<NetworkState>,
    peer: &str,
    stream: u64,
    seq: u64,
    channel: String,
    payload: serde_json::Value,
) {
    let deliver = {
        let mut marks = state.reliable_in.lock();
        let mark = marks.entry(peer.to_string()).or_default();
        if mark.stream != stream {
            // New outbox lifetime on the sender (restart) — adopt it.
            *mark = InboundMark {
                stream,
                last_seq: 0,
            };
        }
        if seq <= mark.last_seq {
            false // duplicate of something we already delivered
        } else {
            mark.last_seq = seq;
            true
        }
    };
    if deliver {
        super::on_channel_frame(state, peer, channel, payload).await;
    }
    // Ack our high-water mark either way — a duplicate usually means
    // our previous ack was lost, and re-acking is what stops the
    // retransmits.
    let up_to = state
        .reliable_in
        .lock()
        .get(peer)
        .map(|m| m.last_seq)
        .unwrap_or(seq);
    if let Err(e) =
        super::send_to_peer(state, peer, &MeshMessage::ChannelAck { stream, up_to }).await
    {
        trace!(peer = %super::short_peer(peer), "channel_ack send failed: {e}");
    }
}

/// Inbound cumulative ack: resolve and drop every entry of `stream`
/// with `seq <= up_to`.
pub(crate) fn on_channel_ack(state: &NetworkState, peer: &str, stream: u64, up_to: u64) {
    let resolved: Vec<oneshot::Sender<Result<()>>> = {
        let mut out = state.reliable_out.lock();
        let Some(outbox) = out.get_mut(peer) else {
            return;
        };
        if outbox.stream != stream {
            // Ack for a previous outbox lifetime — nothing it can settle.
            return;
        }
        let mut done = Vec::new();
        while let Some(front) = outbox.entries.front() {
            if front.seq > up_to {
                break;
            }
            if let Some(reply) = outbox.entries.pop_front().and_then(|p| p.reply) {
                done.push(reply);
            }
        }
        if outbox.entries.is_empty() {
            out.remove(peer);
        }
        done
    };
    for reply in resolved {
        let _ = reply.send(Ok(()));
    }
}

/// Session rebuild for `peer`: everything on the wire for the old
/// session may or may not have landed — mark it unsent so the next
/// ACTIVE retransmits, and let the receiver's high-water mark absorb
/// any double.
pub(crate) fn mark_unsent(state: &NetworkState, peer: &str) {
    let mut out = state.reliable_out.lock();
    if let Some(outbox) = out.get_mut(peer) {
        for p in outbox.entries.iter_mut() {
            p.sent = false;
        }
    }
}

/// Terminal failure for `peer` (denied, auth failure, deliberate
/// removal): the queue has no future — resolve every pending wait with
/// the reason and drop the outbox.
pub(crate) fn fail_peer(state: &NetworkState, peer: &str, reason: &str) {
    let entries: Vec<Pending> = {
        let mut out = state.reliable_out.lock();
        match out.remove(peer) {
            Some(outbox) => outbox.entries.into_iter().collect(),
            None => return,
        }
    };
    let n = entries.len();
    for p in entries {
        if let Some(reply) = p.reply {
            let _ = reply.send(Err(Error::Transport(format!(
                "reliable send to {peer} abandoned: {reason}"
            ))));
        }
    }
    if n > 0 {
        debug!(peer = %super::short_peer(peer), dropped = n, reason, "reliable outbox abandoned");
    }
}

/// State-watch tick: expire lapsed entries (their callers get an error,
/// not silence) and re-attempt flushes for peers holding unsent frames.
pub(crate) async fn tick(state: &Arc<NetworkState>) {
    let now = Instant::now();
    // Expiry pass.
    let mut expired: Vec<(String, oneshot::Sender<Result<()>>)> = Vec::new();
    let mut flush_candidates: Vec<String> = Vec::new();
    {
        let mut out = state.reliable_out.lock();
        out.retain(|peer, outbox| {
            let mut i = 0;
            while i < outbox.entries.len() {
                if outbox.entries[i].expires_at <= now {
                    if let Some(p) = outbox.entries.remove(i) {
                        if let Some(reply) = p.reply {
                            expired.push((peer.clone(), reply));
                        }
                    }
                } else {
                    i += 1;
                }
            }
            if outbox.entries.iter().any(|p| !p.sent) {
                flush_candidates.push(peer.clone());
            }
            !outbox.entries.is_empty()
        });
    }
    for (peer, reply) in expired {
        warn!(peer = %super::short_peer(&peer), "reliable send expired before delivery");
        let _ = reply.send(Err(Error::Transport(format!(
            "reliable send to {peer} expired before delivery"
        ))));
    }
    for peer in flush_candidates {
        flush_peer(state, &peer).await;
    }
}

/// Total frames awaiting delivery across all peers — surfaced in the
/// network's traffic/status snapshot.
pub(crate) fn pending_total(state: &NetworkState) -> usize {
    state.reliable_out.lock().values().map(Outbox::depth).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{build_test_state, insert_session_less_peer};

    fn recv_now(rx: &mut oneshot::Receiver<Result<()>>) -> Option<Result<()>> {
        rx.try_recv().ok()
    }

    #[tokio::test]
    async fn enqueue_parks_when_link_is_down_and_expires_on_tick() {
        let state = build_test_state("rel-park");
        let (tx, mut rx) = oneshot::channel();
        enqueue(
            &state,
            "peer-a",
            "app.control",
            serde_json::json!({"n": 1}),
            Some(0), // expire immediately on the next tick
            tx,
        )
        .await;
        assert_eq!(pending_total(&state), 1, "entry parked, nothing to send to");
        assert!(recv_now(&mut rx).is_none(), "caller still waiting");

        tick(&state).await;
        assert_eq!(pending_total(&state), 0, "expired entry removed");
        match recv_now(&mut rx) {
            Some(Err(_)) => {}
            other => panic!("expected expiry error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn outbox_cap_backpressures() {
        let state = build_test_state("rel-cap");
        for _ in 0..OUTBOX_CAP {
            let (tx, _rx) = oneshot::channel();
            enqueue(&state, "peer-a", "c", serde_json::json!(1), None, tx).await;
        }
        let (tx, mut rx) = oneshot::channel();
        enqueue(&state, "peer-a", "c", serde_json::json!(1), None, tx).await;
        match recv_now(&mut rx) {
            Some(Err(e)) => assert!(e.to_string().contains("full"), "got: {e}"),
            other => panic!("expected outbox-full error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inbound_dedup_delivers_once_and_reacks() {
        let state = build_test_state("rel-dedup");
        insert_session_less_peer(&state, "peer-b", None);
        // First delivery: routes to the channel layer and records seq 1.
        on_channel_seq(&state, "peer-b", 7, 1, "c".into(), serde_json::json!(1)).await;
        {
            let marks = state.reliable_in.lock();
            let m = marks.get("peer-b").copied().unwrap();
            assert_eq!(m.last_seq, 1);
        }
        // Duplicate: high-water mark unchanged (no double delivery).
        on_channel_seq(&state, "peer-b", 7, 1, "c".into(), serde_json::json!(1)).await;
        assert_eq!(state.reliable_in.lock().get("peer-b").unwrap().last_seq, 1);
        // New stream (sender restarted): mark resets and seq 1 delivers.
        on_channel_seq(&state, "peer-b", 9, 1, "c".into(), serde_json::json!(2)).await;
        let m = *state.reliable_in.lock().get("peer-b").unwrap();
        assert_eq!((m.stream, m.last_seq), (9, 1));
    }

    #[tokio::test]
    async fn ack_resolves_callers_in_order() {
        let state = build_test_state("rel-ack");
        let (tx1, mut rx1) = oneshot::channel();
        let (tx2, mut rx2) = oneshot::channel();
        enqueue(&state, "peer-a", "c", serde_json::json!(1), None, tx1).await;
        enqueue(&state, "peer-a", "c", serde_json::json!(2), None, tx2).await;
        let stream = state.reliable_out.lock().get("peer-a").unwrap().stream;

        on_channel_ack(&state, "peer-a", stream, 1);
        assert!(matches!(recv_now(&mut rx1), Some(Ok(()))), "seq 1 acked");
        assert!(recv_now(&mut rx2).is_none(), "seq 2 still pending");

        on_channel_ack(&state, "peer-a", stream, 2);
        assert!(matches!(recv_now(&mut rx2), Some(Ok(()))), "seq 2 acked");
        assert_eq!(pending_total(&state), 0, "outbox drained and removed");
    }

    #[tokio::test]
    async fn stale_stream_ack_settles_nothing() {
        let state = build_test_state("rel-stale-ack");
        let (tx, mut rx) = oneshot::channel();
        enqueue(&state, "peer-a", "c", serde_json::json!(1), None, tx).await;
        let stream = state.reliable_out.lock().get("peer-a").unwrap().stream;
        on_channel_ack(&state, "peer-a", stream.wrapping_add(1), 1);
        assert!(recv_now(&mut rx).is_none(), "wrong-stream ack ignored");
        assert_eq!(pending_total(&state), 1);
    }

    #[tokio::test]
    async fn rebuild_marks_entries_for_retransmit_and_terminal_failure_resolves() {
        let state = build_test_state("rel-rebuild");
        let (tx, mut rx) = oneshot::channel();
        enqueue(&state, "peer-a", "c", serde_json::json!(1), None, tx).await;
        {
            let mut out = state.reliable_out.lock();
            out.get_mut("peer-a").unwrap().entries[0].sent = true;
        }
        mark_unsent(&state, "peer-a");
        assert!(
            !state.reliable_out.lock().get("peer-a").unwrap().entries[0].sent,
            "rebuild resets in-flight entries for retransmit"
        );

        fail_peer(&state, "peer-a", "denied");
        match recv_now(&mut rx) {
            Some(Err(e)) => assert!(e.to_string().contains("denied")),
            other => panic!("expected terminal failure, got {other:?}"),
        }
        assert_eq!(pending_total(&state), 0);
    }
}
