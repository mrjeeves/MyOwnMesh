//! Catalogue of upstream-Trystero limitations our Nostr implementation
//! addresses natively. Each entry corresponds to a fix in MyOwnLLM's
//! `patches/@trystero-p2p__core@0.24.0.patch` — we bake them into the
//! design here so there's nothing to patch.
//!
//! This module is documentation-only. New entries land here when a
//! production trace reveals an upstream bug; the corresponding fix
//! is implemented in [`super::nostr`] or in the mesh engine's
//! reconnection logic.
//!
//! # 1. Subscription replay on WebSocket reconnect
//!
//! **Problem:** Nostr relays drop subscription state when the WebSocket
//! closes (per-spec). Trystero v0.24.0's `makeSocket` transparently
//! reconnects but calls the strategy's `subscribe()` exactly once at
//! room init. After a network swap (e.g. wifi → hotspot) the new
//! sockets reopen but the relay has no record of our REQs; the socket
//! shows `readyState === 1` and outbound publishes succeed, yet zero
//! inbound EVENTs arrive. Natural re-handshake stalls for ~90s until
//! `forceRediscovery` fires a full room rebuild.
//!
//! **Our fix:** Every fresh socket session sends its room REQ as the
//! first thing it does (`run_relay_session`) — subscription state can
//! never outlive the socket it was opened on, so there is nothing to
//! "replay" and nothing to forget. Flood control lives at the one
//! layer that owns reconnection: the owner-configured per-socket dial
//! backoff in `run_relay`, with owner-configured jitter. An earlier design carried a
//! separate REQ-level anti-flood schedule (`SubscriptionReplay`); it
//! was redundant with the socket backoff — a REQ is only ever sent
//! when a socket was just established, which the backoff already
//! paces — and was removed so reconnect pacing has exactly one owner.
//!
//! # 2. Treat `ICE-disconnected` as transient
//!
//! **Problem:** The WebRTC data channel can linger at `readyState ===
//! "open"` for 15-30s after a peer's network actually vanishes. During
//! that window upstream's `getConnectedPeerHealth` returns `"live"`,
//! which makes the signal handler early-return on every announce from
//! the recovered peer and blocks re-handshake on the side that didn't
//! itself swap networks.
//!
//! **Our fix:** In the transport layer (`myownmesh-core::transport`),
//! the per-peer health check treats `connectionState == disconnected`
//! as transient and starts the 7.5s grace window immediately rather
//! than waiting for ICE consent freshness to fail.
//!
//! # 3. Inbound-recency-based zombie clearing
//!
//! **Problem:** Even with (2) above, ICE consent freshness can take
//! 15-30s to flip state, and the 7.5s grace adds more on top. Total
//! stuck-time can hit 20-40s before the engine clears a zombie.
//!
//! **Our fix:** The signal handler tracks the timestamp of the last
//! inbound signaling message per peer. If a fresh announce arrives
//! and the prior gap exceeds the network's checked stale-inbound policy,
//! the previous connection is treated as a zombie regardless of
//! reported `connectionState`. Mesh-level identity validation (the
//! ed25519 auth_response over both pubkeys + nonce) authenticates
//! the new handshake — no grace window needed at the signaling layer.
//!
//! The engine owns the threshold as a checked per-network scheduler policy;
//! the signaling crate supplies no process-wide staleness fallback.
//!
//! Historical offer-pool note: the current engine does not retain a
//! production offer-pool flush timer.
//!
//! # 5. State-transition logging
//!
//! **Problem:** Trystero's default tracing emits one log per announce
//! per relay (5 relays × 5.333s = 1 log per second per peer), which
//! swamps the console and hides actual problems.
//!
//! **Our fix:** Emit log/diag events only on lifecycle transitions
//! (`fresh → offering → connected → disconnected → recovering`) and
//! on stuck thresholds (15s / 30s / 60s of waiting for an answer).
//! Raw per-event logs are suppressed by default.
//!
//! # 6. Cross-relay event deduplication
//!
//! **Problem:** A peer publishes one Nostr event (announce / offer /
//! answer / candidate) but every relay subscribed by both ends
//! delivers it once — so the engine receives N copies of the same
//! event, where N is the redundancy count (typically 4-5). For
//! announces this is cosmetic spam in the log. For Offer / Answer
//! it is **functional**: WebRTC's `RTCPeerConnection::set_remote_description`
//! is not idempotent — applying the same SDP twice once the
//! signaling state has advanced wedges the connection at
//! `Stable → HaveRemoteOffer` and ICE never starts. Peers reach
//! `Sighted` and never advance — the exact "they just sit there"
//! symptom users hit in the field.
//!
//! **Where it is fixed now:** not here. The driver used to keep a bounded
//! ring of inbound event ids and drop the second relay's copy at the driver
//! boundary, which was the wrong layer twice over: the id was recorded before
//! the value was parsed and before it was offered onward, and the offer's
//! result was thrown away — so a copy the consumer refused under pressure left
//! its id behind and the retransmission that would have rescued the attempt was
//! dropped as already seen. Neither copy reached the engine.
//!
//! De-duplication has one owner now, downstream in `engine::signaling_ingress`,
//! which commits a key only after the value has been accepted and scopes that
//! key to the exact connection attempt it describes. The ring here, and the
//! capacity constant that sized it, are deleted rather than moved: two layers
//! holding the same policy is how the refusal-poisoning survived the first fix.
//!
//! # 7. Adaptive announce cadence
//!
//! **Problem:** Trystero's flat 5.333s announce interval makes
//! new-peer discovery snappy at startup, but two devices that
//! never grow their mesh keep
//! pinging at the same rate forever — one line per peer per ~5s
//! in the Activity log, indefinitely. Discovery latency drops at
//! the cost of long-term log + relay traffic, and the trade-off
//! is fixed.
//!
//! **Also a separate bug**: each relay session ran its own
//! `tokio::time::interval`, so an N-relay setup fired N
//! independent announce events per cycle (different timestamps →
//! different sha256 ids → not deduped by item 6). With N=5, the
//! room saw 5× the intended publish rate.
//!
//! **Our fix:** A single global announcer task per driver instance
//! runs the schedule in [`ANNOUNCE_BACKOFF_MS`]: an immediate
//! announce at startup, one 30s safety-net re-announce (catching a
//! silently-failed first publish), then steady-state at
//! [`ANNOUNCE_STEADY_MS`] (120s, jittered ±15% per node). Per-relay
//! timers go away; each tick publishes once via the shared broadcast
//! channel and every connected relay writes the same event from its
//! existing publish-pump. Discovery latency doesn't ride this
//! schedule at all anymore: stored-kind replay (item 8) hands a late
//! joiner every existing peer instantly, and the engine's reactive
//! announce reflection answers a joiner within ~1s.
//!
//! # 8. Presence is stored; connection negotiation is ephemeral
//!
//! **Problem:** Moving all signaling to a stored Nostr kind (1077,
//! item 7) fixed discovery — a late joiner gets every peer's last
//! announce on REQ replay — but it dragged offer / answer / candidate
//! onto the same stored-and-replayed channel. SDP carries
//! session-specific ICE credentials (ufrag/pwd) bound to one live
//! `RTCPeerConnection`. On any fresh subscribe the relay replays the
//! whole `since` window, so a *previous session's* offer/answer is
//! delivered again, the engine applies it as the remote description,
//! and the new PeerConnection is bound to dead credentials. ICE checks
//! never match; the peer reaches `Sighted` and never advances until
//! the stale event ages out of the window (minutes later). Item 6's
//! event-ID dedup doesn't help — a prior session's event has a
//! legitimately distinct id. This is the "they see each other a lot
//! but never actually connect" field symptom, and it is why adding a
//! TURN relay couldn't help: the relay candidates were just as stale.
//!
//! **Our fix:** Split the wire by message class.
//! [`super::nostr::event::SIGNALING_EVENT_KIND`] (stored) carries
//! presence only; offer / answer / candidate go on
//! [`super::nostr::event::SIGNALING_EPHEMERAL_KIND`] in the NIP-01
//! ephemeral range, which relays forward live but never persist.
//! Negotiation can no longer be replayed onto a future session, so a
//! reconnect is always driven by a *live* offer (the engine's reactive
//! announce reflection still triggers it within ~1s). The receive
//! path enforces the split: an Announce is honoured only on the stored
//! kind, an offer/answer/candidate only on the ephemeral kind — so any
//! stale directed message replayed from history (or from a pre-split
//! build) is dropped at the driver boundary instead of poisoning a
//! handshake. Presence persists; the connection is always live.
//!
//! Constant: [`PRESENCE_REPLAY_WINDOW_SECS`].
//!
//! # 9. Recipient-tagged negotiation (room-wide O(N²) → O(N))
//!
//! **Problem:** The room subscription had no recipient constraint, so
//! every directed offer / answer / candidate was delivered to *every*
//! subscriber in the room and filtered client-side against the
//! envelope's `to`. Per pairwise negotiation that is N−2 wasted
//! deliveries; during a join wave where many pairs negotiate at once,
//! relay fan-out grows with the square of the room size — the "the
//! bigger the network, the worse it runs" cost lived here.
//!
//! **Our fix:** Directed ephemeral events carry a `["p", device_id]`
//! tag naming their recipient, and each peer's REQ carries two
//! filters: presence, and `#p`-is-me negotiation. The relay never
//! fans a pairwise negotiation to a bystander. The envelope's `to`
//! check remains as the receive-side backstop.
//!
//! **What was removed with it.** An earlier revision advertised the
//! capability in the announce and kept a third, room-wide catch-all
//! filter until every announced peer had claimed it. The bookkeeping
//! was an unbounded map keyed on unauthenticated announce ids, so one
//! sender could hold the catch-all on for the whole room — an
//! amplification lever and an unbounded allocation on the same map.
//! The hard-alpha cutover has no pre-tag peer to interoperate with, so
//! the negotiation is deleted rather than capped.
//!
//! Implementation: `desired_filters` in [`super::nostr::driver`].

/// Adaptive announce schedule — see `upstream.rs` item 7.
///
/// Each entry is the wait (ms) before the NEXT announce, given how
/// many we've already fired. Index = post-first announce count;
/// once exhausted, all subsequent waits use [`ANNOUNCE_STEADY_MS`].
///
/// Curve:
///   - announce 1 fires at t=0 (daemon startup)
///   - announce 2 fires at t=30s (safety net for a silently-failed
///     first publish)
///   - announces 3+ fire on the 2-minute steady tick
///
/// Rationale: with stored-kind signaling (kind 1077, see
/// `nostr::event::SIGNALING_EVENT_KIND`) and engine-side reactive
/// reflection on every inbound announce, the dense early schedule
/// the ephemeral-kind era required is now redundant. A late joiner
/// receives every existing peer's most recent announce on REQ
/// replay; existing peers re-announce within ~1s of seeing the
/// joiner's announce; per-relay open-announce in
/// `nostr::driver::run_relay_inner` covers freshly-(re)connected
/// relays. The remaining role of the periodic announce is just to
/// refresh storage well inside any reasonable relay retention
/// window — two minutes is still conservative against public relays
/// that retain regular events for hours to days, while keeping a
/// peer's presence fresh enough that a node which dropped and came
/// back (laptop sleep/wake) is rediscovered within one short cycle.
/// The 30s safety net still catches a silently-failed first publish
/// at startup.
pub const ANNOUNCE_BACKOFF_MS: &[u64] = &[30_000];

/// Steady-state announce cadence, used once
/// [`ANNOUNCE_BACKOFF_MS`] is exhausted. Sized to refresh relay
/// storage well inside typical retention while keeping presence
/// fresh enough for fast rediscovery after a drop; see the comment
/// on [`ANNOUNCE_BACKOFF_MS`] for the full rationale.
pub const ANNOUNCE_STEADY_MS: u64 = 120_000;

/// How far back the room subscription's `since` reaches when (re)
/// opening a REQ — see item 8. Replays the last few minutes of
/// **presence** so a late joiner discovers everyone already here.
/// It governs presence only: connection negotiation rides the
/// ephemeral kind ([`super::nostr::event::SIGNALING_EPHEMERAL_KIND`])
/// which relays never store, so there's nothing to replay for it.
/// Matched to [`ANNOUNCE_STEADY_MS`] (120s) so the window is exactly
/// one steady heartbeat — every present peer has re-announced at
/// least once inside it.
pub const PRESENCE_REPLAY_WINDOW_SECS: u64 = 120;
