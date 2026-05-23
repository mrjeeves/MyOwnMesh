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
//! **Our fix:** Track outgoing `["REQ", subId, …]` / `["CLOSE", subId]`
//! per relay socket. On every `onopen` *after the first*, replay the
//! active REQs. Anti-flood schedule: 5s / 10s / 15s / 30s / 60s (sticky
//! at 60s), reset after 60s of quiet so a long-stable connection that
//! finally blips doesn't pay the cap.
//!
//! Implementation: [`super::nostr::relay::SubscriptionReplay`].
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
//! and the prior gap exceeds 25s (~5× the 5.333s announce cadence),
//! the previous connection is treated as a zombie regardless of
//! reported `connectionState`. Mesh-level identity validation (the
//! ed25519 auth_response over both pubkeys + nonce) authenticates
//! the new handshake — no grace window needed at the signaling layer.
//!
//! Constant: [`STALE_INBOUND_MS`] (25,000 ms).
//!
//! # 4. Flush stale offer pool on peer drop
//!
//! **Problem:** Trystero pre-warms a pool of WebRTC offers (with
//! gathered ICE candidates). After a local network change, every
//! pre-cached offer has stale candidates — the remote will ICE-check
//! our old IP, fail, and never respond.
//!
//! **Our fix:** On any peer drop, drain the offer pool so the next
//! checkout allocates a fresh peer with current candidates. Throttled
//! to once per 10s so a wave of drops doesn't hammer the gatherer.
//!
//! Constant: [`OFFER_POOL_FLUSH_THROTTLE_MS`] (10,000 ms).
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

/// Inbound-message staleness threshold for zombie clearing — see
/// item 3. Picked at ~5× Trystero's 5.333s announce cadence, well
/// above any single-relay blip after the subscription-replay fix.
pub const STALE_INBOUND_MS: u64 = 25_000;

/// Minimum time between offer-pool flushes — see item 4. A wave
/// of peer drops within this window collapses to one flush.
pub const OFFER_POOL_FLUSH_THROTTLE_MS: u64 = 10_000;

/// Anti-flood schedule for subscription replays after socket
/// reconnect — see item 1. Indices saturate at the last value;
/// reset after [`BACKOFF_RESET_AFTER_MS`] of quiet.
pub const RESUBSCRIBE_BACKOFF_MS: &[u64] = &[5_000, 10_000, 15_000, 30_000, 60_000];

/// Quiet period after which the resubscribe backoff index resets
/// to 0. Picked at the max backoff so a long-stable socket doesn't
/// pay the cap on the next blip.
pub const BACKOFF_RESET_AFTER_MS: u64 = 60_000;

/// Disconnected-peer grace window before the engine tears down the
/// connection. Matches Trystero's `disconnectedPeerGraceMs`.
pub const DISCONNECTED_PEER_GRACE_MS: u64 = 7_500;

/// Periodic presence-announce cadence. Matches Trystero's
/// `announceIntervalMs`.
pub const ANNOUNCE_INTERVAL_MS: u64 = 5_333;
