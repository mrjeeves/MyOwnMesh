//! Room multiplex. v1 here ships the wire-level constants and
//! placeholder types; the concrete tokio_tungstenite driver lands
//! when the transport layer in `myownmesh-core::transport` is in
//! place.
//!
//! Design notes (preserved from MyOwnLLM's mesh-client.svelte.ts +
//! patches):
//!
//! - Presence-announce cadence: [`crate::upstream::ANNOUNCE_INTERVAL_MS`]
//!   (5333 ms). Warmup uses shorter intervals
//!   ([`ANNOUNCE_WARMUP_INTERVALS_MS`]) so the first peer discovery
//!   happens fast.
//! - Disconnected grace: [`crate::upstream::DISCONNECTED_PEER_GRACE_MS`].
//! - Inbound-recency staleness clearing:
//!   [`crate::upstream::STALE_INBOUND_MS`] — see upstream item 3.
//! - Offer-pool flush on peer drop: throttled by
//!   [`crate::upstream::OFFER_POOL_FLUSH_THROTTLE_MS`] — see item 4.

/// Warmup announce schedule. Sequential delays after `joinRoom`
/// before settling into the steady-state interval. Matches
/// Trystero's `announceWarmupIntervalsMs`.
pub const ANNOUNCE_WARMUP_INTERVALS_MS: &[u64] = &[500, 1_500, 3_000];
