//! Nostr signaling. Wire-compatible with upstream Trystero on the
//! relay shuffle and room-handle derivation.
//!
//! Implementation lands across:
//! - [`relay`] — per-relay WebSocket lifecycle, REQ/EVENT framing,
//!   subscription-replay-on-reconnect (see
//!   [`crate::upstream`] item 1).
//! - [`room`] — `joinRoom`-equivalent: maps a network id to a room
//!   handle, drives the signaling-message multiplex across the
//!   selected relays, and applies the offer-pool-flush + stale-inbound
//!   policies.
//! - [`shuffle`] — deterministic relay selection from a configured
//!   pool; byte-compatible with Trystero so MyOwnMesh and MyOwnLLM
//!   peers using the same TRYSTERO_APP_ID land on the same top-N
//!   relays.
//! - [`handle`] — SHA-256 derivation of the room handle (the wire
//!   identifier) from `(network_id, app_id)`.
//! - [`denylist`] — hostnames excluded from the shuffle.
//! - [`defaults`] — built-in default relay URLs.
//!
//! v1 here ships the wire types and constants; the concrete I/O
//! lives behind the [`crate::SignalingChannel`] trait and is wired
//! up after the WebRTC transport lands in
//! `myownmesh-core::transport`.

pub mod defaults;
pub mod denylist;
pub mod driver;
pub mod event;
pub mod handle;
pub mod relay;
pub mod room;
pub mod shuffle;
