//! Nostr signaling. Wire-compatible with upstream Trystero on the
//! relay shuffle and room-handle derivation.
//!
//! Implementation lands across:
//! - [`driver`] — the whole relay lifecycle: per-relay WebSocket
//!   connect/backoff (jittered), the room subscription (REQ) and its
//!   adaptive filter shape, the announce schedule, and the outbound
//!   publish pump.
//! - [`shuffle`] — deterministic relay selection from a configured
//!   pool; byte-compatible with Trystero so MyOwnMesh and MyOwnLLM
//!   peers using the same TRYSTERO_APP_ID land on the same top-N
//!   relays.
//! - [`handle`] — SHA-256 derivation of the room handle (the wire
//!   identifier) from `(network_id, app_id)`.
//! - [`denylist`] — hostnames excluded from the shuffle.
//! - [`defaults`] — built-in default relay URLs.

pub mod defaults;
pub mod denylist;
pub mod driver;
pub mod event;
pub mod handle;
pub mod shuffle;
