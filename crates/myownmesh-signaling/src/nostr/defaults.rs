//! Built-in default Nostr relay URLs. Sourced from Trystero v0.24's
//! defaults so the deterministic shuffle (see [`super::shuffle`])
//! produces identical top-N picks for MyOwnMesh and JS Trystero
//! peers configured with the same app-id.
//!
//! Maintenance: when upstream Trystero adds or removes a default,
//! mirror the change here so the wire-compat property holds.

/// Built-in default relay URL set. Order matters only as a stable
/// input to the per-app-id shuffle — see [`super::shuffle`].
pub const DEFAULT_RELAY_URLS: &[&str] = &[
    "wss://nos.lol",
    "wss://relay.damus.io",
    "wss://relay.nostr.band",
    "wss://nostr.mom",
    "wss://relay.snort.social",
    "wss://relay.primal.net",
    "wss://nostr-pub.wellorder.net",
    "wss://relay.nostr.bg",
    "wss://nostr.wine",
    "wss://offchain.pub",
];
