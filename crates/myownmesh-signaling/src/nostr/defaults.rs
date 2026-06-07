//! Built-in default signaling relay.
//!
//! Out of the box, MyOwnMesh peers rendezvous on the project's
//! reference relay so a fresh install connects with zero setup. But the
//! relay *is* the program itself: a self-hosted signaling relay is just
//! `myownmesh serve` with `services.signaling` enabled (a
//! Nostr-compatible server), frontable with TLS in one step via
//! `myownmesh install caddy <domain>`. Run your own — on your LAN, over
//! a tailnet, or on your own domain — and point `signaling.servers` at
//! it; it's exactly as secure and robust either way.

/// Built-in default relay URL set, used when `signaling.servers` is
/// empty. One reference relay today, reached over standard `wss://`
/// (port 443) — TLS is terminated by the reverse proxy `myownmesh
/// install caddy` sets up, which forwards to the relay on loopback.
/// Port 443 also sails through restrictive firewalls that block oddball
/// ports. The per-app-id shuffle (see [`super::shuffle`]) still applies
/// when you configure several relays of your own.
pub const DEFAULT_RELAY_URLS: &[&str] = &["wss://myownmesh.com"];

/// Public Nostr relays used **only** as a last-resort fallback, when every
/// configured/primary relay is unreachable (see `signaling.public_fallback`,
/// on by default). Steady state never touches these — a supervisor spins
/// them up only after the primary set has been down for a grace window and
/// spins them down again the moment a primary recovers, so presence isn't
/// leaked to public infrastructure in normal operation. The per-app-id
/// shuffle still produces Trystero-compatible picks for anyone who falls
/// back to the same set.
pub const FALLBACK_RELAY_URLS: &[&str] = &[
    "wss://nos.lol",
    "wss://relay.nostr.band",
    "wss://nostr.mom",
    "wss://relay.snort.social",
    "wss://relay.primal.net",
    "wss://nostr-pub.wellorder.net",
    "wss://relay.nostr.bg",
    "wss://nostr.wine",
    "wss://offchain.pub",
];
