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
/// empty. One reference relay today; the per-app-id shuffle (see
/// [`super::shuffle`]) still applies when you configure several relays
/// of your own.
pub const DEFAULT_RELAY_URLS: &[&str] = &["wss://myownmesh.com:4848"];
