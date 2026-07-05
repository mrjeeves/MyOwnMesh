# myownmesh-signaling

Signaling drivers for MyOwnMesh. Pulled separately from
`myownmesh-core` so an embedder targeting LAN-only or
in-process-only doesn't pay for the Nostr / WebSocket dependency
stack.

```toml
myownmesh-signaling = { git = "https://github.com/mrjeeves/MyOwnMesh", tag = "v0.2.30" }
```

## What's in here

- **`local::LocalBroker`** — in-process loopback. Used by the
  integration test suite and by embedders running multiple
  `Mesh` instances in one process.
- **`mdns::driver`** — LAN-local DNS-SD signaling (pure-Rust
  `mdns-sd`, no avahi/Bonjour binding). Registers one
  `_myownmesh._tcp.local.` instance per network with the room handle
  in TXT, browses for peers in the same room, and exchanges
  offer/answer/candidate frames over a unicast TCP port advertised
  in SRV (SDP is far too large for TXT). Clock-free — works on a
  device whose RTC still reads the epoch. On by default alongside
  the remote strategy (`SignalingConfig.mdns`), so co-located peers
  mesh even with every relay unreachable; pair with
  `strategy = "none"` for a fully LAN-local network.
- **`nostr::driver`** — production Nostr signaling. Connects N relays
  in parallel (deterministic top-N selection per `(app_id,
  network_id)`), subscribes by `#r` tag, and splits the wire by message
  class: **presence/announce** on stored kind `1077` (so late joiners
  receive every existing peer's announce on `REQ since=now-300s`
  replay), and **connection negotiation** (offer/answer/candidate/leave)
  on ephemeral kind `21077` (forwarded live, never persisted, so a stale
  offer can't be replayed onto a new session). See upstream fix #8.

## Trystero compat & upstream fixes

Wire-compatible with [Trystero](https://trystero.dev) v0.24 on the
room-handle derivation (`SHA-256(app_id || ":" || network_id)`) and
relay shuffle. A future hybrid deployment with JS Trystero peers
using the same app id is possible.

The driver bakes in every fix from
`patches/@trystero-p2p__core@0.24.0.patch` in the MyOwnLLM repo —
catalogued in [`src/upstream.rs`](src/upstream.rs):

1. Subscription replay on WebSocket reconnect with anti-flood
   backoff (`5/10/15/30/60 s`).
2. ICE-disconnected treated as transient — start the grace
   window immediately rather than waiting on consent freshness.
3. Inbound-recency-based zombie clearing (`STALE_INBOUND_MS = 25_000`).
4. Offer-pool flush on peer drop, throttled (`10 s`).
5. State-transition logging only — no per-event spam.
6. Cross-relay event deduplication — a bounded seen-event-id ring
   drops duplicate copies of one event delivered by multiple relays
   (re-applying a duplicate offer would wedge the connection).
7. Adaptive announce cadence — a single global announcer (replacing
   the per-relay timers): a brief startup re-publish, then a steady
   2-minute cadence.
8. Presence stored, negotiation ephemeral — announce on stored kind
   `1077`, offer/answer/candidate/leave on ephemeral kind `21077`, so a
   stale negotiation event can't replay onto a future session.

Every `[trystero-patch]` prefix in the driver logs corresponds to
one of those entries — naming the entry in a bug report saves
diagnosis time.

## Custom signaling

`SignalingChannel` is the seam. Implementing a new strategy
(BitTorrent trackers, MQTT, IPFS, Firebase, …) means adding a
sibling crate or module that satisfies that trait and an
`attach_<strategy>` adapter in
`myownmesh-core::engine::signaling_bridge`.
