# myownmesh-signaling

Signaling drivers for MyOwnMesh. Pulled separately from
`myownmesh-core` so an embedder targeting LAN-only or
in-process-only doesn't pay for the Nostr / WebSocket dependency
stack.

```toml
myownmesh-signaling = { git = "https://github.com/mrjeeves/MyOwnMesh", tag = "v0.2.0" }
```

## What's in here

- **`local::LocalBroker`** — in-process loopback. Used by the
  integration test suite and by embedders running multiple
  `Mesh` instances in one process.
- **`nostr::driver`** — production Nostr signaling. Connects N relays
  in parallel (deterministic top-N selection per `(app_id,
  network_id)`), publishes stored NIP-01 regular events (kind 1077),
  subscribes by `#r` tag. Stored kind so late joiners receive every
  existing peer's announce on `REQ since=now-300s` replay; ephemeral
  (20000–29999) was discarded by relays and produced a star-around-
  first-peer failure mode.

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

Every `[trystero-patch]` prefix in the driver logs corresponds to
one of those entries — naming the entry in a bug report saves
diagnosis time.

## Custom signaling

`SignalingChannel` is the seam. Implementing a new strategy
(BitTorrent trackers, MQTT, IPFS, Firebase, …) means adding a
sibling crate or module that satisfies that trait and an
`attach_<strategy>` adapter in
`myownmesh-core::engine::signaling_bridge`.
