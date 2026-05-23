# myownmesh-signaling

Signaling drivers for MyOwnMesh. Two strategies in v1:

- **`local::LocalBroker`** — in-process loopback. Used by the
  integration test suite and by embedders running multiple
  `Mesh` instances in one process.
- **`nostr::driver`** — production Nostr signaling. Connects N relays
  in parallel (deterministic top-N selection per `(app_id,
  network_id)`), publishes ephemeral NIP-01 events (kind 21000),
  subscribes by `#r` tag.

## Trystero compat & upstream fixes

Wire-compatible with Trystero v0.24 on the room-handle derivation
(SHA-256 of `app_id || ":" || network_id`) and relay shuffle. A
future hybrid deployment with JS Trystero peers using the same
app id is possible.

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

## Custom signaling

The `SignalingChannel` trait is the seam. Implementing a new
strategy (BitTorrent trackers, MQTT, IPFS, Firebase, …) means
adding a sibling crate or module that satisfies that trait and
an `attach_<strategy>` adapter in
`myownmesh-core::engine::signaling_bridge`.
