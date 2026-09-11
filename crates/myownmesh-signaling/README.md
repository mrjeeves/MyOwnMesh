# myownmesh-signaling

Signaling drivers for MyOwnMesh. The current package contains the complete
Nostr/WebSocket and mDNS/DNS-SD driver stack; depending on `myownmesh-core`
also brings in this package. There is no current LAN-only dependency feature
that removes the Nostr/WebSocket code.

Replace `vX.Y.Z` below with the exact repository tag selected for the release:

```toml
myownmesh-signaling = { git = "https://github.com/mrjeeves/MyOwnMesh", tag = "vX.Y.Z" }
```

## What's in here

- **`local::LocalBroker`** — in-process loopback used by the
  `transport-lab` integration controls. It is not an advertised production
  carrier.
- **`mdns::driver`** — LAN-local DNS-SD signaling. The embedded backend uses
  pure-Rust `mdns-sd`; iOS and builds selecting `system-dnssd` use the system
  DNS-SD/Bonjour-compatible backend. The selected backend registers one
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
  receive every existing peer's announce on the stored-presence replay
  window, and **connection negotiation** (offer/answer/candidate/leave)
  on ephemeral kind `21077` (forwarded live, never persisted, so a stale
  offer can't be replayed onto a new session). See upstream fix #8.

The V4 signaling envelope is strict: `from`, an explicit `to`, and the
message's current fields are required, and unknown fields are refused. The
room handle is the explicit recipient for announce/leave broadcasts; directed
offer, answer, and candidate messages name one device. Candidate correlation
(`offer_id`) is required, while the genuinely optional ICE candidate fields
(`sdp_mid`, `sdp_mline_index`, and `username_fragment`) remain optional. There
is no capability negotiation or offer-acceptance field on this wire.

## Trystero-derived algorithms and upstream fixes

The room-handle derivation (`SHA-256(app_id || ":" || network_id)`) and relay
shuffle follow the [Trystero](https://trystero.dev) v0.24 algorithms. That
algorithm compatibility is not whole-protocol wire compatibility: MyOwnMesh
requires its strict V4 envelope, explicit recipient, current event kinds, and
recipient tags. No direct JS-Trystero hybrid deployment is claimed.

The driver bakes in every fix from
`patches/@trystero-p2p__core@0.24.0.patch` in the MyOwnLLM repo —
catalogued in [`src/upstream.rs`](src/upstream.rs):

1. Subscription replay on every new WebSocket session, paced by the
   owner-configured per-socket reconnect backoff and jitter.
2. ICE-disconnected treated as transient — start the grace
   window immediately rather than waiting on consent freshness.
3. Inbound-recency-based zombie clearing using the checked, owner-supplied
   per-network scheduler policy.
4. State-transition logging only — no per-event spam.
5. Adaptive announce cadence — a single global announcer (replacing
   the per-relay timers): a brief startup re-publish, then a steady
   2-minute cadence.
6. Presence stored, negotiation ephemeral — announce on stored kind
   `1077`, offer/answer/candidate/leave on ephemeral kind `21077`, so a
   stale negotiation event can't replay onto a future session.
7. Cross-relay event deduplication before one replicated Nostr event reaches
   the bounded signaling ingress more than once.
8. Recipient-tagged negotiation, so relays deliver pairwise ephemeral traffic
   only to the named recipient instead of every room subscriber.

Every `[trystero-patch]` prefix in the driver logs corresponds to
one of those entries — naming the entry in a bug report saves
diagnosis time.

## Custom signaling

`SignalingChannel` is the seam. Implementing a new strategy
(BitTorrent trackers, MQTT, IPFS, Firebase, …) means adding a
sibling crate or module that satisfies that trait and an
`attach_<strategy>` adapter in
`myownmesh-core::engine::signaling_bridge`.
