# Architecture

MyOwnMesh is a pure-Rust peer-to-peer mesh networking stack. It ships
as both a binary (daemon + CLI) and a library (`myownmesh-core`) so
other apps can embed the mesh without inheriting a GUI or HTTP
updater.

## Crates

```
crates/
├── myownmesh-core         # lib   — runtime, protocol, identity, topology
├── myownmesh-signaling    # lib   — Nostr signaling (Trystero-wire-compatible)
├── myownmesh-updater      # lib   — self-update with configurable release feed
└── myownmesh              # bin   — daemon + CLI
```

Embedders depend on `myownmesh-core` and optionally
`myownmesh-signaling`. They don't pull in `myownmesh-updater` or
the CLI binary.

A future `myownmesh-gui` crate (Tauri + Svelte) will sit alongside
these without changing the existing layout. The GUI port from
MyOwnLLM's `CloudMesh*` Svelte components is deferred until the
headless engine is field-tested.

## Trust model

Each device owns a long-lived ed25519 keypair persisted at
`~/.myownmesh/.secrets/identity.json` (mode 0600 on Unix). The
public key — base32-lowercase encoded, 52 chars — is the Device ID
surfaced on the wire.

Authentication is mutual: when two peers meet, each `hello` carries
a random 32-byte nonce. The other side responds with an
`auth_response` containing
`ed25519_sign(SIGN_DOMAIN_TAG || nonce || my_device_id || their_device_id)`,
which is verified against the claimed Device ID's pubkey. Domain
separation by `SIGN_DOMAIN_TAG = "myownmesh-mesh-auth-v1:"` prevents
a signature obtained for one protocol step from being replayed in
another.

A 6-char `[a-z0-9]` verification code travels in each `hello`. The
code is not load-bearing for security — the ed25519 signatures are
— but it's the eyeball-check users perform over voice / video at
first meeting (`"my code is k3m2pq"`). After approval, the peer's
pubkey lands in the per-network roster
(`~/.myownmesh/mesh/rosters/{network_id}.json`) and auto-approves
on subsequent reconnects.

## Topology

Three selectable topologies, all built on the same shelving
primitive:

- **Ring** (default). Sorted-lex ring; each peer keeps its two
  immediate neighbors + `(n_preferred − 2)` shortcuts active.
  Algorithm at `crates/myownmesh-core/src/topology/ring.rs`.
- **Star**. Spokes keep only the configured hub active. Hub
  Device ID is named in config; auto-elect is a follow-up.
- **FullMesh**. Every peer keeps every other peer active. N²
  data channels — intended for small fixed-size deployments.

Selectors are pure functions. Both sides of any peer pair run the
same algorithm over the same sorted input and arrive at the same
answer — that's what makes shelving safe without coordination.

See `CONNECTION-ENGINE.md` for the 7-tier reconnection ladder and
every tunable constant.

## Wire protocol

JSON-framed messages on a WebRTC data channel, each tagged by
`kind`. See `crates/myownmesh-core/src/protocol/` for definitions.
Receivers silently drop unknown `kind`s; embedders gate optional
traffic per-peer via the `features` capability matrix.

## Signaling

Today's only strategy is Nostr (5 relays by default, deterministic
shuffle per app-id). The Trystero v0.24 wire format is preserved
so a future hybrid deployment with JS Trystero peers is possible
if they share an app-id. By default the app-ids differ
(`myownmesh-cloud-mesh-v1` vs `myownllm-cloud-mesh-v1`) so the two
ecosystems never meet on the wire.

The signaling implementation bakes in every upstream-Trystero fix
catalogued in `crates/myownmesh-signaling/src/upstream.rs` — no
patches required.

## Persistent state

```
~/.myownmesh/
├── config.json                 (user-editable)
├── .secrets/identity.json      (0600 — ed25519 keypair)
├── mesh/rosters/{net}.json     (0600 each — per-network approved peers)
└── updates/                    (staging area for self-update)
```

Override the root via `MYOWNMESH_HOME`.

## Out of scope for v1

- GUI (Tauri + Svelte network browser) — planned for v1.x.
- MyOwnLLM migration to depend on `myownmesh-core` — separate plan
  once the core API is stable.
- Onion / payload-layer encryption above DTLS — explicitly
  declined.
- Star auto-elect topology — explicit hub only.
- Signaling strategies other than Nostr — sibling crates later
  (BitTorrent trackers, MQTT, IPFS, Firebase).
- Built-in TURN server — user-configured TURN only, matching
  MyOwnLLM's design.
- Built-in audio / file / LLM RPCs — embedders define their own
  message types over `Channel<T>` or the generic `Rpc`.
