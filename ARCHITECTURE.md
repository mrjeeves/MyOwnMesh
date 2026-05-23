# Architecture

MyOwnMesh is a pure-Rust peer-to-peer mesh networking stack. It ships
as both a binary (daemon + CLI) and a library (`myownmesh-core`) so
other apps embed the mesh without inheriting a GUI or HTTP updater.

## Crates

```
crates/
├── myownmesh-core         # lib  — runtime, engine, transport, protocol, topology, RPC, channels
├── myownmesh-signaling    # lib  — Nostr driver + in-process LocalBroker
├── myownmesh-updater      # lib  — self-update with configurable release feed
└── myownmesh              # bin  — daemon + CLI + control-socket IPC
```

Embedders depend on `myownmesh-core` (and optionally
`myownmesh-signaling` if they want the Nostr driver). They don't pull
in `myownmesh-updater` or the bin.

A future `myownmesh-gui` crate will sit alongside these without
changing the layout. The GUI port from MyOwnLLM's `CloudMesh*` Svelte
components is deferred until the headless engine has been
field-tested.

## Module map (`myownmesh-core`)

```
src/
├── lib.rs                  # public re-exports + crate docs
├── identity.rs             # ed25519 keypair, base32 device id, display suffix
├── signing.rs              # sign / verify / domain-tag handshake payload
├── roster.rs               # per-network approved-peers file (0600)
├── verification.rs         # 6-char OOB verification codes
├── config.rs               # MeshConfig + NetworkConfig + TopologyMode
├── dirs.rs                 # ~/.myownmesh layout
├── error.rs                # crate-wide Error + Result
├── events.rs               # MeshEvent / PeerEvent / DiagEntry surfaced to embedders
├── protocol/               # wire-level MeshMessage variants
├── topology/               # Ring / Star / FullMesh selectors
├── transport/              # webrtc-rs wrapper, ICE config, diag counters
├── engine/                 # the connection engine (see below)
├── channels.rs             # typed pub/sub Channel<T>
├── rpc.rs                  # generic Rpc — single-shot + streaming
└── handle.rs               # Mesh / MeshHandle / JoinedNetwork facade
```

## The engine

The connection engine turns the protocol + transport + topology
primitives into a working mesh. One driver task per joined network.

```
src/engine/
├── mod.rs                  # driver loop — fans in commands, signaling, transport events
├── state.rs                # NetworkState shared between subsystems
├── connection.rs           # per-peer status / tier / diag watermarks
├── handshake.rs            # hello → auth_response state machine + watchdog
├── heartbeat.rs            # ping / pong + silent-peer detection
├── ladder.rs               # 7-tier reconnection state machine
├── ice_watchdog.rs         # Tier 2.5 — restart_ice() before Trystero's 5s timeout
├── wake.rs                 # tick-gap → wake event coalescing
├── reconcile.rs            # Tier 6 — config edit triggers stop+start
├── scheduler.rs            # every tunable constant, named ticks
├── phase.rs                # MeshPhase rollup (Alone / Discovering / Active / Degraded)
└── signaling_bridge.rs     # adapters: attach_local / attach_nostr
```

See `CONNECTION-ENGINE.md` for the 7-tier ladder, every tunable
constant, and the edge cases the engine handles.

## Trust model

Each device owns a long-lived ed25519 keypair persisted at
`~/.myownmesh/.secrets/identity.json` (mode 0600 on Unix). The
public key — base32-lowercase, 52 chars — is the Device ID surfaced
on the wire.

Authentication is mutual: when two peers meet, each `hello` carries
a random 32-byte nonce. The other side responds with an
`auth_response` containing
`ed25519_sign(SIGN_DOMAIN_TAG || nonce || my_device_id || their_device_id)`,
verified against the claimed Device ID's pubkey. Domain separation
by `SIGN_DOMAIN_TAG = "myownmesh-mesh-auth-v1:"` prevents a
signature obtained for one protocol step from being replayed in
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
- **Star**. Spokes keep only the configured hub active. Hub
  Device ID is named in config; auto-elect is a follow-up.
- **FullMesh**. Every peer keeps every other peer active. N²
  channels — intended for small fixed-size deployments.

Selectors are pure functions. Both sides of any peer pair run the
same algorithm over the same sorted input and arrive at the same
answer — that's what makes shelving safe without coordination.

## Wire protocol

JSON-framed messages on a WebRTC data channel, each tagged by
`kind`. See `docs/PROTOCOL.md` for the full reference; the source
of truth is `src/protocol/`. Receivers silently drop unknown
`kind`s; embedders gate optional traffic per-peer via the
`features` capability matrix.

## Signaling

Today the production strategy is Nostr (5 relays by default,
deterministic shuffle per app-id). The Trystero v0.24 wire format
is preserved on the room-handle derivation so a future hybrid
deployment with JS Trystero peers is possible if they share an
app-id. By default the app-ids differ
(`myownmesh-cloud-mesh-v1` vs `myownllm-cloud-mesh-v1`) so the
two ecosystems never meet on the wire.

A second strategy — `local::LocalBroker` — runs entirely
in-process for tests and for embedders that don't need network
signaling.

The Nostr driver bakes in every upstream-Trystero fix catalogued
in `crates/myownmesh-signaling/src/upstream.rs` natively — no
patches required.

## Persistent state

```
~/.myownmesh/
├── config.json                  # user-editable
├── .secrets/identity.json       # 0600 — ed25519 keypair
├── mesh/rosters/{net}.json      # 0600 each — per-network approved peers
├── daemon.sock                  # Unix-domain socket for `myownmesh ctl …`
└── updates/                     # staging area for self-update
```

Override the root via `MYOWNMESH_HOME`.

## API surface

The public re-exports from `myownmesh_core` are the embedder's
working set:

```rust
// Construction
Mesh, MeshHandle, MeshConfig, NetworkConfig, TopologyMode

// Identity
Identity, DeviceId
generate_network_id, normalize_network_id

// Wire data
MeshEvent, PeerEvent, MeshPhase, DiagEntry
CapabilityAdvert
ConnectionTier

// Application surface
JoinedNetwork
Channel, ChannelMessage, ChannelError
Rpc, RpcCall, RpcResponse, RpcError

// Roster
Roster, AuthorizedPeer
```

The engine internals (`engine::*`) are public so the bin can
attach signaling drivers and so embedders can run sophisticated
custom integrations, but the recommended surface for typical use
is the `Mesh` → `MeshHandle` → `JoinedNetwork` flow.

## Out of scope for v1

- GUI (Tauri network browser) — planned for v1.x.
- MyOwnLLM migration to depend on `myownmesh-core` — separate plan
  once the core API is stable.
- Onion / payload-layer encryption above DTLS — explicitly
  declined.
- Star auto-elect topology — explicit hub only.
- Signaling strategies other than Nostr — sibling crates later
  (BitTorrent trackers, MQTT, IPFS, Firebase).
- Built-in TURN server — user-configured TURN only.
- Built-in audio / file / LLM RPCs — embedders define their own
  message types over `Channel<T>` or the generic `Rpc`.
