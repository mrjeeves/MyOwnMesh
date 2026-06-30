# Architecture

MyOwnMesh is a pure-Rust peer-to-peer mesh networking stack. It ships
as both a binary (daemon + CLI) and a library (`myownmesh-core`) so
other apps embed the mesh without inheriting a GUI or HTTP updater.

## Lineage from MyOwnLLM

The code was extracted from
[MyOwnLLM](https://github.com/mrjeeves/MyOwnLLM)'s mesh substrate
once the substrate had outgrown "one app's plumbing":

| MyOwnLLM module (origin) | MyOwnMesh module (here) |
|---|---|
| `src-tauri/src/mesh/identity.rs` | `crates/myownmesh-core/src/identity.rs` |
| `src-tauri/src/mesh/signing.rs` | `crates/myownmesh-core/src/signing.rs` |
| `src-tauri/src/mesh/roster.rs` | `crates/myownmesh-core/src/roster.rs` |
| `src/mesh-client.svelte.ts` (engine half) | `crates/myownmesh-core/src/engine/` |
| `src/mesh-protocol.ts` | `crates/myownmesh-core/src/protocol/` |
| `patches/@trystero-p2p__core@0.24.0.patch` | `crates/myownmesh-signaling/src/upstream.rs` + the Nostr driver |
| `src/self_update.rs` (mesh-relevant fraction) | `crates/myownmesh-updater/` |

The rewrite generalised every embedder-specific bit:
`~/.myownllm/` becomes `~/.myownmesh/` (overridable via
`MYOWNMESH_HOME`), the Trystero app-id moves from
`myownllm-cloud-mesh-v1` to `myownmesh-cloud-mesh-v1`, and the
signing domain tag is `myownmesh-mesh-auth-v1:` rather than
`myownllm-mesh-auth-v1:` — so a MyOwnLLM peer and a bare-MyOwnMesh
peer don't land in the same Nostr room or accept each other's
signatures by accident. Downstream forks change those three
constants (env vars at build time for the URL/app-id; a one-line
edit in `lib.rs` for the domain tag) to non-interop with upstream
on purpose.

## Crates

```
crates/
├── myownmesh-core         # lib  — runtime, engine, transport, protocol, topology, RPC, channels, service roles + relay
├── myownmesh-signaling    # lib  — Nostr driver + in-process LocalBroker + self-hosted NIP-01 relay server
├── myownmesh-services     # lib  — self-hosted STUN + TURN servers (webrtc-rs stun/turn)
├── myownmesh-updater      # lib  — self-update with configurable release feed
└── myownmesh              # bin  — daemon + CLI + control-socket IPC + service manager
```

Embedders depend on `myownmesh-core` (and optionally
`myownmesh-signaling` if they want the Nostr driver, or
`myownmesh-services` if they want to host STUN / TURN). They don't pull
in `myownmesh-updater` or the bin. The heavyweight STUN / TURN
dependency tree lives in `myownmesh-services` precisely so a core-only
embedder doesn't inherit it.

The desktop GUI (`gui/`) is a Tauri + Svelte 5 **client** of the
daemon — it talks to `myownmesh serve` over the local control socket
and never embeds `myownmesh-core`, so it lives in its own Cargo
workspace and a `cargo build --workspace` at the root stays fast
(no Tauri compile).

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
├── network_state.rs        # per-network signed governance log (open/closed kind, roles, splits)
├── protocol/               # wire-level MeshMessage variants
├── topology/               # Ring / Star / FullMesh selectors
├── transport/              # webrtc-rs wrapper, ICE config, diag counters
├── services/               # hosted infra: relay / signaling / STUN / TURN config + runtime
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
├── ladder.rs               # connection-tier enum + topology selector pass
├── ice_watchdog.rs         # Tier 2.5 — restart_ice() before Trystero's 5s timeout
├── wake.rs                 # tick-gap → wake event coalescing
├── network_watch.rs        # OS network-change detection → fast rejoin
├── reconcile.rs            # Tier 6 — config edit triggers stop+start
├── governance.rs           # closed-network state log: proposals / transitions / splits
├── scheduler.rs            # every tunable constant, named ticks
├── phase.rs                # MeshPhase rollup (Joining / Alone / Discovering / Active / Degraded / Stopped)
└── signaling_bridge.rs     # adapters: attach_local / attach_nostr
```

See `CONNECTION-ENGINE.md` for the recovery model, every tunable
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

Alongside the data channel, every connection provisions one **H.264
video track lane** (a sendrecv media transceiver) in the same
offer/answer — negotiated once at setup, so no renegotiation path
exists or is needed. An idle lane sends nothing and costs nothing;
embedders write encoded access units with
`NetworkState::send_video_sample` and subscribe to assembled inbound
units with `subscribe_video` (the daemon mirrors both as `video_send`
/ `video_subscribe` control ops). For the high-rate H.264/Opus path the
daemon also exposes two **dedicated binary media pipes** over the control
socket, so the bitstream crosses the IPC with no base64 or per-frame JSON:
`media_track_pipe` (a client streams length-prefixed access units in) and
`media_source_pipe` (the daemon pushes a subscribed client's inbound frames
out). The base64 `video_send` / `video_inbound` ops remain for clients that
don't open the binary pipes. Media rides RTP/UDP with the default
interceptors (NACK retransmission, reports) — lossy-fresh semantics, unlike
the reliable-ordered data channel; the engine neither encodes nor decodes,
it moves Annex-B access units.

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

A device can also **host** signaling itself:
`myownmesh-signaling::server` is a minimal NIP-01 relay that the
Nostr driver speaks to unchanged. Point a network's
`signaling.servers` at `ws://that-host:port` and the fleet runs
with no dependency on public Nostr at all.

## Hosted services

Beyond consuming signaling / STUN / TURN, a device can host them for
the rest of the mesh — relay routing, a signaling relay, a STUN
server, and a TURN server. All off by default and configured
device-wide under `services` in `config.json`, activatable from the
GUI (Settings → Services), the CLI (`myownmesh ctl services …`), and
config edits.

```
config.services
├── node         # participate as a mesh member; off = pure-infra box (default on)
├── relay        # forwards roster traffic on a reserved channel (core::services::RelayService)
├── signaling    # intelligent NIP-01 relay — live presence, instant leave, flood limits (myownmesh-signaling::server)
├── stun         # RFC 5389 binding (myownmesh-services::stun)
└── turn         # RFC 5766 relay + per-connection bandwidth cap (myownmesh-services::turn)
```

The signaling relay is stateful: it tracks live presence from the
connection lifecycle and emits a `leave` ([`SignalingMessage::Leave`])
the instant a member's socket drops, so the engine's reconnection ladder
reacts immediately instead of waiting out a heartbeat timeout. It stays
plain NIP-01 on the wire and degrades gracefully — an optional
accelerator, never a coordinator the mesh depends on. `node` is itself a
toggle, so a device can be pure infrastructure (signaling / STUN / TURN
with no mesh membership).

The daemon's `ServiceManager` (`crates/myownmesh/src/services.rs`)
owns the running handles, reconciles them against config on demand,
and advertises a [`ServiceRole`](crates/myownmesh-core/src/services/mod.rs)
to peers via the capability matrix (`service:relay`,
`service:signaling`, `service:stun`, `service:turn`) plus an optional
`ServiceAdvert` carrying concrete endpoint URLs. That advertisement is
what lets a peer discover and adopt a host — making a fully
internet-isolated network trivial to stand up. See
[`docs/SERVICES.md`](docs/SERVICES.md) for the operator guide.

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

- MyOwnLLM migration to depend on `myownmesh-core` at the source
  level — staged. The publishing path (git tag, README copy-paste
  block, version-pin discipline) is in place from this end;
  MyOwnLLM's `src-tauri/Cargo.toml` will wire the git dep and
  `src-tauri/src/mesh/{identity,signing,roster,commands}.rs` will
  delegate to `myownmesh-core` once the field-tested behavior here
  is audited against MyOwnLLM's user-visible mesh UX. The migration
  PR lands once that audit clears.
- Onion / payload-layer encryption above DTLS — explicitly
  declined.
- Star auto-elect topology — explicit hub only.
- Additional *consumer* signaling strategies beyond Nostr
  (BitTorrent trackers, MQTT, IPFS, Firebase) — sibling crates
  later. (A device can now *host* signaling via the built-in
  NIP-01 relay; see [Hosted services](#hosted-services).)
- Transparent relay fallback — the relay service forwards roster
  traffic on an explicit channel today; automatic per-peer routing
  through a relay when ICE can't punch through is a follow-up.
- Built-in audio / file / LLM RPCs — embedders define their own
  message types over `Channel<T>` or the generic `Rpc`.

Now in (was out of scope before service hosting landed):

- **Built-in STUN / TURN servers** — `myownmesh-services` hosts both;
  user-configured external STUN / TURN still works as before.
- **Self-hosted signaling** — `myownmesh-signaling::server` is a
  NIP-01 relay usable in place of public Nostr.
- crates.io publish for the library crates — gated on a public-API
  freeze. Until then embedders pull from git pinned to a release
  tag; see [`RELEASE.md`](RELEASE.md).
