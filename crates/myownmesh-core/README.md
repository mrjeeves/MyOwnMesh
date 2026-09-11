# myownmesh-core

The mesh runtime. This is the crate embedders depend on.

Pull the exact repository tag selected for the release; replace `vX.Y.Z`
below with that tag. The library crates are not published by the release
workflow to crates.io:

```toml
myownmesh-core      = { git = "https://github.com/mrjeeves/MyOwnMesh", tag = "vX.Y.Z" }
myownmesh-signaling = { git = "https://github.com/mrjeeves/MyOwnMesh", tag = "vX.Y.Z" }  # signaling drivers
```

See [`../../RELEASE.md`](../../RELEASE.md) for the published-artifact
catalogue and the path to crates.io.

## What's in here

- **Identity:** long-lived ed25519 keypair, base32-lowercase device id.
- **Semantic authority:** per-network signed `FactGraph` with a canonical durable SQLite store.
- **Roster:** non-authoritative per-network UI/diagnostic projection (0600 on Unix).
- **Wire protocol:** `MeshMessage` variants and capability matrix.
- **Topology:** FullMesh (default), Ring, and Star selectors. Required edge predicates are symmetric; local preferred and shortcut selections are deterministic without being universally pairwise symmetric.
- **Transport:** webrtc-rs wrapper. One `PeerSession` per peer, with event queues drained by the engine.
- **Engine:** `hello` → `auth_response` handshake, ping/pong heartbeat, recovery driven by reliable transport signals, and topology shelving. Recovery uses in-place ICE restart confirmed by inbound traffic, then a clean rebuild on failure.
- **Channels:** typed pub/sub via `Channel<T>`.
- **RPC:** generic `Rpc::call`, `serve`, `call_stream`, and `serve_stream` operations.
- **Facade:** `Mesh` → `MeshHandle` → `JoinedNetwork`.

## Public API tour

```rust
use myownmesh_core::{Mesh, MeshConfig, NetworkConfig, TopologyMode, WebRtcConnectorCapablePolicy};

// `connector_policy` is selected by the process owner. The library has no default.
let mesh = Mesh::open_connector_capable(MeshConfig::default(), connector_policy).await?;
let net = mesh.join(NetworkConfig { /* ... */ }).await?;
let chan = net.channel::<MyMessage>("my-channel");
let rpc  = net.rpc();
```

Full surface: `Mesh`, `MeshHandle`, `JoinedNetwork`, `MeshConfig`,
`NetworkConfig`, `TopologyMode`, `Identity`, `DeviceId`, and the semantic
governance API. `Roster` and `AuthorizedPeer` are projection DTOs rather than
authority-bearing state. Event and application surfaces include `MeshEvent`, `PeerEvent`, `MeshPhase`,
`DiagEntry`, `CapabilityAdvert`, `ConnectionTier`, `Channel`,
`ChannelMessage`, `ChannelError`, `Rpc`, `RpcCall`, `RpcResponse`,
`RpcError`. Helpers: `generate_network_id`, `normalize_network_id`.
Constants: `TRYSTERO_APP_ID`, `PROTOCOL_VERSION`.

See [`../../docs/QUICKSTART.md`](../../docs/QUICKSTART.md) for the
narrative walkthrough of identity, channels, RPC, roster,
topology, shutdown.

## Persistent state

```
~/.myownmesh/
├── .secrets/identity.json          (0600, ed25519 keypair)
└── mesh/
    ├── semantic/{slot}-store.sqlite3  (canonical signed semantic state)
    └── rosters/{network_id}.json      (non-authoritative UI projection)
```

Override the root via `MYOWNMESH_HOME=~/.youapp/mesh` so embedders
keep their state under their own directory tree.

## Tests

```
cargo test -p myownmesh-core
```

Includes [`tests/two_peer_handshake.rs`](tests/two_peer_handshake.rs), which uses
two ephemeral identities, joined the same network via the in-process
broker, full handshake + typed channel exchange end-to-end.
