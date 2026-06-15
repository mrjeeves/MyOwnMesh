# myownmesh-core

The mesh runtime. This is the crate embedders depend on.

Pull via git tag — library crates aren't on crates.io yet:

```toml
myownmesh-core      = { git = "https://github.com/mrjeeves/MyOwnMesh", tag = "v0.2.7" }
myownmesh-signaling = { git = "https://github.com/mrjeeves/MyOwnMesh", tag = "v0.2.7" }  # Nostr driver
```

See [`../../RELEASE.md`](../../RELEASE.md) for the published-artifact
catalogue and the path to crates.io.

## What's in here

- **Identity** — long-lived ed25519 keypair, base32-lowercase device id.
- **Roster** — per-network approved-peers file (0600 on Unix).
- **Wire protocol** — `MeshMessage` variants, capability matrix.
- **Topology** — Ring (default) / Star / FullMesh selectors. Pure functions; symmetric across peers.
- **Transport** — webrtc-rs wrapper. `PeerSession` per peer, event mpsc the engine drains.
- **Engine** — `hello` → `auth_response` handshake, ping/pong heartbeat, the 7-tier reconnection ladder (`Steady`, `WakeProbe`, `IceWatchdog`, `IceRestart`, `Rehandshake`, `RoomRejoin`, `StopStart`), topology shelving.
- **Channels** — typed pub/sub via `Channel<T>`.
- **RPC** — generic `Rpc::call` / `serve` / `call_stream` / `serve_stream`.
- **Facade** — `Mesh` → `MeshHandle` → `JoinedNetwork`.

## Public API tour

```rust
use myownmesh_core::{Mesh, MeshConfig, NetworkConfig, TopologyMode};

let mesh = Mesh::open(MeshConfig::default()).await?;
let net = mesh.join(NetworkConfig { /* ... */ }).await?;
let chan = net.channel::<MyMessage>("my-channel");
let rpc  = net.rpc();
```

Full surface: `Mesh`, `MeshHandle`, `JoinedNetwork`, `MeshConfig`,
`NetworkConfig`, `TopologyMode`, `Identity`, `DeviceId`, `Roster`,
`AuthorizedPeer`, `MeshEvent`, `PeerEvent`, `MeshPhase`,
`DiagEntry`, `CapabilityAdvert`, `ConnectionTier`, `Channel`,
`ChannelMessage`, `ChannelError`, `Rpc`, `RpcCall`, `RpcResponse`,
`RpcError`. Helpers: `generate_network_id`, `normalize_network_id`.
Constants: `SIGN_DOMAIN_TAG`, `TRYSTERO_APP_ID`, `PROTOCOL_VERSION`.

See [`../../docs/QUICKSTART.md`](../../docs/QUICKSTART.md) for the
narrative walkthrough — identity, channels, RPC, roster,
topology, shutdown.

## Persistent state

```
~/.myownmesh/
├── .secrets/identity.json       (0600 — ed25519 keypair)
└── mesh/rosters/{network_id}.json  (0600 — per-network approved peers)
```

Override the root via `MYOWNMESH_HOME=~/.youapp/mesh` so embedders
keep their state under their own directory tree.

## Tests

```
cargo test -p myownmesh-core
```

Includes [`tests/two_peer_handshake.rs`](tests/two_peer_handshake.rs) —
two ephemeral identities, joined the same network via the in-process
broker, full handshake + typed channel exchange end-to-end.
