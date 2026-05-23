# myownmesh-core

The mesh runtime. Embedders depend on this crate.

```toml
myownmesh-core = "0.1"
```

## What's in here

- **Identity** — long-lived ed25519 keypair, base32-lowercase device id.
- **Roster** — per-network approved-peers file (0600).
- **Wire protocol** — `MeshMessage` variants, capability matrix.
- **Topology** — Ring (default) / Star / FullMesh selectors. Pure functions; symmetric across peers.
- **Transport** — webrtc-rs wrapper. `PeerSession` per peer, event mpsc the engine drains.
- **Engine** — hello → auth_response handshake, ping/pong heartbeat, 7-tier reconnection ladder (`Steady`, `WakeProbe`, `IceWatchdog`, `IceRestart`, `Rehandshake`, `RoomRejoin`, `StopStart`), topology shelving.
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

See `docs/QUICKSTART.md` at the repo root for the narrative
walkthrough.

## Tests

```
cargo test -p myownmesh-core
```

Includes `tests/two_peer_handshake.rs` — two ephemeral identities,
joined the same network via the in-process broker, full handshake
+ typed channel exchange end-to-end.
