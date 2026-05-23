# MyOwnMesh

A pure-Rust peer-to-peer mesh networking stack on
[webrtc-rs](https://github.com/webrtc-rs/webrtc).

MyOwnMesh ships as both a **binary** (daemon + CLI) and a **library**
(`myownmesh-core`), so other apps embed the mesh without inheriting a
GUI or HTTP updater. ed25519 mutual auth with out-of-band verification
codes, per-network rosters, selectable topologies (Ring / Star /
FullMesh), Trystero-wire-compatible Nostr signaling, self-update with
configurable release feed.

Status: connection engine, WebRTC transport, typed channels, RPC, and
both in-process and Nostr signaling drivers are in. Two-peer
integration test exercises the full stack end-to-end (88 tests pass).

## Workspace

```
crates/
├── myownmesh-core         # lib  — runtime, engine, transport, protocol, topology
├── myownmesh-signaling    # lib  — Nostr signaling driver + local-broker for embedding
├── myownmesh-updater      # lib  — self-update with configurable release feed
└── myownmesh              # bin  — daemon + CLI
```

## Quick start (embedder)

```toml
[dependencies]
myownmesh-core = "0.1"
myownmesh-signaling = "0.1"   # only if you want the Nostr driver
tokio = { version = "1", features = ["full"] }
```

```rust
use myownmesh_core::{Mesh, MeshConfig, NetworkConfig, TopologyMode};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = MeshConfig::load().unwrap_or_default();
    let mesh = Mesh::open(cfg).await?;

    let net = mesh.join(NetworkConfig {
        id: "home".into(),
        network_id: "my-cool-mesh".into(),
        label: "Home mesh".into(),
        topology: TopologyMode::default(),                  // Ring
        signaling: Default::default(),                       // Nostr defaults
        stun_servers: Default::default(),
        turn_servers: Default::default(),
        roster_path: None,
        auto_approve: false,
    }).await?;

    // Attach the production signaling driver.
    let _nostr = myownmesh_core::engine::attach_nostr(&net.state());

    // Subscribe to mesh-wide events.
    let mut events = mesh.events();
    while let Ok(event) = events.recv().await {
        println!("{event:?}");
    }
    Ok(())
}
```

See `examples/` for runnable demos and `docs/QUICKSTART.md` for the
narrative walkthrough.

## Build

```
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Or with `just`:

```
just build       # cargo build --workspace
just test        # cargo test --workspace
just check       # fmt + clippy + test
just dev         # run the daemon in foreground with debug logging
```

## Documentation

- **`docs/QUICKSTART.md`** — embedder walkthrough: dependencies, identity, joining a network, channels, RPC.
- **`docs/PROTOCOL.md`** — complete wire-protocol reference (every `MeshMessage` variant + the handshake sequence).
- **`ARCHITECTURE.md`** — crate layout, trust model, topology, persistent state.
- **`CONNECTION-ENGINE.md`** — the 7-tier reconnection ladder, every tunable constant, every edge case the engine handles.
- **`CONTRIBUTING.md`** — local setup, code conventions, testing.
- **`RELEASE.md`** — cutting a release.
- **Per-crate `README.md`** in each `crates/*/` directory.
- **`crates/myownmesh-signaling/src/upstream.rs`** — catalogue of upstream-Trystero fixes baked into our Nostr driver natively.
- Rustdoc: `cargo doc --workspace --open`.

## License

MIT. See `LICENSE`.
