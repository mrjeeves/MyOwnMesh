# MyOwnMesh

An open-source peer-to-peer mesh networking stack, in pure Rust on
[webrtc-rs](https://github.com/webrtc-rs/webrtc).

MyOwnMesh ships as both a binary (daemon + CLI) and a library
(`myownmesh-core`), so other apps can embed the mesh without
inheriting a GUI or HTTP updater. Auto-update, Trystero-wire-
compatible Nostr signaling, ed25519 mutual auth with out-of-band
verification codes, per-network rosters, and selectable topologies
(Ring / Star / FullMesh).

Status: workspace skeleton + protocol types + topology selectors +
verbatim identity / signing / roster ports from MyOwnLLM are in.
The connection engine and WebRTC transport are next.

## Workspace

```
crates/
├── myownmesh-core         # lib   — runtime + protocol + topology
├── myownmesh-signaling    # lib   — Nostr signaling
├── myownmesh-updater      # lib   — self-update
└── myownmesh              # bin   — daemon + CLI
```

## Build

```
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Or with `just`:

```
just build
just test
just check
```

## Documentation

- `ARCHITECTURE.md` — crate layout, trust model, topology, state.
- `CONNECTION-ENGINE.md` — the 7-tier reconnection ladder, every
  tunable constant, and the edge cases the engine handles.
- `crates/myownmesh-signaling/src/upstream.rs` — catalogue of
  upstream-Trystero limitations our Nostr implementation works
  around natively.

## License

MIT. See `LICENSE`.
