# Contributing to MyOwnMesh

Thanks for the interest. A short orientation:

## Setup

```
just setup       # installs Rust toolchain via rustup
just build       # cargo build --workspace
just check       # fmt + clippy -D warnings + tests
```

The pinned toolchain (`rust-toolchain.toml`) is 1.88.0.

## Repository layout

See `ARCHITECTURE.md` for the crate map and the engine module
breakdown. Short version:

- `crates/myownmesh-core` — runtime, engine, transport, protocol,
  topology, channels, RPC. The crate embedders depend on.
- `crates/myownmesh-signaling` — Nostr driver + in-process broker.
- `crates/myownmesh-updater` — self-update.
- `crates/myownmesh` — daemon + CLI.

## Workflow

1. Branch from `main`.
2. `just check` must pass before pushing.
3. Open a PR. CI runs `fmt --check`, `clippy -D warnings`, and the
   full test suite across linux-x86_64, macos-aarch64, and
   windows-x86_64.

## Code conventions

- **Edge cases are load-bearing.** The connection engine's timing
  constants and the Trystero patch behaviors were each discovered
  by a field bug. If you change one, update
  `CONNECTION-ENGINE.md` and
  `crates/myownmesh-signaling/src/upstream.rs` to match — and the
  commit message should explain which bug your change addresses.

- **Async sync primitives**: use `tokio::sync::*` for cross-task
  coordination, `parking_lot::*` for short critical sections inside
  a task. **Never hold a `parking_lot` guard across an `.await`** —
  the engine driver loop must stay `Send`.

- **Errors at API boundaries**: each lib crate has its own
  `thiserror` enum. `anyhow` lives only in the bin.

- **Comments explain WHY, not WHAT.** Well-named identifiers cover
  the WHAT. Reserve comments for hidden constraints, subtle
  invariants, and field-discovered workarounds.

- **Tests:**
  - Unit tests live alongside the code in `#[cfg(test)] mod tests`.
  - Integration tests live in `crates/myownmesh-core/tests/`.
  - When you add a tunable, add a test that pins its behavior in
    at least one extreme.

## Adding a new protocol message kind

1. Add the variant to `crates/myownmesh-core/src/protocol/`.
2. Add a discriminator entry in `MeshMessage` (with `#[serde(other)]`
   on `Unknown` ensuring forward-compat).
3. If the message is optional, add a feature id in
   `protocol/features.rs` and gate the sender on
   `peer_supports(...)`.
4. Wire dispatch in `engine/mod.rs::handle_inbound_frame`.
5. Document in `docs/PROTOCOL.md`.

## Adding a new topology mode

1. Add a variant to `TopologyMode` in `config.rs`.
2. Add a new file under `topology/` implementing the `Topology`
   trait.
3. Update `topology::from_mode` to construct your selector.
4. Add unit tests pinning the selector's behavior at both
   ends (smallest peer set, largest).

## Cutting a release

See `RELEASE.md`.

## Filing issues

If you hit a network blip the engine doesn't recover from cleanly,
the most useful artifact is the diag stream — set
`MYOWNMESH_LOG=debug,myownmesh=trace` and capture the output from
the start of the trouble through recovery. The `[trystero-patch]`
prefix in the logs corresponds to entries in
`crates/myownmesh-signaling/src/upstream.rs` — naming the entry in
your report saves diagnosis time.

## License

MIT. By contributing you agree your changes ship under the same.
