# MyOwnMesh GUI

Tauri + Svelte 5 visual frontend for the MyOwnMesh daemon. The GUI is a
**client** of the headless daemon (`myownmesh serve`) — it talks to the
daemon over the local control socket and never embeds `myownmesh-core`
directly. That keeps the engine's `cargo test --workspace` runs fast
and lets you crash-restart the UI without touching the running mesh.

## Layout

- **Node graph** — central canvas. Self at the centre, peers laid out
  on a ring (Ring / FullMesh topology) or around the hub (Star
  topology). Colours encode peer status; edge style encodes link
  state. Click a node for detail.
- **Sidebar** — networks list. Each network expands to show its
  current members, click a peer to highlight it on the graph, click
  the `+` to open Networks settings.
- **Settings overlay** — full-window tabbed panel.
  - **Networks** — Status (topology selector + per-network rollup) ·
    Connections (per-peer table with Approve action) · Roster
    (approved devices).
  - **Identity** — device pubkey / display id / daemon version.
  - **Diagnostics** — live event-stream log with level filter.

## Run

```bash
# In another shell:
cd ../   # MyOwnMesh root
cargo run -p myownmesh -- serve

# Then back here:
cd gui
pnpm install
pnpm tauri dev
```

The dev server (vite) runs on port 1421 by default; `pnpm tauri dev`
launches the desktop window and pipes vite's HMR through.

For a release build:

```bash
pnpm tauri build
```

## Wire protocol

The GUI's Tauri backend (`src-tauri/src/control_client.rs`) speaks the
daemon's line-delimited JSON control protocol — same wire shape as
the `myownmesh ctl …` CLI. See
`MyOwnMesh/crates/myownmesh/src/control.rs` for the request/response
catalogue.

In addition to the one-shot ops the CLI uses, the GUI subscribes to a
streaming `events_subscribe` op that converts the connection into a
one-way push channel. Each `MeshEvent` becomes a `mesh://event` Tauri
event on the frontend, which `mesh-client.svelte.ts` ingests and
turns into reactive Svelte 5 state.
