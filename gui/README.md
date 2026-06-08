# MyOwnMesh GUI

Tauri + Svelte 5 visual frontend for the MyOwnMesh daemon. The GUI is a
**client** of the headless daemon (`myownmesh serve`) — it talks to the
daemon over the local control socket and never embeds `myownmesh-core`
directly. That keeps the engine's `cargo test --workspace` runs fast
and lets you crash-restart the UI without touching the running mesh.

## Layout

- **Top bar** — hamburger and gear both open Settings (two equally
  discoverable affordances); the identity chip on the right also
  opens Settings on the Identity tab. There is no daemon-connection
  pill — daemon-down is surfaced on the canvas empty state and in
  the Activity tab so it doesn't read as "online with peers."
- **Node graph** — central canvas. Self at the centre, peers laid out
  on a ring (Ring / FullMesh topology) or around the hub (Star
  topology). Colours encode peer status; edge style encodes link
  state. Click a node — or pick a peer in the sidebar — for detail.
  The detail popup includes the peer's stable display suffix (blue
  tile) and — during pending approval — the per-session verification
  code (amber tile) so approvals can be confirmed without leaving the
  graph.
- **Sidebar** — networks list. Each network expands to show its
  current members; click a peer to highlight it on the graph, click
  the per-network gear to jump to that network's settings, or the
  `+` in the header to open Networks settings. Always visible:
  networks are the primary navigation surface, so the sidebar isn't
  hideable.
- **Settings panel** — full-window tabbed panel.
  - **Approvals** *(default)* — pending peer requests across every
    joined network. Each row shows the peer's label, the stable
    display suffix (`-XXXXX`) in a blue tile, and the per-session
    6-char verification code in an amber tile. Approve / Deny
    inline. Empty state walks new users through how to get a peer
    here in the first place.
  - **Networks** — one home per saved network, chosen with a picker:
    Status (read-only overview) · Settings (label, topology,
    signaling / STUN / TURN, auto-approve, export, remove) ·
    Connections (per-peer table — *connections only*, no Approve
    action; pending approvals live in the Approvals tab) · Roster
    (approved devices + roles) · Governance (open ↔ closed kind +
    propose / sign / deny). The per-network gear in the sidebar
    opens straight here.
  - **Services** — host relay / signaling / STUN / TURN for the rest
    of the mesh; toggle each and edit its bind/port/limits.
  - **Updates** — current version, the auto-update toggle and policy
    (channel + which version bumps auto-apply + check interval), any
    staged update, and the release-feed URL (point a fleet at your
    own release host to white-label).
  - **Identity** — device pubkey / display id / daemon version.
  - **Activity** — live event-stream log spanning every category the
    daemon emits (peer state changes, phase transitions, ICE /
    handshake / signaling diagnostics), with a Quiet toggle that
    suppresses info-level chatter. Warnings and errors always land.

## Run

From the MyOwnMesh root:

```bash
just serve   # one shell — daemon + control socket
just dev     # another shell — Tauri GUI with hot reload
```

Or without `just`:

```bash
cargo run -p myownmesh -- serve           # one shell
cd gui && pnpm install && pnpm tauri dev  # another shell
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
