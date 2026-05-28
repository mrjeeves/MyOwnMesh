<div align="center">

# MyOwnMesh

### The peer-to-peer mesh underneath [MyOwnLLM](https://github.com/mrjeeves/MyOwnLLM) — pure Rust, embed it in anything.

[Quick start](docs/QUICKSTART.md) · [Protocol](docs/PROTOCOL.md) · [Architecture](ARCHITECTURE.md) · [Connection engine](CONNECTION-ENGINE.md) · [Contributing](CONTRIBUTING.md) · [Releases](https://github.com/mrjeeves/MyOwnMesh/releases)

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/macOS_·_Linux_·_Windows_·_Pi-2ea44f.svg)](#platforms)
[![Tests](https://img.shields.io/badge/tests-98_passing-2ea44f.svg)](crates/myownmesh-core/tests)

</div>

## One workspace, three personas

```
myownmesh                # headless daemon + CLI                   (bin: crates/myownmesh)
myownmesh-core           # library — runtime, engine, protocol      (lib: crates/myownmesh-core)
myownmesh-gui            # desktop GUI (Tauri + Svelte 5)            (app: gui/)
```

Plus two supporting library crates the daemon and embedders share:

```
myownmesh-signaling      # Nostr signaling driver + in-process LocalBroker
myownmesh-updater        # self-update with configurable release feed
```

## Install

One command — detects platform, fetches the binary from
[GitHub Releases](https://github.com/mrjeeves/MyOwnMesh/releases),
verifies SHA-256, drops `myownmesh` on your PATH.

```sh
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/mrjeeves/MyOwnMesh/main/scripts/install.sh | sh
```

```powershell
# Windows
irm https://raw.githubusercontent.com/mrjeeves/MyOwnMesh/main/scripts/install.ps1 | iex
```

The installer writes to `/usr/local/bin` (or `~/.local/bin` if not
writable) on Unix and `%LOCALAPPDATA%\Programs\MyOwnMesh` on
Windows, and adds the directory to PATH if it isn't already there.
Pass `--serve` (Unix) or `-Serve` (Windows) to launch the daemon
once the install finishes. `myownmesh update` self-applies later
releases against the same artifacts.

Prefer a tarball directly? The portable binaries
(`myownmesh-<platform>.{tar.gz,zip}` + `.sha256` sidecar) are on
[Releases](https://github.com/mrjeeves/MyOwnMesh/releases) for the
five platforms in the [matrix](#platforms).

## Get started

Pick the persona that matches what you're doing — none of them
depend on each other, so any combination works on the same box.

### 1. Run a node (build from source)

```bash
git clone https://github.com/mrjeeves/MyOwnMesh
cd MyOwnMesh
just setup                                    # Rust toolchain via rustup
cargo install --path crates/myownmesh         # daemon + CLI on $PATH
# or run without installing:
cargo run -p myownmesh -- serve
# or with debug logging:
just serve                                    # MYOWNMESH_LOG=debug cargo run -p myownmesh -- serve
```

### 2. Run the desktop GUI

Pre-built installers (`.deb` / `.AppImage` / `.dmg` / `.msi` /
`.exe`) ship in the same [GitHub Releases](https://github.com/mrjeeves/MyOwnMesh/releases)
as the daemon. The GUI auto-spawns the daemon as a child process,
so installing only the GUI bundle gets you both.

From source, two shells:

```bash
just serve   # one shell — daemon + control socket (with debug logging)
just dev     # another shell — Tauri GUI with hot reload
```

Or without `just`:

```bash
cargo run -p myownmesh -- serve           # one shell
cd gui && pnpm install && pnpm tauri dev  # another shell
```

For a release build of the GUI: `cd gui && pnpm tauri build`.

### 3. Embed in your Rust app (library)

The library crates aren't on crates.io yet — pull them as git
dependencies pinned to a release tag. Cargo dedupes git deps by URL,
so both crates resolve out of the same checkout:

```toml
[dependencies]
myownmesh-core      = { git = "https://github.com/mrjeeves/MyOwnMesh", tag = "v0.1.0" }
myownmesh-signaling = { git = "https://github.com/mrjeeves/MyOwnMesh", tag = "v0.1.0" }  # Nostr driver
tokio = { version = "1", features = ["full"] }
```

```rust
use myownmesh_core::{Mesh, MeshConfig, NetworkConfig, TopologyMode};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mesh = Mesh::open(MeshConfig::load().unwrap_or_default()).await?;

    let net = mesh.join(NetworkConfig {
        id: "home".into(),
        network_id: "my-cool-mesh".into(),
        label: "Home mesh".into(),
        topology: TopologyMode::default(),       // Ring
        signaling: Default::default(),            // Nostr defaults
        stun_servers: Default::default(),
        turn_servers: Default::default(),
        roster_path: None,
        auto_approve: false,
    }).await?;

    let _nostr = myownmesh_core::engine::attach_nostr(&net.state());

    let mut events = mesh.events();
    while let Ok(event) = events.recv().await {
        println!("{event:?}");
    }
    Ok(())
}
```

Three other supported dependency shapes:

```toml
# Track the latest work (no API stability guarantees between commits).
myownmesh-core = { git = "https://github.com/mrjeeves/MyOwnMesh", branch = "main" }

# Pin to an exact commit for build reproducibility.
myownmesh-core = { git = "https://github.com/mrjeeves/MyOwnMesh", rev = "86e6736" }

# Sibling-directory monorepo / vendored checkout.
myownmesh-core = { path = "../MyOwnMesh/crates/myownmesh-core" }
```

Override `MYOWNMESH_HOME=~/.youapp/mesh` to keep your app's identity
+ rosters under its own directory tree (defaults to
`~/.myownmesh/`). Narrative walkthrough:
[`docs/QUICKSTART.md`](docs/QUICKSTART.md).

### 4. Try it without leaving the workspace

Two ephemeral peers exchange a full handshake + a typed channel
message in-process via the LocalBroker — no Nostr relays, no
network, no installation:

```bash
git clone https://github.com/mrjeeves/MyOwnMesh
cd MyOwnMesh
cargo test -p myownmesh-core --test two_peer_handshake -- --nocapture
```

The runnable examples cover the three common embedder shapes:

```bash
cargo run --example two_peer_chat -p myownmesh-core   # typed channel
cargo run --example echo_rpc      -p myownmesh-core   # generic RPC
cargo run --example roster_demo   -p myownmesh-core   # approve / persist / reconnect
```

### 5. Hack on the workspace

```bash
just setup       # Rust toolchain via rustup (idempotent)
just build       # cargo build --workspace
just test        # cargo test --workspace        (98 tests today)
just check       # fmt + clippy -D warnings + test
just fmt         # cargo fmt --all
just lint        # cargo clippy --workspace --all-targets -- -D warnings
```

CI runs `fmt --check`, `clippy -D warnings`, and the full test suite
across `linux-x86_64`, `macos-aarch64`, `windows-x86_64`. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for code conventions, the
protocol-message checklist, and the topology-mode checklist.

## What it gives you

- **ed25519 mutual auth, with eyeballs.** Every peer encounter exchanges a `hello` + `auth_response` where each side signs the other's nonce under `myownmesh-mesh-auth-v1:`. A 6-char `[a-z0-9]` verification code rides along for out-of-band confirmation ("the code I see matches what you read me"). Approved peers land in a per-network roster and skip the prompt on reconnect.
- **A 7-tier reconnection ladder.** Steady → Wake probe → ICE watchdog → ICE restart → Re-handshake → Room rejoin → Stop-and-start. Each tier is the cheapest action that still recovers from the failure class above it. Every tunable constant is documented in [`CONNECTION-ENGINE.md`](CONNECTION-ENGINE.md) with the field bug it was discovered through.
- **Trystero-wire-compatible Nostr signaling.** Same room-handle derivation as JS Trystero v0.24 (`SHA-256(app_id || ":" || network_id)`), same deterministic relay shuffle. Five published-fix patches against `@trystero-p2p/core` are baked in natively — catalogued in [`crates/myownmesh-signaling/src/upstream.rs`](crates/myownmesh-signaling/src/upstream.rs) so upstream-tracking is a code-level diff, not a patches/ folder.
- **Selectable topologies.** Ring (default — sorted-lex with 2 neighbours + shortcuts), Star (explicit hub), FullMesh (everyone to everyone). All built on the same shelving primitive; both sides of every pair run the same pure-function selector over the same sorted input, so the result is symmetric without coordination.
- **Typed pub/sub + generic RPC over one data channel.** `Channel<T>` is a typed publish/subscribe channel keyed by name. `Rpc::call` / `serve` / `call_stream` / `serve_stream` is the generic request/response surface. Embedders define their own message types — the mesh treats payloads opaquely.
- **Embed without the GUI or updater.** The daemon, the library, and the desktop GUI are separate crates. An app embedding `myownmesh-core` doesn't pull in the HTTP self-updater or the Tauri stack. The GUI itself is a *client* of the daemon (over a local control socket) so crashing the UI never disturbs the running mesh.
- **One identity, many networks.** Per-device long-lived ed25519 keypair under `~/.myownmesh/.secrets/identity.json` (0600). Per-network rosters at `~/.myownmesh/mesh/rosters/{network_id}.json`. Switching the active network swaps rosters but preserves identity.

## Daemon + CLI

```sh
myownmesh                  # start the daemon (alias for `serve`)
myownmesh serve            # run the daemon in foreground
myownmesh identity show    # print this device's id
myownmesh ctl status       # query a running daemon
myownmesh ctl networks list
myownmesh update check     # poll the release feed
myownmesh config edit      # open ~/.myownmesh/config.json in $EDITOR
```

Daemon reads `~/.myownmesh/config.json` (auto-created on first edit;
sensible defaults until then), joins every network listed there,
attaches the Nostr signaling driver per network, and listens for
`myownmesh ctl …` clients on a local socket
(`~/.myownmesh/daemon.sock` on Unix, named pipe on Windows). Full
reference in [`crates/myownmesh/README.md`](crates/myownmesh/README.md).

## Desktop GUI

A Tauri + Svelte 5 frontend in [`gui/`](gui/), running as a **client**
of the daemon — talks to `myownmesh serve` over the local control
socket, never embeds `myownmesh-core` directly. Crashing the UI
never disturbs the running mesh.

- **Node graph** — self at the centre, peers laid out by topology, click a node for label / display suffix / RTT / capabilities. During pending approval the popup surfaces the per-session 6-char verification code as a tile for out-of-band confirmation.
- **Approvals tab** (default in Settings) — pending peer requests from every joined network flatten into one list with Approve / Deny inline.
- **Networks** — Status (topology selector + per-network rollup) · Connections (live peer table) · Roster (approved devices).
- **Activity** — unified event log: peer state transitions, phase changes, ICE / handshake / signaling diagnostics. Quiet toggle suppresses info-level chatter; warns and errors always land.

Layout / wire protocol in [`gui/README.md`](gui/README.md).

## Platforms

`linux-x86_64` · `linux-aarch64` (incl. Raspberry Pi 4 / 5) ·
`macos-aarch64` · `macos-x86_64` · `windows-x86_64`. The release
matrix builds and uploads bundles for all five. Linux is pinned to
Ubuntu 22.04 (glibc 2.35) so binaries run on Debian 12, Ubuntu
22.04+, and other distros still on glibc 2.35/2.36/2.38.

## Lineage

MyOwnMesh started as [MyOwnLLM](https://github.com/mrjeeves/MyOwnLLM)'s
`src/mesh-*.ts` + `src-tauri/src/mesh/` substrate. The connection
engine's seven tiers, the Trystero-patch catalogue, the 6-char
verification-code UX, the per-network roster model — all of it was
field-tested inside MyOwnLLM first, then lifted into pure Rust and
generalised so any app that wants a peer-to-peer substrate can
embed it without inheriting the LLM stack. See
[`ARCHITECTURE.md`](ARCHITECTURE.md) for the crate-by-crate
relationship to the original TypeScript modules.

## More

[`docs/QUICKSTART.md`](docs/QUICKSTART.md) — embedder walkthrough ·
[`docs/PROTOCOL.md`](docs/PROTOCOL.md) — wire-protocol reference ·
[`docs/NETWORK-TYPES.md`](docs/NETWORK-TYPES.md) — open vs closed networks (design, decisions locked, awaiting implementation) ·
[`ARCHITECTURE.md`](ARCHITECTURE.md) — crate layout, trust model, persistent state ·
[`CONNECTION-ENGINE.md`](CONNECTION-ENGINE.md) — the 7-tier ladder, every tunable ·
[`CONTRIBUTING.md`](CONTRIBUTING.md) — setup, conventions, testing ·
[`RELEASE.md`](RELEASE.md) — cutting a release ·
[`gui/README.md`](gui/README.md) — desktop GUI ·
Rustdoc: `cargo doc --workspace --no-deps --open` ·
[LICENSE](LICENSE) — MIT
