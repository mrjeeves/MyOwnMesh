<div align="center">

# MyOwnMesh

### A private mesh network you actually own — pure Rust, embed it in anything.

[Quick start](docs/QUICKSTART.md) · [Protocol](docs/PROTOCOL.md) · [Architecture](ARCHITECTURE.md) · [Connection engine](CONNECTION-ENGINE.md) · [Contributing](CONTRIBUTING.md) · [Releases](https://github.com/mrjeeves/MyOwnMesh/releases)

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/macOS_·_Linux_·_Windows_·_Pi-2ea44f.svg)](#platforms)
[![Tests](https://img.shields.io/badge/tests-285_passing-2ea44f.svg)](crates/myownmesh-core/tests)

</div>

## One workspace, three personas

```
myownmesh                # headless daemon + CLI                   (bin: crates/myownmesh)
myownmesh-core           # library — runtime, engine, protocol      (lib: crates/myownmesh-core)
myownmesh-gui            # desktop GUI (Tauri + Svelte 5)            (app: gui/)
```

Plus three supporting library crates the daemon and embedders share:

```
myownmesh-signaling      # Nostr signaling driver + LocalBroker + self-hosted NIP-01 relay
myownmesh-services       # self-hosted STUN + TURN servers
myownmesh-updater        # self-update with configurable release feed
```

## Install

One command — detects platform, fetches the binaries from
[GitHub Releases](https://github.com/mrjeeves/MyOwnMesh/releases),
verifies SHA-256, drops `myownmesh` **and** the `myownmesh-gui`
desktop app on your PATH (so a bare `myownmesh` opens the GUI).

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
The desktop GUI goes in by default — it's small and very handy;
pass `--no-gui` (Unix) or `-NoGui` (Windows) for a daemon-only
install on a headless box. The GUI binary relies on the system
webview (libwebkit2gtk / WebView2 / WKWebView); for full OS
integration (menu entry, icon) grab the `.deb` / `.AppImage` /
`.dmg` / `.msi` bundle from Releases instead. Pass `--serve` (Unix)
or `-Serve` (Windows) to launch the daemon once the install
finishes.

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

The [one-command install](#install) above already includes the GUI
binary, so a bare `myownmesh` opens it. For full OS integration,
pre-built installers (`.deb` / `.AppImage` / `.dmg` / `.msi` /
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
myownmesh-core      = { git = "https://github.com/mrjeeves/MyOwnMesh", tag = "v0.2.7" }
myownmesh-signaling = { git = "https://github.com/mrjeeves/MyOwnMesh", tag = "v0.2.7" }  # Nostr driver
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
        kind: Default::default(),                 // Open governance
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
just test        # cargo test --workspace        (285 tests today)
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
- **Recovery from reliable signals, not ICE guesswork.** webrtc-rs reports ICE `Connected` on dead relay paths and `Failed` on live ones, so the engine trusts only the data-channel open/close events and inbound-frame recency. A graduated ladder — Steady → Wake probe → ICE watchdog → in-place ICE restart (confirmed by inbound traffic, not by ICE state) → clean rebuild → stop-and-start — does the cheapest action that still recovers from the failure class above it, and never tears a live link down on an ICE-state blip. Every tunable constant is documented in [`CONNECTION-ENGINE.md`](CONNECTION-ENGINE.md) with the field bug it was discovered through.
- **Trystero-wire-compatible Nostr signaling.** Same room-handle derivation as JS Trystero v0.24 (`SHA-256(app_id || ":" || network_id)`), same deterministic relay shuffle. Eight published-fix patches against `@trystero-p2p/core` are baked in natively — catalogued in [`crates/myownmesh-signaling/src/upstream.rs`](crates/myownmesh-signaling/src/upstream.rs) so upstream-tracking is a code-level diff, not a patches/ folder.
- **Host your own infrastructure.** A device can be any combination of a mesh node and hosted services: a relay (roster-gated routing), an **intelligent signaling relay** (a NIP-01 server the built-in driver speaks to unchanged — with live presence, instant-departure coordination, and flood limits, so it's safe to run publicly), and STUN / TURN servers (RFC 5389 / 5766, the latter with a per-connection bandwidth cap). Turn off the node role for a **pure-infrastructure box**. Toggle everything from the GUI (Settings → Services), the CLI (`myownmesh ctl services …`), or `config.json`; hosts advertise their roles + endpoints so the fleet self-discovers them. This is what makes a **fully internet-isolated network** trivial — no Google STUN, no Cloudflare TURN, no public relay. See [`docs/SERVICES.md`](docs/SERVICES.md).
- **Selectable topologies.** Ring (default — sorted-lex with 2 neighbours + shortcuts), Star (explicit hub), FullMesh (everyone to everyone). All built on the same shelving primitive; both sides of every pair run the same pure-function selector over the same sorted input, so the result is symmetric without coordination.
- **Typed pub/sub + generic RPC over one data channel.** `Channel<T>` is a typed publish/subscribe channel keyed by name. `Rpc::call` / `serve` / `call_stream` / `serve_stream` is the generic request/response surface. Embedders define their own message types — the mesh treats payloads opaquely.
- **Embed without the GUI or updater.** The daemon, the library, and the desktop GUI are separate crates. An app embedding `myownmesh-core` doesn't pull in the HTTP self-updater or the Tauri stack. The GUI itself is a *client* of the daemon (over a local control socket) so crashing the UI never disturbs the running mesh.
- **One identity, many networks.** Per-device long-lived ed25519 keypair under `~/.myownmesh/.secrets/identity.json` (0600). Per-network rosters at `~/.myownmesh/mesh/rosters/{network_id}.json`. Switching the active network swaps rosters but preserves identity.

## Daemon + CLI

```sh
myownmesh                  # open the desktop GUI (myownmesh-gui)
myownmesh serve            # run the daemon in the foreground (headless)
myownmesh service install  # run serve as a background service (systemd/launchd)
myownmesh service status   # installed / enabled / running (start|stop|restart|uninstall)
myownmesh identity show    # print this device's id
myownmesh ctl status       # query a running daemon
myownmesh ctl networks list
myownmesh ctl networks join <id>    # join a network (defaults) — persist + attach live
myownmesh ctl networks leave <id>   # leave a network — detach + remove from config
myownmesh update           # update everything now (daemon + GUI), then restart
myownmesh update status    # version, channel, policy, staged update
myownmesh update check     # check the feed now and stage if permitted
myownmesh config edit      # open ~/.myownmesh/config.json in $EDITOR
myownmesh install caddy <domain>    # TLS reverse proxy (Caddy) in front of the signaling relay
myownmesh caddy path       # print the Caddyfile location to edit
```

A bare `myownmesh update` fetches the latest release and updates the
daemon **and** the desktop GUI together. The GUI ships as its own binary
beside the daemon, so the self-updater swaps both; restart afterwards to
run the new version. Everything the updater does is also a screen —
Settings → Updates — including the release-feed URL, so you can point a
fleet at your own release host (white-label) without rebuilding.

A bare `myownmesh` (no subcommand) opens the desktop GUI, which
auto-spawns the daemon for you. On a headless box
with no display it prints a pointer to `myownmesh serve` instead, so
servers run the daemon directly. Daemon reads `~/.myownmesh/config.json` (auto-created on first edit;
sensible defaults until then), joins every network listed there,
attaches the Nostr signaling driver per network, and listens for
`myownmesh ctl …` clients on a local socket
(`~/.myownmesh/daemon.sock` on Unix, named pipe on Windows). Full
reference in [`crates/myownmesh/README.md`](crates/myownmesh/README.md).

## Desktop GUI

A Tauri + Svelte 5 frontend in [`gui/`](gui/), running as a **client**
of the daemon — talks to `myownmesh serve` over the local control
socket, never embeds `myownmesh-core` directly. Crashing the UI
never disturbs the running mesh. Launch it with a bare `myownmesh`
(no subcommand) once the bundle is installed — the daemon binary
locates `myownmesh-gui` and hands off to it — or `just dev` from a
source checkout.

- **Node graph** — self at the centre, peers laid out by topology. Click a node (or pick it from the sidebar) for label / display suffix / RTT / capabilities; during pending approval the popup surfaces the per-session 6-char verification code as a tile for out-of-band confirmation.
- **Approvals tab** (default in Settings) — pending peer requests from every joined network flatten into one list with Approve / Deny inline.
- **Networks** — one home per network: Status · Settings (label, topology, signaling / STUN / TURN, auto-approve, export, remove) · Connections (live peer table) · Roster (approved devices + roles) · Governance (open ↔ closed, propose / sign / deny). The per-network gear in the sidebar jumps straight here.
- **Updates** — current version, the auto-update toggle and policy (channel + which version bumps apply on their own), any staged update, and the release-feed URL for white-labelling.
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
engine's recovery ladder, the Trystero-patch catalogue, the 6-char
verification-code UX, the per-network roster model — all of it was
field-tested inside MyOwnLLM first, then lifted into pure Rust and
generalised so any app that wants a peer-to-peer substrate can
embed it without inheriting the LLM stack. See
[`ARCHITECTURE.md`](ARCHITECTURE.md) for the crate-by-crate
relationship to the original TypeScript modules.

## More

[`docs/QUICKSTART.md`](docs/QUICKSTART.md) — embedder walkthrough ·
[`docs/PROTOCOL.md`](docs/PROTOCOL.md) — wire-protocol reference ·
[`docs/NETWORK-TYPES.md`](docs/NETWORK-TYPES.md) — open vs closed networks (role tiers, signed transitions, split + recovery) ·
[`ARCHITECTURE.md`](ARCHITECTURE.md) — crate layout, trust model, persistent state ·
[`CONNECTION-ENGINE.md`](CONNECTION-ENGINE.md) — the recovery ladder, every tunable ·
[`CONTRIBUTING.md`](CONTRIBUTING.md) — setup, conventions, testing ·
[`RELEASE.md`](RELEASE.md) — cutting a release ·
[`gui/README.md`](gui/README.md) — desktop GUI ·
Rustdoc: `cargo doc --workspace --no-deps --open` ·
[LICENSE](LICENSE) — MIT
