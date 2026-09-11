<div align="center">

# MyOwnMesh

### A private mesh network you actually own — pure Rust, embed it in anything.

[Quick start](docs/QUICKSTART.md) · [Protocol](docs/PROTOCOL.md) · [V4 architecture](ARCHITECTURE.md) · [Transition playbook](TRANSITION-PLAYBOOK.md) · [Connection field notes](CONNECTION-ENGINE-FIELD-NOTES.md) · [Contributing](CONTRIBUTING.md) · [Releases](https://github.com/mrjeeves/MyOwnMesh/releases)

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/macOS_·_Linux_·_Windows_·_Pi-2ea44f.svg)](#platforms)

</div>

> The owner-adopted V4 architecture is the target contract. Descriptions of
> current engine behavior elsewhere in this repository are migration evidence,
> not competing authority. See `ARCHITECTURE-OWNERSHIP.md` for the precedence
> rule and `CURRENT-TO-TARGET-MIGRATION-MATRIX.md` for preservation and deletion
> gates.

## One workspace, three personas

```
myownmesh                # headless daemon + CLI                   (bin: crates/myownmesh)
myownmesh-core           # library — runtime, engine, protocol      (lib: crates/myownmesh-core)
myownmesh-gui            # desktop GUI (Tauri + Svelte 5)            (app: gui/)
```

Plus three supporting library crates the daemon and embedders share:

```
myownmesh-signaling      # Nostr + mDNS/DNS-SD drivers + transport-lab LocalBroker + self-hosted NIP-01 relay
myownmesh-services       # self-hosted STUN + TURN servers
myownmesh-updater        # self-update with configurable release feed
```

## Install

The platform installer scripts can fetch a matching release artifact from
[GitHub Releases](https://github.com/mrjeeves/MyOwnMesh/releases), verify its
SHA-256 sidecar, and install the daemon and, when supplied, the GUI bundle.
Exact artifact and platform availability is release-dependent.
Fresh installation trusts GitHub TLS/account control and the published checksum;
the installer scripts do not verify minisign signatures and therefore do not
establish signing-key provenance. This is distinct from the compiled-key checks
performed by the shipped self-updater; see [Release signing](RELEASE-SIGNING.md).

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
The desktop GUI is included by default where the selected release provides
it; pass `--no-gui` (Unix) or `-NoGui` (Windows) for a daemon-only install on
a headless box. The GUI binary relies on the system
webview (libwebkit2gtk / WebView2 / WKWebView); for full OS
integration (menu entry, icon) grab the `.deb` / `.AppImage` /
`.dmg` / `.msi` bundle from Releases instead. Pass `--serve` (Unix)
or `-Serve` (Windows) to launch the daemon once the install
finishes.

Prefer a tarball directly? Portable binaries and their `.sha256` sidecars,
when published for a release, are listed on
[Releases](https://github.com/mrjeeves/MyOwnMesh/releases).

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

Arc 03 connector-capable daemon startup requires an explicit finite process
resource grant. The owner also selects whether optional local ceilings and
codec-neutral real-time ownership are enabled. Ordinary elastic construction
outside an explicitly bounded optional profile does not require static Mesh,
peer, attempt, queue, or flow counts. Hubs coordinate discovery and endpoint
connection setup. Application traffic uses authenticated endpoint WebRTC
connections, directly or through configured TURN; mesh members do not forward
application payloads. See [the quickstart policy input list](docs/QUICKSTART.md#2-open-the-mesh).
An explicitly non-participating infrastructure host needs no connector policy.

### 2. Run the desktop GUI

Where a release provides the GUI bundle, a bare `myownmesh` opens it. For
full OS integration, consult the release-specific platform artifacts. The
GUI auto-spawns the daemon as a child process when the selected bundle
includes that supported pairing.

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
dependencies pinned to the exact tag for the release you selected. Cargo
dedupes git dependencies by URL, so both crates resolve out of the same
checkout. Replace `vX.Y.Z` below with that release's tag:

```toml
[dependencies]
myownmesh-core      = { git = "https://github.com/mrjeeves/MyOwnMesh", tag = "vX.Y.Z" }
myownmesh-signaling = { git = "https://github.com/mrjeeves/MyOwnMesh", tag = "vX.Y.Z" }  # Nostr + mDNS drivers
tokio = { version = "1", features = ["full"] }
```

Start with the [embedding quickstart](docs/QUICKSTART.md) and the
[production bootstrap example](crates/myownmesh-core/examples/application_bootstrap.rs).
The application supplies its process resource grant, WebRTC profile, and
semantic storage policy. Production construction uses
`Mesh::open_connector_capable` with `WebRtcConnectorCapablePolicy`, then
`NetworkConfig::from_network_id_with_semantic_policy` and
`JoinedNetwork::attach_signaling`. Keep the caller runtime alive until the
network and its signaling drivers have completed shutdown.

Choose the integration surface that fits your application:

| Surface | Reference | Covers |
| --- | --- | --- |
| Rust embedding | [Application API](docs/APPLICATION-API.md) | Lifecycle, configuration, identity, governance, channels, RPC, opaque/realtime flows, events, errors, and resource ownership. |
| Separate application process | [Daemon API](docs/DAEMON-API.md) | Local control protocol, authentication, request/reply inventory, subscriptions, and administrative boundaries. |
| Application responsibilities | [Integration contract](APPLICATION-INTEGRATION.md) | Application authorization and payload semantics; discovery/setup versus endpoint data; conceptual views mapped to implemented APIs. |

The references distinguish ordinary application APIs, advanced provider and
administrative interfaces, internal seams, and `transport-lab` controls.
Authenticated peers still require the application's own authorization.
Hubs carry setup traffic only; application data uses endpoint WebRTC directly
or through configured standard TURN. Protected Hub TURN-credential exchange
is excluded from the 1.0.0 release.

Three other supported dependency shapes:

```toml
# Track the latest work (no API stability guarantees between commits).
myownmesh-core = { git = "https://github.com/mrjeeves/MyOwnMesh", branch = "main" }

# Pin to an exact commit for build reproducibility.
myownmesh-core = { git = "https://github.com/mrjeeves/MyOwnMesh", rev = "86e6736" }

# Sibling-directory monorepo / vendored checkout.
myownmesh-core = { path = "../MyOwnMesh/crates/myownmesh-core" }
```

Override `MYOWNMESH_HOME=~/.youapp/mesh` to keep your app's identity,
canonical semantic store, and roster UI projections under its own directory
tree (defaults to `~/.myownmesh/`). Narrative walkthrough:
[`docs/QUICKSTART.md`](docs/QUICKSTART.md).

### 4. Try it without leaving the workspace

The transport-lab control joins two ephemeral peers through `LocalBroker` and
exercises the bounded ingress, authentication, promotion, and typed-channel
path without claiming a production carrier:

```bash
git clone https://github.com/mrjeeves/MyOwnMesh
cd MyOwnMesh
cargo test -p myownmesh-core --features transport-lab --test two_peer_handshake -- --nocapture
```

The runnable examples cover the three common embedder shapes:

```bash
cargo run --example two_peer_chat -p myownmesh-core --features transport-lab   # typed channel
cargo run --example echo_rpc      -p myownmesh-core --features transport-lab   # generic RPC
cargo run --example roster_demo   -p myownmesh-core --features transport-lab   # approve / persist / reconnect
```

### 5. Hack on the workspace

```bash
just setup       # Rust toolchain via rustup (idempotent)
just build       # cargo build --workspace
just test        # cargo test --workspace
just check       # fmt + clippy -D warnings + test
just fmt         # cargo fmt --all
just lint        # cargo clippy --workspace --all-targets -- -D warnings
```

CI runs `fmt --check`, `clippy -D warnings`, and the full test suite
across `linux-x86_64`, `macos-aarch64`, `windows-x86_64`. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for code conventions, the
protocol-message checklist, and the topology-mode checklist.

## What it gives you

- **ed25519 mutual auth, with eyeballs.** Every peer encounter exchanges a `hello` + `auth_response`. Each proof signs the exact role-canonical, length-prefixed endpoint-authentication transcript — mesh context, selected profile, signer role, both Device identities, both fresh contributions, and both channel-binding fingerprints — under `myownmesh-endpoint-auth-v1:`. A 6-char `[a-z0-9]` verification code rides alongside for out-of-band confirmation ("the code I see matches what you read me"). Durable Closed authorization lives in the signed semantic graph; the per-network roster is only its UI/diagnostic projection.
- **Recovery from reliable signals, not ICE guesswork.** webrtc-rs reports ICE `Connected` on dead relay paths and `Failed` on live ones, so the engine trusts only the data-channel open/close events and inbound-frame recency. Its graduated sequence is Steady → Wake probe → ICE watchdog → in-place ICE restart (confirmed by inbound traffic, not by ICE state) → clean rebuild → stop-and-start. It uses the cheapest action that still recovers from the failure class above it and never tears a live link down on an ICE-state blip. The retained pre-V4 evidence for each tunable is in [`CONNECTION-ENGINE-FIELD-NOTES.md`](CONNECTION-ENGINE-FIELD-NOTES.md); V4 ownership and authority come from the canonical architecture documents.
- **Trystero-derived Nostr routing algorithms.** The room-handle derivation matches JS Trystero v0.24 (`SHA-256(app_id || ":" || network_id)`), and the deterministic relay shuffle follows the same algorithm. The strict V4 signaling envelope and recipient-tagged event shapes are MyOwnMesh's current wire and are not a Trystero interoperability claim. Eight upstream-derived fixes are catalogued in [`crates/myownmesh-signaling/src/upstream.rs`](crates/myownmesh-signaling/src/upstream.rs).
- **LAN discovery and signaling.** The signaling package includes mDNS/DNS-SD alongside its configured remote strategy. It advertises a network room handle and exchanges signaling data over the local transport when enabled. Backend, operating-system, and network availability remain deployment-dependent; configure `signaling.mdns` and the remote strategy explicitly for the intended environment. Details in [`crates/myownmesh-signaling/README.md`](crates/myownmesh-signaling/README.md).
- **Hosted infrastructure with separate control and data paths.** A device can host signaling, STUN and TURN as described in [Services](docs/SERVICES.md). Hubs coordinate discovery and endpoint setup. Application channels, RPC and native opaque flows use endpoint WebRTC sessions, directly or through configured TURN. No mesh-member application forwarding or signaling payload tunnel is provided.
- **Self-hosted signaling, STUN, and TURN.** The signaling server speaks the supported NIP-01 subset, while STUN and TURN provide their respective ICE services. Turn off the node role for a **pure-infrastructure box**. Hosted-service configuration and release-specific deployment limits are documented in [`docs/SERVICES.md`](docs/SERVICES.md).
- **Selectable topologies.** FullMesh is the default. Ring uses sorted peers with 2 immediate neighbours and deterministic shortcuts, while Star uses an explicit hub. Exact edge predicates are symmetric where the topology contract requires them; locally selected preferred or shortcut sets are deterministic but are not universally pairwise symmetric.
- **Typed pub/sub + generic RPC over one data channel.** `Channel<T>` is a typed publish/subscribe channel keyed by name. `Rpc::call` / `serve` / `call_stream` / `serve_stream` is the generic request/response surface. Embedders define their own message types — the mesh treats payloads opaquely.
- **Embed without the GUI or updater.** The daemon, the library, and the desktop GUI are separate crates. An app embedding `myownmesh-core` doesn't pull in the HTTP self-updater or the Tauri stack. The GUI itself is a *client* of the daemon (over a local control socket) so crashing the UI never disturbs the running mesh.
- **Appliance documentation.** Cross-building daemon-only musl artifacts is described in [`docs/NANOKVM.md`](docs/NANOKVM.md); availability depends on the selected release artifacts.
- **One identity, many networks.** A device keeps its long-lived ed25519 keypair under `~/.myownmesh/.secrets/identity.json` (0600). Each local network slot has a canonical signed semantic graph persisted under `~/.myownmesh/mesh/semantic/`; roster JSON under `~/.myownmesh/mesh/rosters/` is a non-authoritative UI projection. Switching networks preserves the Device identity while selecting the exact network's semantic context and projection.

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
myownmesh update           # attempt portable updates, daemon first; restart afterwards
myownmesh update status    # version, channel, policy, staged update
myownmesh update check     # check the feed now and stage if permitted
myownmesh config edit      # open ~/.myownmesh/config.json in $EDITOR
myownmesh install caddy <domain>    # signaling WSS + TURN TLS on 5349 (isolated loopback backend)
myownmesh caddy path       # print the Caddyfile location to edit
```

A bare `myownmesh update` targets the latest release for installed portable
components, applying the daemon first and the GUI separately, not atomically.
GUI staging and replacement are best-effort; a failed staged GUI replacement
remains pending for retry, so versions may differ until it succeeds. Restart
afterwards to run the updated binaries. Package-manager installs and full
desktop bundles remain owned by their package manager or installer.
Settings → Updates includes the release-feed URL. A runtime mirror must serve
GitHub-release-shaped JSON and artifacts signed by the updater's compiled trusted
key; changing the URL does not change that key. A vendor signing key requires a
rebuild, not merely a white-label URL override. See [Release signing](RELEASE-SIGNING.md)
for the limits of key rotation.

A bare `myownmesh` (no subcommand) opens the desktop GUI, which
auto-spawns the daemon for you. On a headless box
with no display it prints a pointer to `myownmesh serve` instead, so
servers run the daemon directly. Daemon reads `~/.myownmesh/config.json` (auto-created on first edit;
sensible defaults until then), joins every network listed there,
attaches the signaling drivers per network (Nostr, plus mDNS/DNS-SD
LAN discovery on by default), and listens for
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
- **Networks** — one home per network: Status · Settings (label, topology, signaling / STUN / TURN, auto-approve, export, remove) · Connections (live peer table) · Roster (approved devices + roles) · network policy controls. The per-network gear in the sidebar jumps straight here.
- **Updates** — current version, the auto-update toggle and policy (channel + which version bumps apply on their own), any staged update, and a compatible release-feed mirror URL; the compiled signing trust key is unchanged.
- **Activity** — unified event log: peer state transitions, phase changes, ICE / handshake / signaling diagnostics. Quiet toggle suppresses info-level chatter; warns and errors always land.

Layout / wire protocol in [`gui/README.md`](gui/README.md).

## Platforms

Source and release support are platform-specific. Consult the selected
release artifacts and the installer for the available desktop, daemon, and
appliance targets; the repository's cross-build notes are in
[`docs/NANOKVM.md`](docs/NANOKVM.md). This README does not infer runtime,
installer, or mDNS coverage for a platform from source presence alone.

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
[`docs/NETWORK-TYPES.md`](docs/NETWORK-TYPES.md) — open vs closed networks and role tiers ·
[`docs/NANOKVM.md`](docs/NANOKVM.md) — cross-building the daemon for a NanoKVM (riscv64 + musl) or NanoKVM-Pro (aarch64 + musl) ·
[`ARCHITECTURE.md`](ARCHITECTURE.md) — crate layout, trust model, persistent state ·
[`CONNECTION-ENGINE-FIELD-NOTES.md`](CONNECTION-ENGINE-FIELD-NOTES.md): retained recovery evidence and tunables ·
[`CONTRIBUTING.md`](CONTRIBUTING.md) — setup, conventions, testing ·
[`RELEASE.md`](RELEASE.md) — cutting a release ·
[`gui/README.md`](gui/README.md) — desktop GUI ·
Rustdoc: `cargo doc --workspace --no-deps --open` ·
[LICENSE](LICENSE) — MIT
