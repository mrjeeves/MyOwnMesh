# MyOwnMesh — one-command operations.
# Install `just` (https://just.systems) then run `just setup` to get going.

# `set shell` is used on Linux/macOS. On Windows the global
# `windows-shell` override routes recipes through PowerShell. Recipes
# with bash-specific syntax need a `[windows]` variant; recipes that
# just call cross-platform tools (cargo, git) work in both shells
# unmodified.
set shell := ["bash", "-cu"]
set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]

default: help

help:
    @just --list

# Install dev prerequisites. The daemon is pure Rust, but the GUI is a
# Tauri + Svelte app, so this also pulls the WebKitGTK/GTK libs, Node,
# and pnpm that `just dev` needs.
[unix]
[doc("Install dev prerequisites (GTK/WebKit libs, Rust, Node, pnpm).")]
setup:
    @./scripts/bootstrap.sh

[windows]
[doc("Install dev prerequisites (Rust, Node, pnpm, Tauri deps).")]
setup:
    @& .\scripts\bootstrap.ps1

build:
    @cargo build --workspace

build-release:
    @cargo build --workspace --release

# One-time: add the riscv64 musl Rust target + the Zig-based cross toolchain.
# We build with cargo-zigbuild (Zig = C compiler + linker), NOT the device's
# Sophgo C906 gcc: its vendor ISA (rv64imafdcv0p7xthead) can't be linked against
# rustc's standard rv64gc objects — see .cargo/config.toml. Zig is the most
# reliable way to get a standard rv64gc musl toolchain anywhere. Install zig via
# your package manager (`brew install zig`, `apt install zig`) or `pip install
# ziglang`; see docs/NANOKVM.md.
setup-risc:
    @rustup target add riscv64gc-unknown-linux-musl
    @command -v cargo-zigbuild >/dev/null 2>&1 || cargo install cargo-zigbuild --locked
    @command -v zig >/dev/null 2>&1 \
        && echo "zig OK: $(zig version)" \
        || echo "NOTE: 'zig' not on PATH — install it ('brew install zig', 'apt install zig', or 'pip install ziglang'). See docs/NANOKVM.md."

# Cross-build *just the daemon* for the NanoKVM SoC (Sophgo SG2002, T-Head
# C906, riscv64 + musl) so a KVM can run a real MyOwnMesh node. Only the
# `myownmesh` daemon is built — not the GUI — and myownmesh-core is pure Rust
# (ring + rustls, no OpenSSL), so the lone native dep is ring's riscv64 asm,
# which Zig cross-compiles cleanly into a static musl binary. The KVM ships this
# binary beside NanoKVM-Server; its Go mesh bridge then speaks to it over
# $MYOWNMESH_HOME/daemon.sock. See docs/NANOKVM.md.
build-risc: setup-risc
    @cargo zigbuild --release --bin myownmesh --target riscv64gc-unknown-linux-musl

# Back-compat alias for the original recipe name.
alias build-nanokvm := build-risc

# Run the GUI (Tauri + Svelte) with hot reload. The GUI auto-spawns
# the daemon as a child process, so this is the only command you
# need for a normal dev session. We pre-build the daemon binary so
# the GUI's spawn step finds something ready to launch; subsequent
# runs hit cargo's incremental cache and finish in seconds.
[unix]
[doc("Run the GUI with hot reload. Auto-spawns the daemon.")]
dev *ARGS:
    @cargo build -p myownmesh
    @cd gui && pnpm install --silent && pnpm tauri dev {{ARGS}}

[windows]
[doc("Run the GUI with hot reload. Auto-spawns the daemon.")]
dev *ARGS:
    @cargo build -p myownmesh
    @cd gui; pnpm install --silent; pnpm tauri dev {{ARGS}}

# Run the daemon in the foreground. The GUI's `just dev` connects to this
# over the control socket.
#
# Logging uses the daemon's *tuned default* filter (our crates at info,
# one clean line per connection event, with the webrtc-rs sibling crates
# pinned to error) plus our own binary at debug — set via MYOWNMESH_LOG_EXTRA
# so it *appends* to that default. A bare `MYOWNMESH_LOG="debug,…"` would
# instead *replace* the default and un-pin webrtc-rs, turning the console into
# an unreadable ICE firehose (a single loopback connection: 24 lines clean vs
# 173 with 107 DEBUG lines un-pinned). So we also clear any MYOWNMESH_LOG the
# caller has exported — otherwise a stray one inherited from the shell (or a
# past experiment) would silently override MYOWNMESH_LOG_EXTRA and re-open the
# firehose. For candidate-level engine/signaling detail (still webrtc-quiet),
# use `just serve-trace`; for full raw control, run `cargo run --bin myownmesh
# -- serve` with your own MYOWNMESH_LOG.
[unix]
[doc("Run the daemon in foreground (clean default logs; use serve-trace for detail).")]
serve *ARGS:
    @env -u MYOWNMESH_LOG MYOWNMESH_LOG_EXTRA="myownmesh=debug" cargo run --bin myownmesh -- serve {{ARGS}}

[windows]
[doc("Run the daemon in foreground (clean default logs; use serve-trace for detail).")]
serve *ARGS:
    @Remove-Item Env:\MYOWNMESH_LOG -ErrorAction SilentlyContinue; $env:MYOWNMESH_LOG_EXTRA = "myownmesh=debug"; cargo run --bin myownmesh -- serve {{ARGS}}

# Run the daemon standalone with connection-state tracing on — the
# reliable way to capture detailed connection logs on EVERY OS. On
# Windows the windowless GUI can't forward the daemon's stdout, so
# `just dev` shows nothing there; run this in a terminal instead. If
# you also want the GUI, run `just dev` in another terminal — it
# detects this daemon on the control socket and attaches rather than
# spawning (and silencing) its own. MYOWNMESH_CONN_TRACE=1 turns on
# the per-peer connection tracer; the filter keeps engine + signaling
# detail without the full webrtc-ice firehose (add webrtc_ice=debug
# when you need candidate-level detail).
[unix]
[doc("Daemon standalone with connection tracing on (detailed logs on every OS).")]
serve-trace *ARGS:
    @env -u MYOWNMESH_LOG MYOWNMESH_CONN_TRACE=1 MYOWNMESH_LOG_EXTRA="myownmesh=debug,myownmesh_core=debug,myownmesh_signaling=debug" cargo run --bin myownmesh -- serve {{ARGS}}

[windows]
[doc("Daemon standalone with connection tracing on (detailed logs on every OS).")]
serve-trace *ARGS:
    @Remove-Item Env:\MYOWNMESH_LOG -ErrorAction SilentlyContinue; $env:MYOWNMESH_CONN_TRACE = "1"; $env:MYOWNMESH_LOG_EXTRA = "myownmesh=debug,myownmesh_core=debug,myownmesh_signaling=debug"; cargo run --bin myownmesh -- serve {{ARGS}}

# Stream a network's connection-state trace as JSONL — one ConnTrace
# per line. Needs a running daemon (`just serve-trace`, or any
# `myownmesh serve`). Redirect to a per-machine file and feed the
# files to scripts/merge-traces.py for one cross-machine timeline:
#   just trace home > trace-$(hostname).jsonl
trace NETWORK:
    @cargo run --bin myownmesh -- ctl trace {{NETWORK}}

run *ARGS:
    @cargo run --release --bin myownmesh -- {{ARGS}}

fmt:
    @cargo fmt --all

lint:
    @cargo clippy --workspace --all-targets -- -D warnings

test:
    @cargo test --workspace --no-fail-fast

check:
    @cargo fmt --all --check
    @cargo clippy --workspace --all-targets -- -D warnings
    @cargo test --workspace --no-fail-fast

# Cut a release: bump every crate's version, commit, push, then push
# the `v{{VERSION}}` tag to trigger the workflow. Mirrors MyOwnLLM's
# flow — the user runs `just release 0.2.0` and the release.yml workflow
# verifies manifests, builds per-platform bundles, and publishes the
# GitHub release. Bash script — release flow runs from a Linux/macOS box.
#
# We trigger by pushing the tag (not `gh workflow run`) so the build is
# deterministic. The tag is an immutable ref pinned to the bump commit, so
# the workflow's `actions/checkout` lands exactly on the version we just
# committed. The old `gh workflow run release.yml` used workflow_dispatch,
# which resolves `main` at dispatch time and raced the preceding `git push`:
# GitHub could still see the pre-bump HEAD, check that out, build the old
# version, and fail the "Verify tag matches manifest versions" gate (this
# bit AllMyStuff's v0.1.21 release). release.yml keeps its workflow_dispatch
# trigger as a manual escape hatch for re-running an existing tag.
[unix]
[doc("Cut a release: bump versions, commit, push, tag to trigger the workflow.")]
release VERSION:
    @./scripts/bump-version.sh {{VERSION}}
    @if ! git diff --quiet Cargo.toml Cargo.lock gui/src-tauri/Cargo.toml gui/src-tauri/Cargo.lock gui/package.json; then \
        git add Cargo.toml Cargo.lock crates/*/Cargo.toml gui/src-tauri/Cargo.toml gui/src-tauri/Cargo.lock gui/package.json; \
        git commit -m "chore(release): {{VERSION}}"; \
    fi
    @git push
    @git tag v{{VERSION}}
    @git push origin v{{VERSION}}
    @echo ""
    @echo "✓ pushed tag v{{VERSION}} — the release workflow is building."
    @echo "  watch it:   gh run watch"
    @echo "  list runs:  gh run list --workflow=release.yml"
