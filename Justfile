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

# Install Rust toolchain via rustup if missing.
[unix]
[doc("Install dev prerequisites (Rust via rustup).")]
setup:
    @./scripts/bootstrap.sh

[windows]
[doc("Install dev prerequisites (Rust via rustup).")]
setup:
    @& .\scripts\bootstrap.ps1

build:
    @cargo build --workspace

build-release:
    @cargo build --workspace --release

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

# Run the daemon in the foreground with debug logging. The GUI's
# `just dev` connects to this over the control socket.
[unix]
[doc("Run the daemon in foreground with debug logging.")]
serve *ARGS:
    @MYOWNMESH_LOG="debug,myownmesh=debug" cargo run --bin myownmesh -- serve {{ARGS}}

[windows]
[doc("Run the daemon in foreground with debug logging.")]
serve *ARGS:
    @$env:MYOWNMESH_LOG = "debug,myownmesh=debug"; cargo run --bin myownmesh -- serve {{ARGS}}

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

# Cut a release: bump every crate's version, commit, push, trigger
# the workflow. Mirrors MyOwnLLM's flow — the user runs
# `just release 0.2.0` and the release.yml workflow runs to verify
# manifests, build per-platform bundles, and publish the GitHub
# release. Bash script — release flow runs from a Linux/macOS box.
[unix]
[doc("Cut a release: bump versions, commit, push, trigger the workflow.")]
release VERSION:
    @./scripts/bump-version.sh {{VERSION}}
    @if ! git diff --quiet Cargo.toml Cargo.lock gui/src-tauri/Cargo.toml gui/src-tauri/Cargo.lock gui/package.json; then \
        git add Cargo.toml Cargo.lock crates/*/Cargo.toml gui/src-tauri/Cargo.toml gui/src-tauri/Cargo.lock gui/package.json; \
        git commit -m "chore(release): {{VERSION}}"; \
    fi
    @git push
    @gh workflow run release.yml -f tag=v{{VERSION}}
