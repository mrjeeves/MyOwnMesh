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

# Cut a release: bump every crate's version, commit, push, tag.
# Bash script — release flow runs from a Linux/macOS box. Adding a
# Windows variant is fine when a maintainer needs one.
[unix]
[doc("Cut a release: bump versions, commit, tag, push.")]
release VERSION:
    @./scripts/bump-version.sh {{VERSION}}
    @if ! git diff --quiet Cargo.toml Cargo.lock; then \
        git add Cargo.toml Cargo.lock crates/*/Cargo.toml; \
        git commit -m "chore(release): {{VERSION}}"; \
    fi
    @git tag v{{VERSION}}
    @git push --follow-tags
