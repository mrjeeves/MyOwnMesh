#!/usr/bin/env bash
# Install dev prerequisites for MyOwnMesh on Linux / macOS.
#
# Currently: just Rust (via rustup). The crate set is pure Rust with
# no system deps required for `cargo build --workspace` — when the
# WebRTC transport lands we'll add libssl / libudev / pkg-config
# hints here for the few Linux distros that need them.
#
# Idempotent: re-running is cheap and safe.

set -euo pipefail

bold() { printf "\033[1m%s\033[0m\n" "$*"; }

ensure_rustup() {
    if command -v rustup >/dev/null 2>&1; then
        return
    fi
    bold "→ installing rustup (Rust toolchain manager)"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
    # shellcheck disable=SC1090
    source "$HOME/.cargo/env"
}

ensure_toolchain() {
    # `rust-toolchain.toml` pins the channel; `rustup show` is a no-op
    # when it's already installed and triggers an install when not.
    bold "→ ensuring pinned toolchain is installed"
    rustup show
}

ensure_components() {
    bold "→ ensuring rustfmt + clippy are installed"
    rustup component add rustfmt clippy >/dev/null 2>&1 || true
}

main() {
    ensure_rustup
    ensure_toolchain
    ensure_components
    bold "✓ setup complete — try \`just build\`"
}

main "$@"
