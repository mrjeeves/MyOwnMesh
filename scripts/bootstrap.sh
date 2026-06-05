#!/usr/bin/env bash
# Install dev prerequisites for MyOwnMesh on Linux / macOS.
#
# The workspace crates (the daemon + libraries) are pure Rust, but the
# GUI under gui/ is a Tauri + Svelte app, so a working dev setup also
# needs the WebKitGTK / GTK system libraries, Node, and pnpm. `just dev`
# builds the daemon with cargo and then runs `pnpm tauri dev` in gui/;
# without Node + pnpm that second step dies with "pnpm: command not
# found" (exit 127). This mirrors MyOwnLLM's bootstrap so both apps
# share one setup story.
#
# Idempotent: re-running is cheap and safe — anything already present is
# skipped.

set -euo pipefail

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!!\033[0m %s\n' "$*" >&2; }

have() { command -v "$1" >/dev/null 2>&1; }

OS="$(uname -s)"

# ---------------------------------------------------------------------------
# Platform packages — the WebKitGTK / GTK stack Tauri's webview links
# against. The daemon alone is pure Rust and needs none of this, but the
# GUI won't compile or render without it.
# ---------------------------------------------------------------------------

install_linux_deps() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
  fi

  case "${ID:-}" in
    ubuntu|debian|pop|linuxmint|raspbian)
      log "Installing Tauri build deps (apt)…"
      sudo apt-get update -qq
      # xdg-utils backs Tauri's AppImage bundler (xdg-open ships inside
      # the AppImage); it's preinstalled on the x86_64 runners but
      # missing on Raspberry Pi OS and ubuntu-24.04-arm.
      sudo apt-get install -y --no-install-recommends \
        libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev \
        librsvg2-dev libssl-dev xdg-utils curl wget file build-essential \
        pkg-config
      ;;
    fedora|rhel|centos)
      log "Installing Tauri build deps (dnf)…"
      sudo dnf install -y \
        webkit2gtk4.1-devel gtk3-devel libappindicator-gtk3-devel \
        librsvg2-devel openssl-devel curl wget file gcc gcc-c++ make \
        pkgconf-pkg-config
      ;;
    arch|manjaro)
      log "Installing Tauri build deps (pacman)…"
      sudo pacman -S --needed --noconfirm \
        webkit2gtk-4.1 gtk3 libayatana-appindicator librsvg openssl curl \
        wget file base-devel
      ;;
    *)
      warn "Unrecognised Linux distro (${ID:-?}). Install Tauri deps manually:"
      warn "  https://tauri.app/start/prerequisites/#linux"
      ;;
  esac
}

install_macos_deps() {
  if ! xcode-select -p >/dev/null 2>&1; then
    log "Installing Xcode Command Line Tools (you may be prompted)…"
    xcode-select --install || true
  fi
}

case "$OS" in
  Linux)  install_linux_deps ;;
  Darwin) install_macos_deps ;;
  *)      warn "Unsupported OS: $OS — proceeding anyway." ;;
esac

# ---------------------------------------------------------------------------
# Rust — the channel + rustfmt/clippy components come from
# rust-toolchain.toml (pinned to 1.88.0). `rustup show` reads that file
# and installs the pinned toolchain on first run; a no-op once present.
# ---------------------------------------------------------------------------

if ! have rustup && ! have cargo; then
  log "Installing rustup (Rust toolchain manager)…"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
  # shellcheck disable=SC1090
  . "$HOME/.cargo/env"
fi
if have rustup; then
  log "Ensuring the pinned Rust toolchain is installed…"
  rustup show
fi

# ---------------------------------------------------------------------------
# Node + pnpm — `just dev` runs `pnpm tauri dev` inside gui/. We don't
# auto-install Node from a distro package: those are frequently too old
# for Vite 6 (needs Node 20+), so we point the user at a current release
# and bail rather than wire up a broken toolchain.
# ---------------------------------------------------------------------------

if ! have node; then
  if [[ "$OS" == "Darwin" ]] && have brew; then
    log "Installing Node via brew…"
    brew install node
  else
    warn "Node.js not found. Install Node 20+ from https://nodejs.org (or via"
    warn "fnm/nvm — e.g. \`fnm install 22\`), then re-run \`just setup\`."
    exit 1
  fi
fi

if ! have pnpm; then
  if have corepack; then
    # corepack ships with Node 16.9–24 and is the blessed way to get the
    # exact pnpm pinned in gui/package.json's "packageManager" field.
    log "Enabling pnpm via corepack…"
    corepack enable || true
    corepack prepare pnpm@latest --activate
  elif have npm; then
    # Node 25+ unbundled corepack; older/leaner Node distros may lack it.
    log "Installing pnpm via npm…"
    npm install -g pnpm
  else
    warn "Neither corepack nor npm is on PATH. Install pnpm manually:"
    warn "  https://pnpm.io/installation"
    exit 1
  fi
fi

# Note: the GUI's `pnpm tauri …` commands use the @tauri-apps/cli pulled
# in as a gui/ devDependency, so a global `cargo install tauri-cli` isn't
# needed for `just dev` (and that from-source build is slow on a Pi).

log "✓ setup complete — try \`just dev\`"
