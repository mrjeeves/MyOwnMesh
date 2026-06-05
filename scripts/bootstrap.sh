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
# Node + pnpm — `just dev` runs `pnpm tauri dev` inside gui/, and Vite 6
# needs Node 20+. Install a current Node when it's missing or too old
# (distro packages on Debian / Raspberry Pi OS lag well behind), then get
# pnpm through corepack. This step used to just warn and bail, which left
# `just dev` to die with "pnpm: command not found".
# ---------------------------------------------------------------------------

NODE_MAJOR=22  # LTS line to install when Node is absent or too old.

node_major() { node -v 2>/dev/null | sed 's/^v//; s/\..*//'; }

install_node_linux() {
  [[ -f /etc/os-release ]] && . /etc/os-release
  # Match on ID + ID_LIKE (space-padded) so derivatives resolve too:
  # Raspberry Pi OS is ID=raspbian ID_LIKE=debian; Pop/Mint carry
  # ID_LIKE="ubuntu debian"; etc.
  case " ${ID:-} ${ID_LIKE:-} " in
    *" debian "*|*" ubuntu "*|*" raspbian "*)
      # The distro nodejs is usually too old for Vite 6, so pull a current
      # line from NodeSource — its package bundles npm and corepack.
      log "Installing Node ${NODE_MAJOR}.x via NodeSource…"
      curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | sudo -E bash -
      sudo apt-get install -y nodejs
      ;;
    *" fedora "*|*" rhel "*|*" centos "*)
      log "Installing Node via dnf…"
      sudo dnf install -y nodejs npm
      ;;
    *" arch "*)
      log "Installing Node via pacman…"
      sudo pacman -S --needed --noconfirm nodejs npm
      ;;
    *)
      warn "Don't know how to install Node on this distro (${ID:-?})."
      warn "Install Node ${NODE_MAJOR}+ from https://nodejs.org (or fnm/nvm),"
      warn "then re-run \`just setup\`."
      exit 1
      ;;
  esac
}

ensure_node() {
  if have node; then
    local maj
    maj="$(node_major)"
    if [[ -n "$maj" && "$maj" -ge 20 ]]; then
      return
    fi
    warn "Node $(node -v 2>/dev/null) is older than v20 (Vite 6 needs 20+) — installing v${NODE_MAJOR}."
  fi
  if [[ "$OS" == "Darwin" ]]; then
    if have brew; then
      log "Installing Node via brew…"
      brew install node
    else
      warn "Homebrew not found. Install Node ${NODE_MAJOR}+ from https://nodejs.org, then re-run."
      exit 1
    fi
  else
    install_node_linux
  fi
  hash -r 2>/dev/null || true  # forget the shell's cached "node not found"
}

ensure_pnpm() {
  if have pnpm; then
    return
  fi
  if have corepack; then
    log "Enabling pnpm via corepack…"
    # corepack writes its shims into Node's bin dir: a system Node
    # (NodeSource / dnf / pacman) needs sudo there, a user-managed one
    # (fnm / nvm / brew) doesn't — try without sudo first.
    corepack enable 2>/dev/null || sudo corepack enable 2>/dev/null || true
    corepack prepare pnpm@latest --activate || true
    hash -r 2>/dev/null || true
  fi
  if ! have pnpm && have npm; then
    # Node 25+ unbundled corepack; some distro Nodes ship npm only.
    log "Installing pnpm via npm…"
    sudo npm install -g pnpm 2>/dev/null || npm install -g pnpm || true
    hash -r 2>/dev/null || true
  fi
  if ! have pnpm; then
    warn "Could not put pnpm on PATH automatically. Install it manually:"
    warn "  https://pnpm.io/installation"
    exit 1
  fi
}

ensure_node
ensure_pnpm

# Note: the GUI's `pnpm tauri …` commands use the @tauri-apps/cli pulled
# in as a gui/ devDependency, so a global `cargo install tauri-cli` isn't
# needed for `just dev` (and that from-source build is slow on a Pi).

log "✓ setup complete — try \`just dev\`"
