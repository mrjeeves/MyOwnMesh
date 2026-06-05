#!/bin/sh
# MyOwnMesh end-user installer.
#
# Tries (in order):
#   1. Download a pre-built release binary from GitHub for the current platform.
#   2. Fall back to building from source via cargo.
#
# Installs both the `myownmesh` daemon/CLI and the `myownmesh-gui`
# desktop app (the GUI is small and makes a bare `myownmesh` open the
# app — pass --no-gui for a daemon-only install on a headless box).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/mrjeeves/MyOwnMesh/main/scripts/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/mrjeeves/MyOwnMesh/main/scripts/install.sh | sh -s -- --serve
#   ./scripts/install.sh --dry-run
#   ./scripts/install.sh --no-gui      # daemon only, skip the desktop GUI
#
# POSIX sh-compatible so `curl … | sh` works under dash, ash/busybox sh, and
# bash alike. Avoid bash-only constructs ([[ ]], arrays, ${var^^}, etc.).

set -eu
if (set -o pipefail) 2>/dev/null; then
  set -o pipefail
fi

REPO="${MYOWNMESH_REPO:-mrjeeves/MyOwnMesh}"
DRY_RUN=false
SERVE_AFTER=false
PREFIX_DIR="${MYOWNMESH_PREFIX:-}"
FORCE_SOURCE=false
INSTALL_GUI=true

for arg in "$@"; do
  case "$arg" in
    --dry-run)     DRY_RUN=true ;;
    --serve)       SERVE_AFTER=true ;;
    --from-source) FORCE_SOURCE=true ;;
    --no-gui)      INSTALL_GUI=false ;;
    --prefix=*)    PREFIX_DIR="${arg#*=}" ;;
    *) ;;
  esac
done

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!!\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31mxxx\033[0m %s\n' "$*" >&2; }

OS_RAW="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS_RAW" in
  darwin) OS="macos" ;;
  linux)  OS="linux" ;;
  *)      OS="$OS_RAW" ;;
esac
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64|amd64)  ARCH="x86_64" ;;
  aarch64|arm64) ARCH="aarch64" ;;
  *)             ARCH="$ARCH_RAW" ;;
esac
ASSET="myownmesh-${OS}-${ARCH}.tar.gz"
GUI_ASSET="myownmesh-gui-${OS}-${ARCH}.tar.gz"

# Pick install prefix. Prefer /usr/local/bin if writable (or sudo is cached);
# else ~/.local/bin so a no-sudo install still lands somewhere sensible.
if [ -z "$PREFIX_DIR" ]; then
  if [ -w /usr/local/bin ] || sudo -n true 2>/dev/null; then
    PREFIX_DIR="/usr/local/bin"
  else
    PREFIX_DIR="$HOME/.local/bin"
  fi
fi

install_binary() {
  src="$1"
  mkdir -p "$PREFIX_DIR" 2>/dev/null || sudo mkdir -p "$PREFIX_DIR"
  if [ -w "$PREFIX_DIR" ]; then
    install -m 0755 "$src" "$PREFIX_DIR/myownmesh"
  else
    sudo install -m 0755 "$src" "$PREFIX_DIR/myownmesh"
  fi
  log "Installed: $PREFIX_DIR/myownmesh"
}

install_gui_binary() {
  src="$1"
  mkdir -p "$PREFIX_DIR" 2>/dev/null || sudo mkdir -p "$PREFIX_DIR"
  if [ -w "$PREFIX_DIR" ]; then
    install -m 0755 "$src" "$PREFIX_DIR/myownmesh-gui"
  else
    sudo install -m 0755 "$src" "$PREFIX_DIR/myownmesh-gui"
  fi
  log "Installed: $PREFIX_DIR/myownmesh-gui"
}

ensure_on_path() {
  case ":$PATH:" in
    *":$PREFIX_DIR:"*) return 0 ;;
  esac

  shell_name="$(basename "${SHELL:-bash}")"
  marker="# added by myownmesh installer"
  case "$shell_name" in
    zsh)
      rc="$HOME/.zshrc"
      line="export PATH=\"$PREFIX_DIR:\$PATH\"  $marker"
      ;;
    fish)
      rc="$HOME/.config/fish/config.fish"
      line="fish_add_path -g $PREFIX_DIR  $marker"
      ;;
    *)
      rc="$HOME/.bashrc"
      line="export PATH=\"$PREFIX_DIR:\$PATH\"  $marker"
      ;;
  esac

  if grep -qsF "$marker" "$rc" 2>/dev/null; then
    warn "$PREFIX_DIR not on current PATH; PATH already added to $rc — open a new terminal."
    return 0
  fi

  mkdir -p "$(dirname "$rc")"
  if printf '\n%s\n' "$line" >> "$rc" 2>/dev/null; then
    log "Added $PREFIX_DIR to PATH in $rc"
    log "Open a new terminal (or run: source $rc) for it to take effect."
  else
    warn "$PREFIX_DIR is not on PATH. Add this to your shell rc:"
    warn "  $line"
  fi
}

# Tracked for cleanup since POSIX sh has no function-scoped RETURN trap.
_TRY_RELEASE_TMP=""
_cleanup_try_release() {
  if [ -n "$_TRY_RELEASE_TMP" ] && [ -d "$_TRY_RELEASE_TMP" ]; then
    rm -rf "$_TRY_RELEASE_TMP"
  fi
  _TRY_RELEASE_TMP=""
}

try_release() {
  if ! command -v curl >/dev/null 2>&1; then
    warn "curl missing; skipping release download."
    return 1
  fi
  api="https://api.github.com/repos/${REPO}/releases/latest"
  log "Looking up latest release: $api"
  if ! json="$(curl -fsSL "$api" 2>/dev/null)"; then
    warn "GitHub releases unreachable (or no release yet)."
    return 1
  fi
  url="$(printf '%s' "$json" | grep -Eo "https://[^\"]+/${ASSET}" | head -n1 || true)"
  if [ -z "$url" ]; then
    warn "No release asset matched ${ASSET}."
    return 1
  fi
  sha_url="${url}.sha256"
  log "Downloading $url"
  if [ "$DRY_RUN" = "true" ]; then
    log "(dry-run) would download $url"
    return 0
  fi
  _TRY_RELEASE_TMP="$(mktemp -d)"
  trap _cleanup_try_release EXIT INT TERM
  curl -fsSL "$url" -o "$_TRY_RELEASE_TMP/$ASSET"
  if curl -fsSL "$sha_url" -o "$_TRY_RELEASE_TMP/$ASSET.sha256" 2>/dev/null; then
    (cd "$_TRY_RELEASE_TMP" && (sha256sum -c "$ASSET.sha256" 2>/dev/null || shasum -a 256 -c "$ASSET.sha256"))
  else
    warn "No SHA256 sidecar; skipping integrity check."
  fi
  tar -xzf "$_TRY_RELEASE_TMP/$ASSET" -C "$_TRY_RELEASE_TMP"
  install_binary "$_TRY_RELEASE_TMP/myownmesh"
  _cleanup_try_release
  trap - EXIT INT TERM
  return 0
}

_TRY_GUI_TMP=""
_cleanup_try_gui() {
  if [ -n "$_TRY_GUI_TMP" ] && [ -d "$_TRY_GUI_TMP" ]; then
    rm -rf "$_TRY_GUI_TMP"
  fi
  _TRY_GUI_TMP=""
}

# Best-effort GUI install: fetch the portable `myownmesh-gui` tarball
# and drop it next to the daemon. Returns non-zero (without aborting
# the overall install) if the asset is missing or unreachable — an
# older release may predate the GUI binary, and the daemon is the
# part that must succeed.
try_release_gui() {
  if ! command -v curl >/dev/null 2>&1; then
    return 1
  fi
  api="https://api.github.com/repos/${REPO}/releases/latest"
  if ! json="$(curl -fsSL "$api" 2>/dev/null)"; then
    warn "GitHub releases unreachable; skipping GUI."
    return 1
  fi
  url="$(printf '%s' "$json" | grep -Eo "https://[^\"]+/${GUI_ASSET}" | head -n1 || true)"
  if [ -z "$url" ]; then
    warn "No GUI asset matched ${GUI_ASSET} in the latest release."
    return 1
  fi
  sha_url="${url}.sha256"
  log "Downloading $url"
  if [ "$DRY_RUN" = "true" ]; then
    log "(dry-run) would download $url"
    return 0
  fi
  _TRY_GUI_TMP="$(mktemp -d)"
  trap _cleanup_try_gui EXIT INT TERM
  curl -fsSL "$url" -o "$_TRY_GUI_TMP/$GUI_ASSET"
  if curl -fsSL "$sha_url" -o "$_TRY_GUI_TMP/$GUI_ASSET.sha256" 2>/dev/null; then
    (cd "$_TRY_GUI_TMP" && (sha256sum -c "$GUI_ASSET.sha256" 2>/dev/null || shasum -a 256 -c "$GUI_ASSET.sha256"))
  else
    warn "No SHA256 sidecar for GUI; skipping integrity check."
  fi
  tar -xzf "$_TRY_GUI_TMP/$GUI_ASSET" -C "$_TRY_GUI_TMP"
  install_gui_binary "$_TRY_GUI_TMP/myownmesh-gui"
  _cleanup_try_gui
  trap - EXIT INT TERM
  return 0
}

build_from_source() {
  log "Building from source…"
  if ! command -v cargo >/dev/null 2>&1; then
    err "cargo not found. Install Rust via https://rustup.rs first."
    exit 1
  fi
  if ! command -v git >/dev/null 2>&1; then
    err "git is required to build from source."
    exit 1
  fi
  if [ -f Cargo.toml ] && [ -d crates/myownmesh ]; then
    repo_dir="$(pwd)"
    log "Using current directory as source: $repo_dir"
  else
    repo_dir="$(mktemp -d)/MyOwnMesh"
    log "Cloning into $repo_dir"
    if [ "$DRY_RUN" != "true" ]; then
      git clone --depth 1 "https://github.com/${REPO}.git" "$repo_dir"
    fi
  fi
  if [ "$DRY_RUN" = "true" ]; then
    log "(dry-run) would build in $repo_dir"
    return 0
  fi
  ( cd "$repo_dir" && cargo build --release --bin myownmesh )
  built="$repo_dir/target/release/myownmesh"
  if [ ! -x "$built" ]; then
    err "Build did not produce $built"
    exit 1
  fi
  install_binary "$built"
}

INSTALLED_FROM_RELEASE=false
if [ "$FORCE_SOURCE" = "true" ] || ! try_release; then
  build_from_source
else
  INSTALLED_FROM_RELEASE=true
fi

# Desktop GUI (myownmesh-gui). On by default — it's small and lets a
# bare `myownmesh` open the app. `--no-gui` skips it. Only attempted on
# the release path; building the GUI from source needs the full
# Tauri/pnpm toolchain, which is out of scope for a curl|sh installer.
if [ "$INSTALL_GUI" = "true" ]; then
  if [ "$INSTALLED_FROM_RELEASE" = "true" ]; then
    try_release_gui || warn "GUI binary not installed; a bare 'myownmesh' will print a hint until it is. Re-run the installer later, or build it from gui/."
  elif [ "$DRY_RUN" = "true" ]; then
    log "(dry-run) would install the GUI binary ($GUI_ASSET) next to myownmesh"
  else
    warn "Built the daemon from source; skipping the GUI binary (needs the Tauri/pnpm toolchain)."
    warn "Build it with:  cd gui && pnpm install && pnpm tauri build"
  fi
fi

if [ "$DRY_RUN" != "true" ]; then
  ensure_on_path
fi

if [ "$SERVE_AFTER" = "true" ] && [ "$DRY_RUN" != "true" ]; then
  log "Launching myownmesh serve…"
  exec "$PREFIX_DIR/myownmesh" serve
fi

log "Done."
log ""
log "Quick start:"
if [ "$INSTALL_GUI" = "true" ]; then
  log "  myownmesh                  # open the desktop GUI"
fi
log "  myownmesh serve            # run the daemon in the foreground (headless)"
log "  myownmesh ctl status       # query a running daemon"
log "  myownmesh identity show    # print this device's id"
log "  myownmesh config edit      # open ~/.myownmesh/config.json in \$EDITOR"
