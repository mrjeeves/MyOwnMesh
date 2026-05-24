#!/usr/bin/env bash
# Bump every workspace crate's version + the workspace root in a
# single atomic edit. Argument is the new version, e.g.
# `./scripts/bump-version.sh 0.2.0`.
#
# Edits:
#   - Cargo.toml                    [workspace.package].version
#   - crates/*/Cargo.toml           no-op (they inherit via .workspace = true)
#   - gui/src-tauri/Cargo.toml      [package].version  (separate workspace)
#   - gui/src-tauri/Cargo.lock      myownmesh-gui [[package]] version
#   - gui/package.json              "version"
#
# The GUI lives in its own Cargo workspace (so `cargo build --workspace`
# at the root stays fast — no Tauri compile), so its version doesn't
# auto-inherit and we have to keep it in lockstep here. Tauri reports
# the app version to the frontend from `gui/src-tauri/Cargo.toml`, and
# the release workflow's verify step compares the tag against both that
# file and `gui/package.json`.
#
# After this script: stage + commit + tag — the Justfile's `release`
# recipe does that part.

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <version>" >&2
    exit 2
fi

VERSION="$1"

# Validate looks-like-semver.
if ! echo "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$'; then
    echo "error: '$VERSION' does not look like a semver string" >&2
    exit 2
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKSPACE_TOML="$ROOT/Cargo.toml"
GUI_TAURI_TOML="$ROOT/gui/src-tauri/Cargo.toml"
GUI_TAURI_LOCK="$ROOT/gui/src-tauri/Cargo.lock"
GUI_PACKAGE_JSON="$ROOT/gui/package.json"

if [ ! -f "$WORKSPACE_TOML" ]; then
    echo "error: $WORKSPACE_TOML not found" >&2
    exit 2
fi

# Replace [workspace.package].version + every internal crate's
# version pin under [workspace.dependencies]. The internal crates
# (myownmesh-core / myownmesh-signaling / myownmesh-updater) declare
# `version.workspace = true` and inherit from [workspace.package],
# but inter-crate `version = "..."` pins under [workspace.dependencies]
# need to be kept in sync explicitly — otherwise `cargo update`
# refuses to bump the workspace because the dependency constraints
# don't accept the new version.
python3 - "$WORKSPACE_TOML" "$VERSION" <<'PY'
import re
import sys

path, version = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. [workspace.package].version — the canonical source.
pkg_pattern = re.compile(
    r'(\[workspace\.package\][^\[]*?\n\s*version\s*=\s*")[^"]*(")',
    re.DOTALL,
)
content, n_pkg = pkg_pattern.subn(rf'\g<1>{version}\g<2>', content, count=1)
if n_pkg != 1:
    print(f"error: could not find [workspace.package].version in {path}", file=sys.stderr)
    sys.exit(1)

# 2. [workspace.dependencies] — rewrite every internal myownmesh-*
#    entry's `version = "..."` pin. Matches lines of the form:
#      myownmesh-core = { path = "crates/myownmesh-core", version = "0.1.0" }
#    and any layout variation as long as the `version = "..."` chunk
#    appears within the same inline table.
def fixup_dep(match):
    head, body, tail = match.group(1), match.group(2), match.group(3)
    new_body = re.sub(
        r'(version\s*=\s*")[^"]*(")',
        rf'\g<1>{version}\g<2>',
        body,
        count=1,
    )
    return head + new_body + tail

deps_pattern = re.compile(
    r'(myownmesh-[A-Za-z0-9_-]+\s*=\s*\{)([^}]*)(\})',
)
content, n_deps = deps_pattern.subn(fixup_dep, content)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)
print(f"bumped {path} -> {version} ({n_deps} internal dep pin(s) updated)")
PY

# Refresh Cargo.lock so it tracks the new version.
cd "$ROOT"
cargo update --workspace --quiet || true

# --- GUI sub-workspace --------------------------------------------------

if [ -f "$GUI_TAURI_TOML" ]; then
    # gui/src-tauri/Cargo.toml — bump the [package].version (first match
    # under the [package] header).
    python3 - "$GUI_TAURI_TOML" "$VERSION" <<'PY'
import re
import sys

path, version = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

pattern = re.compile(
    r'(\[package\][^\[]*?\n\s*version\s*=\s*")[^"]*(")',
    re.DOTALL,
)
new_content, n = pattern.subn(rf'\g<1>{version}\g<2>', content, count=1)
if n != 1:
    print(f"error: could not find [package].version in {path}", file=sys.stderr)
    sys.exit(1)

with open(path, "w", encoding="utf-8") as f:
    f.write(new_content)
print(f"bumped {path} -> {version}")
PY
fi

if [ -f "$GUI_TAURI_LOCK" ]; then
    # gui/src-tauri/Cargo.lock — bump the [[package]] entry whose
    # name is "myownmesh-gui". Mirrors the pattern MyOwnLLM uses.
    python3 - "$GUI_TAURI_LOCK" "$VERSION" <<'PY'
import re
import sys

path, version = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Match name = "myownmesh-gui" followed by version = "...". The lock
# file groups each package's fields together so the `version` field
# we want is always the next one after the matching `name`.
pattern = re.compile(
    r'(name\s*=\s*"myownmesh-gui"\s*\nversion\s*=\s*")[^"]*(")',
)
new_content, n = pattern.subn(rf'\g<1>{version}\g<2>', content, count=1)
if n != 1:
    print(f"warning: could not find myownmesh-gui in {path} (skipping)", file=sys.stderr)
else:
    with open(path, "w", encoding="utf-8") as f:
        f.write(new_content)
    print(f"bumped {path} -> {version}")
PY
fi

if [ -f "$GUI_PACKAGE_JSON" ]; then
    # gui/package.json — node is the most portable JSON editor we can
    # rely on across maintainer machines.
    node -e '
        const fs = require("fs");
        const f = process.argv[1];
        const j = JSON.parse(fs.readFileSync(f, "utf8"));
        j.version = process.argv[2];
        fs.writeFileSync(f, JSON.stringify(j, null, 2) + "\n");
        console.log(`bumped ${f} -> ${process.argv[2]}`);
    ' "$GUI_PACKAGE_JSON" "$VERSION"
fi

echo "ok"
