#!/usr/bin/env bash
# Bump every workspace crate's version + the workspace root in a
# single atomic edit. Argument is the new version, e.g.
# `./scripts/bump-version.sh 0.2.0`.
#
# Edits:
#   - Cargo.toml             [workspace.package].version
#   - crates/*/Cargo.toml    no-op (they inherit via .workspace = true)
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

if [ ! -f "$WORKSPACE_TOML" ]; then
    echo "error: $WORKSPACE_TOML not found" >&2
    exit 2
fi

# Replace [workspace.package].version. Stops at the first match after
# the [workspace.package] header so we don't accidentally rewrite a
# version field elsewhere in the file.
python3 - "$WORKSPACE_TOML" "$VERSION" <<'PY'
import re
import sys

path, version = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Find [workspace.package] section, then the next `version = "..."`.
pattern = re.compile(
    r'(\[workspace\.package\][^\[]*?\n\s*version\s*=\s*")[^"]*(")',
    re.DOTALL,
)
new_content, n = pattern.subn(rf'\g<1>{version}\g<2>', content, count=1)
if n != 1:
    print(f"error: could not find [workspace.package].version in {path}", file=sys.stderr)
    sys.exit(1)

with open(path, "w", encoding="utf-8") as f:
    f.write(new_content)
print(f"bumped {path} -> {version}")
PY

# Refresh Cargo.lock so it tracks the new version.
cd "$ROOT"
cargo update --workspace --quiet || true

echo "ok"
