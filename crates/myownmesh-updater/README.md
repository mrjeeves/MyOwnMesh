# myownmesh-updater

Self-update for the `myownmesh` binary. Pulled separately so an
embedder that ships its own update story doesn't inherit ours.

```toml
myownmesh-updater = { git = "https://github.com/mrjeeves/MyOwnMesh", tag = "v0.1.0" }
```

## Lifecycle

1. Background ticker polls the release feed every
   `check_interval_hours` (default 6).
2. Latest version compared to running `CARGO_PKG_VERSION`. If
   newer and policy permits, the asset is downloaded.
3. SHA-256 verified against the sidecar `.sha256` published next
   to the artifact.
4. Extracted into `~/.myownmesh/updates/<version>/` with a
   `pending.json` marker.
5. On next process start, `apply_pending_if_any()` atomically
   swaps the running binary.

Package-manager installs (Homebrew / apt / rpm / MSI / choco) are
detected on first launch and self-update is skipped — the OS
package manager stays the source of truth.

## Configurable release URL

Build-time env defaults:

```
MYOWNMESH_RELEASE_URL_STABLE  → github.com/mrjeeves/MyOwnMesh/releases/latest
MYOWNMESH_RELEASE_URL_BETA    → github.com/mrjeeves/MyOwnMesh/releases
```

Runtime overrides in `~/.myownmesh/config.json`:

```jsonc
{
  "auto_update": {
    "channel": "stable",
    "auto_apply": "patch",
    "stable_url": "https://your.cdn/myownmesh/latest"
  }
}
```

## Apply policy

`auto_update.auto_apply`:

- `patch` — `0.1.5 → 0.1.6` only
- `minor` — `0.1.5 → 0.2.0` ok
- `all`   — any upgrade
- `none`  — stage but never auto-apply

See [`../../RELEASE.md`](../../RELEASE.md) for the publisher side
of the contract — how artifacts get into the feed this crate
consumes.
