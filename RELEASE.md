# Releases

Cutting a release:

```
just release 0.2.0
```

That recipe:

1. Bumps the version in every manifest that pins it via
   `scripts/bump-version.sh` — root `Cargo.toml`
   (`[workspace.package].version` + the matching pins under
   `[workspace.dependencies]`), `gui/src-tauri/Cargo.toml`,
   `gui/src-tauri/Cargo.lock`, and `gui/package.json`.
2. Refreshes the root `Cargo.lock`.
3. Commits the version bumps, pushes the branch, then triggers
   `release.yml` via `gh workflow run` with `tag=v0.2.0`.

The release workflow runs on `push: tags: v*` and on
`workflow_dispatch` (which is what step 3 uses), then for each of
`linux-x86_64`, `linux-aarch64`, `macos-aarch64`, `macos-x86_64`,
`windows-x86_64`:

- Verifies the tag matches every manifest version (catches the
  case where a maintainer pushed a tag without running
  `just release`).
- Builds the headless `myownmesh` daemon and packages it as
  `myownmesh-<platform>.{tar.gz,zip}` + `.sha256` sidecar.
- Builds the Tauri GUI bundle (.deb / .AppImage / .dmg / .msi /
  .exe) via `tauri-action`.
- Uploads everything to the GitHub release.

The matrix mirrors MyOwnLLM's `release.yml` so behaviour is
consistent across both apps.

## What's published, what isn't

| Artifact | Where | Audience |
|---|---|---|
| `myownmesh-<platform>.{tar.gz,zip}` + `.sha256` | [GitHub Releases](https://github.com/mrjeeves/MyOwnMesh/releases) | End users running the headless daemon; the self-updater consumes the same artifacts. |
| Tauri GUI bundles (`.deb` / `.AppImage` / `.dmg` / `.msi` / `.exe`) | GitHub Releases | End users who want the desktop app. |
| `myownmesh-core`, `myownmesh-signaling`, `myownmesh-updater` source | Git tag `vX.Y.Z` | Embedders, via `git = …, tag = "vX.Y.Z"` in their `Cargo.toml`. |

The three library crates are **not on crates.io yet** — embedders
pull them as git dependencies pinned to a release tag. The first
crates.io publish is gated on a public-API freeze; until then the
git-tag pin is the supported integration path (and gives downstream
projects exact reproducibility because the tag content is
immutable).

The order of operations to add crates.io later is straightforward —
`cargo publish -p myownmesh-signaling` first, then `-p myownmesh-core`
(which depends on signaling), then `-p myownmesh-updater` (depends on
core), then `-p myownmesh` (depends on all three). The workspace
dependency table already pins each inter-crate edge with `version =
"X.Y.Z"` alongside the path entry, which is exactly the shape
`cargo publish` requires. When the time comes, add `cargo publish`
steps to `release.yml` after the GitHub-release upload.

## Versioning

Semver. `MAJOR.MINOR.PATCH`:

- **PATCH**: bug fixes, no protocol changes, no API changes that
  break embedders.
- **MINOR**: new optional protocol message kinds (added to the
  `features` matrix so older peers ignore them), new public API
  surface (additive), new config fields with defaults.
- **MAJOR**: incompatible protocol shape change (bumps
  `PROTOCOL_VERSION`), removed / renamed public API, removed
  config keys.

`PROTOCOL_VERSION` is at the wire-protocol layer; embedders that
pin a specific MyOwnMesh version don't need to track it. Bumping
the workspace version doesn't automatically bump the protocol
version.

## Updater channels

The self-updater hits one of two URLs:

- `auto_update.stable_url` (or `MYOWNMESH_RELEASE_URL_STABLE` if
  unset): `https://api.github.com/repos/mrjeeves/MyOwnMesh/releases/latest`
- `auto_update.beta_url` (or `MYOWNMESH_RELEASE_URL_BETA`):
  `https://api.github.com/repos/mrjeeves/MyOwnMesh/releases`

Override either to host your own release feed (forks, internal
fleets).

## Apply policy

Configured via `auto_update.auto_apply`:

- `patch`: auto-apply patch bumps only (`0.1.5 → 0.1.6`).
- `minor`: auto-apply patch + minor (`0.1.5 → 0.2.0` ok).
- `all`: apply any version bump.
- `none`: stage updates but require a manual `myownmesh update apply`.

Package-manager installs (Homebrew / apt / rpm / MSI / choco) are
detected on first launch and self-update is skipped — the OS
package manager stays the source of truth.

## Forking

If you're maintaining a fork that publishes its own releases:

1. Set `MYOWNMESH_RELEASE_URL_STABLE` / `_BETA` at build time to
   your release feed.
2. Set `MYOWNMESH_TRYSTERO_APP_ID` to a fork-specific app id so
   your peers land in their own signaling rooms.
3. Update `SIGN_DOMAIN_TAG` in `crates/myownmesh-core/src/lib.rs`
   if you want signature non-interop with upstream peers (default
   is `"myownmesh-mesh-auth-v1:"`).
