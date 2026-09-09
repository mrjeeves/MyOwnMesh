# Releases

Cutting a release:

```
just release X.Y.Z
```

That recipe:

1. Bumps the root workspace version and the separate GUI version files via
   `scripts/bump-version.sh`.
2. Refreshes the root `Cargo.lock`.
3. Commits and pushes the version bump, then pushes the immutable `vX.Y.Z`
   tag, which triggers `release.yml`.

The release workflow runs on `push: tags: v*`; `workflow_dispatch` remains a
manual rerun path. For each of
`linux-x86_64`, `linux-aarch64`, `macos-aarch64`, `macos-x86_64`,
`windows-x86_64`:

- Verifies the tag matches every manifest version (catches the
  case where a maintainer pushed a tag without running
  `just release`).
- Builds the headless `myownmesh` daemon and packages it as
  `myownmesh-<platform>.{tar.gz,zip}` + `.sha256` sidecar.
- Builds the Tauri GUI bundle (.deb / .AppImage / .dmg / .msi /
  .exe) via `tauri-action`.
- Packages the portable `myownmesh-gui` binary as
  `myownmesh-gui-<platform>.{tar.gz,zip}` + `.sha256` so the
  `curl | sh` installer can drop it next to the daemon (a bare
  `myownmesh` then opens the GUI).
- Uploads everything to the GitHub release.

Two extra **daemon-only** jobs run outside that matrix, building
fully static musl binaries for the KVM appliances (no GUI, no glibc
dependency): `daemon-riscv64` → `myownmesh-linux-riscv64.tar.gz`
(NanoKVM) and `daemon-aarch64-musl` →
`myownmesh-linux-aarch64-musl.tar.gz` (NanoKVM-Pro). Both are
cross-compiled with `cargo-zigbuild`. Note the `-musl` suffix on the
aarch64 appliance asset: the plain `myownmesh-linux-aarch64.tar.gz`
is the dynamic-glibc **desktop** build, so the appliance name must
not collide with it. See [`docs/NANOKVM.md`](docs/NANOKVM.md).

The root Cargo workspace builds the daemon and its library dependencies. The
Tauri GUI is a separate workspace under `gui/src-tauri`; the release matrix
does not turn the GUI into a daemon dependency. Shipped daemon builds use
`--no-default-features`, and no release build enables `transport-lab`; that
feature remains an explicit test-only surface in CI. The release scanner checks
the daemon binary and portable archive members for the seam.

## What's published, what isn't

| Artifact | Where | Audience |
|---|---|---|
| `myownmesh-<platform>.{tar.gz,zip}` + `.sha256` | [GitHub Releases](https://github.com/mrjeeves/MyOwnMesh/releases) | End users running the headless daemon; the self-updater consumes the same artifacts. |
| `myownmesh-gui-<platform>.{tar.gz,zip}` + `.sha256` | GitHub Releases | The shell installer drops this next to the daemon so a bare `myownmesh` opens the GUI. The self-updater keeps it in lockstep with the daemon (it swaps this binary too when one is installed beside `myownmesh`). Lightweight (relies on the system webview); the OS bundles below are the full desktop install. |
| Tauri GUI bundles (`.deb` / `.AppImage` / `.dmg` / `.msi` / `.exe`) | GitHub Releases | End users who want the desktop app with full OS integration. |
| Workspace source and manifests | Git tag `vX.Y.Z` | Embedders and source builders; registry publication is not implied by a tag. |

Portable `.tar.gz` and `.zip` assets are raw executable archives with a
known daemon or GUI member and a separately generated checksum sidecar; they
are the assets consumed by the shell installer and updater. Tauri `.deb`,
`.AppImage`, `.dmg`, `.msi`, and `.exe` outputs are opaque platform installers
for the GUI and are not interchangeable with those portable archives.

The release workflow publishes the GitHub binary artifacts above; it does not
run `cargo publish`. Treat the tagged repository as the source distribution and
check the selected release's package metadata before assuming a registry
artifact exists.

### Artifact evidence

Every release payload is recorded with an exact SHA-256 digest in the
build-owned asset manifest and receives a detached minisign signature. Portable
daemon and GUI archives additionally publish their `.sha256` sidecars. The
artifact verifier checks the workflow and manifest boundary, scans the daemon
binary and portable archive members for the `transport-lab` seam, and verifies
the complete payload/signature set; the opaque Tauri installers are included in
that same manifest and signature set. These are separate verifier modes:
`--binary` and `--archive --member` check forbidden bytes and archive-member
requirements, while `--signature-tree --public-key` also checks checksum
sidecars and detached signatures. `--tree` scans regular files in the Tauri
bundle directory as bytes; it does not unpack opaque installer formats or
prove installation behavior. A binary/archive scan alone is not signing or
publication qualification.

The `sign` job is mandatory. It requires both `MINISIGN_SECRET_KEY` and
`MINISIGN_PUBLIC_KEY`, refuses missing or stale payloads, and verifies every
signature before upload. It then downloads the uploaded assets again and
re-verifies their bytes, digests, signatures, tag, repository, and draft state.
The release remains a draft until the final exact-tag/preflight check succeeds;
there is no unsigned, no-op, or SHA-only publication path.

## Versioning

Semver. `MAJOR.MINOR.PATCH`:

- **PATCH**: bug fixes, no protocol changes, no API changes that
  break embedders.
- **MINOR**: additive public API surface and config fields with defaults when
  the wire protocol remains unchanged.
- **MAJOR**: incompatible protocol shape change (bumps
  `PROTOCOL_VERSION`), removed / renamed public API, removed
  config keys.

`PROTOCOL_VERSION` is currently `3`. It is an exact pre-authentication wire
gate. The frame set is closed: an unknown `kind` is refused rather than
ignored, so old peers do not silently ignore new closed variants. There is no
mixed-version or optional-frame fallback. Adding or changing wire variants
therefore requires an explicit protocol-version review and, when incompatible,
a major release. Bumping the workspace version does not automatically bump the
protocol version.

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

## What updates

A release bumps the daemon (`myownmesh`) and the desktop GUI
(`myownmesh-gui`) together. The self-updater keeps **both** current:
when it stages an update it stages the GUI binary too, as long as one
is installed beside the daemon (the portable `curl | sh` layout), and
the next launch swaps both. This is what keeps the GUI's window title
from lagging behind the daemon it spawns.

A headless box with no GUI updates the daemon alone. A full desktop
bundle (macOS `.app` / `.dmg`, Linux `.deb` / `.AppImage`, Windows
`.msi`) is owned by its own installer and is left untouched — same
rule as a package-manager install.

## Updating by hand

```
myownmesh update
```

Fetches the latest release and updates every installed portable component
(daemon plus the adjacent GUI binary when present). It ignores the
`auto_apply` policy and check interval for this explicit command, but still
defers to the OS package manager. Restart MyOwnMesh afterwards to run the new
binaries.

The granular subcommands remain for scripting and inspection:

- `myownmesh update check` — check the feed now and stage any permitted
  update (respects `auto_apply`).
- `myownmesh update apply` — apply what's already staged.
- `myownmesh update status` — version, channel, policy, last check, staged.
- `myownmesh update enable` / `disable` — toggle background checks.

## Forking

If you're maintaining a fork that publishes its own releases:

1. Set `MYOWNMESH_RELEASE_URL_STABLE` / `_BETA` at build time to
   your release feed.
2. Set `MYOWNMESH_TRYSTERO_APP_ID` to a fork-specific app id so
   your peers land in their own signaling rooms.
3. Update `ENDPOINT_AUTH_DOMAIN_TAG` in
   `crates/myownmesh-core/src/endpoint_auth/mod.rs` if the fork must use a
   deliberately incompatible endpoint-authentication transcript domain.
