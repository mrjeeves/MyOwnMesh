# Release signing (minisign)

The self-updater (`myownmesh-updater`) verifies every downloaded artifact:

1. **Integrity** — a published `<asset>.sha256` (or `SHA256SUMS`) is **mandatory**.
   A missing checksum now fails closed; nothing unverified is ever staged.
2. **Provenance** — when the shipped build has a release public key baked in
   (`MYOWNMESH_RELEASE_PUBKEY`), a valid detached **minisign** signature
   (`<asset>.minisig`) over the artifact is **required** before it is staged.

Until you complete the one-time setup below, releases keep working exactly as
before (SHA-256-only); the signing CI job is a no-op and the client logs that
signing isn't configured.

## One-time setup

1. **Generate a password-less signing key** (CI must sign non-interactively):

   ```sh
   minisign -G -W -p minisign.pub -s minisign.key
   ```

   - `minisign.pub` holds a comment line and the base64 **public key** (line 2).
   - `minisign.key` is the **secret key** — treat it like any signing secret.

2. **Add the secret key to GitHub Actions** as repository secret
   `MINISIGN_SECRET_KEY` (the full contents of `minisign.key`). The `sign` job in
   `.github/workflows/release.yml` keys off this secret.

3. **Bake the public key into the shipped binaries.** Set
   `MYOWNMESH_RELEASE_PUBKEY` to the base64 public-key string (line 2 of
   `minisign.pub`) in the build environment of the **Build daemon** and
   **tauri-action** steps, e.g.:

   ```yaml
   env:
     MYOWNMESH_RELEASE_PUBKEY: ${{ vars.MYOWNMESH_RELEASE_PUBKEY }}
   ```

   A repo *variable* is fine — the public key isn't secret. Once set,
   `RELEASE_PUBKEY` in `crates/myownmesh-updater/src/lib.rs` is `Some(...)` and
   the client refuses any artifact without a valid signature.

4. **Cut a test release** and confirm `.minisig` sidecars sit next to each
   `myownmesh-*.tar.gz` / `.zip`, and that `myownmesh update` on a build compiled
   with the pubkey accepts it.

## Note on the bundled daemon

AllMyStuff ships this `myownmesh` daemon as a Tauri sidecar pinned via
`.myownmesh-rev`. That sidecar is fetched/built at AllMyStuff build time and is
covered by AllMyStuff's own release verification; this key signs the standalone
MyOwnMesh release archives consumed by `myownmesh update`.

## Rotation

Generate a new key, update both `MINISIGN_SECRET_KEY` and
`MYOWNMESH_RELEASE_PUBKEY`, and roll across two releases (sign with the old key
while shipping the new pubkey) for a seamless hand-off.
