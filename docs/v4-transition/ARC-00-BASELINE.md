# V4 Arc 00 baseline record

Status: documentation-adoption slice complete. The full Arc 00 runtime and
field-evidence gate remains open for the items listed in Section 8.

Recorded on 2026-07-31 in America/Chicago.

## 1. Authority and package integrity

The repository owner adopted the supplied V4 transition package as a complete
supersession of earlier architecture decisions.

Package source:

```text
C:\Users\Admin\Downloads\myownmesh-existing-repository-transition.zip
bytes: 87208
sha256: 96CD55800723C7007ED65EC63FA5A50C04B1B33C8643A2C5255A8C8514446336
```

The archive was inspected before extraction. It contained no path traversal.
All 17 files named by `SHA256SUMS.json` matched their declared SHA-256 values.
The 13 canonical files installed in this repository also match the supplied
manifest exactly.

The canonical architecture set is:

- `ARCHITECTURE.md`
- `APPLICATION-INTEGRATION.md`
- `IMPLEMENTATION-CONSTRAINTS-AND-INVARIANTS.md`
- `FORMAL-PROOFS.md`
- `TRANSITION-PLAYBOOK.md`
- `ARCHITECTURE-OWNERSHIP.md`
- `CURRENT-TO-TARGET-MIGRATION-MATRIX.md`
- `PR-CHECKLIST.md`
- `red-teams/MESH-ATTACK-VECTORS.md`
- the four SVG files under `diagrams/`

The former `CONNECTION-ENGINE.md` is retained as
`CONNECTION-ENGINE-FIELD-NOTES.md`. It is field-mechanism evidence, not a
competing architecture contract. Repository links and Rust documentation
comments now use the retained name.

## 2. Exact source baseline

```text
branch: arc/00-v4-baseline
baseline source commit: 9b5b4862d21ddbb92e9ff4fbbade47b41fe6fa75
upstream/main: 9b5b4862d21ddbb92e9ff4fbbade47b41fe6fa75
origin/main: 28c9e27f89fdb8c2af9a9691a0fe0271befbe060
upstream: https://github.com/mrjeeves/MyOwnMesh.git
origin: https://github.com/nathanfraske/MyOwnMeshSecurityReview.git
```

The source baseline is the same commit inspected by
`MEDIA-LANE-GENERALIZATION-AUDIT.md` in the supplied package. No source delta
note is therefore required for the V4 red-team catalog.

The fork-to-upstream delta was inspected, not classified from its commit title
alone. Commit `9213044` changes log levels, log filtering, terminal color
selection, and the matching debugging instructions. Commit `9b5b486` is its
merge commit. No mesh authority, transport, protocol, persistence, service
binding, or packaging behavior is introduced by that delta.

## 3. Host and pinned tools

```text
operating system: Microsoft Windows 11 Pro 10.0.26200, build 26200
target: x86_64-pc-windows-msvc
logical processors: 20
physical memory: 34160754688 bytes
cargo: 1.88.0 (873a06493 2025-05-10)
rustc: 1.88.0 (6b00bc388 2025-06-23)
node: v22.18.0
pnpm: 10.33.0
build jobs used: 16
Rust target directory: C:\t\mom-v4-target
GUI Rust target directory: C:\t\mom-v4-gui-target
```

The job count records the existing approved build setting for this host. It is
not a V4 resource-budget decision.

## 4. Dependency and lock evidence

The checked-in lockfiles and locked dependency graph were read at the source
baseline. No manifest or lockfile changed in this slice.

| Graph | Reproduction command | Result |
|---|---|---|
| Rust workspace | `cargo tree --workspace --locked --all-features --edges normal,build,dev --prefix depth` | 873 UTF-8 LF lines; SHA-256 `E8AD715023136B3472ED61E4B1C1FA9D122BA0E14CD3FD7EC5147F0CF7CF4FE0`; 367 resolved packages and 5 workspace members |
| Tauri workspace | `cargo tree --locked --all-features --edges normal,build,dev --prefix depth` from `gui/src-tauri` | 702 UTF-8 LF lines; SHA-256 `F39B80C0F9FACDA50830A2126EBCE036E6A7FCD5E12AC0738C12B8947BBFE1C7`; 487 resolved packages and 1 workspace member |
| GUI JavaScript | `corepack pnpm@10.33.0 install --frozen-lockfile` | Lockfile accepted without modification |

Lockfile SHA-256 values:

```text
Cargo.lock: 9FE0AC08F4FDB9A3373C3667669937FF19934FE4AE7728373BA59CF4035D57C6
gui/src-tauri/Cargo.lock: EE0F2B7192A00A7E065D5126495992810E6120AAB694EA3BA2B61631D54ACA91
gui/pnpm-lock.yaml: 84374AE6EE7192982B4440547281D4E31B707058A03D64E82CFE1A7FCFE79491
```

## 5. Build and static-check results

Every command in this table used the source baseline named in Section 2 plus
documentation-only working-tree changes.

| Command | Result | Evidence or limitation |
|---|---|---|
| `cargo fmt --all -- --check` | Passed | No formatting changes required at the time of the check |
| `cargo clippy --workspace --all-targets -j 16 -- -D warnings` | Passed | All workspace targets compiled under Clippy |
| `cargo test --workspace --all-targets --no-run -j 16` | Passed | Every workspace test target compiled; test bodies were not executed |
| `corepack pnpm@10.33.0 install --frozen-lockfile` | Passed | pnpm reported that the esbuild install script was ignored; the following checks and build still passed |
| `corepack pnpm@10.33.0 check` | Passed | 0 errors and 0 warnings |
| `corepack pnpm@10.33.0 build` | Passed | 156 modules; output sizes were 0.41 kB HTML, 63.75 kB CSS, and 216.33 kB JavaScript |
| `cargo build --locked --release -p myownmesh -j 16` | Passed | Finished the optimized daemon build in 4 minutes 40 seconds |
| `corepack pnpm@10.33.0 tauri build --bundles msi` | Passed | Finished the optimized GUI and one x64 MSI bundle in 4 minutes 32 seconds |
| `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\install.ps1 -DryRun -FromSource -NoGui -Prefix C:\t\mom-v4-install-dry` | Passed | Syntax and from-source selection only; no files were installed |

No application statement, type, protocol definition, manifest, lockfile, or
runtime configuration changed in this slice. Four Rust documentation comments
were updated to point at the renamed field-notes document.

`git diff --cached --check` reports the eleven two-space Markdown hard breaks
on the numbered PR titles in `TRANSITION-PLAYBOOK.md`. They are intentional and
are preserved so the adopted document remains byte-identical to the verified
package. No other staged whitespace finding is present.

## 6. Package inspection

Build artifact identities:

```text
myownmesh.exe
bytes: 10052096
sha256: 7D41EF7D5619AABDC56D0DC07C65DB30287335BC4A61E999D8A5F4852730E7B2

myownmesh-gui.exe
bytes: 5380096
sha256: 7C6575B0531C2FB86D0196AA868E8DEDD67DA595BC358524FFB79A7B62F7A140

MyOwnMesh_0.3.2_x64_en-US.msi
bytes: 2543616
sha256: 173BFBF4A9EFF379E740EE70A3EA424610ACD36A645EE1546923962AF7C968FD
```

The MSI `File` table was read through the Windows Installer API. It contains
one row, `myownmesh-gui.exe`, and does not contain `myownmesh.exe`. This does
not prove the documented claim that installing the GUI bundle also installs
the daemon. The discrepancy is pre-existing and remains open. It was not
repaired in this documentation-only slice.

The installer was not executed. The dry run does not prove archive download,
hash-sidecar handling, installation, PATH mutation, GUI installation, launch,
upgrade, rollback, or uninstall behavior.

## 7. Firewall and runtime-test containment

The initial command `cargo test --workspace --all-targets -j 16` was stopped
after Windows displayed a firewall prompt while executing the freshly named
`silent_area_scale` integration-test binary. That command has no pass or fail
result. No V4 target executable remained running after cleanup.

Fresh Cargo integration binaries will not be executed directly on this host
unless each listener and external effect has first been audited. The default
workspace check for this transition is compile-only. Live networking belongs
in the sealed sandbox runtime or another proven isolated environment.

The existing sandbox firewall rules were inspected without modification. They
allow inbound TCP and UDP for this one stable path on Private and Public
profiles:

```text
C:\Users\Admin\AppData\Local\AllMyStuffSandboxRuntime\myownmesh.exe
sha256: 89B8A1FFB0AB805FC6A7EC34E72911BCAEDFBB6CC2F4AE38F31E657F634B740D
```

The binary matches its sealed manifest, but its MyOwnMesh source commit is
`28c9e27f89fdb8c2af9a9691a0fe0271befbe060`, not the current baseline.
Results from it cannot be presented as exact-commit V4 baseline evidence.

## 8. Open Arc 00 evidence gates

The following cases have no current-baseline result yet:

- runtime execution of the full Rust workspace tests;
- direct LAN connection trace;
- Nostr-signaled connection trace;
- mDNS-signaled connection trace;
- TURN connection trace;
- reconnect and network-change traces;
- media, typed Channel, and RPC traces;
- daemon start, graceful stop, and restart;
- a real Windows install, launch, upgrade, rollback, and uninstall;
- non-Windows package and integration results;
- mixed-version behavior.

A production AllMyStuff process and its MyOwnMesh child were running during
this baseline. They were not stopped, queried, or modified. A second daemon was
not launched because the Windows control client resolves the default
`myownmesh.sock` name even when `daemon.control_socket` is configured. See
`crates/myownmesh/src/cli/ctl.rs`. Until that isolation boundary is repaired or
the exact source is staged in the sealed harness, a daemon smoke would not be
valid evidence that production state remained untouched.

The annotated pre-transition tag is also open. `TRANSITION-PLAYBOOK.md` makes
the final tag name an owner-selected value, so this slice does not invent one.

## 9. Gate result

The first V4 pull-request slice is ready as a documentation and reproducible
baseline change with no product behavior change. The full Arc 00 gate is not
claimed complete. It requires the exact-commit sandbox, runtime matrix,
installer verification, and owner-selected tag described above.
