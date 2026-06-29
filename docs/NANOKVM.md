# Running a MyOwnMesh node on a NanoKVM

A NanoKVM (Sophgo **SG2002**, single T-Head **C906** riscv64 core, ~256 MB
RAM, musl userland) can run a real MyOwnMesh node so the KVM appears as a
first-class device on an AllMyStuff mesh. The split is deliberate:

- **The `myownmesh` daemon runs natively on the device.** It holds the
  device's ed25519 identity, does the NAT-traversed WebRTC mesh + Nostr
  signaling, and exposes the local control socket at
  `$MYOWNMESH_HOME/daemon.sock`. This is the only Rust artifact on the KVM.
- **The AllMyStuff node logic lives in the NanoKVM Go server** (`NanoKVM-Server`,
  package `service/mesh`), as a *client* of that socket — exactly the sidecar
  pattern the desktop app uses, but with KVM-native backends (its own web UI
  tunneled over the mesh, `/dev/hidg*` and `libkvm` reused in-process). See the
  NanoKVM repo's `docs/MESH.md`.

Only the daemon needs cross-compiling, and it is the easy half: `myownmesh-core`
is pure Rust on `ring` + `rustls` (no OpenSSL, no C system libraries), so the
lone native dependency is ring's riscv64 assembly.

## Build the daemon for the device

The daemon is built with **`cargo-zigbuild`** — Zig supplies the C compiler and
linker for a static `rv64gc` musl binary. All you need is the Rust target, Zig,
and cargo-zigbuild:

```sh
just setup-risc            # add the Rust target + cargo-zigbuild (install zig once)
just build-risc            # cross-build the daemon  (alias: just build-nanokvm)
# → target/riscv64gc-unknown-linux-musl/release/myownmesh
```

Install Zig however suits your box — `brew install zig`, `apt install zig`, or
`pip install ziglang` (then a `zig` shim, or set `ZIG_COMMAND="python3 -m
ziglang"`). On a Mac this is the whole story: no Docker, no hunting for a musl
gcc.

### Why Zig, not the Sophgo C906 toolchain

NanoKVM's Go server is built with the device's Sophgo host-tools
(`riscv64-unknown-linux-musl-gcc`), and it's tempting to reuse it here. **Don't.**
That gcc defaults to the T-Head **vendor** ISA (`rv64imafdcv0p7xthead` — draft-0.7
vector + xthead custom extensions), but rustc always emits **standard** `rv64gc`
objects for `riscv64gc-unknown-linux-musl`. GNU `ld` can't reconcile the vendor
arch attributes with the standard ones and aborts the link:

```
ld: failed to merge target specific data of file
    .../riscv64gc-unknown-linux-musl/lib/self-contained/libc.a(close.lo)
```

The Go server dodges this because it *dynamically* links the C906 `libkvm.so`
(no static-archive attribute merge); the Rust daemon links static musl, so it
hits the conflict head-on. A standard `rv64gc` toolchain (Zig) links cleanly,
and the resulting static-musl binary runs fine on the C906, which implements the
full `rv64gc` base ISA — the vendor extensions only matter to code that uses them,
and the daemon doesn't. `.cargo/config.toml` documents this too.

## On the device

Ship the binary beside `NanoKVM-Server` and start it at boot **before** the KVM
server (so the socket is up when the bridge connects), with a persistent home on
the device's writable `/data` partition:

```sh
export MYOWNMESH_HOME=/data/myownmesh   # identity, rosters, daemon.sock
/kvmapp/myownmesh/myownmesh serve
```

The NanoKVM repo adds an init script (`kvmapp/system/init.d/S94myownmesh`) that
does this. The identity (`$MYOWNMESH_HOME/.secrets/identity.json`, 0600) is
generated once on first boot and persists across updates.

The KVM ships joined to the `cec-backend-client-mesh` network on the standard
public venue and advertises itself as **claimable**, so the machine it is wired
to adopts it into that owner's fleet (the NanoKVM bridge drives the claim).

## Released artifact

The release pipeline builds and publishes the daemon for this target on every
release: a static-musl **`myownmesh-linux-riscv64.tar.gz`** (+ `.sha256`, and a
`.minisig` once signing is configured), cross-compiled with cargo-zigbuild (a
standard `rv64gc` musl toolchain — see *Why Zig* above). A NanoKVM pins a
MyOwnMesh release in its `.myownmesh-rev` and installs that asset — no on-device
or sibling build.

## Status

The daemon is pure-Rust + `ring`, and webrtc 0.13 cross-compiles cleanly to
`riscv64gc-unknown-linux-*` (verified). What remains unproven is **runtime on
real SG2002 hardware** (RAM headroom, NAT-traversal from the device's network);
the protocol/bridge layers above it are exercised by the NanoKVM repo's
host-side contract tests (`go test ./service/mesh/...`).
