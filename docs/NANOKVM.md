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

Prerequisites (the same musl cross-toolchain NanoKVM builds its Go server with):

```sh
rustup target add riscv64gc-unknown-linux-musl
# riscv64-unknown-linux-musl-gcc / -ar must be on $PATH (Sophgo host-tools,
# the toolchain NanoKVM's server/build.sh and docker/Dockerfile already use).
```

Then:

```sh
just build-nanokvm
# → target/riscv64gc-unknown-linux-musl/release/myownmesh
```

`.cargo/config.toml` wires the linker and ring's C build to that toolchain, so a
host build is unaffected and only the riscv64 target uses it.

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

## Status

The daemon is pure-Rust + `ring`; webrtc 0.13 → `riscv64gc-unknown-linux-musl`
has not yet been validated end-to-end on real SG2002 hardware (no public CI
runner for this target). Treat the cross-build recipe as the starting point for
on-device bring-up; the protocol/bridge layers above it are exercised by the
NanoKVM repo's host-side contract tests (`go test ./service/mesh/...`).
