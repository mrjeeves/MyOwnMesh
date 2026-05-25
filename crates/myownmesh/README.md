# myownmesh

The MyOwnMesh daemon + CLI. Headless. Embedders should depend on
[`myownmesh-core`](../myownmesh-core/) instead — this crate is the
shipped binary, not a library.

## Install

Pre-built binaries from [GitHub Releases](https://github.com/mrjeeves/MyOwnMesh/releases):

```bash
# macOS / Linux — replace the platform suffix as needed
curl -fsSL https://github.com/mrjeeves/MyOwnMesh/releases/latest/download/myownmesh-linux-x86_64.tar.gz | tar -xz
./myownmesh serve
```

From source:

```bash
git clone https://github.com/mrjeeves/MyOwnMesh
cd MyOwnMesh
cargo install --path crates/myownmesh        # daemon + CLI on $PATH
# or run without installing:
cargo run -p myownmesh -- serve
```

## Usage

```
myownmesh                  # start the daemon (alias for `serve`)
myownmesh serve            # run the daemon in foreground
myownmesh identity show    # print this device's id
myownmesh ctl status       # query a running daemon
myownmesh ctl networks list
myownmesh update check     # poll the release feed
myownmesh config path      # print ~/.myownmesh/config.json
myownmesh config edit      # open in $EDITOR
```

The daemon reads `~/.myownmesh/config.json` (auto-created on first
edit; sensible defaults until then), joins every network listed
there, attaches the Nostr signaling driver per network, and listens
for `myownmesh ctl …` clients on a local socket
(`~/.myownmesh/daemon.sock` on Unix, named pipe on Windows).

## Logging

`MYOWNMESH_LOG=debug,myownmesh=trace` — recommended when diagnosing
a network issue. See [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md).

## Config snippet

```jsonc
{
  "version": 1,
  "auto_update": {
    "enabled": true,
    "channel": "stable",
    "auto_apply": "patch"
  },
  "daemon": {
    "enabled": true,
    "log_level": "info"
  },
  "networks": [
    {
      "id": "home",
      "network_id": "my-cool-mesh",
      "label": "Home",
      "topology": { "kind": "ring", "n_preferred": 3 },
      "signaling": { "strategy": "nostr", "redundancy": 5 },
      "stun_servers": [{ "urls": ["stun:stun.l.google.com:19302"] }],
      "turn_servers": [],
      "auto_approve": false
    }
  ]
}
```
