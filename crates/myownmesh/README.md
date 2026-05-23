# myownmesh

The MyOwnMesh daemon + CLI.

## Install

From source:

```
cargo install --path crates/myownmesh
```

(Pre-built releases land via `RELEASE.md`'s pipeline once it's
wired.)

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
a network issue. See `CONTRIBUTING.md`.

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
