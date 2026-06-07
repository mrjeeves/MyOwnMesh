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
myownmesh                  # open the desktop GUI (myownmesh-gui)
myownmesh serve            # run the daemon in the foreground (headless)
myownmesh service install  # run serve as a background OS service
myownmesh service status   # is it installed / enabled / running?
myownmesh service stop     # stop it (start / restart / uninstall too)
myownmesh identity show    # print this device's id
myownmesh ctl status       # query a running daemon
myownmesh ctl networks list
myownmesh update status    # version, channel, policy, staged update
myownmesh update check     # check the feed now and stage if permitted
myownmesh config path      # print ~/.myownmesh/config.json
myownmesh config edit      # open in $EDITOR
```

A bare `myownmesh` hands off to the `myownmesh-gui` desktop app
(found next to this binary, on `$PATH`, or via `MYOWNMESH_GUI_BIN`);
the GUI then auto-spawns `myownmesh serve`. On a headless box with no
display it prints a pointer to `serve` instead. This crate stays
headless either way — the GUI lives in [`gui/`](../../gui/).

The daemon reads `~/.myownmesh/config.json` (auto-created on first
edit; sensible defaults until then), joins every network listed
there, attaches the Nostr signaling driver per network, and listens
for `myownmesh ctl …` clients on a local socket
(`~/.myownmesh/daemon.sock` on Unix, named pipe on Windows).

## Running as a background service

`myownmesh service …` registers `serve` with the host init system so
the daemon survives logout and reboot — **systemd** on Linux,
**launchd** on macOS. (This manages the daemon *process*; it's
unrelated to `ctl services`, which toggles the mesh's own hosted
relay / STUN / TURN / signaling roles.)

```bash
myownmesh service install    # write the unit + enable + start it
myownmesh service status     # installed / enabled / running, + log hint
myownmesh service start      # start | stop | restart
myownmesh service uninstall  # stop, disable, remove
```

By default it installs a **per-user** service (no root; state stays in
`~/.myownmesh`; starts at login — on Linux it also enables lingering so
it keeps running while you're logged out). Pass `--system` for a
root-owned service that starts at **boot** and keeps its state under a
system directory:

```bash
sudo myownmesh service --system install
```

The Linux system unit runs unprivileged via `DynamicUser=yes` +
`StateDirectory=` (state in `/var/lib/myownmesh`, no account to
create) with a hardening block; the macOS system daemon stores state
under `/Library/Application Support/MyOwnMesh`. `--system` disables the
in-process self-updater (it can't rewrite a root-owned binary); update
by re-running the installer / `cargo install`, then
`sudo myownmesh service --system restart`.

If `serve` lives in your home (e.g. a `cargo install` build), a
`--system` install copies it to `/usr/local/lib/myownmesh/` so the
service account can execute it. Follow logs with the printed hint
(`journalctl -u myownmesh -f`, or `tail -f` the launchd log).

Windows isn't wired to a service manager yet — `service` there points
you at Task Scheduler / NSSM instead. On a headless / SSH-only Mac,
prefer `--system` (a LaunchAgent needs a GUI session to load).

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
      "stun_servers": [{ "urls": ["stun:stun.myownmesh.com:3478"] }],
      "turn_servers": [
        { "urls": ["turn:turn.myownmesh.com:3478"], "username": "guest", "credential": "theguestpassword" }
      ],
      "auto_approve": false
    }
  ]
}
```
