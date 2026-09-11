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
myownmesh ctl networks join <id>    # join a network (defaults) — persist + attach live
myownmesh ctl networks leave <id>   # leave a network — detach + remove from config
myownmesh update status    # version, channel, policy, staged update
myownmesh update check     # check the feed now and stage if permitted
myownmesh config path      # print ~/.myownmesh/config.json
myownmesh config edit      # open in $EDITOR
myownmesh install caddy <domain>    # signaling WSS + TURN TLS on 5349 (isolated loopback backend)
myownmesh caddy path       # print the Caddyfile location to edit
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
Generated systemd units identify records as `myownmesh` and cap the daemon at
100 records per five minutes. Normal operation is well below that ceiling; it
prevents a dependency regression or hostile packet stream from filling the
journal and `/var/log/syslog` before the host's normal rotation runs.

Windows isn't wired to a service manager yet — `service` there points
you at Task Scheduler / NSSM instead. On a headless / SSH-only Mac,
prefer `--system` (a LaunchAgent needs a GUI session to load).

## Logging

`MYOWNMESH_LOG=debug,myownmesh=trace` — recommended when diagnosing
a network issue. See [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md).

## Config snippet

```jsonc
{
  "version": 2,
  "auto_update": {
    "enabled": true,
    "channel": "stable",
    "auto_apply": "all"
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
      "kind": "open",
      "semantic_policy": {
        "max_fact_encoded_bytes": 65535,
        "max_dependencies_per_fact": 64,
        "max_authority_uses_per_fact": 32,
        "max_authority_predecessors_per_use": 64,
        "max_admitted_facts": 100000,
        "max_admitted_bytes": 134217728,
        "max_quarantined_facts": 4096,
        "max_quarantined_bytes": 16777216,
        "max_quarantined_facts_per_author": 256,
        "max_quarantined_bytes_per_author": 4194304,
        "max_retained_facts_per_author": 10000,
        "max_retained_bytes_per_author": 16777216,
        "max_dependency_edges": 1000000,
        "max_ready_batch": 256,
        "max_pending_proofs": 10000,
        "max_pending_proof_bytes": 16777216,
        "max_proof_records": 100000,
        "max_proof_bytes": 67108864,
        "max_proof_links": 100000,
        "max_author_usage_rows": 100000,
        "max_provisional_rows": 100000,
        "max_transaction_dirty_main_pages": 1024,
        "max_uncheckpointed_wal_frames": 1018,
        "max_freelist_pages": 1024,
        "max_fragmented_pages": 1024,
        "max_main_journal_bytes": 8388608,
        "max_database_bytes": 2147483648,
        "max_wal_bytes": 8413072,
        "wal_checkpoint_threshold_bytes": 4194192,
        "emergency_reserve_bytes": 8388608
      },
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

`semantic_policy` is the complete owner-selected semantic storage policy.
Its database and lifecycle limits are logical named-file reservations: they
bound the main database, WAL/SHM, journal, provisional, checkpoint frames, proof,
and dirty-page footprints that the process may retain. `max_wal_bytes` is the
funded WAL envelope (retained frames plus one bounded transaction), while
`wal_checkpoint_threshold_bytes` selects SQLite's automatic-checkpoint frame
count. SQLite's default VFS owns locking, recovery, WAL reuse, and checkpoint
execution. Neither setting guarantees physical disk space or prevents an
operating-system `ENOSPC`.
