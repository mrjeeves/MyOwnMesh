# Debugging connection-state reliability

A field runbook for the connection-reliability work. The engine is
heavily layered — a 7-tier reconnection ladder, an ICE watchdog, a wake
detector, a network watcher (see [`CONNECTION-ENGINE.md`](../CONNECTION-ENGINE.md)).
When node connection state is nonetheless unreliable, the cause is
almost never a missing tier. It's one of two structural things:

1. **No single source of truth for "is this peer up."** Liveness is
   spread across several independently-updated fields — `status`,
   `tier`, the raw ICE state, the peer-connection state, the selected
   candidate pair, inbound recency. Nothing forces them to agree, so a
   peer can read `status = active` while ICE has already gone
   `Disconnected`. That disagreement *is* the bug.
2. **A detection blind spot.** A half-dead data channel (peer
   unreachable, but no `on_close`/`on_error` and ICE still nominally
   `Connected`) fires no event. The only backstop is the heartbeat, and
   its effective stale cutoff is `HEARTBEAT_TIMEOUT_MS +
   WAKE_DETECTION_THRESHOLD_MS` ≈ **90 s**. ICE-disconnect itself is
   noticed fast (callback-driven), but the ICE watchdog re-drives on a
   **3 s** poll (`ICE_POLL_INTERVAL_MS`).

This document is **Phase 0 + 1** of the cleanup: *make it observable,
then reproduce it deterministically*. We do not change the ladder or its
constants here — we instrument the engine so every fix afterward is
driven by data, not by guesswork. You cannot fix a distributed timing
bug by eyeballing three plain-text logs you can't line up.

---

## What this adds

| Tool | What it gives you |
|------|-------------------|
| `myownmesh ctl trace <network>` | A live JSONL stream of every per-peer connection-state transition. The primary, machine-parseable artifact. |
| `MYOWNMESH_CONN_TRACE=1` | Forces the engine's tracer on even with no live `ctl trace` subscriber, so transitions land in the daemon log. |
| `MYOWNMESH_LOG_FORMAT=json` | Switches the daemon to structured JSON logs — the trace events appear as first-class keyed records alongside the surrounding ICE/signaling context. |
| `scripts/merge-traces.py` | Interleaves several machines' trace files into one wall-clock-ordered timeline. |

The tracer is **free when nobody is watching**: the driver loop checks
one atomic before doing any work, so leaving the code in place costs
nothing in production. It turns on the moment a `ctl trace` client
attaches or `MYOWNMESH_CONN_TRACE` is set.

### Anatomy of a `ConnTrace` record

```json
{
  "ts_wall_ms": 1750100003200,   // wall clock — cross-machine ordering (NTP-skewed)
  "t_mono_ms": 3205,             // ms since this driver started — monotonic, authoritative within one machine
  "network_id": "home",
  "device_id": "3f9a2c1b9988…",
  "epoch": 1,                    // bumps on every session rebuild — flap detector
  "changed": ["ice"],            // which discrete fields moved since the last record for this peer
  "status": "active",            // engine app-level status
  "tier": "steady",              // reconnection-ladder tier
  "ice_state": "Disconnected",   // raw RTCIceConnectionState
  "pc_state": "Connected",       // raw RTCPeerConnectionState
  "pair_class": "lan",           // how traffic flows once nominated: lan | stun | turn
  "rtt_ms": 4,                   // app-level ping/pong RTT
  "last_recv_age_ms": 3200,      // age of last inbound frame
  "authenticated": true,
  "local_shelved": false,
  "remote_shelved": false
}
```

A record is emitted only when one of the **discrete** fields changes
(`epoch`, `status`, `tier`, `ice`, `pc`, `pair`, `auth`,
`local_shelved`, `remote_shelved`). The continuously-varying values
(`rtt_ms`, `last_recv_age_ms`) ride along as context but don't by
themselves trigger a record. `changed` names exactly what moved, plus
the lifetime markers `appeared` / `vanished`.

**The signatures to look for:**

- `status=active` with `ice_state=Disconnected` (or `pc_state` lagging)
  → the **source-of-truth drift**. The engine still thinks the peer is
  live; ICE doesn't. Look at how long it persists before something
  reconciles it.
- **`epoch` climbing** for a peer that looks otherwise stable →
  connection **flapping**: it's being torn down and rebuilt under you.
- `pair_class=turn` (or `stun`) where you expected `lan` → traffic is
  relaying/holepunching when a direct path should exist.
- A long gap in `t_mono_ms` between records, or a `{"lagged":N}` marker
  in the stream → the process was paused (sleep) or a transition storm
  outran the reader.

---

## Capturing a session

Run the daemon and, in a second shell, the trace, on **each** machine.
Tag the file with the hostname so the merge tool can label rows.

> **Running the GUI (`just dev`)?** The GUI auto-spawns the daemon and
> forwards its logs to your terminal — **except on Windows**, where the
> GUI is a windowless process with no console for the daemon's stdout to
> inherit, so you see nothing. On every OS the robust path is to run the
> daemon **standalone** and let the GUI attach to it: `just serve-trace`
> in one terminal (full logs + the connection tracer, on Windows too),
> and — if you want the GUI — `just dev` in another. The GUI probes the
> control socket, finds the running daemon, and attaches instead of
> spawning its own. (`just serve-trace` is just the daemon with
> `MYOWNMESH_CONN_TRACE=1` and a connection-debugging log filter.)

**macOS / Linux**

```sh
# shell 1 — daemon (verbose engine logs; JSON optional)
MYOWNMESH_LOG="info,myownmesh=debug,webrtc_ice=warn" myownmesh serve

# shell 2 — connection trace to a per-host file
myownmesh ctl trace home > "trace-$(hostname -s).jsonl"
```

**Windows (PowerShell)**

```powershell
# shell 1 — daemon
$env:MYOWNMESH_LOG = "info,myownmesh=debug,webrtc_ice=warn"; myownmesh serve

# shell 2 — connection trace
myownmesh ctl trace home > "trace-$env:COMPUTERNAME.jsonl"
```

If you'd rather not keep a `ctl trace` shell open, set
`MYOWNMESH_CONN_TRACE=1` on the daemon and the transitions land in the
daemon log itself; with `MYOWNMESH_LOG_FORMAT=json` they're structured.
The dedicated `ctl trace` file is cleaner for the merge tool, though.

### Merge into one timeline

Pull the per-host files onto one box and:

```sh
scripts/merge-traces.py --skew trace-*.jsonl
```

```
TIME          +ms    HOST   PEER      EPOCH  CHANGED   STATUS  TIER          ICE           PC            PAIR  RTT  AGE
------------  -----  -----  --------  -----  --------  ------  ------------  ------------  ------------  ----  ---  ----
18:53:20.000  +0     mac    3f9a2c1b  1      appeared  active  steady        Connected     Connected     lan   4    120
18:53:21.000  +1000  linux  aa11bb22  7      appeared  active  steady        Connected     Connected     stun  30   50
18:53:23.200  +3200  mac    3f9a2c1b  1      ice       active  steady        Disconnected  Connected     -     4    3200
18:53:23.250  +3250  linux  aa11bb22  7      tier      active  ice_watchdog  Disconnected  Disconnected  stun  31   3300
```

That row at `+3200` — `status=active`, `ice=Disconnected` — is the
drift, caught the instant it happens. Filter to one peer with `--peer
3f9a2c1b`, one network with `--network home`, or a window with `--since
2026-06-16T20:00:00Z`. `--skew` prints each host's wall-clock span so
gross NTP offsets are obvious (sync the boxes with NTP before a run to
keep cross-machine ordering trustworthy; within a machine, `t_mono_ms`
is always correct regardless of skew).

---

## Reproduction scenarios (Phase 1)

The point of three machines is to trigger the real failure modes on
demand and watch them in the merged timeline. Start a capture on every
machine, run a scenario, stop the captures, merge. Keep a short note of
wall-clock-when-you-did-X so you can find it in the timeline.

The transport has no fault-injection seam today (it's a concrete
`webrtc-rs` wrapper, not a trait — an in-process shim is a deliberate
follow-up, see below), so these are **real OS faults on real machines** —
which is exactly the setup you have.

### 1. Baseline connect

Just bring all three up on the same network and let them reach `active`.
Confirm the healthy steady state: every peer `status=active`,
`tier=steady`, `ice=Connected`, stable `epoch`, and a `pair_class` that
matches your topology (`lan` on a LAN, `stun`/`turn` across NAT). This is
your control — know what good looks like before you break things.

### 2. Sleep / wake

The classic killer: heartbeats pause, the OS suspends timers, the
network drops for a beat on resume. Watch for the wake probe (Tier 2),
ICE restarts, and how fast peers return to `active` vs. the 90 s
heartbeat backstop.

- **macOS:** `sudo pmset relative wake 30 && pmset sleepnow` (sleep now,
  auto-wake in 30 s), or just close the lid.
- **Linux:** `sudo rtcwake -m mem -s 30` (suspend to RAM, wake in 30 s).
- **Windows:** `rundll32.exe powrprof.dll,SetSuspendState 0,1,0`, or use
  Sysinternals `psshutdown -d -t 0`.

In the timeline: expect a `t_mono_ms` jump across the sleep, then a
burst of `ice`/`tier`/`epoch` changes as the ladder recovers. A peer
stuck non-`active` long after the others recovered is a bug to chase.

### 3. Network handoff (Wi-Fi ↔ hotspot / interface flip)

Recovering a network change in place is what the ICE-restart and
network-watch machinery exists for. Flip the primary interface and watch
for the `restart_ice` path and `pair_class` changes (a handoff may move
you LAN→STUN→TURN).

- **macOS:** `networksetup -setairportpower en0 off` then `on`; or toggle
  Wi-Fi while tethered to keep a second path.
- **Linux:** `nmcli radio wifi off && sleep 5 && nmcli radio wifi on`, or
  `sudo ip link set <iface> down/up`.
- **Windows:** `netsh interface set interface "Wi-Fi" admin=disabled`
  then `enabled`.

### 4. Relay / signaling loss

If you host signaling (`ctl services enable signaling`), kill it and
watch peers fall back. Even on public Nostr you can block it at the
firewall to simulate a relay blackout. Look for room-rejoin (Tier 5) and
the relay-rescue redial.

```sh
# on the signaling host
myownmesh ctl services disable signaling   # then re-enable after a minute
```

### 5. Hard link drop (the half-dead case)

Pull the ethernet cable or `down` the interface *without* a clean
shutdown — this is the case with no `on_close` event. This is where the
~90 s blind spot bites: note how long the timeline shows `status=active`
with a stale `last_recv_age_ms` before anything reacts. That latency is
the headline number Phase 3 is meant to cut (via a passive
`get_stats()` liveness signal).

---

## What this phase deliberately does **not** do

Per the "measure first, change what the data proves" decision, this is
instrumentation and reproduction only — no behavior change. The fixes
the traces are meant to justify are the next phases:

- **One derived connection state behind a single transition function**,
  replacing the several drifting fields (this is what kills the
  `status≠ice` class of bug at the root).
- **A passive `get_stats()` liveness/consent signal** on the ICE poll
  the engine already runs — closing the 3 s→90 s half-dead gap and
  letting the blanket heartbeat become conditional (less polling).
- **OS-native network-change and sleep/wake hooks** (netlink /
  `nw_path_monitor` / Windows power events) replacing the 3 s IP poll
  and tick-gap inference.
- **An in-process fault-injection harness**, which needs a transport
  trait seam to wrap — a larger, separate change than this additive
  observability layer.

When a captured timeline shows one of these clearly, that's the trace
that justifies making the change.
