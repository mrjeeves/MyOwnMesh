# Hosted services

A MyOwnMesh device can host infrastructure for the rest of the mesh:
relay routing, a signaling server, a STUN server, and a TURN server.
Turning these on lets a device advertise itself as a router, an
ingress / egress point, or a STUN / TURN handler — which is what makes a
**fully internet-isolated network** practical. No Google STUN, no
Cloudflare TURN, no public Nostr relay required: one always-on device
(or a few) can supply every piece of plumbing a closed fleet needs.

A device is **any combination** of a mesh node and these hosted
services — so a dedicated box can be pure infrastructure (signaling +
STUN + TURN, not itself a member). The hosted services are **off by
default** and configured device-wide (not per network); a hosted service
serves every network the device participates in, plus any external client
that points at it. The `node` role is **on by default** (a fresh device
is a normal member).

## The services

| Service | What it does | Default | Needs |
|---|---|---|---|
| **Node** | Participate as a regular mesh member (join configured networks). On by default; off = pure-infra box. | on | nothing |
| **Relay** | Forwards traffic between roster members so peers that can each reach this device, but not each other, can still talk. | off | node on |
| **Signaling** | An *intelligent* Nostr relay (NIP-01 / WebSocket) peers use in place of public Nostr — live presence, instant departure, flood limits. | off · :4848 | nothing |
| **STUN** | Answers RFC 5389 binding requests so peers learn their reflexive address. | off · :3478 | nothing |
| **TURN** | Relays media / data for peers behind symmetric NAT (RFC 5766), with an optional per-connection bandwidth cap. | off · :3478 | public IP + credentials |

### Node

Whether this device participates as a regular mesh member — joining its
configured networks and acting as a peer. It's on by default. Turn it off
to run a **pure-infrastructure box**: the daemon hosts signaling / STUN /
TURN (advertising itself purely as an edge / ingress-egress point) and
joins no networks itself. Because the relay forwards traffic *within* a
network, it needs node participation and goes idle when node is off.

Toggling `node` live joins or leaves every configured network in place —
no restart needed.

### Relay

When enabled, the device forwards typed-channel frames between roster
members on a reserved channel. A spoke sends a `RelayEnvelope`
(`{ dst, payload }`) to the relay; the relay rewrites the authenticated
origin into `src` and forwards it — to one destination (directed) or to
every other reachable member (broadcast, `dst` empty).

Forwarding is **roster-gated on both ends**: a frame is only relayed when
its sender is an approved peer of the relay device, and a directed frame
only reaches its destination when that destination is also approved. The
relay never forwards for or to strangers.

This is application-layer routing built on the existing channel API — it
does not change the WebRTC data path. Transparent relay *fallback* (a
peer automatically routing through a relay when a direct ICE path can't
be found) is a planned follow-up; today a relay node is an explicit
message hub for the roster.

### Signaling

A self-hosted [Nostr](https://github.com/nostr-protocol/nips) relay
speaking the slice of NIP-01 the mesh needs (`REQ` / `EVENT` / `EOSE` /
`CLOSE`, with `kinds` / `since` / `#tag` filters). The win is that the
built-in signaling driver **already speaks NIP-01 to public relays**, so
a peer adopts your relay with zero client changes — just add
`ws://your-host:4848` to that network's signaling servers (see
*Pointing peers at your services* below).

Presence events (kind `1077`) are retained for ~15 minutes so a late
joiner discovers everyone already in the room; negotiation events
(ephemeral kind `21077`) are forwarded live and never stored, so a stale
offer can't bind a fresh connection. The relay does not verify event
signatures — it's a forwarder, and the mesh runs its own ed25519 mutual
auth over the resulting WebRTC channel, so a forged Nostr event buys an
attacker nothing but a failed handshake.

#### Intelligent coordination

A self-hosted relay is *stateful*, the way a normal WebRTC signaling
server is — it does more than blindly forward, which makes connections
come up faster and recover quicker. All of it stays plain NIP-01 on the
wire and **degrades gracefully**: against a public relay (or an older
peer) you simply get the dumb-forwarder baseline.

- **Live presence.** The relay learns `(connection → device, room)` from
  the announces a peer publishes, so it knows who's actually connected
  *now*. A peer subscribing gets the live member set replayed instantly —
  near-instant discovery, even if a member's last announce is old.
- **Instant departure.** When a member's socket closes, the relay emits a
  `leave` to the room. The engine already understands "peer left" and
  tears the connection down immediately, instead of waiting out the
  ~75 s heartbeat timeout. (This is a brand-new `SignalingMessage::Leave`
  the smart relay synthesizes; public relays never send it, so a peer
  that doesn't get one just falls back to timeout detection.)

These accelerate the engine's existing reconnection ladder rather than
replacing it — the relay is an **optional accelerator, never a
coordinator the mesh depends on**. If it goes away, peers fall back to
the public-Nostr behaviour and the mesh keeps working.

#### Flood limits

Because this is meant to be safe to stand up publicly, every connection
is rate-limited and the relay sheds abuse. All limits are tunable
(`services.signaling.limits`), and `0` means "no limit":

| Limit | Default | Guards against |
|---|---|---|
| `max_event_rate` | 50 / s / conn | publish floods |
| `max_req_rate` | 20 / s / conn | subscription churn |
| `max_subscriptions` | 64 / conn | subscription hoarding |
| `max_filters_per_req` | 16 | oversized `REQ`s |
| `max_message_bytes` | 65536 | giant frames |
| `max_connections_per_ip` | 64 | connection storms |

Rates use a token bucket (1-second burst); a connection that keeps
violating limits accrues strikes and is disconnected with a `NOTICE`.

### STUN

A standalone STUN server: it answers binding requests with the source's
XOR-mapped address and does nothing else. Pure reflexion — no auth, no
allocations. Peers add `stun:your-host:3478` to a network's STUN servers.

### TURN

A full TURN server (via the webrtc-rs `turn` crate) for peers behind
symmetric NAT, where a direct path can't be punched. TURN needs two
things that STUN/signaling don't:

- **A public IP** (`public_ip`) — the routable address the server hands
  out in relay allocations. It can't guess this; if the bind address is a
  wildcard (`0.0.0.0`) you *must* set it, or TURN refuses to start.
- **At least one credential** — a username / password pair. Mirror the
  same pair into each peer's TURN config. Enabled without credentials,
  TURN shows as *enabled, not running*.

A TURN server also answers STUN binding requests, so enabling TURN gives
you STUN for free on the same port — you rarely need both the STUN and
TURN services on one host.

**Bandwidth cap (QoS).** `max_bps_per_connection` shapes each
allocation's relayed throughput to a byte/sec ceiling, applied
independently in each direction (`0` = unlimited). It's a global knob —
every allocation gets the same cap, there's no per-user override yet — so
one client can't saturate the relay. It's enforced by a token bucket on
each allocation's relay socket; because the data is UDP, exceeding the
cap creates backpressure and drops rather than unbounded buffering, which
is the honest QoS behaviour for a relay.

## Configuration

Services live under `services` in `~/.myownmesh/config.json`:

```json
{
  "version": 1,
  "services": {
    "node":      { "enabled": true },
    "relay":     { "enabled": true, "max_fanout": 0 },
    "signaling": {
      "enabled": true,
      "bind": "0.0.0.0",
      "port": 4848,
      "limits": {
        "max_event_rate": 50,
        "max_req_rate": 20,
        "max_subscriptions": 64,
        "max_filters_per_req": 16,
        "max_message_bytes": 65536,
        "max_connections_per_ip": 64
      }
    },
    "stun":      { "enabled": true, "bind": "0.0.0.0", "port": 3478 },
    "turn": {
      "enabled": true,
      "bind": "0.0.0.0",
      "port": 3478,
      "public_ip": "203.0.113.7",
      "realm": "myownmesh",
      "credentials": [ { "username": "alice", "password": "s3cret" } ],
      "max_bps_per_connection": 0
    }
  },
  "networks": []
}
```

> `node` is on by default and `services.signaling.limits` fills in safe
> defaults, so neither needs to appear in a hand-written config — they're
> shown here for completeness.

> Because TURN also serves STUN, the example above would try to bind both
> on `3478` and the second would fail. Run one of them on `3478`, or give
> the standalone STUN service a different port.

Changes are picked up three ways, all equivalent:

### GUI

**Settings → Services.** Each service has a toggle and its fields; TURN
adds credential management. A live status pill shows whether each
listener is actually running (a service can be *enabled* but fail to
start — e.g. a port already in use, or TURN with no credentials). Edits
are staged; **Apply changes** persists them and reconciles the running
services.

### CLI

```sh
# Show what's hosted and where it's listening.
myownmesh ctl services status

# Toggle a service: node | relay | signaling | stun | turn.
myownmesh ctl services enable signaling
myownmesh ctl services disable stun

# Turn this box into pure infrastructure (no mesh membership):
myownmesh ctl services disable node
```

`enable` / `disable` flip just the one flag and persist. TURN credentials
+ public IP and the signaling flood limits / TURN bandwidth cap can't be
set from the CLI toggle — edit `config.json` (or use the GUI) for those;
an enabled-but-unconfigured TURN shows as *not running* in
`services status`.

### Editing config.json directly

Edit the `services` block and restart the daemon (`myownmesh serve`), or
re-apply live via the GUI / CLI.

## Discovery: advertising and adopting services

When a device hosts a service it advertises a **service role** to peers
via the capability matrix — stable tags (`service:relay`,
`service:signaling`, `service:stun`, `service:turn`) that ride in the
`hello` handshake every peer already exchanges. A peer can therefore see
"this device is a TURN handler" with no wire-format change.

When the device also knows its own reachable address (it uses the TURN
`public_ip` as the host hint), it additionally advertises concrete
endpoint URLs in a structured `services` blob inside its capability
`extra`:

```json
{ "services": {
    "signaling_url": "ws://203.0.113.7:4848",
    "stun_url": "stun:203.0.113.7:3478",
    "turn_url": "turn:203.0.113.7:3478",
    "relay": true
} }
```

A peer reads this with `ServiceAdvert::from_extra(...)` and can drop the
URLs straight into its own network config.

### Pointing peers at your services

On each peer, edit the network's transport config to use your host
instead of (or alongside) the public defaults:

- **Signaling** → set the network's `signaling.servers` to
  `["ws://your-host:4848"]`. A non-empty list takes full precedence over
  the built-in public-relay pool, so this is how you cut a network off
  from public Nostr entirely.
- **STUN** → add `{ "urls": ["stun:your-host:3478"] }` to
  `stun_servers` (write an explicit `[]` first if you want *only* your
  STUN).
- **TURN** → add
  `{ "urls": ["turn:your-host:3478"], "username": "alice", "credential": "s3cret" }`
  to `turn_servers`.

In the GUI these live under a network's gear icon → **Settings**
(signaling relays / STUN / TURN editors). Once every member points at one
self-hosted device for signaling + TURN, the network needs nothing
outside its own walls.

## Running a public relay

The signaling relay is built to be safe to stand up publicly (that's what
the flood limits are for). Three deployment realities to get right:

### 1. It serves plain `ws://` — terminate TLS in front of it

The relay speaks plain WebSocket; it has **no built-in TLS**. The built-in
default relay list uses `wss://`, and port 443 also sails through
restrictive firewalls that block oddball ports — so a public endpoint
wants a TLS-terminating reverse proxy on **443** that forwards the
WebSocket upgrade to the relay on loopback.

One command does the lot — installs Caddy if it's missing, writes the
site block, binds the relay to loopback, and (re)starts the Caddy
service:

```
myownmesh install caddy relay.example.com
```

It generates a Caddy site that proxies **only** WebSocket upgrades to the
relay and answers everything else (browsers, scanners, health checks)
with a plain 200, so stray hits don't pile up as 502s in the log:

```
relay.example.com {
    @ws {
        header Connection *Upgrade*
        header Upgrade websocket
    }
    handle @ws {
        reverse_proxy 127.0.0.1:4848
    }
    handle {
        respond "MyOwnMesh signaling relay — connect over wss://" 200
    }
}
```

Doing it by hand with nginx instead:

```
location / {
    proxy_pass http://127.0.0.1:4848;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
}
```

Peers then point at `wss://relay.example.com` (no port — 443). Open **80
and 443** at the firewall (Caddy needs 80 for the ACME challenge) and keep
the relay's own port (4848) on loopback — `install caddy` sets
`services.signaling.bind` to `127.0.0.1` for you, so the only public door
is the TLS one.

### 2. Give it its own hostname

If a name is a static site (GitHub Pages, etc.) its DNS points at the
static host, not your relay box — `wss://that-name` hits the site, not the
relay. Run the relay on a server you control and point a **dedicated
subdomain** (e.g. `relay.example.com`) at it.

> Point peers at the **relay's** host, not a static site. The project's
> own site `myownmesh.net` is GitHub Pages — it can't host a WebSocket
> server, so `wss://myownmesh.net` would hit the site, not a relay.
> `myownmesh.com` is the relay (a server running the Caddy proxy above).
> Give your own relay a host or subdomain that resolves to the box it
> runs on.

### 3. Verify traffic is actually arriving

The relay logs every connection and a periodic heartbeat at `info`, and
`ctl services status` reports live counts — so you can tell "nobody's
reaching me" from "I'm broken":

```
$ myownmesh ctl services status        # the signaling.activity block
{ "connections": 2, "connections_total": 5, "rooms": 1, "events_relayed": 42 }
```

In the daemon log, per peer plus a 5-minute heartbeat:

```
INFO signaling: client connected     ip=… active=1
INFO signaling: client disconnected  ip=… active=0
INFO signaling: relay activity       connections=2 rooms=1 events_relayed=42
```

If you see `listening` but **never** a `client connected` (and
`connections` stays `0`) while peers are trying, the relay is fine — the
traffic isn't arriving. Check, in order: **DNS** (does the hostname
resolve to this box?), **TLS / proxy** (is the proxy upgrading
WebSockets?), then **firewall** (is the port open?).

## Where it lives in the code

| Piece | Location |
|---|---|
| Service config schema | `crates/myownmesh-core/src/config.rs` (`ServicesConfig`, `NodeServiceConfig`) |
| Roles, advert, relay runtime | `crates/myownmesh-core/src/services/` |
| STUN / TURN servers (+ bandwidth throttle) | `crates/myownmesh-services/` |
| Intelligent signaling relay (presence / leave / limits) | `crates/myownmesh-signaling/src/server.rs` |
| `Leave` signal + driver `PeerLeft` | `crates/myownmesh-signaling/src/{lib.rs,nostr/driver.rs}` |
| Daemon lifecycle + node toggle | `crates/myownmesh/src/services.rs` (`ServiceManager`) |
| Control ops | `crates/myownmesh/src/control.rs` (`ServicesStatus` / `ServicesSet`) |
| CLI | `crates/myownmesh/src/cli/ctl.rs` (`services` subcommand) |
| GUI | `gui/src/ui/settings/ServicesSection.svelte` |
