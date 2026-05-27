# Wire protocol

Every frame on the WebRTC data channel between two MyOwnMesh peers is
a JSON object tagged by a `kind` discriminator. The source of truth
for these types is `crates/myownmesh-core/src/protocol/`.

```
PROTOCOL_VERSION  = 1
SIGN_DOMAIN_TAG   = "myownmesh-mesh-auth-v1:"
TRYSTERO_APP_ID   = "myownmesh-cloud-mesh-v1"
```

A receiver that sees an unknown `kind` silently drops the frame. New
optional message kinds are gated per-peer via the `features` matrix
on the `hello` frame so a sender doesn't waste cycles on a peer that
doesn't speak them.

## Frame envelope

```jsonc
{
  "kind": "<discriminator>",
  // ...kind-specific fields
}
```

Each variant below lists its discriminator and the fields it carries.
All field names are snake_case.

---

## Handshake

### `hello`
First frame on a fresh data channel from each side.

| Field | Type | Notes |
|---|---|---|
| `protocol` | u32 | Wire-protocol version. v1 today. |
| `device_id` | string | Bare-pubkey Device ID (base32-lowercase, 52 chars). |
| `label` | string | Self-reported human label. Cosmetic. |
| `nonce` | string | Random 32-byte challenge, base32-lowercase. |
| `verification_code` | string | 6-char `[a-z0-9]`. Read aloud over voice. |
| `capabilities` | object? | `CapabilityAdvert` — see below. Optional. |
| `max_connections` | u32? | Hint to the topology selector. |
| `features` | string[] | Capability ids the sender claims. |
| `app_version` | string? | Cosmetic. |

The other side signs
`SIGN_DOMAIN_TAG || nonce || my_device_id || their_device_id`
with their ed25519 secret key and returns the signature in
`auth_response`.

### `auth_response`
Proves possession of the secret key matching `hello.device_id`.

| Field | Type | Notes |
|---|---|---|
| `signature` | string | Base32-lowercase ed25519 signature of the domain-tagged payload. |

### `approve`
Sent once the local side has cleared the peer (either auto-approved
from the roster, or the user clicked "approve"). Empty payload. Both
sides must observe each other's `approve` before the connection
transitions to ACTIVE.

### `deny`
Sent when the local side rejects the peer. Carries an optional reason
string. The peer should not reconnect until the user approves again.

| Field | Type | Notes |
|---|---|---|
| `reason` | string? | Optional human-readable explanation. |

---

## Keepalive

### `ping` / `pong`
| Field | Type | Notes |
|---|---|---|
| `t` | i64 | Sender's monotonic timestamp (ms). Echoed back unchanged so the sender can compute RTT against its own clock. |

`ping` cadence: `HEARTBEAT_INTERVAL_MS = 30_000`. Silent peers past
`HEARTBEAT_TIMEOUT_MS + WAKE_DETECTION_THRESHOLD_MS` (~75 s) escalate
to Tier 4 re-handshake.

---

## Topology

### `shelve`
"I'm not going to send you application traffic for now — keep the
data channel open as a heartbeat path."

| Field | Type | Notes |
|---|---|---|
| `reason` | string? | Surfaced in the Activity log. Optional. |

### `unshelve`
Reverses `shelve`. Empty payload. The receiving side may now expect
app traffic again.

Each side tracks `local_shelved` (we sent shelve) and `remote_shelved`
(they sent it) independently. A connection is effectively shelved
when either flag is set.

---

## Capabilities

### `capabilities_update`
Push an updated `CapabilityAdvert` to peers. Receivers replace their
cached copy wholesale.

| Field | Type | Notes |
|---|---|---|
| `capabilities` | `CapabilityAdvert` | New advertisement. |

### `CapabilityAdvert` shape
| Field | Type | Notes |
|---|---|---|
| `tags` | string[] | Embedder-defined capability tags. |
| `app_version` | string? | |
| `max_connections` | u32? | |
| `extra` | json | Embedder-defined structured advertisement. |

---

## RPC

### `rpc_request`
| Field | Type | Notes |
|---|---|---|
| `request_id` | string | Caller-generated, unique within in-flight map. |
| `method` | string | Embedder-defined dispatch key. |
| `payload` | json | Opaque to the mesh. |
| `streaming` | bool | When true, expect `rpc_stream_chunk`+`rpc_stream_end` rather than `rpc_response`. |

### `rpc_response`
| Field | Type | Notes |
|---|---|---|
| `request_id` | string | Echoes the request id. |
| `ok` | json? | Result payload on success. Mutually exclusive with `error`. |
| `error` | string? | Error message on failure. |

### `rpc_stream_chunk`
| Field | Type | Notes |
|---|---|---|
| `request_id` | string | |
| `seq` | u64 | Monotonic sequence number. WebRTC preserves order, so this is informational. |
| `payload` | json | One chunk of the streamed response. |

### `rpc_stream_end`
| Field | Type | Notes |
|---|---|---|
| `request_id` | string | |
| `error` | string? | Set when the stream terminated abnormally. |

---

## Application channels

### `channel`
Carries embedder payloads on a named typed channel. The mesh treats
the payload opaquely; embedders define their own serialization via
`Channel<T>`.

| Field | Type | Notes |
|---|---|---|
| `channel` | string | The channel name; same on both sides. |
| `payload` | json | The serialized application body. |

---

## Handshake sequence

```
Side A                                              Side B
  │                                                  │
  ├── hello {device_id, nonce, code, ...} ─────────▶ │
  │ ◀───────── hello {device_id, nonce, code, ...} ─┤
  │                                                  │
  │ verifies B's claimed device_id against pubkey ─▶ │
  │ ◀────────── auth_response {signature(payload)} ─┤
  ├── auth_response {signature(payload)} ─────────▶ │
  │                                                  │
  │   each side either:                              │
  │     a) finds peer in roster → auto-approve       │
  │     b) prompts user with verification_code       │
  │                                                  │
  ├── approve ───────────────────────────────────▶  │
  │ ◀──────────────────────────────────── approve ──┤
  │                                                  │
  │            ACTIVE — app traffic flows            │
  │ ◀──── ping / pong / channel / rpc_* / shelve ──▶│
```

The exact byte-shape of the domain-tagged payload that both sides
sign:

```
SIGN_DOMAIN_TAG + nonce + "|" + my_device_id + "|" + their_device_id
```

— see `crate::signing::handshake_payload`. The `|` separators ensure
no `nonce` value can be reinterpreted as part of a device id when the
concatenation is parsed back. Both `device_id` fields are the
canonical base32-lowercase pubkey portion (display suffixes stripped).

---

## Forward-compatibility rules

1. **Unknown `kind`**: receiver silently drops the frame. New
   message kinds added in future revisions don't break older peers.

2. **Unknown fields**: serde deserialization ignores extra fields by
   default. Embedders can add fields to `CapabilityAdvert.extra` without
   protocol-level coordination.

3. **Optional fields with sensible defaults**: a v1 receiver missing
   an optional field treats it as the default (`None`, empty list,
   etc.).

4. **`features` gate optional message kinds**: senders consult the
   peer's advertised `features` list before sending an optional frame.
   Older peers that don't advertise a feature don't receive it.

5. **Bump `PROTOCOL_VERSION` only when an existing message's shape
   changes incompatibly.** Additive changes don't bump.

---

## Signaling envelope (Nostr)

Out-of-band signaling messages (offer / answer / ICE candidate)
travel as NIP-01 ephemeral Nostr events (kind `21000`). The event
content is a JSON envelope:

```jsonc
{
  "from": "<sender device_id>",
  "to":   "<recipient device_id, or null for broadcast>",
  "kind": "offer" | "answer" | "candidate" | "announce",
  ...kind-specific fields
}
```

Room tag: `["r", "<room_handle>"]` where the handle is
`SHA-256(app_id || ":" || network_id)` — deterministic across
runtimes so two peers using the same `(app_id, network_id)` land in
the same Nostr room.

Periodic announce cadence: `ANNOUNCE_INTERVAL_MS = 5_333` ms,
matching upstream Trystero.

Full Nostr-driver behavior — relay selection, subscription replay
on reconnect, transition-only logging — is documented in
`crates/myownmesh-signaling/src/upstream.rs`.
