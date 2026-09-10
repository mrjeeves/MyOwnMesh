# Daemon application API — 1.0.0 reference and release boundary

Status: current-source reference, prepared for the 1.0.0 application surface on
2026-09-09. This inventories **all 62 current daemon `Request` variants**. It is
not a declaration that 1.0.0 has shipped, that every platform has passed its
release tests, or that this private Rust wire module is a separately versioned
public SDK. Match the client to the daemon release; compatibility gaps are
listed at the end.

Use this interface when the application is a **separate local process** and a
running daemon owns the mesh. For in-process Rust embedding, use
[Application integration](../APPLICATION-INTEGRATION.md). The canonical daemon
vocabulary is [control/wire.rs](../crates/myownmesh/src/control/wire.rs), not the
similarly named peer-to-peer [wire protocol](PROTOCOL.md).

## 1. Interface selection and security boundary

The shipped CLI (`myownmesh ctl …`) and GUI speak local IPC. This is not HTTP,
WebSocket, JSON-RPC 2.0, a remote management endpoint, or a browser-accessible
service. `op` selects a daemon operation; it is not a peer `kind` frame.

Applications may use JSON typed channels and RPC, opaque byte flows, and
connector-native realtime flows through current authenticated endpoint
sessions. These are distinct from local network administration, governance,
service configuration, identity changes, and updater operations. The catalog
labels administrative effects so an application does not mistake them for
ordinary data-plane operations. **Those labels are not an implemented per-op
local role/ACL system:** access to the daemon's owner-user IPC endpoint is a
powerful local privilege. Do not expose it to an untrusted process or proxy it
onto the network. A client capability protects a registered client's resources;
it does not sandbox every command available to the local OS user.

Remote application use still requires endpoint Device authentication, exact
mesh context, current Open/Closed policy and a live session. Possessing a local
IPC capability, knowing a peer string, advertising a capability, or receiving a
Hub introduction does not replace these checks. Open participation is
ephemeral; Closed governance uses its canonical signed bootstrap/facts.

Application packets use native endpoint-authenticated WebRTC, directly or via
configured standard TURN. Hubs consolidate discovery/introduction only: no
application plaintext or ciphertext transit. TURN is a distinct service even
if cohosted with a Hub. Current service advertisements carry URLs and TURN
credentials are locally configured. Protected credential distribution is **not
implemented**. Do not put credentials, application payload, or a replacement
payload tunnel into introduction/signaling messages.

## 2. Endpoint, framing, and versioning

### Local endpoint and OS authentication

| Platform | Daemon endpoint | Current server-side admission |
|---|---|---|
| Unix | `<data_dir>/daemon.sock`; normally `~/.myownmesh/daemon.sock`; `MYOWNMESH_HOME` changes the data directory | Owner-only parent/socket and same effective-UID peer check before request parsing. macOS uses its explicit bind/chmod path under the owner-only parent. |
| Windows | Namespaced pipe `myownmesh.sock`, conventionally `\\.\pipe\myownmesh.sock` | Protected pipe DACL naming the daemon process token's user SID. |

`config.daemon.control_socket` can select a custom daemon endpoint. Resolve it
with the platform's local-socket API; do not turn arbitrary strings into TCP
addresses. Client support differs: the CLI honors a custom Unix endpoint and
otherwise uses the default Windows pipe; the current GUI constructs default
addresses and does not mirror `MYOWNMESH_HOME`/custom endpoints.

[Listener source](../crates/myownmesh/src/control/listener.rs) defines admission.
Both the [CLI client](../crates/myownmesh/src/cli/ctl.rs) and
[GUI client](../gui/src-tauri/src/control_client.rs) verify the connected server's
OS account before the first write. On Windows, they obtain the connected pipe's
server PID and require that process's token user SID to equal the current process
user SID. On Unix, the peer effective UID must equal the client's `geteuid()`.
Missing, mismatched or unsupported identity information refuses the connection.
The GUI's central connection path covers requests, event subscriptions and
reachability: an unverified connection cannot report reachability success.

This authenticates an OS account, not a daemon executable, and does not isolate
applications or protect against compromise by another process under the same
user. Independently implemented clients must enforce their own server-verification
boundary. Local Windows controls cover native same-user success and injected
mismatch/unverifiable refusals before any bytes are written; they do not establish
real cross-user, Unix-runtime or PID-reuse qualification.
Another local user may occupy the global Windows pipe name before daemon startup
and prevent startup; identity verification refuses the untrusted server rather
than providing cross-user denial-of-service resistance.

### JSON command connection

Send one UTF-8 JSON object followed by LF (`\n`), then read one JSON response
line. A request is `{"op":"status"}` or that tag plus its fields. The daemon
can process sequential requests on an ordinary connection. There is no request
ID for multiplexing command replies: serialize calls per connection or use
separate connections. The CLI and GUI normally open a new connection per call.

Success is `{"ok":true,"data":...}`. Failure normally is
`{"ok":false,"error":"..."}`; some typed refusals also carry
`"data":{"code":"..."}`. `data` is operation-specific, not always the same
object. Parsing, admission or I/O failure may instead close the connection if
an error response cannot be produced. An EOF is not a success response.

`Request` is internally tagged with snake-case `op` names. Unknown operations
refuse. It does **not** globally declare `deny_unknown_fields`; nested types
can be stricter. Send exactly documented fields rather than depending on
unknown-field tolerance. Optional fields marked below may be absent or null;
defaulted boolean/numeric fields may be omitted but are not nullable. MFA
proposal fields have a special present-even-if-null rule.

There is **no daemon JSON protocol-version negotiation field or hello exchange**
in this request enum. `status.data.version` is the package version, not a wire
negotiation. Peer `PROTOCOL_VERSION = 3` and semantic schema version 4 are
different protocols and must not be added as invented daemon handshakes.

JSON frame storage and parsing are provider-funded. The operator may additionally
set positive `MYOWNMESH_IPC_JSON_LINE_BYTES` and
`MYOWNMESH_IPC_REALTIME_FRAME_BYTES` ceilings; malformed/zero policy refuses
startup. Absent optional ceilings do not waive provider admission. The test
codec's 64 MiB constant is **not** a universal production frame allowance.
Clients must bound their own input/output retention as well. See
[framing.rs](../crates/myownmesh/src/control/framing.rs).

## 3. Names, capabilities, and catalog notation

- `network: string` is preferably the local `config_id` returned by
  `networks_list`, not a display label. Registry lookup also supports the wire
  `network_id` alias; use a consistent local key for subscription/handler
  ownership. Neither name is the cryptographic `MeshContextId`.
- `peer` and governance `target` identify a full canonical Device ID. A display
  suffix, label, address or Hub ID cannot stand in for the remote endpoint.
- `C` in the catalog expands to **both** `client_id: string` and
  `client_capability: string`. Acquire them from `events_subscribe`. `client_id`
  is canonical `c<n>` text, not a JSON number; the capability is currently 32
  random bytes encoded base64url without padding (43 characters). Treat it as
  secret, return it verbatim, do not derive it from the ID or log it.
- `F` means `flow_capability: string`, issued for one owned live flow. It is
  distinct from `C` and from a flow label. It must not be persisted for reuse
  after disconnect, restart or session replacement.
- `K` expands to `network: string, peer: string, method: string,
  request_id: string, operation_id: u64`, the **exact inbound call coordinates**.
  Copy `peer` from the event's `from`. Preserve u64 values losslessly; languages
  with floating-point JSON numbers must not round operation IDs.
- `JSON` is an application-defined JSON value. Byte arrays below are JSON
  arrays of integers 0–255, not base64 strings. All successful reply shapes
  below describe the contents of `data` unless stated otherwise.

Capabilities are runtime-local, owned authorities. The canonical forms and
minting are in [IPC identity.rs](../crates/myownmesh/src/ipc/clients/identity.rs).
Never copy tokens across clients or assume a new session inherits old authority.

## 4. Complete current request catalog

### 4.1 Identity and observation (9 operations)

| `op` | Fields besides `op` | Success data / effect |
|---|---|---|
| `status` | none | `{version, device_id, joined_networks, realtime}`; `realtime={supported,encodings:[{kind,mime,clock_rate,channels}]}` describes registered RTP support, not a remote delivery guarantee. |
| `networks_list` | none | `{networks:[NetworkSummary]}`. Each summary has `config_id, network_id, label, phase, topology, traffic`. |
| `peers_list` | `network` | `{peers:[PeerInfo]}`; local runtime observation, not an authorization proof or globally complete membership list. |
| `roster_list` | `network` | `{roster:[AuthorizedPeer]}`; joined-network roster view, not an API for creating authority. |
| `identity_show` | none | `{device_id,pubkey,label}`; these are public identity values, not private key material. |
| `identity_set_label` | `label: string` | Same identity shape; administrative persistent label update. Empty string clears the label; it does not rotate the key. |
| `network_id_generate` | none | `{network_id: string}`; random rendezvous-name utility, not Closed bootstrap creation. |
| `network_id_normalize` | `input: string` | `{network_id: string}` or validation error. |
| `config_show` | none | `{config: MeshConfig}`; sensitive administrative read: saved configuration can contain credentials. Do not forward or log the complete response. |

Summary nested types are defined in [registry.rs](../crates/myownmesh/src/registry.rs),
[PeerInfo](../crates/myownmesh-core/src/handle.rs),
[AuthorizedPeer](../crates/myownmesh-core/src/roster.rs), and
[core config](../crates/myownmesh-core/src/config.rs). Do not treat diagnostics
such as phase or traffic as a session capability.

### 4.2 Network administration (11 operations)

These mutate local configuration/runtime state, and some persist or delete
state. They are not ordinary application sends. This reference intentionally
does not supply a runnable reset, purge, import or governance workflow.

| `op` | Fields besides `op` | Success data / effect |
|---|---|---|
| `network_add` | `config: NetworkConfig` | `{added: LifecycleSummary}`; configured join/admission. This is not a substitute for Closed creation/import. |
| `network_create_closed` | `config: NetworkConfig` | `{added: LifecycleSummary}`; creates/persists the signed Closed bootstrap before runtime registration. |
| `network_import_closed` | `config: NetworkConfig, expected_context_id: MeshContextId, bootstrap: BootstrapRecord` | `{added: LifecycleSummary}`; imports a verified bootstrap under the explicit expected context. |
| `network_bootstrap_export` | `network` | `{bootstrap: BootstrapRecord}` from a joined Closed network. |
| `network_update` | `config: NetworkConfig` | `{updated: string, restarted:false}` for the in-place path, or `{updated: LifecycleSummary, restarted:true}` for a rebuild. Consumers must handle both shapes. |
| `network_remove` | `network, purge: bool=false` | `{removed: string}`. Unloads/tears down the runtime; explicit purge additionally requests deletion of persisted network state. |
| `network_reconnect` | `network, peer?: string` | `{reconnecting: string}`; queues reconnect for one peer or the network, not proof of reconnection. |
| `network_connect_peer` | `network, peer, pin: bool=false, wait_ms: u64=0` | `{connecting: string,network,pinned: bool,active: bool}`. Zero wait normally reports queued demand; positive wait observes connection outcome. Pin requests persistent reconnect intent, including Silent mode. |
| `topology_set` | `network, topology: string, hub?: string` | `{topology: string}` after local topology change. Parser accepts `ring`, `star`, `hubs`, `full_mesh`/`fullmesh`. Star requires one Hub ID; hubs takes comma-separated IDs with optional `:redundancy`. No `hub_tree` string arm here; typed topology configuration is a separate `NetworkConfig` surface. |
| `forget_all_networks` | none | `{forgotten:[string],restarting:true}`; destructive forget of all joined networks followed by runtime shutdown request. Does not mean the host process already exited. |
| `factory_reset` | none | `{reset:true,restarting:true}`; destructive identity/config/network-state reset and runtime shutdown request. No application should invoke this as cleanup. |

`LifecycleSummary` contains `config_id,network_id,label,phase,topology`.
Current network-update dispatch hot-applies STUN/TURN configuration for future
connections without dropping existing peers; it does not change an existing
ICE connection's servers. Other reconciled changes may require a restart.
Use the actual `restarted` result rather than the older Request comment's
transport-rebuild summary.
Use the exact [NetworkConfig](../crates/myownmesh-core/src/config.rs) serializer,
not a reduced GUI example, for nested configuration. Current cutover config has
`introduction: Option<HubIntroductionPolicyConfig>`; retired `closed_relay`,
`application_transport`, `endpoint_cipher`, and `routing_policy` fields refuse.
Source: [network dispatch](../crates/myownmesh/src/control/dispatch/network.rs),
[topology dispatch](../crates/myownmesh/src/control/dispatch/governance.rs).

### 4.3 Canonical semantic inspection/exchange (4 operations)

These exchange/inspect typed semantic state, not opaque application bytes.
Import does not grant authority to arbitrary local JSON: canonical signatures,
context, causal rules and resource admission still apply.

| `op` | Fields besides `op` | Success data |
|---|---|---|
| `semantic_fact_page_export` | `network, request: SemanticFactPageRequest` | `{semantic_fact_page: SemanticFactPage}` |
| `semantic_fact_page_import` | `network, page: SemanticFactPage` | `{semantic_state_identity: SemanticStateIdentity}` |
| `semantic_state_identity` | `network` | `{semantic_state_identity: SemanticStateIdentity}` |
| `semantic_recent_facts` | `network, request: SemanticRecentFactsRequest` | `{semantic_recent_facts: SemanticRecentFacts}`; bounded non-canonical hot-cache view, not complete history. |

`SemanticFactPageRequest` is `{context_id,cursor,max_facts:u32,max_encoded_bytes:u32}`;
cursor is optional/null and exclusive. A page is
`{context_id,facts:[SignedFact],next_cursor,complete}`. Follow its returned cursor
and completion flag rather than guessing pagination. Recent-facts request is
`{max_facts:u32,max_encoded_bytes:u32}`; response contains
`context_id,total_admitted_fact_count,cached_fact_count,facts`.
`SemanticStateIdentity` contains `context_id,admitted_fact_count,
unresolved_fact_count,projection_commitment,state_commitment`; commitments are
32-byte JSON arrays. These are observations, not transferable authority.
Bounds are checked by core; zero/oversize limits are not an unlimited mode.
Use the [semantic DTOs](../crates/myownmesh-core/src/semantic/mod.rs) and
[bootstrap types](../crates/myownmesh-core/src/semantic/bootstrap.rs) for exact
encodings; do not invent facts or context IDs.

### 4.4 Host infrastructure services (2 operations)

| `op` | Fields besides `op` | Success data / effect |
|---|---|---|
| `services_status` | none | `{status: ServicesReport,config: ServicesConfig}`; local hosted signaling/STUN/TURN state and saved config. Sensitive administrative read. |
| `services_set` | `services: ServicesConfig` | `{status: ServicesReport}`; replaces the services configuration and reconciles actual service lifetimes. Not a partial patch and not remote TURN credential distribution. |

See [service dispatch](../crates/myownmesh/src/control/dispatch/services.rs),
[services documentation](SERVICES.md), and
[configuration types](../crates/myownmesh-core/src/config.rs). Running a service
does not make a Hub an application router.

### 4.5 Closed governance and MFA custody (10 operations)

These are privileged governance/custody operations, not application feature
authorization. Use only an explicitly reviewed owner workflow. Proposal
acceptance is not proof that every peer has received or enacted a change.

| `op` | Fields besides `op` | Success data / effect |
|---|---|---|
| `governance_propose_role_grant` | `network,target,role: "member"\|"controller"\|"owner",mfa_code: string\|null` | `{proposal_id:string}`; canonical authority checks apply. |
| `governance_propose_role_revoke` | `network,target,mfa_code: string\|null` | `{proposal_id:string}` |
| `governance_propose_evict` | `network,target,mfa_code: string\|null` | `{proposal_id:string}` |
| `governance_mfa_prepare` | `network` | `{secret,otpauth_uri,recovery_codes,transaction_id}`; prepares or recovers enrollment; highly sensitive material. |
| `governance_mfa_query` | `network,transaction_id:string` | `{network,transaction_id,state}` and, when prepared, `secret,otpauth_uri,recovery_codes`. Query itself can reveal enrollment secrets. |
| `governance_mfa_redeliver` | `network,transaction_id:string` | Exact prepared enrollment shape as Prepare; refuses absent/already committed material. |
| `governance_mfa_commit` | `network,transaction_id:string` | `{network,transaction_id,state}`; exact transaction settlement, not a successor lookup. |
| `governance_mfa_abort` | `network,transaction_id:string` | `{network,transaction_id,state}`; exact transaction settlement. |
| `governance_mfa_status` | `network` | `{enrolled:bool}` |
| `governance_mfa_disable` | `network,code:string` | `{disabled:true}` on successful custody check/removal. |

All three proposals **require the `mfa_code` field to be present**, even when
its value is null. Null does not bypass an enrolled custody requirement.
Transaction state is `prepared`, `committed`, or `absent`. Prepare reply delivery
is not commit: lost responses preserve the prepared transaction for exact query
and redelivery. Commit/abort report the actual resulting state; do not infer it
solely from the requested verb. Never log enrollment material or recovery codes.
See [governance dispatch](../crates/myownmesh/src/control/dispatch/governance.rs)
and [reply serialization](../crates/myownmesh/src/control/reply.rs).

### 4.6 Event and diagnostic subscriptions (2 operations)

| `op` | Fields besides `op` | Initial success data / connection change |
|---|---|---|
| `events_subscribe` | none | `{subscribed:true,client_id,client_capability}`; then server-push `ServerOut` JSON lines. Keep this connection alive for `C`. |
| `trace_subscribe` | `network` | `{subscribed:true,stream:"conn_trace",network}`; then raw `ConnTrace` JSON lines, not `ServerOut`. No client capability is issued. |

### 4.7 Typed JSON channels and application advertisement (6 operations)

| `op` | Fields besides `op` | Success data / meaning |
|---|---|---|
| `channel_subscribe` | `C,network,channel:string` | `{subscribed:true}`; inbound messages go to that client's event socket. |
| `channel_unsubscribe` | `C,network,channel:string` | `{unsubscribed:true}`; releases this subscription; the last subscriber's pump is retired. |
| `channel_send_to` | `network,channel:string,peer,payload:JSON` | `{sent:true}` after core send success, not a remote application's processing acknowledgement. |
| `channel_send_reliable` | `network,channel:string,peer,payload:JSON` | `{delivered:true}` after the core reliable-delivery acknowledgement; not proof of application side effects. |
| `channel_send_all` | `network,channel:string,payload:JSON` | `{dispatched_to:usize}`; current peer dispatch count, not global delivery/processing count. No Hub payload broadcast path is implied. |
| `capabilities_set` | `network,capabilities:CapabilityAdvert` | `{advertised:true}`; session-bound application metadata, never authorization. |

`CapabilityAdvert` has `tags:[string]` (default empty), `app_version:string|null`
(default null), `extra:JSON` (default null). These are application-defined,
not validated permission grants. See [channel dispatch](../crates/myownmesh/src/control/dispatch/channel.rs)
and [capability DTO](../crates/myownmesh-core/src/protocol/rpc.rs).

### 4.8 RPC (7 operations)

| `op` | Fields besides `op` | Success data / meaning |
|---|---|---|
| `rpc_register` | `C,network,method:string,streaming:bool` | `{registered:true}`; last claim wins; previous owner receives `handler_displaced` and its pending calls are cancelled/failed. |
| `rpc_unregister` | `C,network,method:string` | `{released:bool}`; false if this client did not hold the claim. |
| `rpc_respond` | `C,K,ok?:JSON,error?:string` | `{resolved:true}` only for the exact owned unary call. `error` wins if supplied; absent/null `ok` without error yields JSON null. |
| `rpc_stream_chunk` | `C,K,payload:JSON` | `{delivered:true}` on acceptance into the exact pending stream; wrong/retired call refuses. This is not an application-level remote acknowledgement. |
| `rpc_stream_end` | `C,K,error?:string` | `{closed:bool}`; optional error terminates with failure; false if the exact stream is no longer present. |
| `rpc_call` | `network,peer,method:string,payload:JSON` | `{response:JSON}` after a remote unary reply; remote/core error uses `ok:false,error`. The command waits for core's call result. |
| `rpc_call_stream` | `C,network,peer,method:string,payload:JSON` | `{request_id:string}`; chunks/end arrive on the owning event socket. |

No daemon RPC request has an arbitrary timeout field or a `rpc_cancel` operation.
Clients may impose local wait limits, but must treat possible remote effects
as unknown if they stop waiting. Inbound responses must match the complete `K`,
owner capability and unary/stream class, not just `request_id`. Registration's
streaming preference does not override the inbound event's `streaming` flag.
See [RPC dispatch](../crates/myownmesh/src/control/dispatch/rpc.rs) and
[IPC bridge](../crates/myownmesh/src/ipc/bridge.rs).

### 4.9 Native realtime and opaque flows (7 operations)

| `op` | Fields besides `op` | Success data / meaning |
|---|---|---|
| `realtime_flow_open` | `C,network,peer,flow_label:string,direction:"outbound"\|"inbound",rtp_kind:"audio"\|"video",mime:string,clock_rate:u32,channels:u16` | `{flow_label,flow_capability}`; selects a registered native RTP encoding, not an application codec implementation. |
| `realtime_flow_close` | `C,F` | `{closed:true}` after closing the owned flow; unknown/already removed capability refuses. |
| `opaque_flow_open` | `C,network,peer,label:[u8],direction,mode:OpaqueFlowMode,max_unit_bytes:u32` | `{flow_label:string,flow_capability}`; returned label is lossy UTF-8 display of the bytes, **not** authoritative label round-trip. Keep the original byte label. |
| `opaque_flow_change` | `C,F,network,label:[u8],direction,mode:OpaqueFlowMode,max_unit_bytes:u32` | `{flow_capability,max_unit_bytes}` after an accepted change of the owned flow; does not reopen by peer/label. |
| `opaque_flow_close` | `C,F` | `{closed:true}` after owned close; same ownership rules as realtime close. |
| `opaque_pipe` | `direction,network,C`, plus `F` outbound **or** `peer` inbound | `{opaque_pipe:true}`; connection switches to opaque binary frames. |
| `realtime_pipe` | `direction,network,C`, plus `F` outbound **or** `peer` inbound | `{realtime_pipe:true}`; connection switches to RTP-unit binary frames. |

Directions are from the local application's endpoint: outbound sends, inbound
receives. For both pipe requests, the Rust DTO declares owner fields optional,
but dispatch requires both fields of `C` in **both** directions. Outbound
requires `F` and refuses a non-null peer; inbound requires peer and refuses a
non-null `F`. Omit unused selector fields. The inbound pipe takes the current
session's exclusive inbound-stream lease before ACK. Another consumer cannot
claim it concurrently, including a competing opaque/realtime pipe. These are
not independent subscriber fan-outs; choose the correct format for the stream.

`OpaqueFlowMode` is serde's externally tagged enum:
`"reliable_ordered"` or `{"partial_unordered":{"max_retransmits":N}}` with a
u16 retransmit count. Labels are 1–255 bytes. `max_unit_bytes` is 1–65,507
(`65,535 - 28`), a protocol representation bound, not a queue/resource grant.
Actual admission can refuse below that bound. A bidirectional application uses
separate flow directions. Realtime's string label is UTF-8 bytes under the same
label-width constraint; MIME/clock/channel tuple must match a registered native
encoding. `status.realtime` does not promise any arbitrary codec is supported.

Source: [opaque dispatch](../crates/myownmesh/src/control/dispatch/opaque.rs),
[realtime dispatch](../crates/myownmesh/src/control/dispatch/realtime.rs),
[core flow vocabulary](../crates/myownmesh-core/src/realtime.rs).

### 4.10 Updater administration (4 operations)

| `op` | Fields besides `op` | Success data / effect |
|---|---|---|
| `update_status` | none | `UpdateStatus` snapshot; no network check. |
| `update_check` | none | `CheckOutcome`; can contact release sources and download/stage an eligible update. Not a read-only status query. |
| `update_apply` | none | `{applied:string|null}`; installs staged update; running process replacement/restart is a separate lifecycle concern. |
| `update_set_prefs` | `prefs:JSON` | Updated `UpdateStatus`; administrative partial preference update validated as `UpdatePrefs`. |

`UpdatePrefs` optional fields: `enabled:bool`, `channel:"stable"|"beta"`,
`auto_apply:"patch"|"minor"|"all"|"none"`, positive `check_interval_hours:u32`,
`feed_request_timeout_ms:u64`, `artifact_download_timeout_ms:u64`, and
`stable_url:string`, `beta_url:string` (empty clears an override). Feed changes
are security-sensitive configuration, not ordinary application parameters.

`UpdateStatus` includes `current_version,install_kind,enabled,channel,auto_apply,
check_interval_hours,feed_request_timeout_ms,artifact_download_timeout_ms,
last_check_at,staged_version,release_url,release_url_overridden`.
`CheckOutcome` is tagged `outcome`: `disabled`, `package_manager`, `not_due`,
`up_to_date{current,latest}`, `policy_blocked{current,latest,policy}`, or
`staged{version}`. Package-manager installations defer to their system updater.
See [updater types](../crates/myownmesh-updater/src/lib.rs) and
[dispatch](../crates/myownmesh/src/control/dispatch/updater.rs).

## 5. Streaming, ownership, and cleanup

After `events_subscribe` ACK, send **no more commands on that connection**.
Keep both halves alive and drain it continuously. Use separate command sockets
for `channel_subscribe`, registration, responses and flow control with the
returned `C`. The event connection owns those registrations; reconnection
requires a new subscription, new capability and explicit reinstallation.

The seven [ServerOut](../crates/myownmesh/src/ipc/wire.rs) tags are:

| `kind` | Other fields |
|---|---|
| `event` | `event: MeshEvent` (its own `event_kind` discriminator) |
| `lagged` | `skipped:u64` |
| `rpc_inbound` | `network,from,request_id,operation_id:u64,method,payload,streaming:bool` |
| `rpc_call_stream_chunk` | `request_id,payload:JSON` |
| `rpc_call_stream_end` | `request_id,error:string|null` |
| `channel_inbound` | `network,from,channel,payload:JSON` |
| `handler_displaced` | `network,method,by:string` |

`lagged` reports missing broadcast events. It is not a resumable cursor or a
promise that application messages were dropped/replayed in the same way. IPC
mailbox pressure can refuse work or end the owning client instead. Treat EOF,
lag, parse failure and missing terminal separately; refresh observational state
as appropriate rather than fabricating a complete event history. The GUI
forwards these frames to its frontend as `mesh://event`; that Tauri event name
is not a daemon request or a transport available to other processes.

`trace_subscribe` instead streams raw `ConnTrace` values and `{"lagged":N}`
markers. It is diagnostic observation, not per-message delivery evidence or
endpoint authority. It has no client token and does not establish an application
subscription. [ConnTrace source](../crates/myownmesh-core/src/engine/conn_trace.rs)
defines `ts_wall_ms,t_mono_ms,network_id,device_id,epoch,changed,status,tier,
authenticated,local_shelved,remote_shelved` and optional `ice_state,pc_state,
pair_class,last_recv_age_ms,rtt_ms`. These are sampled peer observations, not
proof of exact per-message worker continuity. Monotonic times from different
processes cannot be subtracted for one-way latency; wall clocks can be skewed.

Closing the event socket ends its registered ownership once the daemon observes
disconnect; handlers, pending operations, flow ownership and pumps follow the
daemon's cleanup paths. Quiet push sockets may observe peer closure on subsequent
I/O rather than instantaneously. Explicitly close flows and unsubscribe/release
handlers while the owner is still live, then close binary/event sockets and join
your own readers/writers. Do not equate a client timeout, dropped local promise,
successful write, or process signal with terminal daemon/native cleanup.
Daemon shutdown cancels accepted connections and drains owned tasks; external
TURN allocation expiry and failed cleanup remain separate observations.

There is no global `shutdown` request among these 62 operations. Do not use
`factory_reset` or `forget_all_networks` to emulate one. Application shutdown
should release its own handles, not destroy the daemon's identity/network state.

## 6. Binary pipe formats

Read the initial JSON ACK completely, **preserving any bytes buffered after its
LF**. Thereafter that socket is binary-only, with no per-unit JSON response,
base64 wrapper, RPC envelope, or codec guessing. An outbound pipe's successful
write means bytes reached local IPC, not peer delivery. End-of-pipe can reflect
closure, malformed input, stale authority or pressure; there is no guaranteed
typed per-unit terminal frame. Applications needing remote processing evidence
must design an endpoint acknowledgement in their own protocol.

All integer prefixes below are unsigned, little-endian. Parse lengths before
allocation under application-selected bounds.

| Pipe/direction | Repeated encoded unit |
|---|---|
| Opaque outbound | `body_len:u32`, then exactly `body_len` application bytes. The bound flow capability supplies the label/session; there is no label in this frame. |
| Opaque inbound | `frame_len:u32`, then `label_len:u8`, `label[label_len]`, then application bytes. `frame_len = 1 + label_len + body_len`. |
| Realtime outbound | `frame_len:u32`, then `label_len:u8`, reserved **zero** byte, `duration_us:u32`, `payload_len:u32`, `label[label_len]`, `payload[payload_len]`. |
| Realtime inbound | `frame_len:u32`, then `label_len:u8`, `marker:u8`, `rtp_timestamp:u32`, `payload_len:u32`, `label[label_len]`, `payload[payload_len]`. |

Realtime `frame_len = 10 + label_len + payload_len`; lengths must account for the
whole body. Outbound duration and inbound RTP timestamp are **not interchangeable**.
Timestamp interpretation uses the flow's `clock_rate`, not wall time. Outbound
label must match the exact opened flow even though the pipe also holds its
capability. No outbound marker bit, media-kind byte, keyframe flag or stream
index is accepted in the reserved byte. Application codecs/processing stay
outside the mesh. Opaque frames have no RTP timestamp or codec fields; keep
these two formats separate. Sources:
[opaque_pipe.rs](../crates/myownmesh/src/control/opaque_pipe.rs),
[realtime_pipe.rs](../crates/myownmesh/src/control/realtime_pipe.rs), and
[framing.rs](../crates/myownmesh/src/control/framing.rs).

## 7. Practical integration examples

These are wire examples, not commands to start/administer a daemon. Use an
already provisioned daemon and the correct authenticated local endpoint.

Read-only request lines (each must end with LF):

```json
{"op":"status"}
{"op":"networks_list"}
{"op":"network_id_normalize","input":" Example-Net "}
```

Example normalization success:

```json
{"ok":true,"data":{"network_id":"example-net"}}
```

To receive typed messages, open a separate event socket and send:

```json
{"op":"events_subscribe"}
```

Read `data.client_id` and `data.client_capability` from its successful ACK, then
construct the following requests using **actual returned values**, not sample
secrets. `command` below means your bounded JSONL command client, not a supplied
JavaScript SDK. `network` is an existing `config_id`; `peer` is a full Device ID
selected from your approved application context/current peer observations.

```javascript
const C = {
  client_id: eventAck.data.client_id,
  client_capability: eventAck.data.client_capability,
};
await command({op: "channel_subscribe", ...C, network, channel: "example.echo"});
await command({op: "channel_send_to", network, peer,
               channel: "example.echo", payload: {sequence: 0, text: "hello"}});
// Drain channel_inbound on the still-open event socket.
// If remote processing matters, require a matching reply from that endpoint.
await command({op: "channel_unsubscribe", ...C, network, channel: "example.echo"});
```

For a unary RPC handler, register a method with `streaming:false`, then respond
on a command connection using the exact received event coordinates:

```javascript
await command({op: "rpc_register", ...C, network,
               method: "example.echo", streaming: false});
// For an authenticated, application-authorized rpc_inbound event e:
await command({op: "rpc_respond", ...C, network: e.network, peer: e.from,
               method: e.method, request_id: e.request_id,
               operation_id: e.operation_id, ok: e.payload});
await command({op: "rpc_unregister", ...C, network, method: "example.echo"});
```

Preserve `operation_id` losslessly in the JSON implementation. The remote caller
uses `rpc_call`; it need not register an event client for a unary call. For
streaming calls, both the event owner and an explicit terminal observation are
needed. Authorize the requested application action before invoking any handler
side effect; being a mesh peer is not permission to read files, run commands,
or access a camera.

For an opaque sender, after an application-approved peer session is current,
open with a byte label such as `[101,99,104,111]`, `direction:"outbound"`,
`mode:"reliable_ordered"`, and an application-selected valid `max_unit_bytes`.
Use the returned `flow_capability` with `opaque_pipe` outbound and the same `C`;
omit `peer` from the pipe request. The receiver uses an appropriate inbound
flow and one inbound pipe with its own `C` and the sender's peer ID. Close the
flow via `opaque_flow_close` before ending its owner. This is an API sequence,
not a claim that an arbitrary remote peer has agreed to that application flow.

Existing source examples/consumers:

- [CLI control client](../crates/myownmesh/src/cli/ctl.rs): local transport and reverse-server checks.
- [GUI canonical client](../gui/src-tauri/src/control_client.rs): wire enum mirrors all 62 daemon variants and field names; frontend/UI consumers expose a subset. Includes unary uncertainty and owned event-reader cancellation; not a stable all-operation SDK.
- [Production daemon E2E example](../scripts/run-production-e2e.py): explicit testbed setup, two-daemon channel exchange and cleanup; not an SDK install command or a release PASS.
- [Daemon opaque-flow integration test](../crates/myownmesh/tests/opaque_app_flow.rs): binary-flow lifecycle example; fixture/runtime results are separate evidence.

## 8. Errors, uncertainty, and retired surfaces

Respect `ok:false` and retain the diagnostic securely; do not parse arbitrary
error prose as a stable enum. Flow/governance operations can provide `data.code`.
Examples include `session_not_current`, `label_in_use`, `flow_refused`,
`provider_configuration_invalid`; governance maps include `mfa`, `authority`,
`signature_invalid`, `peer_denied`, `network`, `governance`, and specific MFA
state refusals. This is not a promise that every failure has a code.

After any potentially mutating request may have been written, a failed write,
flush, read, parse, EOF or local timeout does **not** establish that nothing
happened. The GUI's `RequestError::OutcomeUnknown` is a local classification,
not a daemon response tag. Query authoritative state or the exact transaction
before deciding whether a retry is safe. The GUI's five-second unary response
wait is a client choice, not a universal daemon operation deadline. There is no
generic idempotency-key, transaction rollback, or cancel wire operation.

The following old ops are unknown/refused, not aliases:
`closed_relay_open`, `closed_relay_accept`, `closed_relay_send`,
`closed_relay_recv`, `closed_relay_close`, `closed_relay_state`.
Old codec-specific/base64 `video_send` requests are also not this API. Do not
reintroduce custom encrypted application routes when direct/TURN is unavailable.
Transport-lab pause hooks, test fixtures and diagnostic environment barriers are
not application operations and are unavailable in ordinary release builds.

## 9. Explicit 1.0.0 coverage and unresolved release gates

This document earmarks the complete current local application/administration
inventory for 1.0.0 documentation: **9 observation/identity + 11 network + 4
semantic + 2 services + 10 governance/custody + 2 subscriptions + 6 channels +
7 RPC + 7 flows/pipes + 4 updater = 62 operations**. No unlisted future method,
remote HTTP gateway or language SDK is promised.

The selected [release versioning policy](../RELEASE.md#versioning) applies:
removed or renamed public APIs, removed config keys, and incompatible protocol
shape changes require a major release. Local IPC remains unnegotiated;
third-party clients must target this documented 1.0.0 contract and the matching
daemon release. Core `PROTOCOL_VERSION = 3` is not local IPC version negotiation.
This policy does not introduce a handshake or a mixed-version compatibility promise.

Remaining integration limits and release qualification to record:

1. The GUI wire enum mirrors all 62 daemon variants and field names;
   frontend/UI consumers expose a subset.
   Enum parity and source consumer presence do not establish a stable all-operation SDK.
2. Platform-specific endpoint selection and the remaining runtime qualification
   of the shared CLI/GUI OS-account verification policy above. GUI endpoint
   selection still differs; account verification is not executable authentication
   or isolation among same-user processes.
3. Exact executable coverage of success/refusal, subscription/pipe disconnect,
   operation uncertainty, native cleanup and external TURN behavior on each
   supported platform. No runs were performed to create this document.
4. Application-owned framing limits, deadlines, data authorization and secret
   handling. No hidden default throughput, latency, codec, queue, subscriber,
   or network-size guarantee is supplied by the catalog.

Source custody for this reference: `control/wire.rs` SHA256
`E450921184C07962EDDA99663C1D76C0791C3F0B82F572D047DBAD13BCD80CCA`;
`control/reply.rs` SHA256
`07A0BC9B732E655D95293E1767C9ED10DDC1A15331917F26D6E1B29922BAFD56`.
Live implementation/release evidence remains manager-owned. These source hashes
identify the inspected schema, not a claim of deployed 1.0.0 behavior.
