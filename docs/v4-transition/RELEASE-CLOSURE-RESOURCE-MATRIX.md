# V4 release-closure resource matrix

> Current normative cutover (2026-09-09): application data uses endpoint-authenticated WebRTC, directly or through configured standard TURN. Hubs provide discovery/introduction only, never application plaintext or ciphertext transit. This supersedes custom encrypted Hub and Closed-member payload relay requirements. Open/Closed governance is unchanged. Historical exact-head evidence below remains historical; this edit is not an implementation, runtime, or release PASS.

Status: exact source-publication ledger for review `5058637044`, bound to
source head `de82d6be101b2d67919258f7b66ec76cad27f674`, tree
`4a3da93b0f0d4a7ea9da6c707d7fb178d71e7ff1`, parent
`7226f2d74720c2fbfea317ba1e59899877aaa46d`, and the recorded delta of 8
paths (`+708/-105`). Manifest SHA256 is
`3ee15225c56ff20ab499286d951bd478a4efea2d1b3376387c214c3489e78ca8`.
Hosted CI `33323693733`, attempt 1, completed successfully for all six jobs.
Manager-owned local evidence is check `4e9f0f65`, Clippy `74a9f245`, fmt
`26f4db17`, and full workspace `e1d7a79b`. These identifiers are publication
evidence, not new capacity or performance promises.
PR #7 remains OPEN, draft, unmerged, and on HOLD.

"Finite" below identifies a source bound, not a capacity promise or SLO. A
downstream core admission does not retroactively fund or bound bytes allocated
inside an upstream carrier library.

## Current cutover disposition

The tables below preserve their exact historical source/publication context.
In particular, the historical **Closed member opaque relay** row is
**superseded: removal required**, not an advertised current exception and not
evidence for the replacement path. Its run IDs, failures, source hashes, and
audit outcomes are not rewritten.

Current application carriage is endpoint-authenticated native WebRTC, direct
or configured standard TURN. Hubs consolidate bounded discovery/introduction
only; setup/control and existing typed semantic-control cannot carry application
plaintext or ciphertext. TURN is distinct when cohosted. Advertisements are
URL-only, credentials locally configured; protected distribution is not
implemented. The cutover `introduction: Option<HubIntroductionPolicyConfig>`
replaces the removed `closed_relay`, `application_transport`,
`endpoint_cipher`, and `routing_policy` surfaces, whose old config/wire
forms must refuse. Native opaque channels, realtime and RPC are retained.

New exact-source removal/refusal, direct/TURN behavior, and terminal resource
evidence must be recorded separately before claiming qualification. This
ledger adds no new PASS and adopts no proposed native-runtime owner.

## Historical ownership matrix

| Profile / boundary | Raw input | First funded or finite admission | Maximum retained unit / count | Queue / execution owner | Refusal | Terminal owner | Shutdown / join / baseline | Controls and evidence | Disposition |
|---|---|---|---|---|---|---|---|---|---|
| Unix control socket | Peer credentials, then framed request bytes | Listener and client both verify peer euid before reading or writing request bytes; bounded framing and funded dispatch follow | One bounded frame and exact funded request/reply/task custody | Authenticated connection task and funded reply owner | Euid mismatch, malformed/oversize frame, or provider refusal closes the exact connection/request | Reply terminal, or durable MFA state below | Stop accept, close socket, join connection tasks, require provider baseline | Same/foreign-euid controls; shared malformed/oversize/refusal controls; Unix unread-response MFA recovery | Advertised on Unix; execution and exact-head evidence pending |
| Windows control pipe | Named-pipe connection and framed request | Protected current-user DACL on the server; client verifies connected server SID before request bytes; shared bounded framing follows | One bounded frame and exact funded request/reply/task state; opaque OS buffers excluded | Pipe connection task and shared dispatch | ACL/SID mismatch, malformed/oversize frame, or provider refusal | Reply terminal and pipe task | Stop accept, close pipes, join tasks, require funded baseline | DACL/SID positive and mismatch controls plus shared framing/dispatch controls | Advertised on Windows; does not prove Unix euid or Unix crash choreography |
| Durable MFA Prepare | Prepare, exact Query/Redeliver, then exact Commit or Abort | Prepare durably creates or recovers one Prepared record before returning material | One Prepared record per exact network slot plus bounded secret/recovery hashes and one response copy | Custody store owns Prepared; response carries a redeliverable view | Conflicting Prepare, wrong/stale settlement, and Disable while Prepared refuse | Exact Commit makes Committed; exact Abort makes Absent | Prepared survives response loss and restart; transient response custody returns to baseline | Unread-first-response recovery, exact redelivery, explicit Commit/Abort, stale-successor and Disable-refusal controls | Advertised durable transaction. Strict `GovernanceMfaEnroll` and MFA `ProvisionalHandoff` ownership are deleted |
| LocalBroker | In-process `SignalingMessage` | Lab broker plus normal core admission | One owned fan-out copy per destination and exact funded emission | LocalBroker and lab carrier/attempt owners | Missing destination or derived pressure refuses the exact emission | Routed copy and lab attempt terminal | Drop handles, join lab forwarder, settle attempts, baseline | Local-carrier route/refusal and outbound-owner controls | `transport-lab` only; not an advertised production carrier or field proof |
| Core raw carrier adapter | Normalized carrier observation/raw frame | Exact AccountedMemoryBytes, ParsingOrCpuWork, and OpaqueDependencyResidual claim before core parse | One admitted raw observation/frame and exact carrier/attempt owner | Signaling runtime, carrier guard, engine attempt/session owner | Overflow/provider pressure returns typed Unavailable before parse/mailbox/reducer | Exact carrier/attempt/session terminal | Cancel recovery cohorts, settle carrier instances, join drivers, baseline | Raw-observation refusal/recovery and Nostr frame-provider accounting controls | Advertised core boundary; pre-core allocations remain carrier-owned |
| Closed member opaque relay | Route-bound `Open` / `Offer` / `Accept` / `Close` and opaque packets over independently promoted A-B/B-C legs | Closed projection, exact promoted endpoint witnesses, and provider-backed allocation lease before relay admission | Exact route, generation, endpoint, accepted, pending, closing, and two-direction queue custody under the finite Closed-relay profile | Closed relay engine and runtime relay; endpoints retain key agreement state | Route/control/data mismatch, stale owner/generation, profile/queue pressure, or invalid pending transition refuses before mutation and preserves pending custody | Exact generation terminal tombstone and allocation settlement | Close acknowledgement round trip; shutdown wakes bounded waiters, settles every custody registry, joins owned tasks, and requires baseline | Full-route validation, delayed-old-close/successor fence, duplicate terminal close, admission refusal, bounded control, and shutdown baseline controls | Advertised final architecture; runtime evidence remains governed by the review ledger below |
| mDNS discovery callback | mdns-sd browse service key, TXT, IPv4 addresses, add/remove events | Exact service-instance key is admitted/coalesced before copying TXT/address payload; canonical `DeviceId` is validated later by the driver, never inferred from callback identity | `DiscoveryLimits.event_capacity`, `max_resolve_owners`, `MAX_DNS_NAME_BYTES`, `MAX_TXT_ENTRIES`, `MAX_TXT_KEY_BYTES`, `MAX_TXT_VALUE_BYTES`, `MAX_TXT_BYTES`, and `MAX_RESOLVED_ADDRESSES` | Embedded/system discovery pump, bounded latest-state coalescer, then exact application alias provider | Invalid/oversize input refuses; same-key latest state coalesces; bounded handoff refuses without orphan work | Generation-bearing discovery event, canonical `DeviceId`, and exact alias-provider owner | Daemon acknowledgement keeps dependency drainer alive; then stop/join pump and forwarder; system workers drain/join; provider baseline required | Exact generation on Resolved/Removed, callback admission-before-copy, bounded saturation/progress, canonical-ID and alias-provider controls, final-leave, shutdown/join controls | Advertised bounded pre-core discovery. mdns-sd DnsCache/native allocation and real system daemon remain opaque/pending |
| mDNS resolve | Coalesced exact service instance | Finite `ResolveOwnership` before resolve execution; checked generation never wraps or reuses after exhaustion | At most owner-selected `max_resolve_owners`; one pending follow-up per active instance; event epochs bounded by `max_event_epochs` | Exact resolve lease, bounded queue, native worker, exact alias provider | Duplicate coalesces; cap/exhaustion/stale generation refuses before payload retention | Exact resolve generation through finish/cancel/replacement | Stop intake, invalidate owners, drain native workers in rounds, await joins, release provider custody to baseline | Coalescing, cap, cancel/drop, stale replacement, checked exhaustion, and shutdown controls | Advertised bounded pre-core resolve; mdns-sd resolver/cache execution remains qualified |
| mDNS TCP exchange | Accepted/dialed stream, canonical `DeviceId`, line/frame | Connection permit and exact alias-provider retention admission precede split, reader/writer allocation, and delivery; canonical `DeviceId` validator is the identity source | Owner-selected `max_active_connections`, `max_discovered_peers`, `outbound_queue_capacity`; bounded frames and policy timings (`dial_timeout_ms`, idle/query/backoff values) | Connection lease, reader/writer tasks, exact-generation alias table, queued `OwnedSignal` | Slot, frame, queue, alias-provider, identity, and stale-generation pressure refuse/close exact work | Connection slot, alias, queued-line, and provider owner | Exact replacement/final-alias signals stop; top-level, connection, and writer-reaper tasks join outside locks; provider baseline required | Active-cap release, checked generation exhaustion, bounded line, canonical-ID validation, alias replacement, stop-vs-accept, and exact lifecycle joins | Advertised bounded mDNS exchange; real system-dnssd/iOS, field/firewall, and opaque installer evidence remain pending |
| Nostr client | Primary/fallback WebSocket frames and messages | WebSocket config caps frame and message at 256 KiB before assembly; provider claim precedes JSON parse | 256 KiB frame/message plus finite delivery/session/attempt entries | Owned primary/fallback/outbound/announcer tasks and delivery store | Oversize/invalid input, closed store, or provider refusal creates no retained parse | Exact relay delivery, session, attempt, and parse owner | Close store, cancel attempts, await all owned tasks, baseline | Config/parser bounds, binary validity, inbound funding, closed-store-before-reserve, reconnect/delivery controls | Advertised bounded Nostr client; no production unmetered provider or public driver `start` |
| Self-host relay | TCP accept, handshake, WS frame/message, subscriptions, filters, events, presence | Finite nonzero `Limits` before bind; exact connection admission before handshake; bounded outbound channel and exact-ID completion registry | Finite connection, per-IP, handshake, frame/message, subscription/filter, event-rate, stored-event, presence-membership, replay, strike, and outbound dimensions | Listener, connection tasks, exact-ID registry, cancellation-safe writer reaper, hub maps, bounded outbound sender | Exact over-cap/invalid input is refused; checked connection IDs do not wrap; stale completion is ignored | Exact connection, store/presence entry, completion registry, and writer task | `stop_and_wait` closes intake; cancellation-safe reaper and cooperative shutdown await listener, heartbeat, connection, and writer tasks outside locks | Every-limit validation, exact-ID completion, refusal, presence cap/release, relay delivery/leave, writer reaper, and outside-lock terminal join controls | Advertised finite relay; no public signal-only server stop or unbounded sender |
| Release build | Frozen source and declared platform/profile | Shipped daemon builds use `--no-default-features`; only explicit target features may be enabled | One declared binary/archive per workflow path; CI storage is external | Platform build/package job | Missing build or forbidden transport-lab marker fails | Exact artifact upload record | Job cleanup and exact-head artifact inventory | Static workflow/manifest check plus native release daemon build/scan; hosted CI `33323693733` attempt 1 all six jobs successful | Hosted exact-head CI publication is discharged; packaging and platform qualification remain pending |
| Daemon/portable scan | Raw binary or ZIP/TAR.GZ stream | Scanner reads bounded chunks and requires every declared exact regular-file member to be present and nonempty | 64 KiB chunk plus marker overlap; archive member sizes remain archive/toolchain owned | Scanner stream/member owner | Missing artifact/member, duplicate expected member, non-regular or empty member, unsupported archive, or forbidden marker fails | Exact scan result | Close streams and retain exact artifact/run identity | Cross-chunk marker self-control and workflow/manifest invocation census; actual artifacts pending | Covers daemon and portable GUI archives. Current scanner does not independently prove checksums or signatures |
| Tauri GUI installer | Opaque platform installer emitted by Tauri tooling | Tauri/platform packaging job; it does not enter the portable archive scanner | Exact installer artifacts declared by the workflow | Tauri/platform toolchain and publisher | Build/package failure blocks that artifact | Installer publication record | Hosted job cleanup and artifact inventory | Platform build evidence pending | Separate opaque GUI-only artifact; excluded from daemon/portable scanner and updater-portable claims |

## Value-origin ledger

The following table is exhaustive for the persisted `MdnsPolicyConfig` fields
and relay `Limits` fields. A default is a deserialization/configuration
default, not proof of capacity, throughput, or an SLO. Source-of-truth
anchors refer to the published source family above; bridge translation and
runtime validation are separate evidence from these declarations.

| Domain / field | Value and unit (default) | Retained object | Classification | Source of truth | Selector / configuration | Pressure behavior | Field evidence |
|---|---|---|---|---|---|---|---|
| mDNS `max_active_connections` | 256 connections | Connection semaphore permit/lease | Count cap | `MdnsPolicyConfig` | Persisted `signaling.mdns_policy`; translated to `MdnsLimits` | Refuse/close before split or allocation | `config.rs:400,417,439-454`; `mdns/driver.rs:55-77` |
| mDNS `max_discovered_peers` | 1024 peers | Peer/alias map entry | Count cap | `MdnsPolicyConfig` | Persisted policy | Refuse new exact peer at map cap | `config.rs:401,418,440`; `mdns/driver.rs:56-77` |
| mDNS `outbound_queue_capacity` | 128 slots | Per-driver outbound queue slots | Queue cap | `MdnsPolicyConfig` | Persisted policy | Typed refusal/backpressure at queue admission | `config.rs:402,419,441,451-456` |
| mDNS `max_resolve_owners` | 256 exact service keys | `ResolveOwnership` lease/table entry | Count cap | `MdnsPolicyConfig` plus `DiscoveryLimits` | Persisted policy; discovery backend constructor | Duplicate coalesces; new key refuses at cap | `config.rs:403,420,442,457`; `mdns/discovery/mod.rs:66-100` |
| mDNS `event_capacity` | 128 events | Bounded discovery handoff/coalescer slots | Queue cap | `MdnsPolicyConfig` plus `DiscoveryLimits` | Persisted policy | Latest same-key state coalesces; overflow refuses | `config.rs:404,421,443,452-458`; `mdns/discovery/mod.rs:72-100` |
| mDNS `max_event_epochs` | 1024 generations | Exact service-key epoch table | ABA/fence cap | `MdnsPolicyConfig` plus `DiscoveryLimits` | Persisted policy | Generation exhaustion refuses; never wraps | `config.rs:405,422,444,459`; `mdns/discovery/mod.rs:DiscoveryEvent` |
| mDNS `dial_timeout_ms` | 5,000 ms | Dial future deadline, no durable payload | Timeout | `MdnsPolicyConfig` | Persisted policy translated to timing profile | Failed dial releases attempt/slot and tries permitted next path | `config.rs:406,423,445`; `mdns/driver.rs` timing profile |
| mDNS `connection_idle_timeout_ms` | 30,000 ms | Idle deadline for exchange connection | Timeout | `MdnsPolicyConfig` | Persisted policy | Idle connection closes and releases owner | `config.rs:407,424,446` |
| mDNS `inbound_idle_timeout_ms` | 120,000 ms | Idle deadline for inbound connection | Timeout | `MdnsPolicyConfig` | Persisted policy | Idle inbound connection closes and releases owner | `config.rs:408,425,447` |
| mDNS `reannounce_interval_ms` | 60,000 ms | Reannounce schedule/deadline | Cadence | `MdnsPolicyConfig` | Persisted policy | Reannounce work is bounded by existing registration/peer ownership | `config.rs:409,426,448` |
| mDNS `query_deadline_ms` | 5,000 ms | Discovery query deadline | Timeout | `MdnsPolicyConfig` | Persisted policy translated to discovery timing | Timed-out query releases resolve ownership | `config.rs:410,427,449` |
| mDNS `accept_error_backoff_ms` | 100 ms | Accept retry deadline | Backoff | `MdnsPolicyConfig` | Persisted policy | Accept errors yield bounded retry spacing | `config.rs:411,428,450` |
| relay `max_connections` | 256 connections | Global connection permit/registry entry | Count cap | `Limits` | Relay server configuration / serde defaults | Reject connection before handshake admission | `server.rs:81-84,121-125,145` |
| relay `max_event_rate` | 50 events/second/connection | Token-bucket rate state | Rate cap | `Limits` | Relay server configuration | Refuse/rate-limit event and strike exact connection | `server.rs:84-86,125` |
| relay `max_req_rate` | 20 REQ/second/connection | Token-bucket rate state | Rate cap | `Limits` | Relay server configuration | Refuse/rate-limit REQ and strike exact connection | `server.rs:87-88,126` |
| relay `max_subscriptions` | 64 subscriptions/connection | Subscription map entry | Count cap | `Limits` | Relay server configuration | Refuse excess subscription | `server.rs:89-90,127` |
| relay `max_filters_per_req` | 16 filters/REQ | Parsed filter vector | Count cap | `Limits` | Relay server configuration | Extra filters are dropped/refused per parser policy | `server.rs:91-92,128` |
| relay `max_message_bytes` | 65,536 bytes/frame | Bounded client frame buffer | Byte cap | `Limits` | Relay server configuration | Oversize frame refused before retained parse | `server.rs:93-94,129` |
| relay `max_connections_per_ip` | 64 connections/IP | Per-IP connection counter | Count cap | `Limits` | Relay server configuration | Reject exact IP at cap | `server.rs:95-96,130` |
| relay `max_presence_memberships` | 256 memberships/connection | Presence membership map entry | Count cap | `Limits` | Relay server configuration | Refuse excess presence membership; release on leave | `server.rs:97-100,131` |
| relay `max_handshake_bytes` | 16,384 bytes/HTTP upgrade | Bounded handshake buffer | Byte cap | `Limits` | Relay server configuration | Reject before WebSocket parser on overflow | `server.rs:101-102,132` |
| relay `max_frame_bytes` | 65,536 bytes/WebSocket frame | Bounded frame payload | Byte cap | `Limits` | Relay server configuration | Reject oversize frame before message retention | `server.rs:103-104,133` |
| relay `max_stored_events` | 8,192 events | Durable/in-memory event store entry | Count cap | `Limits` | Relay server configuration | Refuse/evict only under explicit store policy; no unbounded retention | `server.rs:105-106,134` |
| relay `stored_retention_secs` | 900 seconds | Event expiry metadata | Retention duration | `Limits` | Relay server configuration | Expired replay event is unavailable and releases store custody | `server.rs:107-108,135` |
| relay `max_replay_per_req` | 500 events/REQ | Replay materialization vector | Count cap | `Limits` | Relay server configuration | Bound replay output before delivery | `server.rs:109-110,136` |
| relay `outbound_queue_cap` | 128 frames/connection | Bounded writer queue | Queue cap | `Limits` | Relay server configuration | Refuse/close exact overloaded writer; reaper releases it | `server.rs:111-112,137` |
| relay `strike_limit` | 50 violations/connection | Strike counter | Count cap | `Limits` | Relay server configuration | Close exact connection at threshold | `server.rs:113-114,138` |
| relay `handshake_timeout_secs` | 10 seconds | Handshake deadline | Timeout | `Limits` | Relay server configuration | Cancel handshake and release admission permit | `server.rs:115-116,139` |
| relay `writer_stop_timeout_secs` | 2 seconds | Writer-stop deadline | Timeout | `Limits` | Relay server configuration | Cancellation-safe writer reaper closes and releases writer | `server.rs:117-118,140` |

## Evidence still required

Each advertised row must ultimately bind an exact frozen SHA, configuration,
platform/toolchain, raw logs, terminal state, before/after resource baseline,
and run or artifact identifier. Refusal, cancellation, response loss,
disconnect, shutdown, and join paths must release transient custody. Pre-core
carrier bounds and joins need their own proof; a green core baseline cannot
discharge them.

The Unix MFA gate is durable state-machine evidence: Prepare persists before
response, an unread first response leaves Prepared intact, ordinary Prepare
redelivers identical material, and an exact Commit completes enrollment (or an
exact Abort removes it). There is no MFA `ProvisionalHandoff` choreography or
response-write rollback in current source.

## HOLD and non-goals

- HOLD remains until operator acceptance of frozen source, serialized Cargo,
  independent verification and audit, hosted exact-head CI, real-machine field
  qualification, firewall cleanup evidence where applicable, packaging, and
  detached performance characterization.
- This matrix creates no performance threshold, capacity/SLO, retry framework,
  package installation, firewall exception, public listener, or new manifest.
- It does not call LocalBroker a production carrier, treat carrier identity as
  governance authority, add application payload to signaling, or relabel OS,
  resolver, carrier-library, Tauri, or CI storage as core-provider funded.
- Durable MFA recovery is local custody recovery, not remote account recovery.
- Hosted CI `33323693733` attempt 1 completed successfully for all six jobs;
  field, firewall, packaging, and detached-performance qualification remain
  pending for review `5058637044`.
- Explicit ceilings remain: no real system DNS-SD daemon runtime is claimed;
  Windows feature-selector and riscv local failures are non-evidence;
  system-dnssd/iOS, field/firewall, opaque installer, detached performance,
  and packaging/repository closure remain qualified or pending as applicable.
