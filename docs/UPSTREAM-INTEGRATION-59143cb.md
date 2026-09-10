# Upstream content disposition for the V4 integration candidate

Integration inputs: V4 `7268ade96a991833c4b3fb5a7bfdd720931ecf3c` and upstream
`59143cbdb094b6b99464c224a500e148fd7d2113`, common ancestor
`9b5b4862d21ddbb92e9ff4fbbade47b41fe6fa75`. Commit counts are not a count of
missing features: current approved V4 semantics govern the content merge.

| Upstream content | Candidate disposition |
|---|---|
| Nostr event integrity, room/body consistency, stable relay admission and retry spread | Ported into V4 pre-parse accounting and existing delivery custody; EOSE must match this socket's subscription, live counts balance on drop, and no relay-side duplicate cache returns. |
| Stale heartbeat retirement | Ported using the full current-owner token and V4 configured timeout, not a bare peer ID/epoch or upstream fixed timing. |
| Device-ID normalization and display suffix verification | Retained at public lookup/connect/reconnect/unpin and signature boundaries. Semantic wire decoding remains strict. |
| RTP NACK history alias fixes | Scoped interceptor patch: stale bitmap repairs, exact responder sequence and missed-tick Skip; current typed flows/default capacities preserved. |
| STUN probe address parsing and virtual-interface exclusion | Ported with V4 bounded DNS lookup. |
| Service syslog identity/rate limits and TURN server log flood suppression | Retained; local service setup errors remain visible. |
| GUI relay allocation range inputs | Retained against existing UDP service fields, without TCP toggle. |
| Process-shared mDNS singleton, 64-socket pressure circuit/fixed recovery timings | Deliberately superseded by V4 bounded per-driver and exact-owner recovery mechanisms. No claim that the physical scheduling is identical. |
| V3 VideoSample/media lanes, IPC media handoff, frame/replay/socket buffer increases, new NACK worker/coalescing | Excluded. Current typed realtime/data/RPC ownership and grants remain; no legacy diagnostic-history switch. |
| Realtime traffic refreshing heartbeat time | Not ported from the removed Video/Audio event handlers. Current admitted typed delivery and heartbeat remain; any new timestamp update needs its own demonstrated session/peer lock-order integration, not a name-only translation. |
| New listen-only flag | Deferred; current Silent/manual/sticky/inbound behavior remains. No additional dialect/config field introduced. |
| Self-hosted TURN TCP/TLS bridge and related config/Caddy claims | Deferred, unsupported in this candidate. Current UDP service and configured standard TURN client endpoints remain. No protected credential distribution is claimed. |
| Forwarded-IP per-client admission behind Caddy | Deferred without an authenticated trusted-proxy boundary; preserve pre-handshake server admission instead of trusting arbitrary XFF. |
| New diagnostic-cycle daemon/script | Excluded rather than adding a second daemon target or ordinary diagnostic hooks. |
| Legacy two-log governance/roster changes | Superseded by current canonical FactGraph, typed policy, funded durable projection and exact-owner admission. |

The retained upstream investigation documents are historical records, not
evidence that their old mechanisms remain implemented. Retired custom
application relay/cipher and V3 wire/API fields remain removed. The 1.0.0
version/release policy and existing exact-head historical failures are unchanged.

This document records source dispositions; the V1 task-lifetime correction is
included. The manager's evidence packet and CI bind executions to the final
candidate commit/tree. Source dispositions themselves are not runtime or release
qualification, or merge approval.
