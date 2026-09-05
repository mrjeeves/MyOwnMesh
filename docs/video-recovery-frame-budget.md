# Paced-video recovery accounting

## Evidence and reproduced defects

On AMS 0.2.113 / MyOwnMesh 0.3.16, the CECWorkstation2 → Stream PC
viewer logged repeated RTP/disassembly discontinuities followed by daemon IPC
overflow. At 2026-09-05 04:21:47 UTC, recovery produced a 2456.9 ms maximum
accepted-sample gap. At 04:33:27 UTC another episode produced an approximately
1565 ms painted-frame gap. Sender windows stayed near 30 fps with zero reported
encoder drops. These are pipeline gaps, not measurements of NIC saturation.

The new deterministic tests expose two recovery-accounting defects:

1. AMS sends multiple marker-delimited slice groups at one RTP timestamp.
   The old 15-item bound treated each group as a whole frame. Three pictures
   containing 25 groups triggered abandonment after 28 ms; a packet repaired
   at 55 ms was still within the existing 150 ms recovery allowance. The test
   failed before the accounting correction and now preserves all 25 groups,
   including their timestamps and bytes, through the actual engine broadcast.
2. A damaged sample behind another damaged sample did not start its recovery
   clock until it became the queue head. The regression shows two holes that
   were both observable at time zero could consume separate 150 ms allowances.
   The corrected code starts each clock when its marker or a later sample
   makes the hole observable. Both expire at the original deadline, with one
   ordered discontinuity before the next complete sample.

These tests prove the defects, not that either was the unique cause of every
field event. The captured release did not log the assembler abandonment reason.

## Unchanged limits and contracts

- Recovery grace remains 150 ms from an observable hole.
- Pending encoded-picture timestamp limit remains 15.
- Aggregate packet bound remains 4096; per-sample packet bound remains 2048.
- More paced samples can remain within those existing packet/time bounds.
  This is an intentional correction to the unit being counted, not a claim
  that the maximum sample-object count is unchanged.
- RTP markers remain exact sample boundaries; no arbitrary delta trimming,
  missing-reference concealment, sender bitrate/FPS/resolution change, or
  playout delay is introduced.
- Engine and IPC queue capacities and cooperative handoffs are unchanged.
  This patch does not promise that a slow socket consumer cannot overflow.

## Diagnostics

The opt-in `myownmesh_core::video_recovery=debug` target records one diagnostic
per surfaced loss episode: network, peer, lane, RTP timestamp, local sequence,
reason, pending samples/frames/packets, and observed blocked time. Reasons are
`retransmit_deadline`, `pending_frame_limit`, `pending_packet_limit`,
`sample_packet_limit`, and `invalid_payload`. This is local logging only;
there is no media wire-format change or per-packet log.

The companion AMS change enables this narrow target with Detailed Logging,
while preserving explicit MYOWNMESH_LOG and MYOWNMESH_LOG_EXTRA overrides.

## Validation and remaining work

Four focused regressions cover repaired fragmented bursts through engine
fanout, simultaneous-hole deadlines, unrepaired loss expiry, and packet memory.
Existing marker-reordering, late-retransmission, malformed-payload and
distinct-frame-bound tests cover the surrounding invariants.

The bounded daemon IPC fixture is a separate layer test, not an end-to-end
Windows socket/decoder benchmark. The exact source of live IPC pressure still
needs attribution. Cross-platform CI and a paired field capture are required
before claiming the incident resolved. No remote runtime was modified during
implementation, and raw terminal logs/identities are not committed here.
