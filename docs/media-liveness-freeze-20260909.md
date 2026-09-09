# Streaming peer incorrectly classified as silent

## Captured incident

CECWorkstation2 to Stream PC, September 9, 2026, on the PR134 transport build
381b465 and AMS PR305 runtime 22bfac4. Receiver timestamps below are all from
Stream PC; no cross-host clock subtraction is involved.

At 17:56:26.529981 UTC, the receiver reported 7,357 RTP packets in 5,035 ms,
zero forward skips/reordering, a 41 ms maximum read wait and a 1 ms maximum
handoff time. Accepted video was 30 fps, with a 56.1 ms maximum AU gap.

At 17:56:27.154893 the transport logged:

    signaling: e5chvr…x5fq didn't answer the announce-driven probe — rebuilding

It dropped the peer with HeartbeatTimeout, re-offered at 17:56:27.199086,
and became active again at 17:56:28.314984. The replacement track's sample
sequence restarted at one, creating a downstream discontinuity. A clean
entry restored video at 17:56:28.393199. The frontend measured a 1,254.7 ms
decode gap. RTP SSRC changed from 1960974951 to 3788859415.

The relevant receiver capture is retained on Stream PC in:

    C:\Users\Admin\video-diag-runs\freeze-headers-20260909-175545

The bounded, 96-byte NIC-header capture ran for 49.7 seconds and stopped
automatically five seconds after the discontinuity trigger. Its transcript
reported no lost trace events. Do not interpret its raw sequence-skip totals
as network loss: its NIC observations contain duplicate packets and far fewer
packets than the application received even in healthy windows. The teardown
attribution above comes from the directly correlated connection, RTP and GUI
logs, not an unsupported completeness assumption about that capture.

## Defect and correction

`handle_inbound_frame` refreshed `PeerStateData.last_recv_at` for accepted
data-channel frames. `TransportEvent::VideoSample` and `AudioSample` bypassed
that function and never refreshed this shared transport-liveness clock.
An announce-driven probe could therefore classify a continuously streaming
peer as silent and tear down the whole connection.

Current-session media now refreshes that clock only when the peer is admitted.
The existing epoch fence rejects old-session events before the update, and
unauthenticated or handshaking peers cannot use media to establish liveness.
No timeout, codec, bitrate, frame rate, queue capacity or pacing policy changes.
Explicit channel closure and genuinely silent-peer recovery remain intact.

## Focused regression evidence

Two tests fail against the old runtime code and pass with the correction:

- Receiving video or audio prevents a stale announce probe from being armed.
- Video arriving after a probe is armed prevents its silence teardown.

A third verifies unadmitted and old-epoch media cannot refresh liveness.
The existing reannounce tests cover genuinely silent-peer rebuilding and
fresh/restarting/non-established peers. An additional deterministic assembler
test passes with the pre-existing PR fix across 64 packet reorderings; it
does not establish another assembler defect.

This explains the captured connection-rebuild freeze. It does not establish
that every earlier RTP reordering/repair-expiry incident has the same cause.
The running test binaries have not been changed as part of this capture.
