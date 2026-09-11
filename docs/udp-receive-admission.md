> Historical upstream investigation retained from `59143cb`. This is not a
> current V4 contract or candidate qualification result. Legacy media APIs,
> diagnostic hooks and resource/recovery designs described below may be
> deliberately superseded; see [integration disposition](UPSTREAM-INTEGRATION-59143cb.md).

# UDP receive admission and the video recovery loop

## Evidence

The Windows receiver's packet capture showed original RTP packets arriving
in sequence at the NIC, followed by application sequence gaps and repairs.
A subsequent error-only `Microsoft-Windows-Winsock-AFD` trace recorded **366
datagrams from the active media source discarded in 20 seconds**, all with
the reason **Insufficient local buffer space**. The generic Packet Monitor
drop trace and IPv4 UDP receive-error counter had not exposed these drops.

A fresh Windows UDP socket reported a 65,536-byte receive capacity. The
existing AMS pacer permits a 96 KiB immediate burst, followed by its normal
frame-budget pacing. Therefore one permitted burst can exceed the entire
socket admission capacity before the receive task gets scheduled. Dropping
originals here creates NACK work, incomplete frames and recovery traffic even
when the LAN delivered every original packet. Repair-worker deduplication
does not fix this initial loss.

This identifies a real source of recovery episodes, not proof that every
reported 300 Mbps incident has the same cause. Post-deployment validation
must check both Winsock drops and video assembly/delivery.

## Change

Configure real ICE/STUN/TURN UDP sockets with bounded **1 MiB receive
capacity**, retaining any larger existing capacity. The opt-in upstream
`Net` hook runs before exposing a socket to a reader/candidate. Bound and
connected sockets use the same policy. Real interface enumeration remains
fresh across candidate gathers; virtual network behavior is unchanged.

This is available kernel admission capacity, **not** a fill target or a
playout buffer. Reads drain immediately. No timer, low-water mark, extra
application queue, bitrate/FPS reduction, assembly deadline, or playback
delay is introduced. No system-wide socket or security setting is changed.
The OS's actual capacity is logged once per socket at the
`myownmesh_core::transport::udp_socket` debug target; an OS
clamp is warned about rather than silently claiming the requested capacity.

## Focused verification

`cargo test --locked -p myownmesh-core --lib udp_socket -j 2 -- --nocapture`

- Bound and connected sockets receive the policy and deliver fresh data.
- On Windows, an 81-packet, 1,216-byte-per-packet burst reproduces loss with
  64 KiB admission and must arrive completely with configured admission.
  The reader is deliberately not scheduled until that single burst is sent.
- Compare a short live Winsock AFD drop trace and the existing RTP timing
  logs before and after deployment. Exclude restart/reoffer intervals.

The source display remains native 1080p in the current test. Passing this
test is not a claim that native 4K60 has been exercised.

## Live validation: a real fix, not the entire incident

Both Windows endpoints passed the focused tests and were deployed with the
socket change. The Windows burst regression measured **54/81 packets** with
64 KiB and **81/81** with the configured socket. In the subsequent 20-second
AFD trace there were no media-socket drops, but the displayed video still
froze. This change must not be presented as a complete stutter fix.

The diagnostic branch therefore reports bounded internal packet-buffer
overflows under the existing detailed-video target, identifying the ICE,
mux or decrypted SRTP constructor site. It changes no queue behavior and
emits at most once per five seconds per overflowing buffer, with no packet
contents or successful-packet timing overhead. Its visibility was verified
with the production filters.

A later event-triggered NIC-plus-AFD capture (2026-09-08 22:43:28–22:44:02
UTC on Stream PC) captured a remaining failure. The NIC and application
reported exactly **1,622 skipped video packets and 1,400 reordered repairs**.
Audio also had 11 missing packets at the NIC. No AFD or internal packet-buffer
overflow was reported. This incident's loss therefore precedes the receiver
application pipeline; paired sender/receiver captures are needed to separate
sender egress from loss in transit. It is not evidence of LAN saturation by
itself. Native 1080p and the existing latency/bitrate/FPS targets were retained.

## Subsequent awake check

A short paired capture on 2026-09-09 around 00:34 UTC contained no video
sequence skips, reordering, or retransmitted duplicates on either endpoint.
The receiver's approximately 64-second window averaged 3.3 Mbps, peaking at
40.4 Mbps over 100 ms. Sender output was roughly 45–49 fps with about 6 ms
encode time. This did not reproduce the reported 300–600 Mbps bursts or a
multi-second freeze; it is not evidence that all remaining issues are fixed.
The endpoints' capture windows differ, so their separate maximum packet gaps
must not be subtracted to estimate network delay.

The internal admission diagnostic also exposed overflowing 100,000-byte
SRTCP report buffers after a long session. These are not the 1,000,000-byte
video SRTP buffers, and no causal link to the video incident was established.
Sleep/idle intervals and this unrelated report-buffer warning must not be
used as evidence of a reproduced active-video stall.
