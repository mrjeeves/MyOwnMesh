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
The OS's actual capacity is logged once per socket in detailed logs; an OS
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
