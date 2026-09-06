# Encrypted video repair contract

The receive-side H.264 assembler cannot repair a hole if the encrypted
transport discards the requested packet first. Our NACK generator tracks 512
packets and the responder retains 8192, but the default SRTP session rejected
unseen packets more than 63 sequence numbers behind the receive head.

The transport now configures the finite SRTP replay window to match the
responder's 8192-packet history. This is sequence-history bookkeeping, not an
8192-packet playout queue. Authentication and replay protection stay enabled;
the 150 ms assembly deadline, packet-memory guards, NACK interval, media
bitrates, resolution and FPS targets are unchanged.

## Wraparound duplicate protection

The encrypted regression also exposed a webrtc-util 0.11 boundary issue:
`WrappedSlidingWindowDetector::check` computes a wrapped age, while `accept`
marks a raw subtraction. A late pre-wrap repair may consequently not be
remembered. A small authenticated RTP interceptor now fences duplicates with
a bounded sequence bitmap before NACK tracking. It neither decrypts packets
itself nor disables the underlying SRTP checks. Its lifetime is per remote
stream, and its bitmap uses 1024 bytes at the configured window size.

## Focused proof

`encrypted_video_repair_reaches_assembler_after_packet_advance` encrypts an
H.264 picture, withholds one fragment, delivers 200 newer packets, and then
repairs the fragment at a synthetic 55 ms. It covers both SRTP protection
profiles, ordinary sequence numbers, and 16-bit wraparound. The legacy
64-packet window rejects the repair; the configured path reconstructs exactly
one key access unit. Repeating the repair is rejected by SRTP or the duplicate
fence. A separate boundary test checks unseen expired packets and duplicates.

These are offline tests using synthetic keys and the actual linked crypto
dependency, not an application rebuild or a benchmark on a live host.

## Scope

This corrects a reproduced transport integration defect. It does not establish
the source of every initial packet loss, guarantee that downstream daemon IPC
cannot overflow, or substitute for a paired before/after field run. No queue
capacity or scheduler-yield policy is changed in this patch.
