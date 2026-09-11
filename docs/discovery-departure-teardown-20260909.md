> Historical upstream investigation retained from `59143cb`. This is not a
> current V4 contract or candidate qualification result. Legacy media APIs,
> diagnostic hooks and resource/recovery designs described below may be
> deliberately superseded; see [integration disposition](UPSTREAM-INTEGRATION-59143cb.md).

# Discovery departure incorrectly becomes transport teardown

## Confirmed code defect

The discovery layer reports absence of an mDNS service record, not proof that
an authenticated WebRTC peer has left. The current implementation loses this
distinction:

1. `mdns/discovery/embedded.rs` converts `ServiceRemoved` to
   `DiscoveryEvent::Removed`. The discovery contract explicitly includes cache
   expiry as well as goodbye.
2. `mdns/driver.rs::run_browse` removes the discovery entry and sends
   `MdnsInbound::PeerLeft`.
3. `engine/signaling_bridge.rs` converts that to `SignalingInbound::PeerLeft`,
   discarding the discovery provenance. The event also has no session epoch.
4. `engine/mod.rs::handle_signaling_inbound` unconditionally invokes
   `drop_peer(..., UserLeft)`, even if the current peer just delivered valid
   authenticated media. `drop_peer_inner` removes the peer and closes its
   transport session when present.
5. `UserLeft` is treated as intentional: reconnect intent is cleared, queued
   reliable sends fail, and connect waiters fail. Discovery loss therefore
   destroys transport state and suppresses normal recoverable-drop retry.

This is not an encoder, decoder, bitrate, buffering, or timer problem. A
discovery-record removal is insufficient authority to terminate an otherwise
live authenticated media connection. The system DNS-SD backend feeds the same
Removed contract; its per-interface removal accounting also needs care, but
that is not established as the cause on the Windows test endpoints.

## Minimal reproduction

The original characterization test inserted
an authenticated active peer, admits a current-epoch video sample, verifies
that receive liveness was refreshed, delivers the event currently emitted by
the discovery bridge, then observes peer removal and `Dropped(UserLeft)`.
It reproduced the bug without network sockets. The replacement regression,
`discovery_departure_preserves_fresh_media_but_explicit_leave_drops_it`, now
requires advisory discovery loss to preserve that peer and epoch, followed by
an explicit leave to remove it normally.

Command:

```text
cargo test --offline --locked -p myownmesh-core --lib -j 2 discovery_departure_preserves -- --nocapture
```

Result: one test passed, 344 filtered out, runtime 0.01 seconds. The initial
test assertion incorrectly assumed the first emitted event was Dropped rather
than the preceding diagnostic event; that test-only assertion was corrected.
`git diff --check` passed. No broader test suite was run.

## Live evidence and its limits

CECWorkstation2 and Stream PC retain the same AMS/Mesh processes and creation
times through the observed outage. Stream PC logs many signaling-left events
for the test peer, followed by UserLeft teardown and repeated reconnection.
During the 19:41 UTC outage it receives no frontend input for approximately
44.5 seconds while the sender continues reporting approximately 60 fps. At
19:41:44.606 the peer becomes ACTIVE; at 19:41:44.609 clean-entry delivery
succeeds, matching the return of frontend frames.

This establishes that the live stream encountered the teardown path. It does
not establish the origin and network/session scope of every departure: the
console log omits the signaling driver and network ID. The mDNS driver's
existing `mdns peer withdrew` diagnostic is DEBUG, while the daemon's default
filter leaves `myownmesh_signaling` at INFO. Thus the needed provenance cannot
be recovered from those historical text lines alone. Do not state that all
earlier freezes, or the NIC-boundary packet delay, have been explained.

A subsequent 60-second mDNS-only Packet Monitor capture completed on Stream
PC at 19:52:22 UTC. It caught a smooth video interval, with no signaling-left
events in the collected test-peer log window. One HeartbeatTimeout log occurred
without interrupting video, reinforcing that multi-network events must not be
equated blindly with the video session. The PCAP remains on Stream PC at
`C:\Users\Admin\video-diag-runs\mdns-departure-20260909\mdns.pcapng`;
the diagnostic file route failed to answer, so no local PCAP analysis is claimed.

## Correct fix boundary

Keep discovery disappearance distinct from explicit, authoritative departure.
Expire discovery endpoints without removing an established authenticated peer
or suppressing its reconnect intent. Preserve transport failure detection and
explicit membership/authorization removal semantics. Do not globally ignore
all leave events or compensate with video buffering. Retain minimal provenance
on departure diagnostics (driver/reason, network and session epoch) so the next
test can attribute a teardown unambiguously.

## Implemented boundary and CPU work

Discovery removal now emits a separate advisory event. It invalidates discovery
endpoints but preserves existing signaling and media transports. Explicit Leave
and transport liveness failure retain their existing behavior. Removal of one
service key does not remove a peer still represented by another key.

The local installed Mesh process was measured at 427–478% CPU, with nine mDNS
daemon threads dominating a three-second stack sample. CECWorkstation2's running
diagnostic Mesh consumed 3.19 CPU cores in a separate two-second measurement.
The embedded backend now shares one process-wide ServiceDaemon and one browse
per service type, with per-network subscriptions and advertisement lifetimes.
Late subscribers receive cached observations under the same lock as publication;
stopping one network does not shut down others. The last owner closes the daemon.

The CPU mechanism still requires before/after live verification. These changes
do not establish that every historical video stall had the same cause.
