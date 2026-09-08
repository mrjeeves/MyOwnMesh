# Diagnostic NACK history fix

Source: crates.io `interceptor` 0.14.0, package checksum
`1ac0781c825d602095113772e389ef0607afcb869ae0e68a590d8e0799cdcef8`.
Original manifests, source/tests, README, and both upstream licenses are retained.

The correction is the range check around the final
`set_received` in `GeneratorStreamInternal::add`. A previously unseen repair
older than the NACK bitmap must not mark a newer missing sequence that shares
its ring slot as received. The packet is still returned to the RTP consumer.

For the live diagnostic A/B only, setting
`MYOWNMESH_DIAG_LEGACY_NACK_HISTORY=1` before starting the backend restores the
old bitmap-write behavior. It is captured at stream creation, with one warning
per affected stream, and does not add environment reads to the packet hot path.
Without this variable (or with `0`), the correction remains enabled. This is
a temporary test switch, not a recommended runtime configuration.

The root workspace patches this transitive dependency to the checked-in copy;
the lockfile uses that path without changing dependency versions. Remove the
patch once a pinned upstream release contains an equivalent tested correction.

Focused integration regressions live in
`crates/myownmesh-core/src/transport/nack_history_tests.rs` and exercise the
actual generator reader, MyOwnMesh replay fence, and generated RTCP feedback.
Run `cargo test --locked -p myownmesh-core --lib nack_history_tests -j 2`.

The generator also exposes `with_max_nacks_per_tick`: feedback work is bounded
independently of receive-history retention. The upstream default is unchanged
(no additional cap). MyOwnMesh retains a 512-request per-track feedback cap,
while its history now holds 1024 sequence bits to cover the current AMS
96 KiB + 256 Mbps/20ms burst envelope. Previously an early hole could leave
the 512-bit history before the first NACK, although the assembler still needed
the packet. Truncated feedback does not mark remaining holes as received.

The 8192-packet replay/responder history, 20 ms feedback interval, reorder tail,
assembly deadline, media queues and quality targets are unchanged. Focused
regressions cover feedback bounds and a ~627 KiB frame whose missing packet
is now requested and delivered through assembly rather than timing out.
