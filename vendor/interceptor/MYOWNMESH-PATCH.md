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

No changes to the 512-packet NACK history, 8192-packet replay/responder history,
20 ms feedback interval, reorder tail, assembly deadline, queues, or quality
targets. This fixes reproduced bookkeeping corruption; the live stutter still
requires comparison on the diagnostic endpoints before making a release claim.
