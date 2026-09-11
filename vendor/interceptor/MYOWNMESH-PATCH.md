# Scoped RTP history correctness patch

Source: crates.io `interceptor` 0.14.0, package checksum
`1ac0781c825d602095113772e389ef0607afcb869ae0e68a590d8e0799cdcef8`.
Original manifests, stock sources/tests and both licenses are retained.

This V4 integration selectively carries the upstream stale-repair bitmap
range check, exact sequence validation when reading a responder ring slot,
and Skip behavior for missed generator timer ticks. It does not change the
default history capacities, feedback interval, or application flow policy.
The workspace's existing native typed flows use the default interceptor registry.

The upstream legacy-NACK environment switch, V3 media API tests, expanded
replay/socket buffers, max-feedback configuration and new per-SSRC repair
worker implementation are deliberately excluded. In particular, this patch
makes no new task-ownership or whole-transport resource qualification claim.
The dependency's existing responder lifecycle remains unchanged.

Co-located controls: `stale_repair_does_not_acknowledge_newer_ring_alias` and
`retained_slot_must_match_exact_requested_sequence`, plus original tests.

This crate is excluded from the workspace. Its separate `Cargo.lock` pins
the original manifest's development dependencies (including `chrono` and
`tokio-test`) for standalone tests; it is not the workspace production
dependency graph. The root lockfile and dependency declarations are unchanged
by this standalone test pin. Run the two exact controls from the repository
root, rather than selecting the excluded crate with workspace `-p`:

```sh
cargo test --locked --manifest-path vendor/interceptor/Cargo.toml --lib \
  nack::generator::generator_stream::test::stale_repair_does_not_acknowledge_newer_ring_alias \
  -- --exact --test-threads=1
cargo test --locked --manifest-path vendor/interceptor/Cargo.toml --lib \
  nack::responder::responder_stream::test::retained_slot_must_match_exact_requested_sequence \
  -- --exact --test-threads=1
```

CI requires one passed test, zero failed and zero ignored for each command.
These commands document the validation contract, not a passed-run claim;
manager-owned execution and native qualification remain separate evidence.
