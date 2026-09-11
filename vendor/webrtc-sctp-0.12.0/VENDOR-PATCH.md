# Same-version delayed-ACK timer repair

Upstream: crates.io `webrtc-sctp` 0.12.0, crate archive SHA-256
`07439c134425d51d2f10907aaf2f815fdfb587dce19fe94a4ae8b5faf2aae5ae`.
Published VCS revision: `fa3b850527f5db19f8e7d844e8356e1d3676f616`, path `sctp`.
The MIT and Apache-2.0 license files and package version are preserved.

Initial copy: all 71 files in the extracted locked registry source, except
Cargo's `.cargo-ok` installation marker. All 71 relative paths were SHA-256
compared before modification; zero mismatches. No destination existed before
the copy. Registry source and archive were not modified.

Changed upstream files:

- `src/timer/ack_timer.rs`: per-start active marker permits rearm after expiry;
  cancellation remains effective while awaiting the observer lock. Each old
  task can clear only its own marker. Expiry claims its callback once under the
  observer lock; cancellation does not revoke a callback already claimed.
- `Cargo.toml`: explicitly registers only the new `ack_timer_rearm` test target
  because the published manifest disables automatic test discovery.

Added files: this note and `tests/ack_timer_rearm.rs`. The latter imports the
actual timer source for focused paused-time controls without enabling the
unrelated legacy library test suite. Existing `tokio-test` supplies `test-util`;
no dependency, feature, version, ACK interval or RTO policy has been changed.

The independent core public-Association regression remains outside this patch.
Source inspection and deterministic control implementation are not execution
evidence or proof that this defect causes the observed field latency.
