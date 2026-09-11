# Upstream v0.3.2–v0.3.21 inventory and TURN TCP/TLS restoration

## Scope and reading guide

This is a source-bound inventory and restoration ledger, not a release announcement.
It accounts for all **92 commits** in `28c9e27..59143cb`, all **20 releases**
from v0.3.2 through v0.3.21, all **173 net upstream changed paths**, and the nine
TURN-related commits identified below. The original v0.3.2 commit is the excluded
lower bound of the commit range, but is included in the release table.

**The omission baseline is the pre-port candidate `3d530976`.** Restoration is
selected work, not an already-tested feature. Concurrent implementation may change
working files after that baseline. The implementation/test/audit placeholders at
the end must be filled from a frozen successor's evidence, not from this document's
presence. The older [integration disposition](UPSTREAM-INTEGRATION-59143cb.md)
records the earlier deliberate TCP/TLS deferral; this ledger records its reopening
for restoration without rewriting that historical decision.

The integration author also authored this inventory. This is not an independent
audit. No Git, build, test, deployment, firewall or release operation was performed
to create it.

### Pinned identities

| Role | Commit identity | Tree identity |
| --- | --- | --- |
| Original fork / v0.3.2 | `28c9e27f89fdb8c2af9a9691a0fe0271befbe060` | `858e365` |
| V4 common base | `9b5b4862d21ddbb92e9ff4fbbade47b41fe6fa75` | `1d9cef` |
| Upstream v0.3.21 | `59143cbdb094b6b99464c224a500e148fd7d2113` | `d022469` |
| Prior integration merge | `0ff7c071`; parents `7268ade` + `59143cb` | See final candidate custody packet |
| Current pre-restoration candidate | `3d530976fb9f9686eb008b5598594b39c3a6fa20` | `4273405f7c2a72eae0b7da7ea5817ab7914de344` |

Short identities in this table are the recorded object prefixes, not fabricated
full object IDs. Full upstream commit and release-target IDs appear below.

**Ancestry is not feature preservation.** A merge can contain an upstream commit
as an ancestor while resolving its files to V4 replacements, dropping a module,
or retaining syntax without a working transport. The prior source-resolution
packet recorded 37 upstream-exact, 31 adapted, 39 V4-exact and 66 excluded paths
among 173 net paths. Those are historical blob relationships, not 173 passing
behavioral checks or the current working-tree status.

### Classification key

- **P — preserved/integrated:** the named behavior or specified part was retained
  in the V4 source disposition. It is not a new runtime PASS.
- **S — superseded by V4 / intentionally not carried:** current authority, lifetime,
  resource or application boundaries govern instead. Where the feature remains
  absent, that absence is stated; “superseded” does not mean an equivalent feature.
- **R — omitted and selected for restoration now:** implementation and qualification
  remain pending unless a final matrix cell cites successor evidence. This is the
  “omitted/restored now” work category, not a completed-restoration claim.
- **I — informational/no independent implementation action:** release metadata,
  merge bookkeeping, formatting, or historical evidence. A merge's constituent
  changes retain their own P/S/R dispositions.

Mixed classifications explicitly split a commit or tranche; they never authorize
whole-file copying. **A1–A7**, **M**, and **T1–T11** name the action groups below.
Release-number edits remain historical; the selected public V4 version is 1.0.0.

### Evidence and date semantics

The manager-owned, read-only capture is retained at
[target/qualification-evidence/upstream-turn-tcp-tls](../target/qualification-evidence/upstream-turn-tcp-tls/).
Its chronological TSV supplies exact subjects, full SHAs and committer dates;
the topological packet supplies parents and per-commit name-status where available.
First-containing release groups below were derived from that parent graph, not
merely from commit timestamps. All 92 entries are unique and covered.

| Retained input | SHA-256 |
| --- | --- |
| `upstream-commits-92.tsv` | `2A0EA1B6577821C6C97DF7CD6E6C773CE4A7E05D8EA920D323CA7658901B9930` |
| `upstream-releases-v0.3.2-v0.3.21.tsv` | `29ED657301A1C49FE2759AB63505414CBE7DE8B8462F43EF9D218A72AE77A213` |
| `upstream-tags.tsv` | `16051353A785C8B3F63285FE75D02B3363A8F3A2A6C8C48E29A1D2E847D62A52` |
| `upstream-commits-topo-with-paths.txt` | `2B01E1119655311385B3605A165441FAF54B8611944263F0C2757BAAA2B19996` |
| `upstream-net-paths.tsv` | `170F18F45943ADDD6DD6990C9B85B483B9DFC3A2DBA5BC488C6548CD377DE03A` |

The nine full patches and the two exact upstream stream-module snapshots are
alongside those inputs, with `SHA256SUMS.tsv`. Historical integration evidence is
[resolved-candidate.json](../target/qualification-evidence/v1-upstream-integration/resolved-candidate.json)
and [FINAL-HANDOFF.md](../target/qualification-evidence/v1-upstream-integration/FINAL-HANDOFF.md);
the latter's old pending statuses are historical, not current instructions.

## Release and tag inventory

Release IDs and UTC publication timestamps are distinct from commit dates. In the
captured tag inventory these tags point directly to the listed commits (no separate
peeled annotated-tag ID is supplied); the tag-date column is the target commit's
date, **not a separately attested tag-creation time**. Release publication does not
certify current source, binary, signing or deployment equivalence.


| Release | Tag target commit (full SHA) | Tag-target commit date | Release published (UTC) | GitHub release ID |
| --- | --- | --- | --- | --- |
| v0.3.2 | `28c9e27f89fdb8c2af9a9691a0fe0271befbe060` | 2026-07-23T16:25:50-05:00 | 2026-07-23T21:30:11Z | 358965734 |
| v0.3.3 | `6cf48ab0422aec2b5ca72207488e45c2c1f27489` | 2026-08-02T16:57:12-05:00 | 2026-08-02T22:01:38Z | 363905277 |
| v0.3.4 | `fe240b01d03ed9c06081346474ff7746c027f132` | 2026-08-12T05:52:19-05:00 | 2026-08-12T10:56:43Z | 369172081 |
| v0.3.5 | `4dedf70983cb97210c2feed0e784d4fb924236c9` | 2026-08-12T06:25:20-05:00 | 2026-08-12T11:29:08Z | 369189878 |
| v0.3.6 | `a4c9d53f7b6f98ae0db2e00f58489d6a82cdf62a` | 2026-08-16T02:34:25-05:00 | 2026-08-16T07:43:33Z | 371263963 |
| v0.3.7 | `cc0d2bc2d889a7996f33a95e9b47200ee7c56b0f` | 2026-08-17T18:43:04-05:00 | 2026-08-17T23:47:39Z | 372010487 |
| v0.3.8 | `a622cb566f181a003e712eb00ece04cc8629c008` | 2026-08-18T23:18:46-05:00 | 2026-08-19T04:23:20Z | 372796230 |
| v0.3.9 | `f51b184f7cd4bead74a49932765b14074138b23b` | 2026-08-23T19:54:57-05:00 | 2026-08-24T00:59:01Z | 375378176 |
| v0.3.10 | `5b99e6860346cafc8940ebed4c4b80c4cfcc50cc` | 2026-08-29T22:38:18-05:00 | 2026-08-30T03:42:09Z | 379172390 |
| v0.3.11 | `af21cbaa8d1662fce506bed8b8087ce808bac790` | 2026-08-30T21:08:41-05:00 | 2026-08-31T02:13:17Z | 379468388 |
| v0.3.12 | `201d9331a839d7f905e59cfe2079a93f0ce6d298` | 2026-08-31T20:59:41-05:00 | 2026-09-01T02:03:40Z | 380166067 |
| v0.3.13 | `f36262743df73dd070f55d11491d294a1fff7435` | 2026-09-03T18:43:46-05:00 | 2026-09-03T23:47:46Z | 382393251 |
| v0.3.14 | `3daf155256908ec797a19fdc85b2e02039e91d93` | 2026-09-04T15:26:48-05:00 | 2026-09-04T20:30:47Z | 382998765 |
| v0.3.15 | `19b1b9075fdd5f7deeb33f5341d6400dfcb9d0e4` | 2026-09-04T17:33:19-05:00 | 2026-09-04T22:38:01Z | 383048980 |
| v0.3.16 | `187404241a111f55aa9f6ab0a0acbf1ae272ebe1` | 2026-09-04T21:18:02-05:00 | 2026-09-05T02:22:06Z | 383105456 |
| v0.3.17 | `0dcbd4ff9a38269cd2d7a34891bfeb2f639169b0` | 2026-09-05T00:00:29-05:00 | 2026-09-05T05:04:12Z | 383140137 |
| v0.3.18 | `13b9cdfaddc68abc026f50ad567878623d2942c5` | 2026-09-05T23:57:34-05:00 | 2026-09-06T05:02:13Z | 383471443 |
| v0.3.19 | `fca7955f9cfa0e99ebff9f7edf9299436e86ce47` | 2026-09-06T14:13:55-05:00 | 2026-09-06T19:18:16Z | 383690174 |
| v0.3.20 | `ccdec687d030edb6db23428ae99e80412a22d75b` | 2026-09-08T20:49:54-05:00 | 2026-09-09T01:54:43Z | 385173636 |
| v0.3.21 | `59143cbdb094b6b99464c224a500e148fd7d2113` | 2026-09-09T17:04:55-05:00 | 2026-09-09T22:09:40Z | 385878423 |

## Chronological 92-commit inventory

Rows follow the captured chronological order (committer epoch); displayed timestamps
retain their original offsets. Release grouping is the first containing tag found
through recorded parent ancestry, including merge-side commits, not the date alone.
A release-target marker identifies a row whose SHA is itself the tag target.

| # | First containing release/tag | Full commit SHA | Commit date (original offset) | Exact subject | Content disposition |
| --- | --- | --- | --- | --- | --- |
| 1 | v0.3.3 | `92130448e114fb64a65e96eb7165a255c3fda744` | 2026-07-29T09:32:48Z | fix(logging): quiet the default log and stop colouring syslog | P · A1 |
| 2 | v0.3.3 | `9b5b4862d21ddbb92e9ff4fbbade47b41fe6fa75` | 2026-07-30T08:37:17-05:00 | Merge pull request #108 from mrjeeves/claude/allmystuff-cecsupport-auto-updates-r6rjxi | I · merge; constituent dispositions apply |
| 3 | v0.3.3 | `c07a9e1dfca35d9d59a64138a6972f795afffe45` | 2026-07-31T05:39:04Z | fix(handshake): stop going ACTIVE off our own approve | P/S · A2 |
| 4 | v0.3.3 | `58c8ee24da67ed59a159511afce04b2e8549c506` | 2026-08-02T20:39:46Z | signaling: listen-only (lurk) joins — subscribe to a room without ever announcing | S · A3 |
| 5 | v0.3.3 | `3e9fce39a1c8fe7e3ca9c0e3e1b256f788c0342f` | 2026-08-02T20:52:46Z | style: rustfmt the listen-only additions | I · A3 |
| 6 | v0.3.3 | `0766a75c31a75227a84fd46d625d8b5251a4d182` | 2026-08-02T16:46:11-05:00 | Merge pull request #113 from mrjeeves/claude/cec-support-mesh-visibility-tgyccq | I · merge; constituent dispositions apply |
| 7 | v0.3.3 | `276a59b560907d5197f4717d515954aa8f2b13f7` | 2026-08-02T16:48:15-05:00 | Merge pull request #109 from mrjeeves/claude/kvm-wifi-interface-auth-l96vcx | I · merge; constituent dispositions apply |
| 8 | v0.3.3 (tag target) | `6cf48ab0422aec2b5ca72207488e45c2c1f27489` | 2026-08-02T16:57:12-05:00 | chore(release): 0.3.3 | I · release metadata |
| 9 | v0.3.4 | `9d1a555687ccb75ea7d032d86c6d8e07ab0b31de` | 2026-08-03T07:38:07-05:00 | deduplicate CI runs | P · A1 |
| 10 | v0.3.4 | `31683ab03d7477f5e228d0c123f458bb14c0f66a` | 2026-08-03T07:47:56-05:00 | Merge pull request #114 from mrjeeves/codex/standardize-just-ci | I · merge; constituent dispositions apply |
| 11 | v0.3.4 | `007f21f7776d0cf8e23bdd62fcb456a8df5b2c46` | 2026-08-03T14:01:09Z | docs: bring the copy-paste dependency snippets up to v0.3.3 | I · A1 |
| 12 | v0.3.4 | `95bc6dce7eb05f0e6a3a4efa0a5197fb8eea24e9` | 2026-08-03T17:00:27-05:00 | Merge pull request #115 from mrjeeves/claude/allmykvm-cec-rename-x85mm3 | I · merge; constituent dispositions apply |
| 13 | v0.3.4 | `5c41aaa4cfc5c982cf14f310f31cf448e2e12339` | 2026-08-12T04:34:28-05:00 | bound TURN service logging | P · T7 |
| 14 | v0.3.4 | `8c0d23473aad191f66e0f21bf54a2f4841361f6d` | 2026-08-12T05:16:29-05:00 | add TURN TCP and TLS fallback | R · T1–T6 |
| 15 | v0.3.4 | `15c0733087e1f3cd0f1f569cfde06dc7588fd566` | 2026-08-12T05:21:48-05:00 | expire idle TURN TCP clients | R · T2 |
| 16 | v0.3.4 | `afcbd49cb8797085636579d46f3ccc92118d5368` | 2026-08-12T05:23:39-05:00 | expose TURN transport settings | P/R · T3 |
| 17 | v0.3.4 | `495573edaba4580e916f4c583683240bec318850` | 2026-08-12T05:35:32-05:00 | test TURN TCP allocation and relay | R · T8 |
| 18 | v0.3.4 | `f818fe89cda54063c9320e3232b5dc1e754be6a0` | 2026-08-12T05:36:40-05:00 | document provider TURN firewall rules | P/R · T6 |
| 19 | v0.3.4 | `31058c53982b1a0d2bd7eb5a2ae10f094ece6605` | 2026-08-12T05:43:35-05:00 | make Caddy convergence nonblocking | R · T6 |
| 20 | v0.3.4 | `c88c092a424e33d4e49516b0986958cc0055f992` | 2026-08-12T05:49:55-05:00 | Merge pull request #116 from mrjeeves/codex/bound-turn-logs | I · merge; constituent dispositions apply |
| 21 | v0.3.4 (tag target) | `fe240b01d03ed9c06081346474ff7746c027f132` | 2026-08-12T05:52:19-05:00 | chore(release): 0.3.4 | I · release metadata |
| 22 | v0.3.5 | `4f3ebaad2a391af0a2ebf8aa30d2ab3132299332` | 2026-08-12T06:12:16-05:00 | migrate existing TURN clients to TCP and TLS fallbacks | R · T4 |
| 23 | v0.3.5 | `7006283ac85d9dc6adcf53c9844ad0740cf04357` | 2026-08-12T06:21:51-05:00 | Merge pull request #117 from mrjeeves/codex/migrate-turn-fallbacks | I · merge; constituent dispositions apply |
| 24 | v0.3.5 (tag target) | `4dedf70983cb97210c2feed0e784d4fb924236c9` | 2026-08-12T06:25:20-05:00 | chore(release): 0.3.5 | I · release metadata |
| 25 | v0.3.6 | `9ad526f406dbec4c0789cb3645b66c2e3cf12e8b` | 2026-08-16T01:57:31-05:00 | harden mDNS endpoint dialing | P/S · A4 |
| 26 | v0.3.6 | `bdc825fc17471951b680dd2619c32e2ced2de738` | 2026-08-16T02:10:12-05:00 | Merge pull request #118 from mrjeeves/codex/fix-mdns-endpoint-backoff | I · merge; constituent dispositions apply |
| 27 | v0.3.6 | `f7d20283cab17e7709ab2a525a8650a8e596eb39` | 2026-08-16T02:22:19-05:00 | prepare 0.3.6 and quiet repetitive diagnostics | P/S/I · T9 |
| 28 | v0.3.6 (tag target) | `a4c9d53f7b6f98ae0db2e00f58489d6a82cdf62a` | 2026-08-16T02:34:25-05:00 | Merge pull request #119 from mrjeeves/codex/fix-mdns-endpoint-backoff | I · merge; constituent dispositions apply |
| 29 | v0.3.7 | `78a0a3feee42a8851871c214e896ca5be7fec90b` | 2026-08-17T18:27:18-05:00 | back off unconfirmed relay rescues | S · A4 |
| 30 | v0.3.7 | `7b0c3344cc7bd06ff7bc7730aba6b8a945f69f19` | 2026-08-17T18:42:01-05:00 | Merge pull request #120 from mrjeeves/codex/backoff-relay-rescue | I · merge; constituent dispositions apply |
| 31 | v0.3.7 (tag target) | `cc0d2bc2d889a7996f33a95e9b47200ee7c56b0f` | 2026-08-17T18:43:04-05:00 | chore(release): 0.3.7 | I · release metadata |
| 32 | v0.3.8 | `be9aa56c9c43051ae57704f0f7625dcb46230ccb` | 2026-08-18T22:58:57-05:00 | Fix relay admission and reconnect flapping | P/S · A5 |
| 33 | v0.3.8 | `66942bde6e3142c5a9c523246f5b0f95546c12bf` | 2026-08-18T23:17:38-05:00 | Merge pull request #121 from mrjeeves/agent/fix-relay-proxy-flapping | I · merge; constituent dispositions apply |
| 34 | v0.3.8 (tag target) | `a622cb566f181a003e712eb00ece04cc8629c008` | 2026-08-18T23:18:46-05:00 | chore(release): 0.3.8 | I · release metadata |
| 35 | v0.3.9 | `e38b78402e410acdb1e0e9b60da5c10556d477d6` | 2026-08-23T19:37:32-05:00 | Harden connection recovery and signaling identity | P/S · A2/A4/A5 |
| 36 | v0.3.9 | `8a38b53e5236a4aa29a3386d3e0ee0e5658dd8c7` | 2026-08-23T19:50:08-05:00 | Merge pull request #122 from mrjeeves/codex/harden-connection-recovery | I · merge; constituent dispositions apply |
| 37 | v0.3.9 (tag target) | `f51b184f7cd4bead74a49932765b14074138b23b` | 2026-08-23T19:54:57-05:00 | chore(release): 0.3.9 | I · release metadata |
| 38 | v0.3.10 | `534eaf3ff60c98334ee806badac01bd27da0b7a0` | 2026-08-29T20:54:01-05:00 | Repair signed roster projections | S · A6 |
| 39 | v0.3.10 | `6ca22112515fe269336aa3d30fb04dc5f47da74e` | 2026-08-29T21:49:19-05:00 | Preserve eviction proof before teardown | S · A6 |
| 40 | v0.3.10 | `3ea2a6824da4a97fb45f5b5ef5865f8c02c5a1ec` | 2026-08-29T22:34:46-05:00 | Merge pull request #123 from mrjeeves/codex/reconcile-signed-rosters | I · merge; constituent dispositions apply |
| 41 | v0.3.10 (tag target) | `5b99e6860346cafc8940ebed4c4b80c4cfcc50cc` | 2026-08-29T22:38:18-05:00 | chore(release): 0.3.10 | I · release metadata |
| 42 | v0.3.11 | `adf3e5d2c6ec256c54ab2bba63b63e7b273a1df7` | 2026-08-30T17:30:53-05:00 | fix(governance): protect signed roster projection | S · A6 |
| 43 | v0.3.11 | `2a01ca4daa9076259dc78ee773e3eb5e2f6dc3fb` | 2026-08-30T21:00:03-05:00 | Merge pull request #124 from mrjeeves/codex/guard-signed-roster-projection | I · merge; constituent dispositions apply |
| 44 | v0.3.11 (tag target) | `af21cbaa8d1662fce506bed8b8087ce808bac790` | 2026-08-30T21:08:41-05:00 | chore(release): 0.3.11 | I · release metadata |
| 45 | v0.3.12 | `f10aa0bc6a39f8d5c9c4c0a90692859c735ba03d` | 2026-08-31T14:00:25-05:00 | fix(video): recover packet loss without stale-frame buildup | S · M |
| 46 | v0.3.12 | `674f3f03a335ebce3473c3066069b544bd8f1720` | 2026-08-31T20:58:17-05:00 | Merge pull request #125 from mrjeeves/codex/fix-video-retransmit-window | I · merge; constituent dispositions apply |
| 47 | v0.3.12 (tag target) | `201d9331a839d7f905e59cfe2079a93f0ce6d298` | 2026-08-31T20:59:41-05:00 | chore(release): 0.3.12 | I · release metadata |
| 48 | v0.3.13 | `5b6f35480fef1153ef6f82c7383deeebf038e292` | 2026-09-03T16:38:03-05:00 | fix(video): bound RTP retransmit amplification | S · M |
| 49 | v0.3.13 | `dc174d801c99c5e60e511225f97e279ae5237224` | 2026-09-03T18:41:42-05:00 | Merge pull request #126 from mrjeeves/fix/bound-video-retransmits | I · merge; constituent dispositions apply |
| 50 | v0.3.13 (tag target) | `f36262743df73dd070f55d11491d294a1fff7435` | 2026-09-03T18:43:46-05:00 | chore(release): 0.3.13 | I · release metadata |
| 51 | v0.3.14 | `d6793ae50e3f25c780c340c7ee79d4f80eb35572` | 2026-09-04T15:05:50-05:00 | fix(video): preserve paced sample boundaries during retransmit | S · M |
| 52 | v0.3.14 | `3abd30b9114892ec8240552ceb070118c55fc0f0` | 2026-09-04T15:21:30-05:00 | Merge pull request #127 from mrjeeves/fix/preserve-paced-video-sample-boundaries | I · merge; constituent dispositions apply |
| 53 | v0.3.14 (tag target) | `3daf155256908ec797a19fdc85b2e02039e91d93` | 2026-09-04T15:26:48-05:00 | chore(release): 0.3.14 | I · release metadata |
| 54 | v0.3.15 | `220c897b6cab55c41710ae7310e8df2c77edc0fe` | 2026-09-04T17:16:27-05:00 | fix(video): recover motion-burst packet loss promptly | S · M |
| 55 | v0.3.15 | `cff42f49c4c58ee06e49198ef4e11943e0f07678` | 2026-09-04T17:32:50-05:00 | Merge pull request #128 from mrjeeves/fix/video-loss-recovery | I · merge; constituent dispositions apply |
| 56 | v0.3.15 (tag target) | `19b1b9075fdd5f7deeb33f5341d6400dfcb9d0e4` | 2026-09-04T17:33:19-05:00 | chore(release): 0.3.15 | I · release metadata |
| 57 | v0.3.16 | `a3aba6d78aea36626181e5b6e01c89c57edf9563` | 2026-09-04T21:05:10-05:00 | fix(video): preserve ready consumers across media fanout bursts | S · M |
| 58 | v0.3.16 | `03d7fde1d1fe9e38b00cce5a189c342896c37a3e` | 2026-09-04T21:17:24-05:00 | Merge pull request #129 from mrjeeves/fix/video-fanout-fairness | I · merge; constituent dispositions apply |
| 59 | v0.3.16 (tag target) | `187404241a111f55aa9f6ab0a0acbf1ae272ebe1` | 2026-09-04T21:18:02-05:00 | chore(release): 0.3.16 | I · release metadata |
| 60 | v0.3.17 | `e694272aae9ea758fe63476862b2524398b43bb5` | 2026-09-04T23:41:59-05:00 | fix(video): budget RTP recovery by frames and observable holes | S · M |
| 61 | v0.3.17 | `e8089992f4378e88243a7189302ca5be38ab013c` | 2026-09-04T23:44:09-05:00 | docs(video): keep public recovery evidence synthetic | I · M |
| 62 | v0.3.17 | `7efaa97cf527d0c858bc5cf0e1f8b74bad9a0f00` | 2026-09-05T00:00:03-05:00 | Merge pull request #130 from mrjeeves/fix/video-recovery-frame-budget | I · merge; constituent dispositions apply |
| 63 | v0.3.17 (tag target) | `0dcbd4ff9a38269cd2d7a34891bfeb2f639169b0` | 2026-09-05T00:00:29-05:00 | chore(release): 0.3.17 | I · release metadata |
| 64 | v0.3.18 | `01278264217fde0991f4c108984d41d1417d3080` | 2026-09-05T21:26:51-05:00 | fix: admit encrypted video repairs within retained RTP history | S · M |
| 65 | v0.3.18 | `f2fdf8e81eeb87f06d7db1440d52cab6637b0b73` | 2026-09-05T23:54:41-05:00 | Merge pull request #131 from mrjeeves/fix/encrypted-video-repair-window | I · merge; constituent dispositions apply |
| 66 | v0.3.18 (tag target) | `13b9cdfaddc68abc026f50ad567878623d2942c5` | 2026-09-05T23:57:34-05:00 | chore(release): 0.3.18 | I · release metadata |
| 67 | v0.3.19 | `c9f8274ed2b260dd2bfa01628fba2ba52b10e69f` | 2026-09-06T13:52:30-05:00 | fix: preserve delayed RTP pictures through bounded media IPC | S · M |
| 68 | v0.3.19 | `44cb2f1ea20ab5d6923c1acd12cf29b71816d332` | 2026-09-06T13:57:45-05:00 | fix: remove unused public queue length test helper | S · M |
| 69 | v0.3.19 | `cd6268ae97827429a310e559e56a9779252faa74` | 2026-09-06T14:12:51-05:00 | Merge pull request #132 from mrjeeves/fix/frame-aware-media-ipc | I · merge; constituent dispositions apply |
| 70 | v0.3.19 (tag target) | `fca7955f9cfa0e99ebff9f7edf9299436e86ce47` | 2026-09-06T14:13:55-05:00 | chore(release): 0.3.19 | I · release metadata |
| 71 | v0.3.20 | `6e866a6f3b7abd81f11eb1bf7aca3f23ee3597a0` | 2026-09-07T09:50:45-05:00 | diag: add bounded video transport and IPC timing summaries | S · M |
| 72 | v0.3.20 | `7387806905646c0aac814b46ec9762e1c327acb9` | 2026-09-07T17:55:16-05:00 | fix(diag): keep stale RTP repairs out of current NACK bitmap | P/S · M |
| 73 | v0.3.20 | `ee4edb57db1992fe9ada14abdbc3eebb1699fcdd` | 2026-09-07T18:33:04-05:00 | diag: stage Windows backend swaps and toggle NACK history for A/B | S · M |
| 74 | v0.3.20 | `7e24d9c98b713af5c69211365647514cd5f6de0e` | 2026-09-07T18:46:32-05:00 | diag: fix Windows readiness exit code and allow saved-slot retry | S · M |
| 75 | v0.3.20 | `aa586260281ee961b5cfa27c6265a4e8fb18d6bb` | 2026-09-07T19:32:12-05:00 | Align local video handoff with bounded RTP repair releases | S · M |
| 76 | v0.3.20 | `bdf40596ad37276efc5bf32897e10182564ffc65` | 2026-09-08T15:16:19-05:00 | Test bounded repair releases through a busy media pipe | S/I · M |
| 77 | v0.3.20 | `f068625918c0d1c05491fb598bb246fa0cda6484` | 2026-09-08T15:24:20-05:00 | Preserve paced pictures across engine video fanout | S · M |
| 78 | v0.3.20 | `129e4348261deb710c17c59ee9e4d03f8c413cc7` | 2026-09-08T15:42:43-05:00 | Retain NACK repair history across frame-budget bursts | S/I · M |
| 79 | v0.3.20 | `9aba800cb7901ba8a7933a2b42dba1a048c7c863` | 2026-09-08T16:09:48-05:00 | Coalesce in-flight RTP repairs and skip stale feedback ticks | P/S · M |
| 80 | v0.3.20 | `c8d314e1f1bff5341a55b1234812e5f4cd81315b` | 2026-09-08T16:57:59-05:00 | Fix media UDP receive admission below permitted burst size | S · M |
| 81 | v0.3.20 | `4a483c97712dd656e029dbefbe67ec532249dfa5` | 2026-09-08T17:17:31-05:00 | Locate remaining packet admission loss with bounded detailed diagnostics | S · M |
| 82 | v0.3.20 | `bedadba16246924899afb4f16720d6d9dd454b41` | 2026-09-08T17:41:32-05:00 | Exercise receive admission diagnostics under production log filters | S · M |
| 83 | v0.3.20 | `dd79dcd6687aed1b75174b0b30f1711153ac7465` | 2026-09-08T18:21:02-05:00 | Record live socket fix results and remaining pre-receiver packet loss | I · M |
| 84 | v0.3.20 | `a8e0dcfe264b6aa338095e1fc0e72cc3e6972836` | 2026-09-08T20:05:52-05:00 | Document awake paired capture and remaining validation limits | I · M |
| 85 | v0.3.20 | `c1a27d3d644b83dc25306e868eb96f05da6603a6` | 2026-09-08T20:46:29-05:00 | Merge pull request #133 from mrjeeves/diag/video-handoff-timing | I · merge; constituent dispositions apply |
| 86 | v0.3.20 (tag target) | `ccdec687d030edb6db23428ae99e80412a22d75b` | 2026-09-08T20:49:54-05:00 | chore(release): 0.3.20 | I · release metadata |
| 87 | v0.3.21 | `381b465bafc14e724f6bd39e64270b80696b23d0` | 2026-09-09T10:31:35-05:00 | Fix late paced-sample admission and preserve repair deadlines | S · M |
| 88 | v0.3.21 | `cbf3f59c2e02cb2a599671be31e131b95591dc60` | 2026-09-09T13:02:57-05:00 | Count admitted RTP media as transport liveness | S · M |
| 89 | v0.3.21 | `f93b928a54505e79280f89f4352df827471f86e0` | 2026-09-09T16:28:30-05:00 | Share mDNS discovery and keep cache loss separate from transport leave | P/S · A7 |
| 90 | v0.3.21 | `cf89e653c9e6d1fac79dfc54606ad3f0abf2e82e` | 2026-09-09T16:40:28-05:00 | Test advisory mDNS withdrawal without losing the live exchange | S · A7 |
| 91 | v0.3.21 | `3b37a5d84305d7ce7af46153d9692d19fc50777d` | 2026-09-09T16:54:58-05:00 | Merge pull request #134 from mrjeeves/fix/paced-video-late-sample-repair | I · merge; constituent dispositions apply |
| 92 | v0.3.21 (tag target) | `59143cbdb094b6b99464c224a500e148fd7d2113` | 2026-09-09T17:04:55-05:00 | chore(release): 0.3.21 | I · release metadata |

## Exact TURN tranche and transport distinctions

The nine commits below span the v0.3.4, v0.3.5 and v0.3.6 release groups.
Their full patches, not their titles alone, establish the behavior inventory.

| Commit | Upstream behavior | Pre-port disposition and restoration group |
| --- | --- | --- |
| `5c41aaa4cfc5c982cf14f310f31cf448e2e12339` | Bound systemd log volume; disable noisy dependency TURN-server target while retaining own startup/client errors. | P, T7; do not mistake this for the stream implementation. |
| `8c0d23473aad191f66e0f21bf54a2f4841361f6d` | Client stream adapters, server TCP front end, config/defaults, Caddy Layer 4 TLS and deployment integration. | R, T1–T6; both adapters and associated executable wiring were omitted. |
| `15c0733087e1f3cd0f1f569cfde06dc7588fd566` | Idle expiry/reset and cancellation in the server's TCP client loop. | R, T2; must compose with retained parsing progress and joined child ownership. |
| `afcbd49cb8797085636579d46f3ccc92118d5368` | GUI `tcp_enabled` plus UDP allocation range settings. | P/R, T3; relay range survived, TCP toggle did not. |
| `495573edaba4580e916f4c583683240bec318850` | Real authenticated TURN allocation and bidirectional UDP relay through a TCP listener. | R, T8; test source is not a current executed result. |
| `f818fe89cda54063c9320e3232b5dc1e754be6a0` | Report actual control/allocation ports and external-provider firewall requirements. | P/R, T6; generic provider/UDP guidance retained, TCP/TLS installer guidance needs restoration. Provider UI prose remains historical. |
| `31058c53982b1a0d2bd7eb5a2ae10f094ece6605` | Skip unchanged/running Caddy reload; bounded reload/restart attempts and rollback-related workflow. | R, T6; adapt to current configuration transactions and truthful partial-failure reporting. |
| `4f3ebaad2a391af0a2ebf8aa30d2ab3132299332` | Upgrade only the exact legacy reference TURN entry; preserve custom entries and explicit opt-outs. | R, T4; old upstream config-version migration cannot bypass V4 bootstrap/config admission. |
| `f7d20283cab17e7709ab2a525a8650a8e596eb39` | 0.3.6 metadata, repetitive diagnostics changes, Windows opt-in/early-return socket tests. | P/S/I, T9; do not restore old governance state or count early returns as successful live tests. |

### What the feature does — and does not do

The captured upstream adapters implement this intended layering (the selected
V4 proxy/backend change is specified separately in T10):

```text
endpoint WebRTC/TURN client
  -> local owned UDP adapter -> TCP or TLS connection
  -> [TLS termination in Caddy, when configured]
  -> native TCP TURN front end -> existing UDP TURN allocation engine
  -> UDP allocated relay socket -> peer
```

1. **Client-to-server TCP/TLS is not TCP peer allocation.** The stream carries TURN
   control and ChannelData between a client and its TURN server. The server keeps
   its existing UDP allocations/permissions/channel bindings and UDP peer-facing
   relay sockets. This does not implement RFC 6062 TCP allocations.
2. **Caddy TLS termination is distinct from the native TCP bridge.** The upstream
   Caddy Layer 4 route terminates TLS for the TURN hostname and forwards plain TCP
   to the local bridge. The native bridge itself does not load a TLS certificate.
   HTTPS/WSS signaling proxy support alone is not TURN TLS support.
3. **Parser acceptance is not runtime support.** In the pre-port V4,
   [build_rtc_configuration](../crates/myownmesh-core/src/transport/ice.rs) passes
   TURN URLs through. The vendored ICE URL parser recognizes TCP/`turns:`, but
   [agent_gather.rs](../vendor/webrtc-ice-0.13.0/src/agent/agent_gather.rs)'s relay
   branch only handles UDP `turn:`; the other cases are TODO and return without
   a relay candidate. A deserialized URL or advertised service cannot establish
   working TCP/TLS gathering. Earlier broad “configured standard TURN” wording
   must therefore be read with this implementation limit.
4. **A URL list is not a proven ordered failover algorithm.** Restoring UDP, TCP
   and TLS URLs supplies choices; candidate gathering/selection and any bounded
   fallback behavior need runtime evidence.
5. **Hubs never relay application packets.** Hubs remain discovery/introduction
   and bounded setup/control services. Endpoint-authenticated WebRTC carries
   application data over direct ICE or configured standard TURN. Co-hosting TURN
   on a Hub machine does not make Hub control messages an application tunnel.
6. **Credentials and authority are unchanged.** TURN authentication remains
   configured long-term credentials. Service advertisements are not protected
   credential distribution. Neither Nostr signatures, TURN credentials nor Hub
   discovery grant Closed-network membership or replace endpoint authentication.
7. **Successful allocation is weaker than successful delivery.** Both the host
   firewall and provider security group must permit the configured UDP relay
   range. TCP control or a TLS handshake can succeed while peer-facing UDP is
   blocked. No new firewall change is performed or authorized by this inventory.

### Required V4 adaptation, not a verbatim upstream copy

The captured client source owns an endpoint map and spawns per-client tasks;
the captured server retains its accept-loop handle but spawns child connections
without retaining their join handles. The client also stores a top-level handle
without an explicit complete shutdown barrier. These are reasons to adapt the
feature to V4's existing exact-owner/custody/resource boundaries, not to import
new unbounded maps or detach child work.

Both captured modules call a multi-read framing future inside `select!`.
A competing branch can cancel that future after a partial read. Restoration must
retain parser progress or use an appropriately owned reader, including split
headers, split payloads and padded ChannelData. Socket closure, EOF, failure,
idle expiry, cancellation and shutdown must retain exact ownership through join.
Admission must fund retained endpoints, clients, queues, frames, sockets and
tasks before publication; the old per-queue capacity is not an aggregate budget.
Do not invent new blanket resource grants or turn an upstream ten-minute idle
constant into a demonstrated V4 lifetime bound.

The historical client module tests URL recognition and a plain TCP frame echo.
The server module tests STUN/ChannelData framing; the later service test performs
a real authenticated allocation and bidirectional relay. None alone proves TLS
certificate verification, selected WebRTC relay candidates, bounded overload,
cancellation-safe framing, full cleanup, cloud reachability or throughput.
All restoration tests remain unqualified in this document until the final matrix
is bound to a successor's actual executions.

## TURN tranche: exhaustive file-by-file restoration map

Every path touched by the nine TURN commits is listed here, including their
non-TURN/version side effects. The last column names evidence to retain, not
tests claimed to have passed. Links refer to maintained paths; new stream paths
are named as restoration targets while their upstream versions are in the
capture packet.


| File | Group | Upstream behavior | Pre-port state/omission | V4 adaptation/action | Required controls and limitation |
| --- | --- | --- | --- | --- | --- |
| `Cargo.toml` | T1/T2/T9 | Adds TLS client dependencies; later 0.3.6 version bump. | Stream wiring omitted; V4 stays 1.0.0. | Add only reviewed dependencies/features needed by owned adapters; preserve release profile. | Locked dependency review and ordinary/feature builds; no dependency bump inferred. |
| `Cargo.lock` | T1/T2/T9 | Resolves stream dependencies and release metadata. | Pre-port root graph is V4, not upstream's whole lock. | Resolve the approved adapter graph without restoring unrelated media patches. | Exact lock/source/binary custody; a lock entry alone is not reachable behavior. |
| `README.md` | T5/T6 | Promotes combined WSS/TURN installer behavior. | Current installer text is signal-only. | Describe only frozen restored behavior, separate setup from payload. | CLI/docs parity; do not promise cloud deployment from local tests. |
| `crates/myownmesh-core/Cargo.toml` | T1 | Adds rustls/tokio-rustls/webpki-roots client dependencies. | No upstream client stream module integration. | Funded native adapter dependencies only. | Ordinary and transport-lab compile coverage; TLS runtime separate. |
| `crates/myownmesh-core/src/config.rs` | T3/T4 | Three reference URLs, tcp_enabled default false; exact legacy-entry migration. | Pre-port single UDP default/no TCP flag; V4 rejects unsupported config versions. | Restore explicit transport fields/defaults and narrow default migration under V4 admission; preserve custom URLs/credentials and []. | Default/opt-out/custom/idempotence/rejection controls; never import old schema migration wholesale. |
| `crates/myownmesh-core/src/transport/mod.rs` | T1 | Declares client stream module. | Module absent. | Register only the new owned adapter. | Module visibility/feature boundary; no lab dependency in ordinary API. |
| `crates/myownmesh-core/src/transport/turn_stream.rs` | T1 | UDP facade to persistent TCP/TLS TURN streams, URL parsing, framing and per-client queues. | Upstream file excluded. | Bounded owner-scoped endpoints and clients, checked TLS, retained parser state, joined shutdown. | URL negatives, framing split/concat/padding, pressure and exact cleanup; original plain echo does not prove TLS. |
| `crates/myownmesh-core/src/transport/webrtc.rs` | T1/T9 | Rewrites TURN servers before peer creation; retains bridges; later Windows test opt-in. | No upstream rewrite; V4 exact native-session ownership retained. | Integrate before gather with failure/retirement custody; keep peer identity/profile unchanged. | Selected relay candidate + byte-equal endpoint exchange; no early-return PASS. |
| `crates/myownmesh-services/Cargo.toml` | T2 | Enables cancellation support for bridge lifecycle. | Pre-port service has V4 owned cleanup dependencies. | Use existing service runtime/custody and reviewed dependency graph. | Compile and finite lifecycle tests; no extra owner thread assumed necessary. |
| `crates/myownmesh-services/src/lib.rs` | T2 | Declares TCP bridge module. | Module absent. | Expose only service-internal owned bridge seam. | Service API/owner review; no standalone unowned accept loop. |
| `crates/myownmesh-services/src/turn.rs` | T2/T8 | Starts/stops optional TCP bridge; Binding and authenticated allocation/relay tests. | UDP service and native owned cleanup retained; TCP absent. | Integrate startup rollback, accept/child joins and existing allocation engine; preserve budgets. | Port Binding and allocation/data/return tests plus cleanup/rollback negatives. |
| `crates/myownmesh-services/src/turn_stream.rs` | T2/T8 | TCP listener, one connected UDP socket/client, STUN and padded ChannelData framing, idle expiry. | Upstream file excluded. | Fund accepted clients/frames, retain parser progress and exact task joins; apply T10 trusted-proxy boundary. | Framing, EOF/partial/oversize, idle/cancel, admission, socket reuse; TCP control is not TCP peer allocation. |
| `crates/myownmesh/README.md` | T5/T6/T7 | Service log cap, client URL examples and combined installer description. | Log guidance retained; stream workflow omitted. | Keep log behavior; restore truthful transport/setup examples after code freeze. | Doc/CLI parity; preserve updater and 1.0 policy. |
| `crates/myownmesh/src/cli/caddy.rs` | T5/T6/T10 | Layer 4 module, TURN-domain/public-IP options, managed blocks, service apply, firewall and convergence. | Signal-only WSS installer; no TURN Layer 4 workflow. | Preserve operator blocks, checked transactions, truthful reload/rollback; planned distinct trusted loopback PROXYv2 backend. | Render/idempotence/rollback/failure controls then actual Caddy validation; no deploy claim. |
| `crates/myownmesh/src/cli/ctl.rs` | T5/T6 | Live ServicesConfig apply and UDP/TCP firewall help. | Current service apply exists; TCP-related arguments/guidance absent. | Carry new config without overwriting unrelated service settings; accurate direct/proxy mode help. | Round-trip and refused-apply controls; saved config is not running service. |
| `crates/myownmesh/src/cli/service.rs` | T7 | SyslogIdentifier and 100 records/5min systemd rate cap. | Preserved. | No TURN-restoration logic change required. | Existing systemd rendering controls; not a proof against every log source. |
| `crates/myownmesh/src/main.rs` | T7 | Narrow dependency turn::server log suppression. | Preserved; own startup errors remain visible. | Retain current filter, do not suppress service failures. | Filter/source parity; no new log-volume benchmark claim. |
| `docs/DEBUGGING-CONNECTIONS.md` | T7 | Explains default filter and opt-in dependency diagnostics. | Scoped log guidance retained. | Preserve historical diagnosis and current failure visibility. | Documentation review; log silence is not healthy transport. |
| `docs/SERVICES.md` | T5/T6 | TCP/TLS path, firewall/cloud ranges, JSON examples and deployment guidance. | Explicitly documents TCP/TLS unsupported at pre-port baseline. | Replace omission only after restoration source freeze; distinguish Caddy, bridge and peer UDP; T10 modes. | Source-linked docs + separately retained actual setup; provider UI details need current verification before use. |
| `gui/src/types.ts` | T3 | tcp_enabled and relay port range shape. | Range retained; TCP flag omitted. | Match frozen Rust service config, including approved proxy-mode fields if exposed. | Type/wire parity; TS field alone is not a running service. |
| `gui/src/ui/settings/ServicesSection.svelte` | T3 | TCP toggle and relay-range form fields. | Range UI retained; TCP toggle omitted. | Expose explicit modes without silently enabling direct plaintext on TLS-only install. | UI serialization/apply smoke; no credential-distribution claim. |
| `crates/myownmesh-core/src/engine/governance.rs` | T9/A6 | Stable old zero-transition Open/Silent drift suppression. | Old governance model superseded. | Do not restore legacy drift map/projection; retain canonical V4 semantics. | Existing canonical policy controls; unrelated to TCP restoration. |
| `crates/myownmesh-core/src/engine/mod.rs` | T9/A4 | Lowers repetitive recovery-probe preamble logging. | Current exact-owner/recovery behavior governs. | Preserve useful diagnostic intent without importing old recovery authority. | Owner-fence/recovery controls; not TURN stream implementation. |
| `crates/myownmesh-core/src/engine/state.rs` | T9/A6 | Adds legacy stable-governance-drift HashSet. | Excluded in favor of current canonical/funded state. | No unbounded per-peer diagnostic history restoration. | State/resource audit; no new map merely for parity. |
| `crates/myownmesh-signaling/tests/mdns_driver.rs` | T9/A7 | Windows live-LAN early-return opt-in. | V4 test and discovery ownership retained. | No blanket skipped-native-test restoration; record actual execution/skip separately. | Existing mDNS controls; no LAN or TURN PASS from early return. |
| `gui/package.json` | T9 | Version 0.3.6 metadata. | Superseded by 1.0.0. | No version rollback. | Release-version consistency only. |
| `gui/src-tauri/Cargo.lock` | T9 | GUI release version resolution. | V4 lock graph retained. | Only reviewed dependency resolution; no old lock transplant. | Exact frozen lock custody. |
| `gui/src-tauri/Cargo.toml` | T9 | GUI package version 0.3.6. | Superseded by 1.0.0. | No version rollback. | Release-version consistency only. |

## Later upstream changes: what is already integrated or superseded

### A1 — logging, CI and release documentation

Baseline quiet logging and systemd log limits were retained. CI trigger
deduplication was integrated alongside V4's explicit test gates. Version bumps,
dependency-copy examples and merge bookkeeping are historical metadata, not
instructions to downgrade 1.0.0 or claim the old releases' qualification.
Applicable source paths and every historical net path are enumerated below.

### A2 — handshake and public identity

The one-sided-approve defect's safety intent is preserved by current authenticated
owner/session gates, not by reviving the old roster fixture. Public display-ID
normalization and suffix verification were integrated at public lookup/connect
boundaries. Canonical semantic wire identities remain strict. Source custody does
not replace the existing endpoint authentication/replacement controls.

### A3 — listen-only preference

The upstream `listen_only` flag and its tests were not imported. V4 Silent,
manual connect, sticky reconnect and inbound behavior remain. They are not claimed
to be a drop-in implementation of the upstream “subscribe but never announce”
flag. This absence is deliberate and outside the selected TURN restoration;
the matrix keeps it visible rather than implying full feature preservation.

### A4 — endpoint discovery, recovery and liveness

Selected public-ID/STUN-address/virtual-interface corrections and full-owner
stale-heartbeat retirement were integrated. Upstream fixed retry/backoff policies,
64-socket pressure mechanisms and older recovery state were deliberately
superseded by current bounded owner-specific mechanisms. This is a behavior
disposition, not an assertion that the scheduling is physically identical.
The later Video/Audio `last_recv_at` refresh was not translated into V4's nested
session/peer locks; no new media-as-liveness behavior is claimed.

### A5 — Nostr integrity and relay admission

Signed event verification, room/body consistency, exact subscription EOSE
readiness, balanced live counts, stable-admission backoff and room/relay jitter
were selectively integrated while preserving V4 pre-parse leases, downstream
acceptance-scoped deduplication and sender-claimed attribution. Arbitrary XFF
trust was not imported. A relay's signed presence/departure does not authenticate
the named Mesh endpoint. The later synthetic-leave recipient and external
accounting-fixture corrections have their own evidence; they do not change the
original upstream commit subjects or make the full upstream patch unmodified.

### A6 — governance and durable projection

The v0.3.10–v0.3.11 two-log/roster projection repairs and f7d2028's stable-drift map
were superseded by canonical FactGraph admission, typed policy, funded durable
projection and exact-owner fences. Their important authorization/persistence
intent is not a license to restore obsolete storage, V3 wire, implicit Open
durability or roster-based authority. Existing V4 canonical controls, not old
roster compatibility fixtures, are the qualification boundary.

### M — v0.3.12–v0.3.21 media, replay and diagnostic work

The later media sequence is fully present in the 92-row history but not preserved
wholesale in the code. Removed V3 VideoSample/AudioSample/media-lane APIs, engine
video fanout, picture-aware IPC queues, RTP replay/history expansion, new repair
workers, socket-buffer retuning and ordinary diagnostic/A-B hooks remain excluded.
Current generic endpoint data/RPC/opaque and typed realtime flows are not evidence
that each old media scheduling behavior was ported.

Three narrow interceptor corrections remain: reject stale generator bitmap aliases,
validate exact responder ring-slot sequence, and skip missed generator timer ticks.
See [the scoped vendor patch](../vendor/interceptor/MYOWNMESH-PATCH.md).
The larger NACK history/max-feedback/worker and new webrtc-util socket-buffer patch
were not imported. Named controls include
`stale_repair_does_not_acknowledge_newer_ring_alias` and
`retained_slot_must_match_exact_requested_sequence`; their existence or CI command
is not proof of current runtime execution.

Upstream investigation documents (encrypted repair, frame budget, picture-aware
handoff, UDP admission, media liveness and discovery departure) were retained with
historical/V4-disposition labels. Old live captures, failures and synthetic reports
must not be rewritten as current performance evidence. The TURN restoration does
not reopen these excluded media frameworks or invent new loss/FPS guarantees.

### A7 — mDNS singleton versus advisory withdrawal

The upstream f93b928 tranche combined shared-daemon lifetime with separation of
cache loss from transport departure; cf89e65 added a companion live-exchange test.
V4 preserved its bounded per-driver cache/queue/task custody and exact
alias/incarnation handling instead of importing the process-shared singleton.
V4's attribution boundary already separates a sender-claimed advertisement from
an authenticated transport owner: disappearance cannot become authority simply
because a carrier observed it. This is the retained safety intent, **not** an
assertion that the upstream singleton, physical schedule or companion test was
ported. The historical integration records mark the three mDNS source/test files
V4-exact. Existing V4 mDNS/native controls must supply any runtime claim.

## Deliberate security adaptations beyond upstream

These manager-selected restoration requirements are **implemented and locally
tested** under the source binding and run records in final rows T10–T11 below.
**Independent final audit remains pending; local PASS does not close that gate.**

- **T10 — trusted proxy admission:** managed Caddy TLS is configured to send
  PROXYv2 to a distinct **loopback-only backend port 3479**, allowing bridge quotas
  to use the original client IP. Public direct TCP rejects PROXY headers, and
  TLS-only configuration leaves public plaintext direct TCP disabled. This
  replaces the upstream same-control-port backend plan; it does not generalize
  trust to arbitrary loopback callers, XFF headers or Internet senders.
  Workspace `922b6658` passed all 16 service TCP/TLS controls, including original-IP
  quotas, direct-PROXY spoof and missing-header refusal, proxy-only mode and
  authenticated TLS/proxy UDP relay. Caddy `8ab78917` passed 14/14 rendering and
  installer controls. The local test TLS front end is not deployed Caddy,
  ACME, firewall or cloud evidence; loopback is not process identity.
  Native forced TLS and RFC 6062 TCP peer allocation are not proven.
- **T11 — nonce retention:** abandoned per-challenge retained nonce accumulation
  is replaced with **one reusable live nonce**, plus expiry sweep/release, in
  `vendor/turn-0.10.0/src/server/request.rs` and server-owned nonce state/lifecycle.
  Full vendor TURN `ed6bc516` passed 70/70 controls, including abandoned/concurrent
  challenge reuse, legitimate authentication, expiry/stale replacement and
  close/drop lease release. This is a locally tested resource correction, not a
  larger nonce quota or authentication bypass. Independent final review of nonce
  authorization, retention and terminal cleanup remains pending; these local
  results do not establish deployment or physical-network qualification.

These extra V4 adaptations are additional action rows, not fictitious upstream
commits. They do not alter any tag/release metadata above or retroactively change
the pre-port file census.


## Exhaustive net-path disposition appendix

This appendix lists each of the **173 net changed paths exactly once**. `A` and
`M` are upstream added/modified status over the captured range, not actions taken
by this document. The historical relationship column is copied from the original
resolved-merge blob census (relative to upstream and the then-V4 parent); later
fixes and the current restoration can change those bytes. It is **not** a current
hash attestation. The action column applies this ledger's current source disposition;
TURN behavior and tests are detailed in the 28-path table above. Stock vendor files
are enumerated to make the inventory exhaustive, not to imply 173 separate features.
The excluded upstream `vendor/webrtc-util` tree is not a claim that the dependency
library itself is absent from V4's dependency graph.

| Net upstream path | Change | Historical merge relationship | Current disposition/action group |
| --- | --- | --- | --- |
| `.github/workflows/ci.yml` | M | adapted | P A1: applicable CI/release trigger corrections |
| `.github/workflows/release.yml` | M | adapted | P A1: applicable CI/release trigger corrections |
| `Cargo.lock` | M | adapted | R T1/T2 dependency resolution; S old lock transplant (T9/M) |
| `Cargo.toml` | M | adapted | R T1/T2 dependencies; S old versions/media graph (T9/M) |
| `README.md` | M | v4-exact | R T5/T6; preserve A1 version/API boundaries |
| `crates/myownmesh-core/Cargo.toml` | M | v4-exact | R T1 |
| `crates/myownmesh-core/README.md` | M | v4-exact | P/S A1: current V4 docs/version policy retained |
| `crates/myownmesh-core/src/config.rs` | M | v4-exact | R T3/T4; S A3 listen-only flag |
| `crates/myownmesh-core/src/engine/connection.rs` | M | v4-exact | S A4: V4 exact-owner recovery/wake retained |
| `crates/myownmesh-core/src/engine/governance.rs` | M | v4-exact | S T9/A6 old drift map and roster |
| `crates/myownmesh-core/src/engine/handshake.rs` | M | v4-exact | P/S A2: V4 authenticated-owner gates |
| `crates/myownmesh-core/src/engine/heartbeat.rs` | M | adapted | P/S A4: selected corrections; V4 limits retained |
| `crates/myownmesh-core/src/engine/ice_watchdog.rs` | M | v4-exact | S A4: V4 exact-owner recovery/wake retained |
| `crates/myownmesh-core/src/engine/mod.rs` | M | v4-exact | P/S T9/A4; S M legacy media |
| `crates/myownmesh-core/src/engine/network_watch.rs` | M | adapted | P/S A4: selected corrections; V4 limits retained |
| `crates/myownmesh-core/src/engine/scheduler.rs` | M | v4-exact | S A4: V4 exact-owner recovery/wake retained |
| `crates/myownmesh-core/src/engine/signaling_bridge.rs` | M | v4-exact | S A3/A4: V4 accounted ingress and selection retained |
| `crates/myownmesh-core/src/engine/state.rs` | M | v4-exact | S T9/A6/A4 legacy state |
| `crates/myownmesh-core/src/engine/video_fanout.rs` | A | excluded | S M: no retired V3 media/replay/handoff restoration |
| `crates/myownmesh-core/src/engine/wake.rs` | M | v4-exact | S A4: V4 exact-owner recovery/wake retained |
| `crates/myownmesh-core/src/handle.rs` | M | adapted | P A2: public IDs; preserve typed V4 API |
| `crates/myownmesh-core/src/identity.rs` | M | adapted | P A2: public IDs; preserve typed V4 API |
| `crates/myownmesh-core/src/lib.rs` | M | adapted | P A2: public IDs; preserve typed V4 API |
| `crates/myownmesh-core/src/signing.rs` | M | adapted | P A2: public IDs; preserve typed V4 API |
| `crates/myownmesh-core/src/transport/mod.rs` | M | v4-exact | R T1; S M legacy media modules |
| `crates/myownmesh-core/src/transport/nack_history_tests.rs` | A | excluded | S M: no retired V3 media/replay/handoff restoration |
| `crates/myownmesh-core/src/transport/rtp_replay.rs` | A | excluded | S M: no retired V3 media/replay/handoff restoration |
| `crates/myownmesh-core/src/transport/turn_stream.rs` | A | excluded | R T1 |
| `crates/myownmesh-core/src/transport/udp_socket.rs` | A | excluded | S M: no retired V3 media/replay/handoff restoration |
| `crates/myownmesh-core/src/transport/webrtc.rs` | M | v4-exact | R T1; S M legacy media scheduling; preserve T9 execution honesty |
| `crates/myownmesh-core/tests/closed_network_governance.rs` | M | v4-exact | S A2/A6: canonical V4 authority; old roster tests excluded |
| `crates/myownmesh-core/tests/listen_only.rs` | A | excluded | S A3: upstream listen-only remains absent |
| `crates/myownmesh-core/tests/one_sided_roster.rs` | A | excluded | S A2/A6: canonical V4 authority; old roster tests excluded |
| `crates/myownmesh-services/Cargo.toml` | M | v4-exact | R T2 |
| `crates/myownmesh-services/src/lib.rs` | M | v4-exact | R T2 |
| `crates/myownmesh-services/src/turn.rs` | M | v4-exact | R T2/T8 |
| `crates/myownmesh-services/src/turn_stream.rs` | A | excluded | R T2/T8 |
| `crates/myownmesh-signaling/README.md` | M | v4-exact | P/S A1: current V4 docs/version policy retained |
| `crates/myownmesh-signaling/src/lib.rs` | M | adapted | P A5 borrowed ID accessor; preserve strict wire |
| `crates/myownmesh-signaling/src/local.rs` | M | v4-exact | P/S A3/A5: carrier sender binding retained; no listen-only |
| `crates/myownmesh-signaling/src/mdns/discovery/embedded.rs` | M | v4-exact | S A7: bounded V4 per-driver lifecycle retained |
| `crates/myownmesh-signaling/src/mdns/driver.rs` | M | v4-exact | S A7: bounded V4 per-driver lifecycle retained |
| `crates/myownmesh-signaling/src/nostr/driver.rs` | M | adapted | P/S A5: integrity/EOSE/admission port, V4 custody retained |
| `crates/myownmesh-signaling/src/server.rs` | M | v4-exact | S A5: unproven XFF trust omitted; retain funded admission |
| `crates/myownmesh-signaling/tests/mdns_driver.rs` | M | v4-exact | S T9/A7 upstream scheduling/early-return; retain V4 controls |
| `crates/myownmesh-signaling/tests/signaling_server.rs` | M | v4-exact | S A5: unproven XFF trust omitted; retain funded admission |
| `crates/myownmesh-updater/README.md` | M | v4-exact | P/S A1: current V4 docs/version policy retained |
| `crates/myownmesh/Cargo.toml` | M | v4-exact | S/I M: ordinary diagnostic target/script excluded |
| `crates/myownmesh/README.md` | M | adapted | P T7; R T5/T6 |
| `crates/myownmesh/src/cli/caddy.rs` | M | v4-exact | R T5/T6/T10 |
| `crates/myownmesh/src/cli/ctl.rs` | M | v4-exact | R T5/T6 |
| `crates/myownmesh/src/cli/service.rs` | M | adapted | P T7; R T5 only where restored installer wiring requires it |
| `crates/myownmesh/src/control.rs` | M | v4-exact | S M: no retired V3 media/replay/handoff restoration |
| `crates/myownmesh/src/ipc/bridge.rs` | M | v4-exact | S M: no retired V3 media/replay/handoff restoration |
| `crates/myownmesh/src/ipc/clients.rs` | M | v4-exact | S M: no retired V3 media/replay/handoff restoration |
| `crates/myownmesh/src/ipc/media_queue.rs` | A | excluded | S M: no retired V3 media/replay/handoff restoration |
| `crates/myownmesh/src/ipc/mod.rs` | M | v4-exact | S M: no retired V3 media/replay/handoff restoration |
| `crates/myownmesh/src/main.rs` | M | adapted | P T7 |
| `docs/DEBUGGING-CONNECTIONS.md` | M | adapted | P T7 |
| `docs/NETWORK-TYPES.md` | M | v4-exact | S A3: upstream listen-only remains absent |
| `docs/QUICKSTART.md` | M | v4-exact | P/S A1: current V4 docs/version policy retained |
| `docs/SERVICES.md` | M | adapted | R T5/T6 |
| `docs/discovery-departure-teardown-20260909.md` | A | adapted | I A7: historical investigation, not current runtime proof |
| `docs/encrypted-video-repair.md` | A | adapted | I M: historical investigation, not current performance proof |
| `docs/media-liveness-freeze-20260909.md` | A | adapted | I M: historical investigation, not current performance proof |
| `docs/nack-burst-repair.md` | A | adapted | I M: historical investigation, not current performance proof |
| `docs/picture-aware-receive-handoff.md` | A | adapted | I M: historical investigation, not current performance proof |
| `docs/udp-receive-admission.md` | A | adapted | I M: historical investigation, not current performance proof |
| `docs/video-recovery-frame-budget.md` | A | adapted | I M: historical investigation, not current performance proof |
| `gui/package.json` | M | v4-exact | I/S T9 old version metadata |
| `gui/src-tauri/Cargo.lock` | M | v4-exact | I/S T9 old release graph |
| `gui/src-tauri/Cargo.toml` | M | v4-exact | I/S T9 old version metadata |
| `gui/src/types.ts` | M | adapted | P relay-range; R T3 TCP/proxy shape |
| `gui/src/ui/settings/ServicesSection.svelte` | M | adapted | P relay-range; R T3 TCP/proxy UI |
| `scripts/windows-diag-cycle.ps1` | A | excluded | S/I M: ordinary diagnostic target/script excluded |
| `vendor/interceptor/Cargo.toml` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/Cargo.toml.orig` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/LICENSE-APACHE` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/LICENSE-MIT` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/MYOWNMESH-PATCH.md` | A | adapted | P/S M: scoped fixes; larger history/worker changes excluded |
| `vendor/interceptor/README.md` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/chain.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/error.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/lib.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/mock/mock_builder.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/mock/mock_interceptor.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/mock/mock_stream.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/mock/mock_time.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/mock/mod.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/nack/generator/generator_stream.rs` | A | adapted | P/S M: scoped fixes; larger history/worker changes excluded |
| `vendor/interceptor/src/nack/generator/generator_test.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/nack/generator/mod.rs` | A | adapted | P/S M: scoped fixes; larger history/worker changes excluded |
| `vendor/interceptor/src/nack/mod.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/nack/responder/mod.rs` | A | adapted | P/S M: scoped fixes; larger history/worker changes excluded |
| `vendor/interceptor/src/nack/responder/responder_stream.rs` | A | adapted | P/S M: scoped fixes; larger history/worker changes excluded |
| `vendor/interceptor/src/nack/responder/responder_test.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/noop.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/registry.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/report/mod.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/report/receiver/mod.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/report/receiver/receiver_stream.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/report/receiver/receiver_test.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/report/sender/mod.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/report/sender/sender_stream.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/report/sender/sender_test.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/stats/interceptor.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/stats/mod.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/stream_info.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/stream_reader.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/twcc/mod.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/twcc/receiver/mod.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/twcc/receiver/receiver_stream.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/twcc/receiver/receiver_test.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/twcc/sender/mod.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/twcc/sender/sender_stream.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/twcc/sender/sender_test.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/interceptor/src/twcc/twcc_test.rs` | A | upstream-exact | P M: stock 0.14.0 support for three scoped fixes |
| `vendor/webrtc-util/.cargo_vcs_info.json` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/.gitignore` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/CHANGELOG.md` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/Cargo.toml` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/Cargo.toml.orig` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/LICENSE-APACHE` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/LICENSE-MIT` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/MYOWNMESH-PATCH.md` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/README.md` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/benches/bench.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/codecov.yml` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/doc/webrtc.rs.png` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/examples/display-interfaces.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/buffer/buffer_test.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/buffer/mod.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/conn/conn_bridge.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/conn/conn_bridge_test.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/conn/conn_disconnected_packet.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/conn/conn_pipe.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/conn/conn_pipe_test.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/conn/conn_test.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/conn/conn_udp.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/conn/conn_udp_listener.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/conn/conn_udp_listener_test.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/conn/mod.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/error.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/fixed_big_int/fixed_big_int_test.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/fixed_big_int/mod.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/ifaces/ffi/mod.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/ifaces/ffi/unix/mod.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/ifaces/ffi/windows/mod.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/ifaces/mod.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/lib.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/marshal/exact_size_buf.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/marshal/mod.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/replay_detector/mod.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/replay_detector/replay_detector_test.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/sync/mod.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/vnet/chunk.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/vnet/chunk/chunk_test.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/vnet/chunk_queue.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/vnet/chunk_queue/chunk_queue_test.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/vnet/conn.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/vnet/conn/conn_test.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/vnet/conn_map.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/vnet/conn_map/conn_map_test.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/vnet/interface.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/vnet/mod.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/vnet/nat.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/vnet/nat/nat_test.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/vnet/net.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/vnet/net/net_test.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/vnet/resolver.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/vnet/resolver/resolver_test.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/vnet/router.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |
| `vendor/webrtc-util/src/vnet/router/router_test.rs` | A | excluded | S M: upstream vendored socket-buffer tree excluded |

## Final action and qualification matrix

Every commit classification and net-path action resolves to a row below.
**Source disposition** describes what was selected or retained, not a completed
runtime qualification. Bracketed cells are deliberately unfilled evidence slots.
They require the responsible owner's frozen successor commit/tree and source
hashes, actual test selectors/run IDs/results, and separate verifier/auditor
findings. This inventory neither duplicates those owners' implementation nor
certifies its own correctness.

| Group | Exhaustive action/tranche | Implementation status / required frozen source | Test status / required evidence | Independent audit status |
| --- | --- | --- | --- | --- |
| A1 | Retain quiet logging, CI/release trigger corrections and 1.0.0 policy; historical release bumps/merges require no rollback. | P/I source disposition recorded; [final candidate custody pending]. | [Final CI/release/log-render evidence link pending]; no old release implies current PASS. | [Final source/runtime review link pending]. |
| A2 | Retain applicable public-ID corrections and canonical authenticated-owner handshake behavior; no old one-sided roster authority. | P/S source disposition recorded; [final candidate custody pending]. | [Public-ID, handshake, owner replacement/admission controls link pending]. | [Identity/authority review link pending]. |
| A3 | Do not import listen_only; disclose absence and preserve Silent/manual/sticky/inbound semantics. | S deliberate exclusion; no restoration selected. | [Current Silent/explicit/sticky regression evidence link pending]; no upstream listen-only equivalence claim. | [Disposition/absence review link pending]. |
| A4 | Preserve selected STUN/interface/heartbeat corrections and V4 bounded exact-owner recovery; exclude 64-socket/backoff and legacy media-liveness rewrites. | P/S source disposition recorded; [final candidate custody pending]. | [Recovery, exact retirement, STUN parser and lifetime controls link pending]. | [Owner/resource-boundary review link pending]. |
| A5 | Keep Nostr signature/room/from/EOSE and stable-admission corrections with funded custody; retain SenderClaimed; do not trust arbitrary XFF. | P/S source disposition recorded; later signed Leave/fixture correction tracked separately. | [Final signaling lib/external controls and exact source tuple pending]; old failures remain historical. | [Signature, attribution and admission review link pending]. |
| A6 | Keep V4 canonical graph/durable projection, typed policy and exact-owner fences instead of legacy roster/two-log/drift maps. | S old implementation; preserve current V4 source. | [Canonical policy/durability/NoOp/ownership regression evidence link pending]. | [Authority/durable-state review link pending]. |
| A7 | Keep bounded per-driver mDNS custody and advisory withdrawal/alias fences; exclude upstream singleton and unported companion scheduling test. | P/S source disposition recorded; no shared-daemon restoration selected. | [Existing V4 mDNS/native lifecycle, disappearance and attribution controls link pending]; not upstream singleton or physical-schedule equivalence. | [Carrier-versus-owner and lifecycle review link pending]. |
| M | Preserve only three scoped interceptor fixes plus stock support; exclude retired V3 media, replay/history/worker/socket retuning and ordinary diagnostic hooks; retain historical reports as historical. | P/S/I source disposition recorded; no broader media restoration selected. | [Exact stale-ring, exact-sequence and missed-tick controls link pending]; no new FPS/loss/throughput claim. | [Selective port and excluded-tree review link pending]. |
| T1 | Restore client UDP facade over TCP/TLS and WebRTC gather wiring under native owner/resource custody. | Implemented; the source used by the local runs in T1–T11 is bound to manifest `8a7b69b8a721d6f9c2d2744b16462bd986f501402468933e8c6b545bfb3331df`. This run-source binding is distinct from historical manifests and this later evidence-row edit. | Local Windows PASS: fmt `9a888f35`, workspace/all-targets locked check `9004b9af`; workspace `922b6658` and core transport-lab `c595036c` each passed all 16 client stream controls and `turn_stream_exact_connector_failed_open_joins_endpoint_before_release`. Includes TCP/test-TLS round-trips, TLS refusal, framing, funding and cancelled-close custody. | Final independent candidate audit remains separate; these local fixtures do not prove native Linux TCP, native forced TLS, physical-network or cloud operation. |
| T2 | Restore optional TCP front end over the existing UDP TURN allocation engine, with retained framing progress and joined owned clients. | Implemented in source bound by T1; client-to-server TCP/TLS does not implement RFC 6062 TCP peer allocation. | Workspace `922b6658` PASS includes service TCP/TLS **16/16**: fragmentation/coalescing, admission/refusal, restart/rollback, authentication deadline, live-client drop, original-runtime destruction and authenticated bidirectional UDP relay. TLS coverage uses a local test TLS/proxy front end, not actual Caddy. | Ownership/framing/resource audit is separate from this execution record; no general deployment/platform or RFC 6062 proof. |
| T3 | Restore explicit service TCP/proxy configuration and GUI/Rust shape while retaining UDP range settings. | Implemented in source bound by T1; configuration schema remains version 2. | Workspace `922b6658` and core transport-lab `c595036c` PASS include all 11 `config::tests::turn_` controls: defaults/round-trip, client choices, limits, URL shapes, class capacity and proxy-only mode. This Rust evidence set does not qualify GUI check/tests/build or GUI-to-service runtime behavior. | Final config/UI/runtime parity review remains separate; parser acceptance or UI fields alone are not service-operation proof. |
| T4 | Upgrade only the exact legacy reference TURN entry in-version; preserve custom choices, opt-outs and unsupported-version refusal. | Narrow normalization in source bound by T1; no wholesale upstream v2-to-v3 migration or authority relaxation. | Workspace `922b6658` and core transport-lab `c595036c` PASS explicitly reach `exact_reference_turn_upgrade_is_in_version_and_idempotent`, alongside default-trio, custom-choice and empty-list controls. This closes the earlier focused-filter omission; earlier evidence is not rewritten. | Final migration-scope review remains separate; no custom-server/credential replacement or unsupported-schema acceptance is authorized. |
| T5 | Restore daemon service/installer integration while preserving operator configuration and Hub setup/data separation. | Implemented in source bound by T1. Hubs do not carry application payload; TURN remains a distinct service. | Caddy/installer controls `8ab78917` **14/14 PASS**, including public service transaction preservation and invalid-config refusal before side effects. No actual Caddy/ACME installation, firewall change or deployment is established by these controls. | Final installer/transaction/documentation review remains separate; no installation-success or protected credential-distribution claim. |
| T6 | Restore managed Caddy Layer 4 TLS configuration, unchanged-config convergence and accurate TCP-control/UDP-relay guidance. | Implemented in source bound by T1; T10 replaces the upstream shared-backend arrangement. | `8ab78917` **14/14 PASS** includes managed-block preservation/idempotence, certificate-site deduplication/replacement, isolated PROXYv2 rendering and unchanged-running reload avoidance. Unit/configuration evidence does not prove actual Caddy validation, ACME issuance, reload/rollback execution, provider firewall or cloud reachability. | Final TLS-termination/deployment/failure-state review remains separate; actual Caddy/ACME/firewall/cloud deployment is unproven. |
| T7 | Retain own error visibility, dependency TURN log suppression and systemd log cap. | Prior retained source disposition unchanged; no new transport behavior attributed to logging. | Fmt `9a888f35`, check `9004b9af`, ordinary strict Clippy `c4a69417`, lab strict Clippy `cb9e981c` and workspace `922b6658` PASS. Workspace includes systemd quoting, hardened-system and minimal-user rendering controls; these are not a dedicated runtime log-volume or failure-visibility qualification. | Final review for accidental failure suppression remains separate; no new logging-performance claim. |
| T8 | Restore substantive authenticated allocation/relay controls and V4 framing, funding and lifecycle coverage. | Maintained tests included in source bound by T1. | Workspace `922b6658` PASS includes client **16/16**, service **16/16** and exact connector cleanup; core-lab `c595036c` repeats the client/connector controls. Tests cover local TCP/test-TLS exchange, permissions/ChannelData, bidirectional UDP relay and refusal/cleanup. The Linux-only native TCP endpoint selector is not executed by these Windows runs; native Linux TCP, native forced TLS and physical/cloud proof remain absent. | Independent executed-oracle review remains separate; no allocation-only or fixture-to-field promotion, and no RFC 6062 qualification. |
| T9 | Preserve 1.0.0, current governance and truthful execution accounting; no old drift state or early-return qualification. | Source bound by T1; prior P/S/I dispositions remain. Retained Hub timers have explicit event-driven replacement TODOs: replace the retained periodic Hub work with owned event-driven triggers; timer removal is not claimed complete. | Local PASS: fmt `9a888f35`, check `9004b9af`, ordinary Clippy `c4a69417`, lab Clippy `cb9e981c`, full workspace `922b6658`, full core-lab `c595036c`, full vendor `ed6bc516` **70/70**, Caddy `8ab78917` **14/14**. Broad PASS retains reported ignored/zero-test targets; it does not mean every native control ran. Earlier failures and predecessor tuples remain historical. | Final candidate/platform/release audit remains separate; no whole hosted-CI, GUI runtime, merge or release approval inferred from this local set. |
| T10 | Managed Caddy TLS sends PROXYv2 to distinct loopback backend 3479; original-IP quotas; public direct TCP rejects PROXY; TLS-only leaves public plaintext disabled. | Implemented in source bound by T1; deliberate V4 adaptation beyond upstream. | Workspace `922b6658` service **16/16 PASS** includes original-IP/class quotas, direct-PROXY spoof and missing-backend-header refusal, proxy-only plaintext absence, TLS certificate refusals and authenticated TLS/proxy UDP relay. Caddy `8ab78917` **14/14** and the 11 config controls PASS cover rendering/configuration. | Final proxy-trust/deployment review remains separate. No actual Caddy/ACME/firewall deployment; loopback alone does not authenticate a Caddy process. |
| T11 | Reuse one live TURN nonce and release/sweep expired retention instead of accumulating abandoned challenge leases. | Implemented in source bound by T1; deliberate V4 resource correction, not a quota increase or authentication bypass. | Full vendor TURN `ed6bc516` **70/70 PASS**, including four nonce controls for abandoned/concurrent challenge reuse, legitimate authentication, expiry/stale replacement and close/drop lease release, plus retained allocation-lifetime and server controls. | Final nonce authorization/lifetime/resource audit remains separate; local vendor PASS does not establish deployment, physical-network or cloud qualification. |

### Historical test names are recipes, not current PASS records

The retained upstream sources include
`parses_tcp_and_tls_turn_urls_only`,
`rewritten_tcp_url_round_trips_a_turn_frame`,
`stream_frames_stun_and_padded_channel_data`,
`answers_binding_request_through_tcp_listener` and
`allocates_and_relays_data_through_tcp_listener`.
The migration/reload tranche includes
`v2_reference_turn_migrates_to_udp_tcp_and_tls`,
`v2_turn_migration_preserves_opt_outs_and_custom_servers` and
`identical_running_install_skips_caddy_reload`.
These names identify upstream controls to adapt or compare; they do not promise
the same names in the restored V4 tree, waive current admission boundaries, or
claim execution. In particular the old config-version fixture must not establish
compatibility with a schema V4 deliberately refuses.

A final handoff must bind results to the frozen restored candidate, including
ordinary and applicable feature/platform builds, exact allocation/data/negative
controls and cleanup evidence. Native TLS/Caddy/cloud scenarios not actually run
must remain explicitly untested. No number in this inventory is a performance
measurement, a firewall permission, a signing/publication claim, or merge approval.
