# Network types and V4 authority

## V4 contract

The implemented V4 authority model is a canonical `FactGraph` of verified
`SignedFact` records, persisted by `DurableSemanticStore`. A fact is identified
by its content-derived `FactId`; its domain, mesh context, author, parents, and
explicit authority uses are verified before durable semantic admission. The
graph, not a roster file or quorum count, is the authority source.

The ordinary governance bodies are typed `RoleGrant { target, role }`,
`RoleRevoke { target }`, and `Evict { target }`. Their typed authoring requests
are exactly `NetworkCmd::ProposeRoleGrant`, `NetworkCmd::ProposeRoleRevoke`,
and `NetworkCmd::ProposeEvict`; a command is an authoring request, never an
authority bypass. `MembershipAdmit` is a Closed governance fact. Open
participation has no base durable fact: exact-context handshake and Device-key
possession authenticate a runtime participant. Same-cell `Resolution { cell,
cited_heads, selected_head }` is distinct from cross-cell
`AuthorityLineageResolution`, which carries its complete cited lineage.

`NetworkKind` is local configuration/profile shape (`open`, `closed`, or
`silent`), matched to verified bootstrap state; it is not a free-standing
authority fact. Topology and transport context are outside ordinary semantic
facts, and roster/member views are projections for UI and routing hints, not
authoritative state. There is no V4 quorum table, transition-log rewrite rule,
or split-network authority path.

The base ledger is Closed authority/governance only. Retained Closed classes
are `RoleGrant` and `RoleRevoke` for role state, `MembershipAdmit` and `Evict`
for member decisions, `EvictionProof` for admissibility evidence,
`SelfStandDown` and `Attestation` for typed governance evidence, and
`Resolution`/`AuthorityLineageResolution` for exclusive-cell and complete
cross-cell lineage decisions. Reviewed application contract facts, if enabled,
use a separate explicitly selected domain and are not base Closed authority.
Join, leave, presence, and reconnect for both Open and Closed are
runtime observations and never semantic history; roster and topology are
read-only projections/context.

Ledger admission uses owner-selected finite limits for fact count, encoded
bytes, causal edges, per-author count/bytes, proof-verification work, and
indexed database bytes. The reducer computes the full candidate delta before
mutation and refuses the exact `N+1` fact or dependency before graph,
projection, ACK, identity, or authority changes. Missing dependencies use a
finite dependency-indexed quarantine; duplicates are idempotent and failed
proofs release their exact custody. There is no silent time eviction, retry
timer, or unbounded cache.

Closed facts persist through indexed `O(delta)` commits with one semantic
writer, WAL journaling, and `FULL` synchronous durability. Exact history
remains until an archive or authority-ratified checkpoint makes semantic
deletion safe, and reopen must recover the exact semantic identity. For the
`StorageBytes` dimension, one process-accounted claim is `B = M + W + S + R`:
the main database, WAL, shared-memory/sidecar bytes, and explicit reserve
bytes. Named-file or VFS accounting does not prove backing disk capacity,
filesystem metadata capacity, or `ENOSPC` behavior. The shipped compaction
boundary is bounded checkpointing only; a full-copy `VACUUM` requires
separately funded temporary-copy, metadata, and cleanup custody. The finite
count/byte/edge/author/proof and database vector bounds normal growth and
failure spam: rejected attempts consume no semantic record or ACK, while
failed cleanup retains its exact charge until an observed terminal settlement.

Final production compliance remains pending until durable runs demonstrate
Open/Closed separation, scale and exact `N+1` refusal, duplicate/no-op
invariance, exact Closed restart/reopen identity, deterministic fault/crash
reconciliation, and terminal provider/resource baselines. Source or unit
evidence alone is not a final compliance PASS.

Open and Closed networks use the same application transport boundary: an
authenticated endpoint-to-endpoint WebRTC session, using configured TURN when
a direct ICE path is unavailable. Hubs help discover and introduce endpoints;
they do not forward application plaintext or ciphertext. Closed authorization
still comes from the canonical governance graph and endpoint admission.

## Removed legacy model

The former roster/two-log `NetworkState` model, including its quorum,
transition, split, persistence, and `network_state_*` wire authority, is
excluded from the V4 contract. It must not be reintroduced as an executable
architecture or used as an authority source. See the canonical
authority ownership rules in [`ARCHITECTURE-OWNERSHIP.md`](../ARCHITECTURE-OWNERSHIP.md)
and the migration disposition in
[`CURRENT-TO-TARGET-MIGRATION-MATRIX.md`](../CURRENT-TO-TARGET-MIGRATION-MATRIX.md).
