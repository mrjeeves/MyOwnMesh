# MyOwnMesh architecture ownership and upstream intake policy

Status: final execution and ownership policy for the architecture-owned repository.

This document answers one question: when the adopted MyOwnMesh architecture and the existing or upstream implementation disagree, which one controls the product?

## 1. Authority order

The authority order is:

1. owner-adopted product requirements and owner decisions;
2. [`ARCHITECTURE.md`](ARCHITECTURE.md);
3. [`IMPLEMENTATION-CONSTRAINTS-AND-INVARIANTS.md`](IMPLEMENTATION-CONSTRAINTS-AND-INVARIANTS.md);
4. [`FORMAL-PROOFS.md`](FORMAL-PROOFS.md) and the conformance evidence required by it;
5. [`APPLICATION-INTEGRATION.md`](APPLICATION-INTEGRATION.md);
6. [`red-teams/MESH-ATTACK-VECTORS.md`](red-teams/MESH-ATTACK-VECTORS.md);
7. the architecture-owned implementation and tests;
8. existing and upstream implementation behavior.

Existing code is strong evidence that a mechanism works in the field. It is not authority for semantics that conflict with the adopted architecture.

## 2. Conflict rule

When an upstream or legacy implementation conflicts with an architecture-owned semantic, state-owner, type-boundary, or security invariant:

```text
architecture wins
```

## 2a. Implemented V4 authority ownership

The sole durable semantic authority is the canonical `FactGraph` persisted
through `DurableSemanticStore`. Its inputs are verified `SignedFact`
records, including content-derived identity, mesh context, author, parents,
and explicit authority uses. The exact ordinary governance bodies are
`FactBody::RoleGrant`, `FactBody::RoleRevoke`, and `FactBody::Evict`.
The corresponding `NetworkCmd::ProposeRoleGrant`,
`NetworkCmd::ProposeRoleRevoke`, and `NetworkCmd::ProposeEvict` values are
typed authoring requests into that semantic owner, not independent authority.

Same-cell selection is represented by `FactBody::Resolution`; cross-cell
authority selection is represented separately by
`FactBody::AuthorityLineageResolution`. This distinction prevents a
same-cell Role resolution from being reused as a cross-cell authority claim.
`NetworkKind` is configuration/profile shape. Topology, transport context,
and roster/peer-registry data are projections or runtime inputs and cannot
authorize durable participation or application operations.

The bounded Closed-member opaque relay is an explicit forwarding profile; it is
not permission to forward plaintext. A-B and B-C are independently
authenticated and promoted; A, B, and C then use route-bound `Open`, `Offer`,
and `Accept` controls. Endpoint sessions seal/open plaintext, while B forwards
only opaque packets under exact route, current-owner, and allocation-generation
witnesses.
The separately owned Hub profile has different semantics: a Hub may introduce
bounded direct endpoint demand, but owns no payload. If residual Hub transit is
used, endpoints derive a fresh endpoint-to-endpoint E2E epoch bound to the
exact mesh context and full endpoint keys. The Hub may copy/forward endpoint
ciphertext and observe metadata, but cannot decrypt or read application
plaintext; it has no Closed `Open`/`Offer`/`Accept` allocation semantics,
membership authority, or veto over an independently viable path. Failure to
establish that endpoint epoch is refusal. This is adopted Hub direction, not a
qualification claim for the depicted LAN path.
Relay state has no key material, and its allocations, packet bytes, queues,
retention, and cleanup are finite under the configured profile. Admission
refusal preserves pending custody. Generation tombstones make duplicate
terminal closes idempotent and keep delayed predecessor controls away from
successors. Shutdown wakes bounded waiters, settles every relay custody class,
and joins owned tasks before completion.

The former roster/two-log `NetworkState` authority model, including quorum,
transition, split, and persistence authority, is excluded from the V4
contract. No legacy implementation is an executable authority path.

Examples include:

- unbounded or plaintext ordinary mesh-member application forwarding;
- Closed admission through legacy `auto_approve`;
- a connected socket, peer string, route, or IPC routing label acting as authority;
- topology or carrier state mutating durable participation;
- application payload entering signaling;
- legacy quorum/transition/split governance replacing canonical facts;
- governance whose signed content omits state-determining inputs;
- a monolithic shared state owner gaining another unrelated responsibility.

## 3. Dominance test for a competing design

A competing implementation may replace an adopted mechanism only when the change is proven to dominate it within every owner-selected supported deployment and requirement. The review must show all of the following:

1. every applicable architecture invariant still holds;
2. the same or a narrower authority set is accepted;
3. the same or less application data is exposed before promotion;
4. transport independence is preserved without removing transport behavior;
5. supported connection latency, recovery, throughput, memory, CPU, portability, and failure behavior are not worse in any reviewed case;
6. resource accounting and cleanup are at least as strong;
7. tests and field reproductions cover every behavior the replaced mechanism handled;
8. supported interfaces and deployment behavior remain viable;
9. the replacement creates no new state owner, implicit route-around, or grab-bag module.

A real tradeoff fails the dominance test. It becomes an explicit owner decision rather than an automatic upstream win.

## 4. Upstream intake classes

Every upstream change is classified before integration.

| Class | Meaning | Action |
|---|---|---|
| U0 Orthogonal | Logging, packaging, installer, updater, GUI polish, CI, platform fix, documentation, or dependency work with no owned-boundary effect | Merge or cherry-pick after normal tests |
| U1 Conforming improvement | Fits the adopted owner and type boundaries and passes the dominance test | Adopt directly |
| U2 Valuable mechanism in another owner | Fixes a real transport or operational problem but is implemented outside the owning node | Port the mechanism, reproduction, and tests into the architecture-owned node |
| U3 Semantic conflict | Reintroduces prohibited authority, forwarding, signaling/payload conflation, or state ownership | Reject the behavior; architecture wins |
| U4 Ambiguous tradeoff | Improves one property while weakening another or lacks evidence | Hold for owner review |
| U5 Obsolete-path change | Modifies a path excluded from the final owner graph | Ignore unless the change reveals a still-relevant defect |

No architecture-owned subsystem accepts automatic upstream merges.

## 5. Ownership acceptance rule

A path is architecture-owned when its change record has:

- named the sole state owner;
- installed the final typed ports;
- passed its positive and negative conformance tests;
- redirected all production callers;
- excluded or made unreachable any conflicting authority path;
- updated the ownership matrix.

After that point, changes to the upstream legacy predecessor are U2, U3, or U5. They are never merged mechanically into the owned path.

## 6. Translation boundaries

A translation boundary may connect distinct typed interfaces only when it has
one named owner and cannot make a domain decision.

It may not:

- gain new product behavior;
- become a second state owner;
- make an authorization decision;
- synthesize a higher-authority capability;
- become a second public authority surface;
- persist as an unowned product behavior.

Every translation boundary must name its owner and its bounded contract.

## 7. Required change record

Every pull request touching an architecture-owned boundary records:

```text
Owned state changed:
Ports changed:
Capability boundary changed:
Excluded path or boundary impact:
Architecture invariants exercised:
Red-team cases exercised:
Performance and resource measurements:
Upstream classification, when applicable:
Owner decision required, if any:
```
