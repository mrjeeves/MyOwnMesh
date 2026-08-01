# MyOwnMesh architecture ownership and upstream intake policy

Status: execution policy for the existing-repository transition.

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

The mechanism, reproduction, diagnostic, and test may be retained or ported. The conflicting authority model does not survive merely because the code already exists.

Examples include:

- ordinary mesh-member application forwarding;
- Closed admission through `auto_approve`;
- a connected socket, peer string, route, or IPC routing label acting as authority;
- topology or carrier state mutating durable participation;
- application payload entering signaling;
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
8. migration and compatibility remain viable;
9. the replacement creates no new state owner, implicit route-around, or grab-bag module.

A real tradeoff fails the dominance test. It becomes an explicit owner decision rather than an automatic upstream win.

## 4. Upstream intake classes

Every upstream change is classified before integration.

| Class | Meaning | Action |
|---|---|---|
| U0 Orthogonal | Logging, packaging, installer, updater, GUI polish, CI, platform fix, documentation, or dependency work with no owned-boundary effect | Merge or cherry-pick after normal tests |
| U1 Compatible improvement | Fits the adopted owner and type boundaries and passes the dominance test | Adopt directly |
| U2 Valuable mechanism in a conflicting subsystem | Fixes a real transport or operational problem but is implemented in a legacy owner | Port the mechanism, reproduction, and tests into the architecture-owned node |
| U3 Semantic conflict | Reintroduces prohibited authority, forwarding, signaling/payload conflation, or state ownership | Reject the behavior; architecture wins |
| U4 Ambiguous tradeoff | Improves one property while weakening another or lacks evidence | Hold for owner review |
| U5 Dead-path change | Modifies a legacy path already deleted or scheduled for deletion | Ignore unless the change reveals a still-relevant defect |

No architecture-owned subsystem accepts automatic upstream merges.

## 5. Ownership transition rule

A path becomes architecture-owned when its migration pull request has:

- named the sole state owner;
- installed the target typed ports;
- passed its positive and negative conformance tests;
- redirected all production callers;
- removed or made unreachable the old authority path;
- updated the migration matrix.

After that point, changes to the upstream legacy predecessor are U2, U3, or U5. They are never merged mechanically into the owned path.

## 6. Compatibility adapters

A compatibility adapter may translate between legacy and target interfaces only while a migration arc is active.

It may not:

- gain new product behavior;
- become a second state owner;
- make an authorization decision;
- synthesize a higher-authority capability;
- remain after all callers have migrated;
- become the permanent public API by inertia.

Every adapter must name the pull request or arc that deletes it.

## 7. Required change record

Every pull request touching an architecture-owned boundary records:

```text
Owned state changed:
Ports changed:
Capability transition changed:
Legacy path removed or retained:
Architecture invariants exercised:
Red-team cases exercised:
Performance and resource measurements:
Upstream classification, when applicable:
Owner decision required, if any:
```
