# MyOwnMesh architecture ownership and upstream intake policy

> Current normative cutover (2026-09-09): application data uses endpoint-authenticated WebRTC, directly or through configured standard TURN. Hubs provide discovery/introduction only, never application plaintext or ciphertext transit. This supersedes custom encrypted Hub and Closed-member payload relay requirements. Open/Closed governance is unchanged. Historical exact-head evidence below remains historical; this edit is not an implementation, runtime, or release PASS.

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

Application payload belongs only to the authenticated endpoints. Native WebRTC
direct connectivity is preferred; configured standard TURN supplies the
indirect packet-carriage path when direct connectivity is unavailable. Neither
a Hub nor an ordinary Open/Closed member is a custom application-data relay,
including for endpoint ciphertext. Hub discovery and bounded introduction
create no membership authority, payload route, or endpoint-session capability.

The current configuration contract uses
`introduction: Option<HubIntroductionPolicyConfig>`. The removed
`closed_relay`, `application_transport`, `endpoint_cipher`, and
`routing_policy` fields and their removed wire messages must be refused,
not silently translated into a compatible payload path. Native direct opaque
channels, realtime flows, and RPC remain endpoint-session operations.

A TURN service is distinct from a Hub even when cohosted. Service
advertisements currently provide URLs; credentials are configured locally.
Protected TURN credential distribution is not implemented and is not claimed.
Signaling carries bounded setup/control and existing typed semantic-control,
never an application plaintext or ciphertext tunnel. Existing owned cleanup
and resource obligations apply; no new native-runtime owner is adopted by
this document.

The former roster/two-log `NetworkState` authority model, including quorum,
transition, split, and persistence authority, is excluded from the V4
contract. No legacy implementation is an executable authority path.

Examples include:

- any custom Hub or ordinary mesh-member application forwarding, plaintext or ciphertext;
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
