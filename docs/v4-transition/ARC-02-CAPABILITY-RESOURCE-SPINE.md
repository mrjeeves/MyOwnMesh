# V4 Arc 02 capability and resource spine

Status: capability spine complete as a bounded implementation slice. Resource observation primitive complete for integration. Full Arc 02 gate open because current production allocations are not instrumented.

Branch: `arc/02-capability-resource-spine`

Parent commit: `9f2b174a1a45970d7554d28bd5b89ddeb0ee9067`

No transport, signaling, endpoint-authentication, application-delivery, listener, or firewall behavior changed in this slice.

## 1. Change contract

| Required field | Result |
|---|---|
| State class moved | None. Target-owned authority seams were linked before production state migration. |
| Old owner | Existing engine, transport, daemon, and service owners remain unchanged. |
| New sole owner | Attempt Node, Connector Worker, Endpoint Auth Task, Session Broker, Relay Node, and Application Gateway own the new type boundaries. They do not yet own migrated production state. |
| New typed inputs | Pre-authentication, endpoint-authentication, session, relay-allocation, application-queue, connected-channel, authenticated-channel, and local-principal authority types. |
| New typed outputs | Candidate, connected-channel, authenticated-channel, and session capability types. |
| Capability transition added or changed | Owner-private structural transitions were added for the attempt and connector seams. No production transition is called. |
| Pre-auth and post-auth resource effects | Thirty-two closed observation families, split into 22 pre-authentication and 10 post-authentication families. No limit or admission effect was added. |
| Legacy adapter introduced | Five crate-private containers require an already-issued capability and keep the legacy object private. |
| Deletion arc for adapter | Candidate in Arc 03, connected channel in Arc 04, authenticated channel in Arc 05, session and local principal in Arc 06. |
| Production callers redirected | None. |
| Positive controls | Public type paths resolve; runtime bindings compose in test scaffolding; resource reports include every family. |
| Negative controls | Public construction, conversion, cloning, serialization, session minting, runtime minting, trait factories, and raw-wrapper escapes are rejected. |
| Red-team cases | Source mutations cover wrapped and second-implementation mints, aliases, raw identifiers, parenthesized targets, `where` clauses, macros, attributes, descendant modules, alternate runtime factories, public-label conversions, renamed extractors, wrapper traits, missing boundaries, and missing compile controls. |
| Performance measurements | Not applicable to production behavior because there is no production caller. Runtime overhead has not been claimed or measured. |
| Documentation updated | Seven target boundaries, this report, the Arc 02 red-team execution record, and the additive Arc 01 ownership inventory. |

## 2. Authority types and owners

| Owner | Types | Production construction status |
|---|---|---|
| Attempt Node | `PreAuthAttemptPermit`, `CandidateCapability` | Private definitions exist. No production caller can create the runtime witness needed to issue either type. |
| Connector Worker | `ConnectedChannelCapability` | The consuming transition is private and has no production caller. |
| Endpoint Auth Task | `EndpointAuthPermit`, `AuthenticatedChannelCapability` | Test-only composition exists. Arc 04 must supply the real channel-bound transcript verifier. |
| Session Broker | `SessionPermit`, `SessionCapability` | No production mint exists. The test-only composition is not a promotion implementation. |
| Relay Node | `RelayAllocationPermit` | Test-only issuer only. Arc 12 must supply the exact allocation profile. |
| Application Gateway | `LocalPrincipalCapability`, `ApplicationQueuePermit` | Test-only issuers only. The operating-system principal binding remains undecided. |

Every field is private. None of these ten types implements `Clone`, `Copy`, `Default`, `Serialize`, `Deserialize`, `From`, or `TryFrom`. The source gate also rejects any production trait implementation that mentions an authority type.

The compile-time boundary assumes safe Rust and an uncompromised compiler and process. It does not claim to survive arbitrary memory corruption. The source gate records a SHA-256 fingerprint of the canonical production tokens in the crate root and every authority-owner module, so an unreviewed production-token change fails closed even when it uses a legal Rust spelling that the semantic checks do not recognize. It also binds the Cargo library target to `src/lib.rs` and rejects module-path redirection.

The types retain one crate-private `RuntimeIncarnation` witness. That witness uses `Arc` pointer identity and has no serialized form. It prevents values from different live runtime incarnations from composing in the test scaffold.

This does not make retained values revoke themselves. A later authority-consuming operation must compare the retained witness with the Runtime Supervisor's current witness. No production authority consumer exists yet, so same-process restart rejection is an obligation for the migration arcs, not a completed claim.

## 3. Session mint boundary

`SessionCapability` contains all authority types that Arc 02 can represent without inventing policy:

- one `AuthenticatedChannelCapability`;
- one `LocalPrincipalCapability`;
- one `SessionPermit`;
- their common runtime-incarnation witness.

There is deliberately no production constructor. The complete `MayPromote` predicate still needs a currently working channel, fresh mutual Device authentication, exact mesh context, current Open or Closed policy, an authenticated and allowed local principal, and reserved post-authentication resources. Arc 02 cannot mint a real session before those inputs have production owners.

The checker rejects direct constructors, wrapped `Result<Self, _>` constructors, factory traits, public or crate-visible value-returning functions, manual conversion traits, aliases, renamed imports, production code-generating macros and attributes, descendant owner modules, and unsafe construction patterns. It normalizes raw identifiers and recognizes parenthesized and `where`-qualified inherent implementations. The only Session struct expression is under `cfg(test)`.

## 4. Legacy adapters

The five adapters are crate-private and carry two separate values:

```text
already-issued capability + private legacy object
```

They cannot infer authority from the legacy object. Their raw extraction method remains owner-private. The gate rejects renamed public tuple extractors and `Deref`, `AsRef`, `Borrow`, conversion, or other trait implementations that mention the wrapper.

The wrappers have no production caller in this slice. They are migration seams, not permanent public APIs.

## 5. Resource observation primitive

`ResourceAccountant` is an explicitly created, per-instance observer. Clones share only that selected instance. There is no global accountant.

Each family report contains:

- current items, bytes, and tasks;
- peak active items, bytes, tasks, and lease count;
- current and completed lease counts;
- the oldest active lifetime and total completed lifetime;
- the final measured quantity of completed leases;
- a sticky `measurement_inexact` flag.

`ObservationLease` uses RAII cleanup. A collection or buffer owner may replace its observed quantity as the live object grows or shrinks. Replacement changes measurement only. It does not resize, reserve, accept, reject, prioritize, or authorize work.

Arithmetic is checked before saturation. Underflow, overflow, inconsistent cleanup, and recovery from a poisoned state make the report inexact instead of wrapping or claiming precision. `report()` acquires the state lock before taking its monotonic timestamp, so an included observation cannot begin after the report time.

The observer has no filesystem, process, socket, signaling, connector, relay, application, policy, permit, or capability operation.

## 6. Production resource coverage

The full Arc 02 resource gate is not met.

| Current area | Arc 01 resource records | Production observation hooks |
|---|---:|---:|
| Core | 25 | 0 |
| Signaling | 42 | 0 |
| Daemon | 27 | 0 |
| Updater | 3 | 0 |
| Services | 14 | 0 |
| Total | 111 | 0 |

The 111 records are inventory records, not 111 proven independent allocations. They include canonical allocations, mutation sites, duplicate views, configuration behavior, and dependency-owned resources. Instrumenting every record independently would double-count some resources.

Two additional facts prevent a safe whole-workspace mechanical hookup:

1. `myownmesh-core` depends on `myownmesh-signaling`, so signaling cannot import the core observer without a dependency cycle.
2. The updater records belong to operational U0. The V4 mesh resource contract does not assign them to a pre-authentication or post-authentication mesh family.

A zero report from the current primitive means no caller reported activity. It does not mean the process used no resources and does not prove coverage.

## 7. Verification

Workspace, Clippy, and test artifacts used an isolated Cargo target under `C:\Users\Admin\.allmystuff-sandbox-stage`. The compiler-boundary harness used its own temporary Cargo project. No listener or integration binary was started.

The executable attack catalog is [`red-teams/ARC-02-AUTHORITY-AND-RESOURCE-SPINE.md`](../../red-teams/ARC-02-AUTHORITY-AND-RESOURCE-SPINE.md).

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | Passed |
| `cargo check -p myownmesh-core --lib -j 16` | Passed without warnings |
| `cargo clippy -p myownmesh-core --all-targets -j 16 -- -D warnings` | Passed |
| `cargo check --workspace --all-targets -j 16` | Passed |
| `cargo test -p myownmesh-core --lib v4_arc02 -j 16` | 19 passed, 0 failed, 276 filtered out |
| `cargo test -p myownmesh-core --doc -j 16` | 10 passed, including 8 compile-fail controls, 1 authority type-path control, and the existing crate example |
| `python scripts/check-v4-arc02-compiler-boundaries.py` | 1 positive control and 10 cause-matched rejection controls passed |
| `python scripts/check-v4-arc02-spine.py` | Passed |
| `python scripts/check-v4-arc02-spine.py --negative-controls` | All recorded mutation families were rejected |
| Arc 01 positive and negative gates | Passed at 106 production source units, 1,535 declaration members, 1,637 surfaces, 75 semantic markers, and 111 resource records |

The compiler-boundary script exists because rustdoc accepts a `compile_fail` example when any compiler error occurs. Its optional error-code suffix did not prove the failure cause. The separate script checks the compiler diagnostic code, type-specific message fragments, and the marked primary source line for each rejected expression. It also proves that wrong-code, wrong-fragment, and wrong-line expectations do not match.

## 8. Nonclaims and next gate

This slice does not claim that:

- the current engine requires these capabilities;
- legacy application delivery is gated by `SessionCapability`;
- current allocations are measured or bounded;
- a resource reservation or permit issuer exists;
- runtime replacement rejection is enforced at production operation boundaries;
- `MayPromote` is implemented;
- Arc 02 is complete.

The next bounded step is to normalize one proven duplicate pair before adding a production hook. The candidate-vector declaration and candidate append are one pending-candidate backlog plus one mutation site, not two allocations. That record must also include the existing asynchronous drain path.

Before instrumentation, the owner must select the report scope, define what candidate bytes mean, define when backlog lifetime ends as candidates move into asynchronous application, and encapsulate every mutation path. Those are semantic values, so this slice does not invent them. Once that small record is settled, the same canonical-allocation, alias or mutation, configuration-evidence, and dependency-internal classification can proceed across the remaining inventory. Cross-crate families still require a shared observation seam that does not create a dependency cycle or split one report into unrelated accountants.

The reviewed candidate design requires a private observed-candidate wrapper, a private queue, and removal of `Clone` from the public `PeerStateData`. Otherwise an embedder can duplicate or mutate the queue without an observation hook. One byte definition would count the exact retained bytes in the candidate string values. Another would count allocator-facing vector and string capacities. They answer different questions and require different lifetimes, so neither is silently selected here. A per-`Mesh` report is the natural current root, but direct `spawn_network` callers and multiple `Mesh` instances make the required global aggregation scope an owner decision as well.
