# Resource admission and observation boundary

## Purpose

This module contains two separate mechanisms:

- `provider` grants finite resource leases and may refuse work;
- the accountant in `resource/mod.rs` records caller-reported use and grants no authority.

A provider lease is admission evidence for the exact resource claim it carries. An observation lease is measurement evidence only. Neither proves identity, mesh authority, endpoint authentication, or application permission.

## Admission provider

`ResourceProviderPort` is the authority-bearing process entry point. The process owner installs one finite provider grant. Mesh, attempt, candidate, callback, cleanup, and real-time owners receive scopes or leases over that same grant.

The port fixes properties, not an arbitration algorithm. Any provider installed behind it must hold:

- creating or cloning a scope creates no capacity, and no accounting or observation path mints any;
- concurrently held charges never exceed the grant in any dimension, and exact release restores exactly that capacity;
- no basal weights, quotas, reserved shares, or partitions exist;
- unused capacity is borrowable unless an explicit local isolation policy forbids it. Such a policy is explicit, named, and recorded, and is never derived from a transient observation `O`;
- arbitration distributes existing capacity only; it never releases, revokes, replaces, or reuses another owner's live claim;
- arbitration attributes a demand to a FairnessRoot: a trusted local process or ingress scheduling attribution, assigned by the local process and never minted, chosen, or supplied by the claimant it attributes. A FairnessRoot is never a Device ID, Mesh Context, durable identity, endpoint identity, authentication or authorization root or capability, or wire-visible value, and carries no authority. The root is not those values, which does not prevent the local owner from using facts it has itself verified or authenticated as inputs when it assigns one. An AttributionChildScope refines accounting beneath exactly one FairnessRoot;
- P6 partition non-amplification, also called subdivision monotonicity. What is held fixed is the input workload, not a trace of outcomes: a finite set of FairnessRoots, one initial provider state including the committed grant `Gc` in every dimension, one identical finite sequence of demand arrivals, each arrival's exact claim by dimension, authority class, and reclaimability under its owner contract, and one deterministic owner response rule fixed in advance. Releases are derived by applying that rule to the work actually admitted; they are never supplied as inputs, because when an owner releases depends on when its work was admitted. The two executions differ in attribution and in nothing else. Both start from the same state, with the same pre-existing FairnessRoots, the same AttributionChildScope topology already created in both, the same bookkeeping claims already charged in both, and the same stable DemandIds. Only the mapping from DemandId to AttributionChildScope differs: the baseline maps root `A`'s demands to one scope beneath `A`, and the subdivided execution spreads those same DemandIds across several scopes beneath that same root. A deterministic, clock-free environment steps both executions through one fixed reducer that interleaves exogenous arrivals and owner-derived actions, and terminal stuttering is permitted so the executions stay comparable at equal decision indices once their work is exhausted. Scope state is itself finite and fallible: creating and retaining an AttributionChildScope consumes a bookkeeping charge that admission can refuse. Neither this property nor any normalization of it promises an unlimited number of scopes, and no wording here may be read as a guarantee that scope creation never meets a ceiling. The bound is a set of prefix inequalities over the provider's ordered decision points `k`: for every `k`, `A`'s cumulative selections in the subdivided run must not exceed its baseline value; for every `k` and every resource dimension `d`, `A`'s cumulative admitted quantity in `d` must not exceed its baseline value; and for every competitor root `B` other than `A` and every demand of `B`, that demand's selection position in the subdivided run must be no later than in the baseline, with a selection that never occurs taking position infinity. The bound is one-way: it requires no equality of outcome, no share ratio, and no scheduler; a subdivision that leaves `A` worse off or a competitor better off is conforming. [`FORMAL-PROOFS.md`](../../../../FORMAL-PROOFS.md) Note 14.5e states this model and comparison canonically and governs if this summary ever diverges from it;
- work conservation constrains immediate refusal. An immediate, nonwaiting acquisition returns typed pressure instead of retaining a demand only for a claim that does not fit, meaning one that cannot be met from capacity that is neither live nor reserved for an in-flight admission, in every dimension the claim requires. Fit is computed from absolute capacities — `AccountingCapacity`, then `EffectiveCapacity`, then the residual `EffectiveFit` — as defined in the capacity subsection below. No step reads a transient observation `O` or a contraction target `T`. A fitting claim is admitted, except under a proven structural limit, under an explicit local isolation policy or optional local ceiling, or when the accounting needed to admit it safely is unavailable, unsafe, or poisoned. Refusal may not be used to hold capacity for an anticipated demand, to smooth a demand rate, or to enforce an undeclared share; any such reservation is a partition and is conforming only as explicit local isolation policy;
- only a lease whose owner contract declares it reclaimable can be selected for reclamation;
- `Cleanup` and `Admitted` leases are never reclamation victims, and cleanup capacity that must be available under every condition is still reserved before allocation;
- refusal names an unavailable resource dimension and is a resource result, never an authorization result;
- elapsed time creates, releases, and expires nothing.

**What P6, partition non-amplification, does and does not claim.** Which local values map onto a FairnessRoot is provider and deployment policy. A trusted local owner may use one root for the whole process, or one per local principal, per listener, per ingress class, or per Mesh runtime. The mapping may take verified inputs: the trusted local provider or ingress owner may use facts it has itself verified or authenticated, including an authenticated local principal, an authenticated remote identity, or an isolated ingress path. What no mapping may do is let a claimant-supplied or wire-visible value directly name, select, split, or multiply a root, or let any party increase the number of roots it is attributed to by asserting something. Verification and assignment stay with the local owner: the mapping need not be independent of verified facts, but it must be independent of unverified assertion. A coarser mapping reduces exposure to an actor that can obtain several roots and reduces fairness granularity; a finer mapping does the reverse. This module fixes no scheduler model, root taxonomy, or principal enumeration.

P6 is stated over one fixed input workload and compared prefix-wise, so its nonclaims are explicit. It asserts no equality of outcome, no share ratio, no scheduling policy, no root taxonomy, and no timer or elapsed-time behavior. It asserts nothing about infinite runs, eventual admission, throughput, or latency: a provider that refuses every arrival in the workload is still non-amplifying, so this property alone proves no progress. It asserts no correspondence between a FairnessRoot and a real-world claimant or actor, so it is not Sybil resistance and rests on no real-world claimant identity premise; if one actor legitimately holds several roots, the property is silent about the total share that actor obtains, and countering that belongs to deployment admission and root-assignment policy. It is not the hostile-ingress obligation: progress, backpressure, and bounded admission for unknown remote input are separate obligations of the pre-authentication ingress path, where each retained unit holds a finite claim, pressure is typed and dimension-named, and no unbounded producer queue exists. A fairness argument is not evidence for those obligations, and an ingress backpressure control is not evidence for fairness.

**Capacity and fit.** [`FORMAL-PROOFS.md`](../../../../FORMAL-PROOFS.md) states this model canonically and governs; what follows is a summary of it and defers to it on every formula. Capacity is stated absolutely and reduced to a residual only at the end. Every quantity is per resource dimension. `S(d)` is the charged sum, live claims plus failed-cleanup-retained claims. `R_flight(d)` is the in-flight admission reservation: the aggregate exact capacity reserved for all admissions currently in flight, and zero when none is in flight. It is a distinct symbol from the global `R` that FORMAL uses for the multiset of live and failed-cleanup-retained lease claims, and the two are never interchanged.

```text
AccountingCapacity(d)
    the absolute committed grant Gc(d), narrowed only by an explicit P5
    restriction from the closed vocabulary below. It is a capacity, not
    a residual: no charge has been subtracted from it

EffectiveCapacity(d)
    AccountingCapacity(d), intersected with E(d) where E is proved in d,
    and with B(d) where B is proved in d. Still absolute

EffectiveFit(d)
    max(0, EffectiveCapacity(d) - S(d) - R_flight(d))
    the residual actually available to a new claim in d
```

A claim `q` fits in a dimension exactly when `q <= EffectiveFit(d)` there. A composite claim fits only when it fits in every dimension it names; headroom in one dimension never compensates for its absence in another.

The intersections are independent, and each applies only where its premise is proved in that dimension: neither proved leaves `EffectiveCapacity` equal to `AccountingCapacity`, `E` proved alone intersects `E`, `B` proved alone intersects `B`, and both proved intersects both. Proving one never requires or implies the other, and the neither-proved case is the accounting-only case, explicitly allowed and not a hidden claim.

Subtracting `S(d)` and `R_flight(d)` last is deliberate. `E` and `B` are absolute substrate bounds, so intersecting them with a figure from which charges had already been deducted would compare a residual against an absolute and silently understate the bound. `R_flight(d)` is subtracted so that concurrent admissions cannot each read the same headroom as free. The `max(0, ...)` clamp is not cosmetic: the difference can be negative when a proved premise falls below existing committed use, and the clamp keeps `EffectiveFit(d)` a well-formed residual that makes the fit test refuse rather than yielding a negative bound that arithmetic elsewhere might treat as slack.

`O` and `T` participate nowhere in this computation. An observation is not a bound and a contraction target is not a bound; admitting against either would admit against a quantity no one committed, and a measurement showing apparent headroom is not evidence that a claim fits.

Admission remains fallible in every case. A successful fit does not guarantee that the allocator, kernel, runtime, transport, external relay, or hardware will succeed. Narrowing capacity by a proved premise does not convert an accounting result into a guarantee of execution, and neither proof, taken at admission, makes its premise hold later.

**The closed P5 vocabulary.** An explicit P5 restriction narrowing `AccountingCapacity` is exactly one of three:

```text
named local isolation domain
    an explicitly named domain confining a scope to part of the
    dimension

named partition or reserved share
    an explicitly named division of the dimension, or a quantity
    withheld from general admission and held for a named scope

named optional local ceiling or cost boundary
    an explicitly named upper bound below Gc, whether selected for
    policy, appliance, deployment, or cost reasons
```

Each is explicit, named, and recorded. Nothing outside this list narrows `AccountingCapacity`: no observation, target, measurement, generic owner preference, workload calibration, anticipated future demand, rate smoothing, inferred restriction, or undeclared product policy. An undeclared narrowing is an arbitrary refusal, which P4 forbids. A P5 restriction can only reduce availability: it may refuse a claim the provider could grant, never approve one the provider refused, and it creates no capacity and no mesh authority.

**Provider labels.** The labels name which premises a provider has proved, per dimension. They are not a ladder, and a provider need not fit exactly one. An accounting-only provider proves `S <= Gc` and claims neither `E` nor `B`; its grant is a bookkeeping commitment this process respects by its own arithmetic. An isolated provider additionally claims `E`, and because containment is not availability, that claim says nothing about whether capacity within the envelope can be obtained. A backed provider additionally claims `B`, and because reservation is not containment, that claim says nothing about whether consumption beyond it is prevented. A provider may hold both, and may hold them in different dimensions — `E` proved in one dimension and `B` in another is an ordinary configuration, not a contradiction. A provider that cannot prove `E` must not describe itself as isolated, and one that cannot prove `B` must not describe itself as backed.

**Safe contraction of a committed grant.** Six quantities are distinct per dimension and may never be conflated: `S`, the sum of live claims and failed-cleanup-retained charges; `Gc`, the provider-owned committed grant that admission is checked against; `E`, an enforceable containment ceiling; `B`, capacity actually reserved for and owned by this provider; `T`, an owner-selected contraction target; and `O`, an external observation of host capacity.

`E` and `B` answer different questions and are never substituted for each other. `E` is a containment premise: a mechanism such as a cgroup, job object, process limit, appliance bound, or provider-side quota that can cap what this process consumes. It promises that use stays within the ceiling; it promises nothing about the resource being available when a claim is admitted. `B` is an availability premise: capacity actually reserved for and owned by this provider, which is a guarantee only to the extent it is genuinely reserved and owned. A provider may prove `E` alone, `B` alone, both, or neither, per dimension. Neither implies the other, and the two are not tiers of one ladder. A provider proving neither in a dimension is accounting-only there: its numbers are honest bookkeeping over an owner-supplied vector and nothing more.

`O` is inert. It is an input, never a grant, never a limit, and never a fit test. It may be stale, wrong, adversarially influenced, in foreign units, or absent. No admission decision reads it and no refusal is justified by it. `T` is owner-selected. An owner may name a target directly, or a named, recorded local policy may derive one, and that policy may take an optional `O` into account. There is no mandatory path from `O` to `T`: a deployment may set `T` with no observation at all, and this boundary prescribes no schema beyond `T` being owner-selected and any derivation being named and recorded. `T` is a request, not an act: it asks `Gc` to descend toward it, and by itself it lowers no grant, releases no charge, and refuses no admission. `Gc` descends toward `T` only after owner-driven release lowers committed use enough to make each step safe, one safe step at a time, and `Gc` is never installed or reduced below the contraction floor `S(d) + R_flight(d)`, so an in-flight reservation can never be stranded. `S(d) + R_flight(d) <= Gc(d)` holds at every instant in every dimension, with no exception and no window; since `R_flight(d) >= 0` this implies `S <= Gc`, and `S > Gc` is not a reachable state and must not be described as one. Contraction applies only to admission decisions taken after it, leaves every committed lease owned and charged, releases, revokes, invalidates, and reuses nothing, and is never a reclamation mechanism. A probe that reports committed use `S(d) + R_flight(d)` at an instant is not a contraction, and the two must never be substituted for each other.

A provider claiming `B` in a dimension proves `Gc <= B` there at admission, and one claiming `E` proves `Gc <= E` there; each such proof requires the Slice C mapping described below. A provider proving neither claims nothing of the kind, and admission does not universally require either proof. A proved premise may fall, and the model distinguishes two regimes per dimension by where it falls relative to committed use. FORMAL states these regimes and their proof canonically and governs; the summary below defers to it. While `premise >= S(d) + R_flight(d)`, residual headroom remains and it is usable: `EffectiveFit(d)` is recomputed against the reduced premise, stays non-negative, and ordinary admission continues within it, and that condition alone requires no loss report. Once `premise < S(d) + R_flight(d)`, the premise is below committed use: the provider reports a typed containment-loss, backing-loss, or external-overcommitment result and admits no new work that would conflict with the shortfall in that dimension. The first regime matters as much as the second, because treating every fall as an emergency would refuse work the provider can honor while reporting a loss that has not occurred. In both regimes every charge in `S(d)` and every reservation in `R_flight(d)` is retained: nothing is released, revoked, reduced, or written off, no release is inferred or forced, a premise falling is not a release, and `Gc` is not lowered below `S(d) + R_flight(d)`. Retirement may be requested only from exact owners whose contracts declare their leases reclaimable, the provider releases nothing itself, and no part of a shortfall is reported as available. Such a proof taken at admission is historical: it does not make the premise hold later, and when it fails, substrate availability may genuinely have failed. Charges remain charged and commitments remain owed, but the underlying resource may simply not be there. These states are conservative accounting, not an assurance of physical backing, and must never be reported as one. Where an adapter can prove neither premise for a dimension, that shortfall is a named Slice C residual: it is not silently treated as contained or reserved and is counted into neither `E` nor `B`.

**Slice C mapping handoff.** Every `Gc <= E` or `Gc <= B` claim requires a mapping that Slice C must supply and this boundary does not implement. The mapping is dimension specific: it names the exact substrate quantity that is contained or reserved for that one resource dimension. It is unit correct: it states the conversion between the MyOwnMesh `ResourceClaim` quantity and that substrate quantity, in both directions of reading, with no implicit unit. And it is monotone: a larger charge in the dimension must correspond to no less of the mapped substrate quantity being contained or reserved, so that a proof at one charge level cannot be borrowed for a larger one. The mapping must satisfy all eight obligations that FORMAL states:

```text
dimension-specific   established for that resource dimension, not
                     inferred from another dimension
unit-correct         relating the charged unit to the substrate unit
                     without silent conversion or reinterpretation
monotone             a larger charged quantity never maps to a smaller
                     substrate quantity
coverage             the mapping accounts for every consumer of that
                     substrate quantity, not only the charged ones. A
                     consumer this model does not charge is included
                     conservatively, by subtracting its use from the
                     premise rather than assuming it absent. A
                     partially mapped dimension is not a mapped
                     dimension
composition          no two ResourceClass dimensions, and no two
                     providers, may claim the same substrate quantity.
                     A quantity counted twice is not thereby contained
                     twice or reserved twice
subject alignment    the contained or reserved subject is exactly the
                     subject Gc is committed for: the same process,
                     worker, and provider, neither broader nor narrower
lifetime and loss    the mapping names when it begins, when it ends,
                     and who observes it. Where its loss cannot be
                     observed before a fail-stop, the charge is
                     retained and the premise is not claimed for that
                     unobservable interval
B exclusivity        reserved capacity is exclusive to that subject.
                     Competing unaccounted use is deducted from B, and
                     a shared pool another party may consume from is
                     not B
```
 Where no such mapping exists for a dimension, that dimension remains accounting-only, or an explicit named residual, and no `E` or `B` claim may be made for it; it may not be reported as contained or reserved, and it is counted into neither `E` nor `B`. `OpaqueDependencyResidual` is the clearest case: a quantity that is merely recorded is neither contained nor reserved, so it does not become `E` or `B` by being given a number, and absent a dimension-specific, unit-correct, monotone mapping it stays accounting-only and residual.

Accounting-only is a coherent label, and a provider bearing it can satisfy this boundary's accounting model. That is a claim about the accounting model alone. It is not a claim that such a provider satisfies P1 through P8, and in particular not P6, which are established separately and are not discharged by bearing the label. Accounting alone is also not sufficient for final production closure, which additionally requires the containment or reservation premises that accounting does not supply. Establishing those mappings for a real substrate is an obligation discharged outside this boundary, and nothing here is evidence that any provider has established either premise. This subsection is a textual handoff only: no mapping, adapter, or enforcement is implemented here.

A typed report exists only while the process is alive and the condition is observable to it. Process death — an out-of-memory kill, a fail-stop, or any other abrupt termination — emits no typed result at all and destroys the live in-process capabilities that would have carried one. Recovery is an ordinary restart, not a resource state. Nothing here claims that external reservations, provider-side allocations, or retained cleanup obligations outside this process necessarily vanish with it; what is lost is the live in-process capability and the ability to report.

The shipped `FiniteResourceProvider` proves neither `E` nor `B` in any dimension: its grant is an owner-supplied vector, and an owner-supplied vector is neither host containment nor host reservation. It is therefore accounting-only in every dimension, `EffectiveCapacity` equals `AccountingCapacity` throughout, and it proves `S <= Gc` and nothing more. Its numbers are honest bookkeeping, never an enforcement or availability claim, and no admission it makes is evidence that capacity exists or that an allocation will succeed. It fixes its grant at construction, exposes no contraction entry point, models no `O`, and derives no `T`. The absence of a contraction path is not evidence that contraction is safe.

**Concrete policy of the shipped `FiniteResourceProvider`.** This provider is immediate. It holds one shared finite grant, fixed at construction. A scope attributes accounting beneath that grant and mints no capacity of its own, so subdividing attribution cannot increase what may be admitted. Every successful acquisition returns one non-cloneable `ResourceLease` carrying the exact claim it was granted, released exactly or transitioned explicitly. A demand that the remaining grant cannot cover is refused immediately, with typed pressure naming the dimension at fault; nothing is queued, deferred, or scheduled on the claimant's behalf, and there is no arbitration, rotation, reclamation, or cooperative-demand path.

P1 through P8 above are the normative obligations on any conforming provider. This provider's immediacy is not a claim to have implemented a scheduler, and no fairness, progress, latency, or non-starvation behavior may be cited from it.

`ResourceScopeId` is the allocation address of the scope identity and is the unstable exact-accounting identity: it is not reproducible across runs, processes, allocators, builds, platforms, or thread schedules; an address may be reused once its scope identity drops; and it is unique only among live scopes rather than over the life of the process. No caller, control, or diagnostic may treat it as stable, meaningfully ordered, comparable across time, or unique over time.

Under any conforming provider, a retirement request is a sticky notification to the exact owner. It does not release the lease, infer cleanup from elapsed time, or make the charge reusable. The owner must fence new work and either drop the lease after cleanup succeeds or retain the exact charge after cleanup failure. Without a pending demand, a slow reclaimable lease may remain live indefinitely. Arbitration cannot manufacture capacity held by non-reclaimable work.

Every successful acquisition returns one non-cloneable `ResourceLease`. The lease retains its declared claim until an explicit transition, exact release on Drop, or failed-cleanup retention. Each resource dimension is independent. No value is an unlimited sentinel.

Exactness is limited to the quantity named by the claim. Allocator overhead, native WebRTC memory, dependency tasks, kernel handles, driver state, and external relay allocations remain explicit residuals until an adapter can claim or isolate them.

## Observation hierarchy

Production observations use one fixed hierarchy:

```text
process root
  -> one live Mesh runtime
    -> one live joined network instance
      -> one attempt or peer connection
```

A leaf observation updates the leaf and all three ancestors. Sibling network instances and sibling peers do not observe each other. The process root aggregates measurements and grants no authority.

The network-instance scope describes a live runtime owner. It is not called an exact Mesh Context because it is not bound to an immutable context identity. Carrier, ingress source, attempt, and known-origin attribution are separate dimensions. They must not be inferred from the runtime aggregation path.

Each scope keeps fixed-size report state for the closed resource families. The hierarchy has no child registry, per-active-lease collection, or hierarchy-wide mutex. Begin, replacement, and completion update each scope independently. A diagnostic snapshot can therefore observe a transient difference between an ancestor and a descendant. It does not claim global linearizability.

## Measurements

`ResourceUse` has four independent axes:

- items;
- logical bytes;
- retained bytes;
- tasks.

Logical bytes describe live content. Retained bytes use the producer's documented measurement contract and include unused capacity only when that producer reports it. The two values are not substituted for each other. A producer that reports Rust `String` or `Vec` capacity does not thereby measure allocator metadata, stack use, native dependency memory, or process RSS.

Each family report includes current and peak use, current and peak lease counts, the oldest active lifetime when known, completed lease count, final completed quantities, total completed lifetime, and a sticky `measurement_inexact` flag.

Oldest-lease tracking uses constant metadata. If the oldest of several leases ends, the next-oldest start cannot be recovered without retaining one timestamp per active lease. The report sets `oldest_active_lifetime_inexact` and stops reporting an exact oldest lifetime until the family becomes empty. Other exact counters remain exact.

## Observation ownership and cleanup

Callers provide a family and a measured `ResourceUse`. The accountant returns an `ObservationLease`. Dropping that lease removes the active measurement and records its lifetime at every scope in its path.

A caller that owns a growing or shrinking collection may replace the lease's measured quantity with a fresh measurement from that same object. This changes measurement only.

Arithmetic is checked before saturation. Overflow, an unsupported platform-sized measurement, inconsistent subtraction, or a poisoned scope lock marks the affected report inexact. Counters do not wrap or underflow. Production measurement code has no deliberate panic path for measurement failure.

Measurements are memory-only. Process restart destroys them. They are not reconstructed from durable state.

## Observation restrictions

The accountant must not:

- define or infer a numeric limit;
- accept or refuse work;
- reserve capacity;
- create an admission permit or authority capability;
- authorize an identity, mesh, connection, session, route, or application action;
- provide backpressure, eviction, prioritization, or admission policy;
- perform networking or mutate production domain state.

An `ObservationLease` proves only that a caller-reported quantity is being measured. It is never evidence that work was admitted, authenticated, or safe.

## Arc 03 integration

Arc 03 installs provider-backed ownership for the bounded WebRTC connector paths named in its report. Connector construction, candidate content and application, callbacks, cleanup, and selected real-time work hold finite claims at their declared boundaries. The library selects no production grant and no universal Mesh, peer, attempt, session, queue, or flow count. A deployment supplies the finite process grant.

This is not repository-wide resource closure. Signaling queues, complete WebRTC and ICE internals, sockets, DNS, dependency-created tasks, native tracks, and external TURN allocations remain either later work or explicit residuals where the current adapter cannot enforce them. Where the adapter cannot prove what actually backs a dimension, that shortfall is a named Slice C residual and is never counted as backed.
