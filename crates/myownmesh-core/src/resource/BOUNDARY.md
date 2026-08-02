# Resource observation boundary

## Purpose

This module measures resource use by the closed pre-authentication and post-authentication families defined in sections 14.1 and 14.2 of `IMPLEMENTATION-CONSTRAINTS-AND-INVARIANTS.md`.

It is observation infrastructure. It is not resource policy.

## Observation hierarchy

Production observations use one fixed hierarchy:

```text
process root
  -> one live Mesh runtime
    -> one live joined network instance
      -> one attempt or peer connection
```

A leaf observation updates the leaf and all three ancestors. Sibling network instances and sibling peers do not observe each other. The process root is the only process-global accountant. It aggregates measurements and grants no authority.

The network-instance scope describes a live runtime owner. It is not called an exact Mesh Context because it is not bound to an immutable context identity. Carrier, ingress source, attempt, and known-origin attribution are orthogonal dimensions. They must not be inferred from the runtime aggregation path.

Each scope keeps fixed-size report state for the closed resource families. The hierarchy has no child registry, per-active-lease collection, or hierarchy-wide mutex. Begin, replacement, and completion update each scope independently. A diagnostic snapshot can therefore observe a transient difference between an ancestor and a descendant. It does not claim global linearizability.

## Measurements

`ResourceUse` has four independent axes:

- items;
- logical bytes;
- retained bytes;
- tasks.

Logical bytes describe live content. Retained bytes use the producer's documented measurement contract and include unused capacity only when that producer reports it. The two byte values are not substituted for each other. The remote-candidate pilot reports Rust `String` and `Vec` capacity bytes. It does not claim allocator metadata, allocator usable size, stack use, or process RSS.

Each family report includes current and peak use, current and peak lease counts, the oldest active lifetime when it is known, completed lease count, final completed quantities, total completed lifetime, and a sticky `measurement_inexact` flag.

Oldest-lease tracking uses constant metadata. If the oldest of several leases ends, the next-oldest start cannot be recovered without retaining one timestamp per active lease. The report sets `oldest_active_lifetime_inexact` and stops reporting an exact oldest lifetime until the family becomes empty. Other exact counters remain exact.

## Ownership and cleanup

Callers provide a family and a measured `ResourceUse`. The accountant returns an `ObservationLease`. Dropping that lease removes the active measurement and records its lifetime at every scope in its path.

A caller that owns a growing or shrinking collection may replace the lease's measured quantity with a fresh measurement from that same object. This changes measurement only.

Arithmetic is checked before saturation. Overflow, an unsupported platform-sized measurement, inconsistent subtraction, or a poisoned scope lock marks the affected report inexact. Counters do not wrap or underflow. Production measurement code has no `expect`, `unwrap`, or panic path.

Measurements are memory-only. Process restart destroys them. They are not reconstructed from durable state.

## Dependencies

The module uses standard-library synchronization, collections, and monotonic time. It performs no filesystem, process, socket, signaling, connector, relay, or application operation.

## Forbidden responsibilities

This module must not:

- define or infer a numeric limit;
- accept or refuse work;
- reserve capacity;
- create a permit or capability;
- authorize an identity, mesh, connection, session, route, or application action;
- treat a pre-authentication observation as post-authentication capacity;
- provide backpressure, eviction, prioritization, or admission policy;
- perform networking or mutate production domain state.

An `ObservationLease` proves only that a caller-reported quantity is being measured. It is never evidence that the work was allowed, reserved, authenticated, or safe.

## Arc 03 integration status

Remote ICE candidate values and the pre-SDP queue container are observed. The WebRTC connector also observes its wrapper, callbacks, worker tasks, parser work, and selected queue sites. These observations do not cover signaling queues, complete WebRTC or ICE agent internals, sockets, DNS, every dependency task, or a complete hostile-ingress resource family.

The attempt owner acquires a child reservation before asynchronous native construction. One attempt may issue several candidate capabilities under one aggregate reservation. Candidate promotion explicitly releases candidate-only construction work and retains the connected transport claim. No production numeric budget has been selected, so the existing candidate queue remains observation-only and must not be described as an enforcement guard.

Frame, parser, attempt, candidate, and connector-work reservations belong at their respective allocation boundaries. Unknown input must be admissible through anonymous-ingress and global budgets before a Device identity or Closed authorization exists. Arc 03 installs connector ownership and per-worker callback backpressure, but it does not create owner-approved anonymous-ingress or process capacities. Later resource-policy work installs those guards only after measured values receive owner approval.
