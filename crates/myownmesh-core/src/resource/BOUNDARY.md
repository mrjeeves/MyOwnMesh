# Resource observation boundary

## Purpose

This module measures resource use by the closed pre-authentication and post-authentication families defined in sections 14.1 and 14.2 of `IMPLEMENTATION-CONSTRAINTS-AND-INVARIANTS.md`.

It is observation infrastructure. It is not resource policy.

## Observation hierarchy

Production observations use one fixed hierarchy:

```text
process root
  -> one live Mesh runtime
    -> one exact joined mesh context
      -> one attempt or peer connection
```

A leaf observation updates the leaf and all three ancestors. Sibling contexts and sibling peers do not observe each other. The process root is the only process-global accountant. It aggregates measurements and grants no authority.

Each scope keeps its own report state. The hierarchy holds no registry of child scopes, so dropping a child does not leave a permanent per-child record at the process root. A shared transaction lock makes one begin, replacement, or completion visible to all scopes as one accounting operation.

## Measurements

`ResourceUse` has four independent axes:

- items;
- logical bytes;
- retained bytes;
- tasks.

Logical bytes describe live content. Retained bytes use the producer's documented measurement contract and include unused capacity only when that producer reports it. The two byte values are not substituted for each other. The remote-candidate pilot reports Rust `String` and `Vec` capacity bytes. It does not claim allocator metadata, allocator usable size, stack use, or process RSS.

Each family report includes current and peak use, current and peak lease counts, the oldest active lifetime, completed lease count, final completed quantities, total completed lifetime, and a sticky `measurement_inexact` flag.

## Ownership and cleanup

Callers provide a family and a measured `ResourceUse`. The accountant returns an `ObservationLease`. Dropping that lease removes the active measurement and records its lifetime at every scope in its path.

A caller that owns a growing or shrinking collection may replace the lease's measured quantity with a fresh measurement from that same object. This changes measurement only.

Arithmetic is checked before saturation. Overflow, inconsistent subtraction, a poisoned scope lock, or a poisoned hierarchy transaction marks the affected report inexact. Counters do not wrap or underflow.

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

## Arc 02B integration status

The remote ICE candidate pilot is the first production caller. Candidate values and the pre-SDP queue container are observed. The pilot does not cover signaling queues, WebRTC or ICE agent internals, other pre-authentication allocations, post-authentication allocations, or a complete resource family.

No enforcement occurs. A later arc must acquire a real `PreAuthAttemptPermit` before queue insertion. The current queue is a compatibility owner until Attempt Node or Connector Worker owns this state.
