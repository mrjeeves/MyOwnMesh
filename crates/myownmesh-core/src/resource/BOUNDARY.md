# Resource observation boundary

## Purpose

This module measures resource use by the closed pre-authentication and post-authentication families defined in sections 14.1 and 14.2 of `IMPLEMENTATION-CONSTRAINTS-AND-INVARIANTS.md`.

It is observation infrastructure. It is not resource policy.

## Owned state

Each explicitly created `ResourceAccountant` owns one isolated in-memory measurement state. That state contains:

- active item, byte, and task totals by family;
- peak active item, byte, task, and lease totals by family;
- active observation counts and start times;
- completed observation counts, final measured quantities, and total lifetimes;
- a sticky indication that overflow or inconsistent subtraction made a measurement inexact.

There is no process-global accountant.

## Inputs and outputs

Callers provide a family and a measured `ResourceUse`. The accountant returns an `ObservationLease`. Dropping that lease removes the active measurement and records its lifetime.

A caller that owns a growing or shrinking collection may replace the lease's measured quantity with a new value derived from that live object. This changes the measurement only.

Reports include every closed family, including families with zero activity. They preserve active, peak, completed, and lifetime measurements. They are snapshots of measurements only.

## Dependencies

The module uses only standard-library synchronization, collections, and monotonic time. It performs no filesystem, process, socket, signaling, connector, relay, or application operation.

## Resource and restart behavior

An accountant retains one small record for each family it has observed and one start-time entry for each distinct active observation start. All arithmetic is checked first and saturates instead of wrapping. Lease completion uses checked subtraction with a zero floor, so dropping a lease cannot underflow counters.

Measurements are in memory and disappear with the owning process. They are not reconstructed from durable state after restart.

## Forbidden responsibilities

This module must not:

- define or infer a limit;
- accept or refuse work;
- reserve capacity;
- create a permit or capability;
- authorize an identity, mesh, connection, session, route, or application action;
- treat a pre-authentication observation as post-authentication capacity;
- provide backpressure, eviction, prioritization, or admission policy;
- perform networking or mutate production domain state.

An `ObservationLease` proves only that this accountant is currently measuring a caller-reported quantity. It is never evidence that the measured work was allowed, reserved, authenticated, or safe.

## Arc 02 integration status

This module has no production allocation caller in the current slice. A report containing zeros therefore does not prove zero use or complete coverage. Current allocation instrumentation remains an open Arc 02 gate.
