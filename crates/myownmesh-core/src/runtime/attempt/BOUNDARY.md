# Attempt node boundary

## Purpose

Own one bounded connection attempt from admitted speculative work through candidate output. Arc 02 defines the authority and reservation boundary without redirecting the current connector runtime.

## Owned state

The target owner holds one attempt's candidate set, race state, cancellation state, and ephemeral correlation. None of that mutable state moves in Arc 02.

## Inputs

- local connection intent;
- bounded transport hints;
- one aggregate pre-authentication resource reservation represented by `PreAuthAttemptPermit`;
- typed connector-control input and cancellation.

## Outputs

- `CandidateCapability` with one child reservation and exact attempt ownership;
- bounded observations, candidate updates, cancellation, or failure.

## Dependencies

The capability spine depends only on local ownership and move semantics. Arc 03 may depend on connector ports, but this node does not depend on application APIs, durable projection, or endpoint authentication.

## Resources

`PreAuthAttemptPermit` is not consumed by its first candidate. It owns one aggregate reservation and may issue several child reservations. Each candidate carries its child reservation and an unforgeable witness for the exact attempt that issued it.

The child is acquired before the candidate allocation closure runs. A refused child claim does not run that closure. Dropping a candidate returns its active claim to the aggregate.

Arc 02 does not invent a production capacity. The resource owner must supply measured, owner-approved capacity before the production attempt path is migrated. Anonymous-ingress and process-global admission must remain possible before a Device identity or Closed authorization is known.

## Restart behavior

Possession of an attempt permit or candidate capability grants the authority represented by that type. Its runtime witness grants no authority. The witness only prevents use against a replacement runtime object. Attempt permits and candidate capabilities are memory-only and disappear on process restart. Durable records and public identifiers cannot recreate them.

## Forbidden responsibilities

This node does not own durable facts, Open or Closed policy, endpoint identity proof, application payload, session authority, relay fanout, or unbounded speculative work.

## Compatibility adapter

`LegacyCandidate<T>` carries an existing legacy candidate beside an already-created capability. It cannot create authority from the legacy value. Arc 03 deletes it when all connector callers consume `CandidateCapability` directly.
