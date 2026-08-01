# Attempt node boundary

## Purpose

Own one bounded connection attempt from admitted speculative work through candidate output. Arc 02 adds the authority types without changing the current runtime.

## Owned state

The target owner holds one attempt's candidate set, race state, cancellation state, and ephemeral correlation. None of that mutable state moves in Arc 02.

## Inputs

- local connection intent;
- bounded transport hints;
- a pre-authentication resource admission represented by `PreAuthAttemptPermit`;
- typed connector-control input and cancellation.

## Outputs

- `CandidateCapability` for one admitted candidate;
- bounded observations, candidate updates, cancellation, or failure.

## Dependencies

The capability spine depends only on local ownership and move semantics. Arc 03 may depend on connector ports, but this node does not depend on application APIs, durable projection, or endpoint authentication.

## Resources

`PreAuthAttemptPermit` is the typed seam for resource admission. Arc 02 does not invent or enforce an unmeasured value. The resource owner supplies accounting before the production attempt path is migrated.

## Restart behavior

Possession of an attempt permit or candidate capability grants the authority represented by that type. Its runtime witness grants no authority. The witness only prevents use against a replacement runtime object. Attempt permits and candidate capabilities are memory-only and disappear on process restart. Durable records and public identifiers cannot recreate them.

## Forbidden responsibilities

This node does not own durable facts, Open or Closed policy, endpoint identity proof, application payload, session authority, relay fanout, or unbounded speculative work.

## Compatibility adapter

`LegacyCandidate<T>` carries an existing legacy candidate beside an already-created capability. It cannot create authority from the legacy value. Arc 03 deletes it when all connector callers consume `CandidateCapability` directly.
