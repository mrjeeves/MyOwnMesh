# Attempt node boundary

## Purpose

Own one bounded connection attempt from admitted speculative work through candidate output. Arc 02 defines the authority and reservation boundary without redirecting the current connector runtime.

## Owned state

The target owner holds one attempt's connector-candidate set, race state, `AttemptLifetime`, and ephemeral correlation. One attempt may own multiple connector candidates. A WebRTC connector candidate is one complete `RTCPeerConnection` and ICE-agent instantiation, not one trickled ICE candidate.

## Inputs

- local connection intent;
- bounded transport hints;
- one aggregate pre-authentication resource reservation represented by `PreAuthAttemptPermit`;
- typed connector-control input and cancellation.

## Outputs

- `ConnectorCandidateCapability` with one child reservation and exact attempt ownership;
- bounded observations, candidate updates, cancellation, or failure.

## Dependencies

The capability spine depends only on local ownership and move semantics. Arc 03 may depend on connector ports, but this node does not depend on application APIs, durable projection, or endpoint authentication.

## Resources

`PreAuthAttemptPermit` is not consumed by its first connector candidate. It owns one aggregate reservation and may issue several child reservations. Each connector candidate carries its child reservation and an unforgeable witness for the exact attempt that issued it.

The aggregate is a fixed vector over the closed pre-authentication resource-family set. Capacity in one family cannot pay for another family. Arc 03 still supplies no production capacity.

The child is acquired before the candidate allocation closure runs. A refused child claim does not run that closure. Dropping a candidate returns its active claim to the aggregate.

Arc 02 does not invent a production capacity. The resource owner must supply measured, owner-approved capacity before the production attempt path is migrated. Anonymous-ingress and process-global admission must remain possible before a Device identity or Closed authorization is known.

## Restart behavior

Possession of an attempt permit or connector-candidate capability grants the authority represented by that type. `AttemptLifetime` grants no connector authority. It retires candidate capabilities that are still owned by the exact attempt and rejects their delayed work after cancellation. A candidate already consumed into `ConnectedChannelCapability` has completed that transition and is no longer an awaiting race candidate. Runtime and lifetime witnesses cannot recreate authority. Attempt permits and connector-candidate capabilities are memory-only and disappear on process restart.

## Forbidden responsibilities

This node does not own durable facts, Open or Closed policy, endpoint identity proof, application payload, session authority, relay fanout, or unbounded speculative work.

## Compatibility adapter

`LegacyConnectorCandidate<T>` carries an existing legacy connector object beside an already-created capability. It cannot create authority from the legacy value. Arc 03 deletes it when all connector callers consume `ConnectorCandidateCapability` directly.
