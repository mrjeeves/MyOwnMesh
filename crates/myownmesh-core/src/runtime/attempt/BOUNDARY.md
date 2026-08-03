# Attempt node boundary

## Purpose

Own one bounded connection attempt from admitted speculative work through candidate output. Arc 03 connects this authority and reservation boundary to the production WebRTC connector owner.

## Owned state

The target owner holds one attempt's connector-candidate set, race state, `AttemptLifetime`, and ephemeral correlation. One attempt may own multiple connector candidates. A WebRTC connector candidate is one complete `RTCPeerConnection` and ICE-agent instantiation, not one trickled ICE candidate.

## Inputs

- local connection intent;
- bounded transport hints;
- one unforgeable `MeshConnectorResourceScope` issued by the process owner;
- typed connector-control input and cancellation.

## Outputs

- `ConnectorCandidateCapability` with one child reservation and exact attempt ownership;
- bounded observations, candidate updates, cancellation, or failure.

## Dependencies

The capability spine depends only on local ownership and move semantics. Arc 03 may depend on connector ports, but this node does not depend on application APIs, durable projection, or endpoint authentication.

## Resources

`PreAuthAttemptPermit` is not consumed by its first connector candidate. It may request several child reservations, but it cannot create capacity. Every request goes through the exact Mesh child scope. Each connector candidate carries its admitted reservation and an unforgeable witness for the exact attempt that issued it.

The active claim is a fixed vector over the closed pre-authentication resource-family set. Capacity in one family cannot pay for another family. Arc 03 supplies only the fixed per-candidate structure needed to prove ownership of one transport object, construction work, and an owned task slot. `ProcessResourceRoot` installs one process owner and issues a separate child scope for each live Mesh runtime. Admission updates the process and exact child atomically. The external owner supplies the process and per-Mesh candidate ceilings, pre-SDP candidate item and byte ceilings, reliable callback mailbox capacities, scheduler weights, and structural real-time flow limits. Real-time may instead be explicitly disabled without placeholder media values. There is no production default or inferred child share. Native close remains `Closing` until the dependency returns. Elapsed time and caller cancellation do not prove cleanup disposition.

The child is acquired before connector construction starts. A refused child claim performs no allocation. Real asynchronous construction runs in an owned task. Cancellation fences publication, closes any private native result, and returns the child claim only after successful native cleanup.

Candidate promotion atomically changes the child from its opening claim to its connected claim. Candidate-only construction work is released while the transport claim remains with the connected-channel capability.

Arc 03 does not invent production values. The resource owner must supply measured, owner-approved values. Anonymous-ingress and process-global admission remain possible before a Device identity or Closed authorization is known. A known per-candidate cleanup failure retains that exact claim without poisoning unrelated process slots. Only accounting states whose aggregate total cannot be proved refuse all later admission. The current port bounds active connector candidates, but it is not a complete hostile-ingress model for every dependency-owned allocation.

## Restart behavior

Possession of an attempt permit or connector-candidate capability grants the authority represented by that type. `AttemptLifetime` grants no connector authority. It retires candidate capabilities that are still owned by the exact attempt and rejects their delayed work after cancellation. A candidate already consumed into `ConnectedChannelCapability` has completed that transition and is no longer an awaiting race candidate. Runtime and lifetime witnesses cannot recreate authority. Attempt permits and connector-candidate capabilities are memory-only and disappear on process restart.

## Forbidden responsibilities

This node does not own durable facts, Open or Closed policy, endpoint identity proof, application payload, session authority, relay fanout, or unbounded speculative work.
