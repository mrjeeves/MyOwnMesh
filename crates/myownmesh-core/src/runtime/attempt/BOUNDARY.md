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

Each active claim is an exact vector over the closed resource-class set. Capacity in one class cannot pay for another class. Arc 03 derives the connector floor from the owned transport object, construction work, cleanup obligation, candidate-attempt root, and task ownership. `FiniteResourceProvider` owns one explicit process grant. Every live Mesh runtime receives an attribution scope over that same grant, not another grant or a mandatory share. Connector scope creation and its first lease commit atomically, so concurrent empty scopes cannot consume the bookkeeping needed by an otherwise admissible connector. Admission succeeds while the named resource classes are available and otherwise returns typed pressure. Basal MyOwnMesh sets no Mesh, peer, attempt, session, or flow count.

Remote candidate content, callback work, real-time units, storage, and cleanup work obtain separate finite leases at their ownership boundaries. Exactness applies only to the quantity named by each lease. For local ICE conversion, structural work and an opaque residual precede `webrtc-rs::RTCIceCandidate::to_json`; exact returned String content and capacities are charged before MyOwnMesh retention. Optional local ceilings may restrict a locked-down deployment or a compatibility provider, but ordinary construction does not require product counts. Real-time may be explicitly disabled without placeholder media values. Native close remains `Closing` until the dependency returns. Elapsed time and caller cancellation do not prove cleanup disposition.

The child is acquired before connector construction starts. A refused child claim performs no allocation. Real asynchronous construction runs in an owned task. Cancellation fences publication, closes any private native result, and returns the child claim only after successful native cleanup.

Candidate promotion atomically changes the child from its opening claim to its connected claim. Candidate-only construction work is released while the transport claim remains with the connected-channel capability.

Arc 03 does not invent production values. A deployment supplies a finite provider grant in actual resource dimensions. Measurements characterize performance, expose opaque allocations, and inform optional local policy, but they do not define a universal object count. Anonymous-ingress and process-global admission remain possible before a Device identity or Closed authorization is known. A known per-candidate cleanup failure retains that exact claim without poisoning unrelated process capacity. Only an accounting state whose aggregate total cannot be proved poisons that aggregate. Dependency-owned allocations that cannot yet be measured or enforced remain named residuals rather than guessed peer or flow costs.

## Restart behavior

Possession of an attempt permit or connector-candidate capability grants the authority represented by that type. `AttemptLifetime` grants no connector authority. It retires candidate capabilities that are still owned by the exact attempt and rejects their delayed work after cancellation. A candidate already consumed into `ConnectedChannelCapability` has completed that transition and is no longer an awaiting race candidate. Runtime and lifetime witnesses cannot recreate authority. Attempt permits and connector-candidate capabilities are memory-only and disappear on process restart.

## Forbidden responsibilities

This node does not own durable facts, Open or Closed policy, endpoint identity proof, application payload, session authority, relay fanout, or unbounded speculative work.
