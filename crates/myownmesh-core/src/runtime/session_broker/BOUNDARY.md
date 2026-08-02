# Session Broker boundary

## Purpose

Own the single atomic transition from authenticated channel plus current policy, authenticated local principal, and post-authentication capacity into `SessionCapability`. Arc 02 defines the types only. Arc 05 implements promotion.

## Owned state

The target owner holds current policy guards, principal bindings, post-authentication permits, and live promoted-session capabilities. No mutable production state moves here in Arc 02.

## Inputs

- one currently working `AuthenticatedChannelCapability`;
- exact mesh and endpoint bindings from fresh endpoint authentication;
- current Open or Closed policy result;
- one allowed `LocalPrincipalCapability`;
- one `SessionPermit` for separately admitted post-authentication capacity.

## Outputs

- a fresh `SessionCapability` after one atomic successful promotion;
- typed policy, principal, resource, stale-channel, or authentication failures.

## Dependencies

Session Broker depends on Semantic Node policy output, Endpoint Auth Task output, Application Gateway principal proof, and post-authentication resource policy. It does not depend on signaling carrier identity or public route and peer labels.

## Resources

Session capacity is a post-authentication class distinct from all attempt and endpoint-authentication work. Arc 02 defines `SessionPermit` but has no production issuer and chooses no bound.

## Restart behavior

Possession of a session capability or permit grants the authority represented by that type. Its runtime witness grants no authority. The witness only prevents use against a replacement runtime object. Session capabilities and permits are memory-only and disappear on process restart. Opening durable state, replaying an old transcript, or presenting an old label does not reconstruct them.

## Forbidden responsibilities

This node does not gather candidates, run packet loops, parse application meaning, infer a principal from a client label, accept a connected channel as authenticated, or promote without every `MayPromote` predicate.

## Arc 02 construction status

There is no production Session mint in Arc 02. The `cfg(test)` scaffold exists only to prove type composition and runtime binding. It is not a policy or authentication implementation.

## Compatibility adapter

`LegacySession<T>` can hold a legacy session only beside an already-issued capability and cannot expose its raw value outside this owner. Arc 06 deletes it when application entry points require `SessionCapability` directly.
