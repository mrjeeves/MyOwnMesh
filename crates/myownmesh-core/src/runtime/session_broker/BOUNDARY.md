# Session Broker boundary

## Purpose

Own the single atomic transition from authenticated channel plus current policy, authenticated local principal, and post-authentication capacity into `SessionCapability`.

## Owned state

The owner holds current policy guards, principal bindings, post-authentication permits, and live promoted-session capabilities.

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

Session capacity is a post-authentication class distinct from all attempt and endpoint-authentication work. `SessionPermit` is reserved against the owner's resource scope inside `promote`, so a session that could not be paid for is not promoted; the bound is the provider's, not a constant chosen here.

## Restart behavior

Possession of a session capability or permit grants the authority represented by that type. Its runtime witness grants no authority. The witness only prevents use against a replacement runtime object. Session capabilities and permits are memory-only and disappear on process restart. Opening durable state, replaying an old transcript, or presenting an old label does not reconstruct them.

## Forbidden responsibilities

This node does not gather candidates, run packet loops, parse application meaning, infer a principal from a client label, accept a connected channel as authenticated, or promote without every `MayPromote` predicate.

`SessionBroker::promote` is the sole mint. There is no adapter that pairs a session capability with an unpromoted value: application entry points require `SessionCapability` directly.
