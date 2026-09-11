# Application Gateway boundary

## Purpose

Bind an authenticated local operating-system principal to public handles and post-promotion application operations.

## Owned state

The owner holds authenticated local principals, IPC connections, public handle leases, and subscriptions.

## Inputs

- operating-system principal evidence through the owner-selected binding, which is the local process itself;
- a live `SessionCapability` from Session Broker;
- typed application operations.

## Outputs

- `LocalPrincipalCapability` after local authentication;
- bounded public handles, callbacks, and application operations after session promotion.

## Dependencies

The gateway depends on local operating-system authentication and Session Broker output. It does not depend on connector internals or signaling carrier control.

## Resources

Local handles, subscriptions, callbacks, and application queues use the post-authentication resource class. This owner issues no capacity proof of its own: application queue capacity is admitted by the resource policy that owns it, and a separate permit type here would be a second claim to keep in step with the first.

## Restart behavior

Possession of a principal capability grants the authority represented by that type. Its runtime witness grants no authority. The witness only prevents use against a replacement runtime object. Principals, handles, and subscriptions disappear on process restart. A stored client, request, session, route, or peer label cannot recreate them.

## Forbidden responsibilities

The gateway does not mint `SessionCapability`, control a connector, decide endpoint authentication, mutate durable mesh authority, or send application payload through signaling.
