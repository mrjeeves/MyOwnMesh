# Application Gateway boundary

## Purpose

Bind an authenticated local operating-system principal to public handles and post-promotion application operations. Arc 02 installs the principal and queue permit types without selecting the operating-system binding.

## Owned state

The target owner holds authenticated local principals, IPC connections, public handle leases, and subscriptions. Existing production state remains in the legacy daemon and facade during Arc 02.

## Inputs

- operating-system principal evidence through the owner-selected binding;
- a live `SessionCapability` from Session Broker;
- an `ApplicationQueuePermit` from post-authentication resource admission;
- typed application operations.

## Outputs

- `LocalPrincipalCapability` after local authentication;
- bounded public handles, callbacks, and application operations after session promotion.

## Dependencies

The gateway depends on local operating-system authentication, Session Broker output, and post-authentication resource policy. It does not depend on connector internals or signaling carrier control.

## Resources

Local handles, subscriptions, callbacks, and application queues use the post-authentication resource class. Arc 02 defines the queue permit but does not issue it in production or select a capacity.

## Restart behavior

Principals, queue permits, handles, and subscriptions are tied to one runtime and disappear on process restart. After a same-process runtime replacement, a future consumer must compare their witness with the current Runtime Supervisor witness before use. A stored client, request, session, route, or peer label cannot recreate them.

## Forbidden responsibilities

The gateway does not mint `SessionCapability`, control a connector, decide endpoint authentication, mutate durable mesh authority, or send application payload through signaling.

## Compatibility adapter

`LegacyPrincipal<T>` can hold a legacy principal only beside an already-issued capability. It cannot infer authority from the legacy value or expose the raw value outside this owner. Arc 06 deletes it with the legacy application facade.
