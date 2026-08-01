# Relay Node boundary

## Purpose

Own exact bounded opaque relay allocations. Arc 02 installs `RelayAllocationPermit`; Arc 12 supplies production allocation profiles and deletes ordinary member forwarding.

## Owned state

The target owner holds exact allocation endpoints, bounded queues and buffers, allocation lifetime, and relay-local observations. No mutable relay state moves in Arc 02.

## Inputs

- one exact allocation request tied to live attempt or session authority;
- exact permitted destination and endpoints;
- one `RelayAllocationPermit` from resource admission;
- typed payload-blind carrier bytes.

## Outputs

- one exact opaque relay allocation or typed failure;
- bounded allocation, bandwidth, buffer, and lifetime observations.

## Dependencies

Relay Node depends on typed attempt or session ports and the selected relay profile. It does not depend on application parsing, signaling service identity, durable governance mutation, or arbitrary next-hop selection.

## Resources

Pre-authentication relay attempts and post-authentication relay data use separate reviewed resource families. Arc 02 creates no production permit issuer and selects no allocation, queue, lifetime, or bandwidth value.

## Restart behavior

Allocation permits and live allocations are memory-only and tied to one runtime. A process restart destroys them. After a same-process runtime replacement, a future consumer must compare their witness with the current Runtime Supervisor witness before use. Public destinations, route labels, and stored records cannot recreate them.

## Forbidden responsibilities

This node does not authenticate endpoints, mint sessions, parse application payload, fan out to ordinary mesh members, authorize a destination from a public label, or treat relay identity as peer identity.
