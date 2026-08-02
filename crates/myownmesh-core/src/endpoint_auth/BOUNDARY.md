# Endpoint Auth Task boundary

## Purpose

Own fresh mutual Device authentication for one exact connected channel. Arc 03 moves the connected-channel capability into this owner and binds its installation to the exact connector incarnation. Arc 04 adds the verified transcript and authenticated-channel transition.

## Owned state

The Arc 03 task owns connected-channel provenance. Its handoff records the exact process-local connector incarnation and cleanup owner. Arc 04 adds admitted authentication work, the fresh transcript, ordered endpoint roles, exact mesh-context binding, exact channel binding, and the authenticated result.

## Inputs

- one `ConnectedChannelCapability`;
- one `EndpointAuthPermit` issued after pre-authentication resource admission in Arc 04;
- fresh contributions from both endpoints in Arc 04;
- exact local and remote Device IDs, mesh context, and channel exporter evidence in Arc 04.

## Outputs

- `AuthenticatedChannelCapability` on complete verification;
- bounded authentication observations or a typed failure.

## Dependencies

This task depends on the connected-channel capability and the selected cryptographic profile. It does not depend on application payload, Open or Closed policy decisions, or durable projection.

## Resources

Endpoint-authentication work remains pre-authentication work. The connected transport claim stays owned until native close succeeds. Arc 02 defines the authentication permit type, but Arc 03 does not create a production issuer, admit authentication resources, verify the Arc 04 transcript, or infer a limit.

## Restart behavior

Possession of the permit or authenticated-channel capability grants the authority represented by that type. Its runtime witness grants no authority. The witness only prevents use against a replacement runtime object. The transcript, permit, and capability are memory-only and disappear on process restart. Stored IDs or an old transcript cannot reconstruct them.

## Forbidden responsibilities

This task does not decide mesh policy, mint `SessionCapability`, authorize an application, choose a route, mutate durable facts, or treat a working channel as authenticated without the complete fresh proof.

## Compatibility adapter

`LegacyAuthenticatedChannel<T>` can hold a legacy object only beside an already-issued capability. It cannot create authentication or expose the raw object outside this owner. Arc 05 deletes it when Session Broker consumes the typed channel directly.
