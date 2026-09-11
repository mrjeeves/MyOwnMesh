# Connector worker boundary

## Purpose

Own native connector work and turn one admitted candidate into a live connected channel. The WebRTC runtime sits behind this owner; the transport protocol on the wire is unchanged by that placement.

## Owned state

`WebRtcConnectorWorker` holds connector-native attempt state, one live channel, its callback incarnation, pending remote candidates, cleanup state, and optional connector-native flow state.

## Inputs

- one `ConnectorCandidateCapability` consumed by the connector;
- typed candidate updates and connector callbacks;
- bounded cancellation and observation requests.

## Outputs

- `ConnectedChannelCapability` after the channel is proven to work;
- connector observations, failure, or cleanup completion.

The connector issues no separate real-time authority. Real-time work is authorized by the promoted session that owns the flow set, which the engine mints under its registry fence; the connector only carries units for flows that session already opened.

## Dependencies

The connector depends on the attempt capability and its connector-specific transport implementation. It does not depend on application codecs, durable semantic projection, Open or Closed policy, or application authorization.

## Resources

Connector work remains covered by the child reservation owned by the consumed candidate. Promotion explicitly transfers the opening claim to a connected claim. The connected claim moves into Endpoint Auth Task, while the connector cleanup owner retains release responsibility through successful native close. A returned close error or cleanup-start failure retains only that connector's exact claim. A native close that does not return remains `Closing` and retains its finite claim. No timer changes that state. Aggregate accounting corruption remains process-fatal because the total can no longer be proved. The structural claim covers the known WebRTC ownership sites; resources held inside the dependency itself remain outside it.

## Restart behavior

Possession of a connected-channel capability grants the authority represented by that type. Its process-local connector incarnation grants no authority. The incarnation only prevents a handoff from being installed against another connector, including a replacement in the same runtime. Connected-channel capabilities and native channel objects are memory-only and disappear on process restart. Public labels and stored diagnostics cannot recreate them.

## Forbidden responsibilities

This worker does not mint session authority, decide mesh authorization, authenticate a Device, parse application payload meaning, mutate durable facts, or forward application data through signaling. It names no codec, media kind, or application lane meaning; the real-time authority it carries units under is session-bound, principal-bound, policy-guarded, and independently resource-reserved, and is minted elsewhere.

## Handoff to endpoint authentication

Endpoint authentication consumes the connected channel directly. `EndpointAuthHandoff` carries capability, connector incarnation, and close owner together; `EndpointAuthHandoff::into_generic` narrows it to the transport-neutral `ConnectedChannelHandoff`; `EndpointAuthTask::begin` takes that whole value, so close-owner retention travels with the promotion. There is no wrapper type between the two, and no path that pairs a capability with an unauthenticated native object.
