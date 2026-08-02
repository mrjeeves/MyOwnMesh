# Connector worker boundary

## Purpose

Own native connector work and turn one admitted candidate into a live connected channel. Arc 03 places the existing WebRTC runtime behind this owner without changing its transport protocol.

## Owned state

`WebRtcConnectorWorker` holds connector-native attempt state, one live channel, its callback incarnation, pending remote candidates, cleanup state, and optional connector-native flow state.

## Inputs

- one `ConnectorCandidateCapability` consumed by the connector;
- typed candidate updates and connector callbacks;
- bounded cancellation and observation requests.

## Outputs

- `ConnectedChannelCapability` after the channel is proven to work;
- an optional compatibility-only `ConnectorRealtimeFlowCapability` after the current peer is admitted through exact Endpoint Auth provenance;
- connector observations, failure, or cleanup completion.

## Dependencies

The connector depends on the attempt capability and its connector-specific transport implementation. It does not depend on application codecs, durable semantic projection, Open or Closed policy, or application authorization.

## Resources

Connector work remains covered by the child reservation owned by the consumed candidate. Promotion explicitly transfers the opening claim to a connected claim. The connected claim moves into Endpoint Auth Task, while the connector cleanup owner retains release responsibility through successful native close. A known close error, timeout, or cleanup-start failure retains only that connector's exact claim. It does not poison unrelated slots. Aggregate accounting corruption remains process-fatal because the total can no longer be proved. Arc 03 observes known WebRTC ownership sites, but complete dependency resources remain outside the structural claim.

## Restart behavior

Possession of a connected-channel capability grants the authority represented by that type. Its process-local connector incarnation grants no authority. The incarnation only prevents a handoff from being installed against another connector, including a replacement in the same runtime. Connected-channel capabilities and native channel objects are memory-only and disappear on process restart. Public labels and stored diagnostics cannot recreate them.

## Forbidden responsibilities

This worker does not mint session authority, decide mesh authorization, authenticate a Device, parse application payload meaning, mutate durable facts, or forward application data through signaling. The compatibility real-time capability names no codec, media kind, or application lane meaning. A final real-time capability must be session-bound, principal-bound, policy-guarded, and independently resource-reserved.

## Compatibility adapter

`LegacyConnectedChannel<T>` keeps the current native channel object beside an already-created capability. It cannot create authority from the legacy value. Arc 04 deletes it when endpoint authentication consumes `ConnectedChannelCapability` directly.
