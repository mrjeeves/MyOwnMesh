# Connector worker boundary

## Purpose

Own native connector work and turn one admitted candidate into a live connected channel. Arc 02 installs the type boundary without changing transport behavior.

## Owned state

The target owner holds connector-native attempt state, one live channel, and optional connector-native flow state. The existing implementation keeps that mutable state until Arc 03.

## Inputs

- one `CandidateCapability` consumed by the connector;
- typed candidate updates and connector callbacks;
- bounded cancellation and observation requests.

## Outputs

- `ConnectedChannelCapability` after the channel is proven to work;
- connector observations, failure, or cleanup completion.

## Dependencies

The connector depends on the attempt capability and its connector-specific transport implementation. It does not depend on application codecs, durable semantic projection, Open or Closed policy, or application authorization.

## Resources

Connector work remains covered by the pre-authentication permit owned by the consumed candidate. Arc 03 will attach the existing WebRTC, ICE, STUN, and TURN allocations to measured resource accounting.

## Restart behavior

Possession of a connected-channel capability grants the authority represented by that type. Its runtime witness grants no authority. The witness only prevents use against a replacement runtime object. Connected-channel capabilities and native channel objects are memory-only and disappear on process restart. Public labels and stored diagnostics cannot recreate them.

## Forbidden responsibilities

This worker does not mint session authority, decide mesh authorization, authenticate a Device, parse application payload meaning, mutate durable facts, or forward application data through signaling.

## Compatibility adapter

`LegacyConnectedChannel<T>` keeps the current native channel object beside an already-created capability. It cannot create authority from the legacy value. Arc 04 deletes it when endpoint authentication consumes `ConnectedChannelCapability` directly.
