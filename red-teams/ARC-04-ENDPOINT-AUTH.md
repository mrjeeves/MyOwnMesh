# Arc 04 endpoint authentication — threats and residuals

The current threat and residual record for the endpoint-authentication
boundary. [`MESH-ATTACK-VECTORS.md`](MESH-ATTACK-VECTORS.md) remains the
architecture-level threat catalog.

## The boundary

```text
real connector work
    -> ConnectedChannelCapability
    -> EndpointAuthTask
    -> AuthenticatedChannelCapability
    -> current Open or Closed policy
    -> local principal
    -> post-authentication resource admission
    -> SessionCapability
    -> session-bound Channel, reliable, RPC and realtime operations
```

| Concern | Current owner |
|---|---|
| Peer `hello` contribution intake | `EndpointAuthTask::accept_peer_hello` → `AcceptedPeerHello::{FirstBinding, ExactDuplicate}` |
| Peer `auth_response` proof intake | `EndpointAuthTask::accept_peer_proof` → `PeerProofAcceptance::{Promoted, AlreadyPromoted}` |
| Sole mint of the authenticated channel | `EndpointAuthTask::accept_peer_proof`; `AuthenticatedChannelCapability::from_verified_exchange` mints the permit internally and `PeerConnection` owns the capability |
| Terminal failure vocabulary | `EndpointAuthError`, returned only by the two intake operations, every variant terminal for the attempt |
| Setup refusal vocabulary | `EndpointAuthSetupError`, fires before or beside an attempt and terminalizes nothing; no conversion exists in either direction |
| Signed transcript commitment | `endpoint_auth::transcript`, domain-tagged and length-prefixed, role-canonical by `transcript::role_of` |
| Channel binding term | `connector::EndpointAuthBinding::webrtc_certificate_fingerprints` |
| Binding-supplier refusal cleanup | the engine `TransportEvent::DataChannelOpen` arm: `worker.refuse_data_channel_open()` then `drop_peer_if_current` |

`endpoint_auth_v1` is an advertisement, not a negotiation input. It decides only
whether an attempt begins; it can never select a weaker profile, and its absence
fails closed with a typed refusal before any transcript is assembled or any
signature is produced or verified.

`rpc::PendingOpId` is a process-local ownership token — a local capability for
naming one filed pending entry again. It is not network authority, not durable,
not a route or session authority, and not a credential. It is never serialized,
never sent, never derived from anything a peer supplies, and no inbound path
reads it.

## Named residuals

- **The channel binding is not session-unique.** The selected term is a DTLS
  certificate fingerprint pair. It is not an RFC 5705 exporter and does not
  cover the key exchange; two channels between the same device pair reusing the
  same certificates carry an identical binding. What it does prove is retained:
  an interceptor terminating DTLS on each leg presents its own certificate, so
  the fingerprints disagree and the signature fails. Replay separation across
  channels is carried by the two per-attempt CSPRNG contributions and by exact
  connector-incarnation ownership, not by the binding. Ownership invalidates
  already-issued tasks and capabilities on channel replacement; it does not make
  an otherwise-valid signature invalid.
- **A true exporter is deferred.** RFC 5705 export is implemented in
  `webrtc-dtls` but unreachable, since `DTLSConn.state` and
  `RTCDtlsTransport::conn()` are both crate-private, so reaching it would mean
  vendoring a third dependency while vendored-tree integrity is still an open
  gate.
- **The permit is not an independent admission.** `EndpointAuthPermit` is
  derived from the runtime of the `ConnectedChannelCapability` the task already
  owns, so what it attests is existing connected-channel ownership rather than a
  fresh pre-authentication admission decision. A real pre-authentication
  admission remains unimplemented and the permit must not be cited as evidence
  of one.
- **There is no runtime-mismatch cause on the issuer path, and one could not
  fire there.** The permit is minted from the connected capability's own
  runtime, because the engine holds no independent `RuntimeIncarnation` to
  compare it against. Exactness on install is carried instead by the retained
  binding record compared in `EndpointAuthTask::issued` and by
  connector-incarnation ownership.
- **Install exactness rests on falsifiable conjuncts only, and adding one back
  is a paired change.** The record retains mesh, local and remote Device, proved
  role, connector incarnation, runtime incarnation, and one transcript identity.
  None of those is a conjunct no fixture can falsify. Two things are left out,
  for two different reasons. The record deliberately does not restate the
  profile or the binding pair: `transcript::transcript_bytes` already commits
  the profile tag and the role-canonical fingerprint pair inside the bytes the
  compared transcript digest covers, so a substituted record differing in
  either already fails that conjunct, and a second stored copy would only be a
  second thing that can drift from the proof. Connector binding provenance is
  not retained at all: it has one reachable variant, is committed nowhere, and
  no consumer distinguishes it. A second binding profile, or a provenance
  distinction some consumer acts on, must land the retained field **and its
  negative control together**; a field re-added alone reintroduces exactly the
  unfalsifiable conjunct this rules out.
- **The RPC fence claims authorization atomicity, not cancellation.** A
  replacement landing after the mint does not cancel a running handler; the run
  is owner-bound, so its replies fail closed against a superseded installation.
