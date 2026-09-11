# Endpoint Auth Task boundary

## Purpose

Own fresh mutual Device authentication for one exact connected channel. The connected-channel capability lives in this owner, its installation is bound to the exact connector incarnation, and this owner runs the verified transcript and the authenticated-channel transition.

Ownership is narrower than "endpoint authentication" as a whole, and the split matters because three other owners are involved on every attempt:

- **This owner** holds the exchange state machine (`EndpointAuthTask`), the closed profile (`EndpointAuthProfile`, fixed in `context`), the signed transcript framing (`transcript`), both refusal vocabularies (`EndpointAuthSetupError` and `EndpointAuthError`), and the two frame-intake operations `EndpointAuthTask::accept_peer_hello` and `EndpointAuthTask::accept_peer_proof`. It is the sole issuer of `AuthenticatedChannelCapability`.
- **The connector** supplies the channel-binding term and nothing else. `EndpointAuthBinding::webrtc_certificate_fingerprints` is read from the connector worker's live native session; this owner never reads SDP, a certificate, or a key.
- **The engine handshake path** (`engine::handshake::on_hello`, `on_auth_response`) owns the wire frames, the peer registry effects, and the fail-closed corroboration after promotion. It calls the two intake operations; it does not decide authentication.
- **The engine `DataChannelOpen` arm** owns the refusal-and-cleanup path when the binding supplier has nothing to supply. See "Fail-closed binding supply" below.

This owner therefore never sees a `HelloMessage`, never sends a frame, and never touches the peer registry.

## Owned state

The task owns connected-channel provenance. Its handoff records the exact process-local connector incarnation and cleanup owner. It also owns the fresh transcript, ordered endpoint roles, exact mesh-context binding, the selected channel-binding terms (both endpoints' DTLS certificate fingerprints, which are not session-unique — see Residual), and the authenticated result. It performs **no** independent resource admission: the permit attests the connected-channel ownership this task already holds. Exactness of channel identity is carried by the composition of per-attempt contribution freshness and process-local connector-incarnation ownership, not by the binding terms.

## Inputs

- one `ConnectedChannelCapability`;
- one `EndpointAuthPermit` per attempt. **It is not backed by a separate resource admission.** The constructor derives it from the runtime of the `ConnectedChannelCapability` the task already owns, so what it attests is existing connected-channel ownership, not a fresh admission decision. A real pre-authentication admission is unimplemented; the permit must not be cited as evidence of one;
- fresh contributions from both endpoints;
- exact local and remote Device IDs, mesh context, and the selected channel binding — the DTLS certificate fingerprints of **both** endpoints, in role-canonical order. Not an exporter; see Residual.

Exactly two operations take peer-supplied bytes, and each answers a closed outcome rather than a bool:

- `accept_peer_hello` takes the peer's contribution and answers `AcceptedPeerHello::FirstBinding` or `AcceptedPeerHello::ExactDuplicate`. A retransmission carrying the same contribution is answered from the cached proof; a *different* contribution is the terminal `EndpointAuthError::ConflictingPeerContribution`, and none of the frame's other fields are ever adopted.
- `accept_peer_proof` takes the peer's signature and answers `PeerProofAcceptance::Promoted(Box<AuthenticatedChannelCapability>)` or the payload-free `PeerProofAcceptance::AlreadyPromoted`.

`AlreadyPromoted` is a lifecycle fact and nothing more. It does not say the replayed signature verified — a promoted attempt's state is read under the lock before any verification, so those bytes are never examined — and it does not say the capability was installed. It carries no payload precisely so a second caller cannot be handed, or lent, the capability the promoting caller already holds. Callers must corroborate installation and current-attempt ownership against their own state and fail closed without both.

## Closed profile and the compatibility precondition

The profile is a closed single-variant enum, `EndpointAuthProfile::V1Ed25519Dtls`, **fixed** in `context` and committed inside the signed transcript as its own profile tag, alongside — not folded into — the Arc-04 domain tag that leads the transcript. It is never supplied by the engine and never by a peer.

`negotiate_profile` resolves what to prove under from the peer's advertised `features`, and despite its name it is not a negotiation: advertising `endpoint_auth_v1` is how a peer states it speaks the one closed profile, not how it chooses among alternatives. There is no second inhabitant, no fallback, and no third outcome. Absence is `EndpointAuthSetupError::IncompatibleProfile`, refused **before** any proof work — no transcript is assembled, no signature is produced or verified, and no capability can be minted. Treat the advertisement as a fail-closed compatibility precondition against pre-Arc-04 peers, never as a profile-selection input a peer could steer.

It is a *setup* refusal and deliberately not a terminal one: the gate runs on the inbound Hello before the attempt is reached, so nothing has been terminalized when it fires. What closes the connection is the handler's own fail-closed drop of the exact current peer.

## Two refusal vocabularies, and no conversion between them

- `EndpointAuthSetupError` — this input was unusable, and no attempt was harmed. `MissingIdentityField`, `MissingContribution`, `ContributionWrongWidth`, `ContributionMalformed`, `IncompatibleProfile`. These fire before or beside an attempt and terminalize nothing.
- `EndpointAuthError` — this attempt is over. Returned only by the task's own lifecycle transitions, `accept_peer_hello` and `accept_peer_proof`: `NoBoundTranscript`, `NotMutual`, `ContributionNotFresh`, `SignatureInvalid`, `ChannelNotCurrent`, `ConflictingPeerContribution`. Every one of them means the attempt has been terminalized, is retired, belongs to no connector, and vouches for nothing.

The closure holds in both directions, and there is deliberately no conversion either way. A setup refusal widened into a terminal cause would let a parse failure claim a lifecycle transition it never made; a terminal cause narrowed into a setup refusal would lose the retirement it actually performed. Neither type is ever used to say "this call had nothing to do" — that is the non-error `AcceptedPeerHello::ExactDuplicate` or `PeerProofAcceptance::AlreadyPromoted`.

## Signed transcript commitment

`transcript` owns the byte layout and nothing else, and it is the single implementation, so no second copy can drift from the bytes a peer verifies. Two properties are load-bearing: every paired field is ordered by role — derived from the Device pair by `transcript::role_of`, never chosen by a caller — so both endpoints derive byte-identical input from opposite views; and every field is length-prefixed rather than separator-joined, so no free-form value can shift a later field boundary and make two distinct field tuples serialize identically. The transcript commits to the domain tag, the mesh context, the selected profile, the signer's role, the ordered Device pair, the ordered contribution pair, and the ordered binding pair. Because the profile is a signed field, a peer cannot advertise one profile and prove another.

## Fail-closed binding supply

The binding is supplied, not derived here. When the connector's `endpoint_auth_binding()` yields nothing at `DataChannelOpen`, the engine arm fails closed and the refusal is a *cleanup* obligation as well as a refusal: the connector is fenced first via `refuse_data_channel_open`, which starts exactly one native close synchronously — there is no watchdog behind it, so a close not started there would never start — and only then `drop_peer_if_current` removes the peer, and only if it is still the exact entry the open was admitted for. A replacement installed for the same device while the binding was being read is left untouched: the refusal is about one channel, not about the device. No task is built, no `hello` is sent, no proof is computed, and no profile is resolved.

## Residual: the channel binding is not session-unique

The selected binding term is a DTLS **certificate fingerprint** pair. A certificate fingerprint identifies the certificate, not the session: reusing a certificate across connections yields the same fingerprint, and it does not cover the key exchange. It is therefore **not an RFC 5705 exporter**, and two channels between the same device pair reusing the same certificates carry an identical binding.

What the binding does prove is real and is retained: an interceptor terminating DTLS on each leg must present its own certificate, so the fingerprints disagree and the signature fails. That defeats the terminating signaling man-in-the-middle.

What it does not carry is replay separation across channels. **That is carried by the two per-attempt CSPRNG contributions and by exact connector-incarnation ownership, not by the binding.** If either weakens, the property is lost. Ownership invalidates already-issued tasks and capabilities on channel replacement; it does not make an otherwise-valid signature invalid.

A true exporter is deferred: RFC 5705 export is implemented in `webrtc-dtls` but unreachable, since `DTLSConn.state` and `RTCDtlsTransport::conn()` are both crate-private, so reaching it would mean vendoring a third dependency while vendored-tree integrity is still an open gate.

## Outputs

- `AuthenticatedChannelCapability` on complete verification;
- bounded authentication observations or a typed failure.

## Dependencies

This task depends on the connected-channel capability and the selected cryptographic profile. It does not depend on application payload, Open or Closed policy decisions, or durable projection.

## Resources

Endpoint-authentication work remains pre-authentication work. The connected transport claim stays owned until native close succeeds. No authentication resource class is admitted here and no limit is inferred.

**Enforcement.** The capability is gated on, not merely stored. `PeerConnection::is_application_admitted` requires a live `AuthenticatedChannelCapability` **and** the existing approval policy, and every production application, reliable, and real-time admission gate routes through it. Reading `PeerStateData::authenticated` directly is not sufficient: that bool records policy history, survives channel replacement, and is deliberately left set by `retire_connector` — so a gate consulting it alone would keep admitting traffic after the authority artifact was dropped. Protocol admission traffic (Hello, AuthResponse, Approve, Deny) stays outside the gate, since it is what establishes the capability.

**Sole issuer.** `EndpointAuthTask::accept_peer_proof` is the only task transition that constructs `PeerProofAcceptance::Promoted`, and that variant is the only carrier of an `AuthenticatedChannelCapability`; the capability's own constructor, `AuthenticatedChannelCapability::from_verified_exchange`, mints the `EndpointAuthPermit` internally from the verified binding record, so there is no separate permit-issuing entry point to reach. `PeerConnection` owns the capability, dropping it whenever the connector is retired or replaced.

There is no runtime-mismatch cause, and there deliberately is not one: the permit is minted from the connected capability's own runtime, because the engine holds no independent `RuntimeIncarnation` to compare it against, so such a variant could never fire on the issuer path. What carries exactness on install instead is the retained binding record — `EndpointAuthTask::issued` compares the capability's recorded mesh, local and remote Device, proved role, runtime, connector, and transcript identity against the exchange it ran under — together with connector-incarnation ownership.

No conjunct in that comparison is one no fixture can falsify. The record deliberately does not restate the profile or the binding pair: `transcript::transcript_bytes` already commits the profile tag and the role-canonical fingerprint pair inside the bytes the compared transcript digest covers, so a substituted record differing in either already fails that conjunct, and a second stored copy would only be a second thing that can drift from the proof. Connector binding provenance is not retained at all — it had one reachable variant, was committed nowhere, and no consumer distinguished it. A second binding profile, or a provenance distinction some consumer actually acts on, is a future change that must add the field **together with the negative control that discriminates it** — never the field alone.

## Restart behavior

Possession of the permit or authenticated-channel capability grants the authority represented by that type. Its runtime witness grants no authority. The witness only prevents use against a replacement runtime object. The transcript, permit, and capability are memory-only and disappear on process restart. Stored IDs or an old transcript cannot reconstruct them.

## Forbidden responsibilities

This task does not decide mesh policy, mint `SessionCapability`, authorize an application, choose a route, mutate durable facts, or treat a working channel as authenticated without the complete fresh proof.

It also does not own the inbound application-admission witnesses. `AdmittedInboundDispatch` and its siblings are `engine::state`'s, minted inside `PeerRegistry::with_current`; they name one exact peer installation for one synchronous effect and are unrelated to endpoint-authentication authority. Nor does it own `rpc::PendingOpId`, which is a process-local ownership token — a local capability for naming one filed pending entry again so a failed-send withdrawal removes that entry and not a newer occupant of the same key. `PendingOpId` is not network authority, not durable, not a route or session authority, not a credential, and not a generation counter; it is never serialized, never sent, never derived from anything a peer supplies, and no inbound path reads it.

There is no adapter that pairs an authenticated-channel capability with an unauthenticated object. Session Broker consumes the typed channel directly.
