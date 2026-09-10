//! Hello → auth_response state machine.
//!
//! This file owns wire translation and peer lifecycle. It owns no
//! cryptographic state: the context, both contributions, the transcript
//! framing, the signing key, the one cached local proof, and the terminal
//! state all belong to the exact current `EndpointAuthTask`. Nothing here
//! draws a contribution, assembles a transcript, selects profile semantics,
//! or signs.
//!
//! On data channel open:
//!   - Reads the task's own single contribution and a verification code.
//!   - Sends `hello { device_id, label, nonce, verification_code,
//!     features }`. No application capability metadata: the Hello is
//!     admitted before a session exists, and what this node offers is
//!     sent after promotion over `CapabilitiesUpdate`.
//!   - Watchdog scheduled at the configured handshake timeout; up to three
//!     hello retries on the [`HANDSHAKE_HELLO_RETRY_SCHEDULE_MS`].
//!
//! On inbound hello:
//!   - Hand the typed peer contribution to the exact current task first,
//!     before recording anything from the frame, and send back the proof
//!     it returns.
//!   - The task classifies the Hello: a first binding, an exact
//!     retransmission answered from the cached proof with no draw and no
//!     second signature, or a conflicting value, which is the typed
//!     terminal `ConflictingPeerContribution` for that exact task — its
//!     own cause, never the currentness one.
//!   - Only a first binding records the peer's label and verification code,
//!     under the exact-current owner fence. The feature list is a gate input,
//!     not retained peer state. A retransmission is answered without adopting
//!     any cosmetic metadata.
//!
//! On inbound auth_response:
//!   - Hand the wire signature to the exact current task, which verifies
//!     it against the transcript it already built. A one-directional
//!     proof is not accepted as mutual.
//!   - On success: install the `AuthenticatedChannelCapability` on the
//!     peer before any diagnostic admission state, emit `PeerAuthenticated`,
//!     activate canonical Open participation without pair approval. Closed
//!     retains its canonical policy and bilateral approval/configuration gate
//!     (the roster is diagnostic/UI metadata).
//!   - Duplicates are idempotent for a channel this exact current task
//!     already promoted; anything else fails closed.
//!
//! No alternate signature payload is produced or accepted on this path. The
//! fingerprint pair is not a session-unique exporter; see
//! `endpoint_auth/BOUNDARY.md`.
//!
//! On inbound approve:
//!   - Record the actual observation and recheck activation. Closed also
//!     requires our approval send; Open does not require either observation.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, warn};

use crate::events::{DropReason, MeshEvent, PeerEvent};
use crate::protocol::{
    features::ADVERTISED_FEATURES,
    handshake::{ApproveMessage, AuthResponseMessage, DenyMessage, HelloMessage},
    MeshMessage,
};
use crate::signing;
use crate::verification;
use crate::PROTOCOL_VERSION;

use super::connection::PeerStatus;
use super::ladder::ConnectionTier;
use super::peer_registry::{PeerOwnerToken, WeakPeerOwnerToken};
use super::state::NetworkState;
use super::{phase, send_to_peer_owner};
use crate::config::SchedulerPolicyConfig;

/// Send a proof through the witness that already passed the final canonical,
/// owner, and pending-operation fence.  This must not call the generic
/// pending-semantic helper: that helper mints a second admission after the
/// fence and would reopen the replacement window this witness closes.
async fn send_admitted_eviction_proof(
    state: &Arc<NetworkState>,
    admission: super::state::DurableProofSendAdmission,
) -> crate::Result<()> {
    let (captured_owner, worker, _endpoint_auth, _mesh_context, bytes, _work) =
        admission.into_parts();
    let send = worker.begin_send()?;
    let sent = tokio::time::timeout(
        Duration::from_millis(super::scheduler_policy(state).peer_send_timeout_ms),
        send.send(bytes),
    )
    .await
    .map_err(|_| crate::error::Error::Transport("peer send timed out".into()))??;
    let mut data = captured_owner.connection().state.write();
    data.diag.bytes_out += sent as u64;
    data.diag.frames_out += 1;
    drop(data);
    state
        .traffic
        .record_tx(super::traffic::FrameClass::Gossip, sent);
    Ok(())
}

/// The Hello this node sends, built in exactly one place.
///
/// No capability advertisement travels here. The local advert is sent after
/// promotion, over `CapabilitiesUpdate`, so this frame cannot disclose what this
/// node offers to an endpoint that has not yet authenticated.
///
/// That absence is why this is a named builder rather than a struct literal
/// inline in [`initiate`]. A control asserting the absence against a Hello it
/// constructed itself proves only that the control declined to add one — it
/// would still pass if this builder started reading the local advertisement, or
/// if the field came back as an `Option` that a fresh value leaves `None`.
/// Asserting against *this* function is what makes the claim about production.
///
/// Everything it reads is a pre-session fact: identity, the profile list this
/// build advertises, and the two per-attempt values the caller draws.
pub(super) fn local_hello(
    state: &Arc<NetworkState>,
    contribution: String,
    verification_code: String,
) -> HelloMessage {
    HelloMessage {
        protocol: PROTOCOL_VERSION,
        device_id: state.identity.public_id().to_string(),
        label: state.identity.label().to_string(),
        nonce: contribution,
        verification_code,
        features: ADVERTISED_FEATURES.iter().map(|s| s.to_string()).collect(),
    }
}

/// Kick off the handshake — called once the data channel opens.
/// Sends the first hello and schedules the timeout watchdog.
pub(super) async fn initiate(
    state: &Arc<NetworkState>,
    owner: &PeerOwnerToken,
    auth_task: Arc<crate::endpoint_auth::EndpointAuthTask>,
) {
    if state
        .peers
        .with_current(owner, |peer| peer.endpoint_auth_is_current(&auth_task))
        != Some(true)
    {
        return;
    }
    let device_id = owner.device_id();
    let scheduler_policy = state
        .config
        .read()
        .scheduler_policy()
        .expect("scheduler policy is validated before engine side effects");
    // The contribution on the wire is the task's own single draw, read out
    // rather than generated here. The task signs and verifies against the value
    // it drew, so a second draw made at this boundary would put a contribution
    // on the wire that this endpoint's own transcript does not contain.
    let contribution = auth_task.local_contribution();
    let code = verification::generate_code();
    let hello = local_hello(state, contribution, code.clone());
    // `with_current` rather than `get_if_current`, for the same reason as the
    // first-Hello metadata write below: this is a synchronous multi-field write
    // that must linearize against registry replacement, not merely observe that
    // the owner was current a moment ago. There is no await inside, so
    // replacement orders strictly before or after the whole block and a peer
    // replaced after the lookup cannot be started into Handshaking.
    state.peers.with_current(owner, |peer| {
        let mut data = peer.state.write();
        data.status = PeerStatus::Handshaking;
        data.verification_code_sent = Some(code.clone());
        data.handshake_started_at = Some(Instant::now());
        data.hello_attempt = 1;
        data.diag.hellos_sent += 1;
    });
    state.log_diag_with(
        crate::events::DiagLevel::Debug,
        "handshake",
        format!(
            "sending hello to {} (code: {code})",
            super::short_peer(device_id)
        ),
        serde_json::json!({ "peer": device_id, "code": code }),
    );
    let hello_msg = MeshMessage::Hello(hello);
    if let Err(e) = send_to_peer_owner(state, owner, &hello_msg).await {
        state.log_diag_with(
            crate::events::DiagLevel::Error,
            "handshake",
            format!("send hello to {} failed: {e}", super::short_peer(device_id)),
            serde_json::json!({ "peer": device_id, "error": e.to_string() }),
        );
        warn!(peer = %device_id, "send hello failed: {e}");
    }
    let delayed_device_id = device_id.to_string();
    schedule_hello_retries(
        state,
        owner.downgrade(),
        hello_msg,
        delayed_device_id.clone(),
        scheduler_policy,
    );
    schedule_watchdog(
        state,
        owner.downgrade(),
        delayed_device_id,
        scheduler_policy,
    );
}

/// Re-send the same hello at each tick of
/// [`HANDSHAKE_HELLO_RETRY_SCHEDULE_MS`] until the peer authenticates
/// or the watchdog tears down. Replaying the hello is safe because the
/// contribution it carries is the task's one immutable draw: the
/// receiver's task recognises the exact duplicate and answers from its
/// cached proof, without a new draw, a rebuilt transcript, or a second
/// signature. Idempotence is a property of the task, not of a slot
/// this path overwrites.
async fn shutdown_requested_now(state: &Arc<NetworkState>) -> bool {
    tokio::select! {
        biased;
        _ = state.wait_for_shutdown() => true,
        _ = std::future::ready(()) => false,
    }
}

fn schedule_hello_retries(
    state: &Arc<NetworkState>,
    owner: WeakPeerOwnerToken,
    hello: MeshMessage,
    device_id: String,
    scheduler_policy: SchedulerPolicyConfig,
) {
    let Some(shutdown_permit) = state.try_admit_shutdown_mutation() else {
        return;
    };
    let weak_state = Arc::downgrade(state);
    state.register_cancellable_shutdown_task(&shutdown_permit, || {
        tokio::spawn(async move {
            for &delay_ms in &scheduler_policy.handshake_hello_retry_schedule_ms {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                let Some(state) = weak_state.upgrade() else {
                    return;
                };
                let Some(owner) = owner.upgrade() else {
                    return;
                };
                if shutdown_requested_now(&state).await {
                    return;
                }
                let still_handshaking = {
                    let Some(peer) = state.peers.get_if_current(&owner) else {
                        return;
                    };
                    let data = peer.state.read();
                    matches!(data.status, PeerStatus::Handshaking) && !data.authenticated
                };
                if !still_handshaking {
                    return;
                }
                if shutdown_requested_now(&state).await {
                    return;
                }
                if let Err(e) = send_to_peer_owner(&state, &owner, &hello).await {
                    debug!(peer = %device_id, "hello retry send failed: {e}");
                }
                if shutdown_requested_now(&state).await {
                    return;
                }
                if let Some(peer) = state.peers.get_if_current(&owner) {
                    let mut data = peer.state.write();
                    data.hello_attempt = data.hello_attempt.saturating_add(1);
                    data.diag.hellos_sent = data.diag.hellos_sent.saturating_add(1);
                }
            }
        })
    });
}

fn schedule_watchdog(
    state: &Arc<NetworkState>,
    owner: WeakPeerOwnerToken,
    device_id: String,
    scheduler_policy: SchedulerPolicyConfig,
) {
    let Some(shutdown_permit) = state.try_admit_shutdown_mutation() else {
        return;
    };
    let weak_state = Arc::downgrade(state);
    state.register_cancellable_shutdown_task(&shutdown_permit, || {
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(
                scheduler_policy.handshake_timeout_ms,
            ))
            .await;
            let Some(state) = weak_state.upgrade() else {
                return;
            };
            let Some(owner) = owner.upgrade() else {
                return;
            };
            if shutdown_requested_now(&state).await {
                return;
            }
            let should_fail = {
                let Some(peer) = state.peers.get_if_current(&owner) else {
                    return;
                };
                let data = peer.state.read();
                !data.authenticated
                    && matches!(data.status, PeerStatus::Handshaking)
                    && data
                        .handshake_started_at
                        .map(|t| {
                            t.elapsed().as_millis() as u64 >= scheduler_policy.handshake_timeout_ms
                        })
                        .unwrap_or(false)
            };
            if should_fail && !shutdown_requested_now(&state).await {
                state.log_diag_with(
                    crate::events::DiagLevel::Warn,
                    "handshake",
                    format!("handshake watchdog fired for {device_id} — tearing down"),
                    serde_json::json!({ "peer": device_id }),
                );
                super::drop_peer_if_current(&state, &owner, DropReason::HeartbeatTimeout).await;
            }
        })
    });
}

pub async fn on_hello(state: &Arc<NetworkState>, owner: &PeerOwnerToken, hello: HelloMessage) {
    on_hello_with_retention(state, owner, hello, None).await
}

pub(super) async fn on_hello_with_retention(
    state: &Arc<NetworkState>,
    owner: &PeerOwnerToken,
    hello: HelloMessage,
    retention: Option<crate::resource::ResourceLease>,
) {
    let device_id = owner.device_id();
    // Sanity-check: the device id the peer claimed in the hello
    // must match the connection id we're using to route this
    // frame. If a peer claims to be someone else, refuse — the
    // signature check would catch this anyway, but failing early
    // surfaces a clearer diagnostic.
    if signing::pubkey_part(&hello.device_id) != signing::pubkey_part(device_id) {
        state.log_diag_with(
            crate::events::DiagLevel::Error,
            "handshake",
            format!(
                "hello from {} claimed a different id ({}) — dropping",
                super::short_peer(device_id),
                super::short_peer(&hello.device_id)
            ),
            serde_json::json!({
                "connection_peer": device_id,
                "claimed_peer": hello.device_id,
            }),
        );
        warn!(
            peer = %device_id,
            claimed = %hello.device_id,
            "hello claimed a different device id than the connection — dropping"
        );
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    }

    if !crate::protocol::handshake::verification_code_has_protocol_shape(&hello.verification_code) {
        warn!(peer = %device_id, "hello carried a malformed verification code — dropping");
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    }

    // Profile first, before any proof work. A peer that does not advertise the
    // closed endpoint-auth profile has no agreed transcript, so nothing it
    // sends can be verified and nothing we send it can be verified either.
    // Refusing here means no contribution is bound, no transcript is built and
    // no signature is computed for an unauthenticatable peer. There is no
    // fallback: a mismatched profile fails closed rather than being offered
    // anything weaker, which is the whole point of advertising the profile.
    if let Err(error) = crate::endpoint_auth::negotiate_profile(&hello.features) {
        state.log_diag_with(
            crate::events::DiagLevel::Error,
            "handshake",
            format!(
                "hello from {} does not advertise the endpoint-auth profile — dropping",
                super::short_peer(device_id)
            ),
            serde_json::json!({
                "peer": device_id,
                "error": format!("{error:?}"),
                "required": crate::protocol::features::Feature::ENDPOINT_AUTH_V1,
            }),
        );
        warn!(peer = %device_id, "endpoint-auth profile not advertised: {error:?} — dropping");
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    }

    // The peer's contribution must arrive in its exact canonical encoding. A
    // short or non-canonical value cannot carry a full-width draw, and since
    // freshness — not the channel binding — is what separates two channels
    // between the same pair, accepting one would silently weaken the property
    // rather than fail visibly.
    let Ok(peer_contribution) = crate::endpoint_auth::PeerContribution::from_wire(&hello.nonce)
    else {
        warn!(peer = %device_id, "hello carried a malformed endpoint-auth contribution — dropping");
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    };

    // Hand the typed contribution to the exact current task *before* recording
    // anything from this frame. The channel binding, the transcript, the role
    // ordering, the profile, and the signature all belong to the task — this
    // path translates wire values and nothing else. Domain separation means
    // any other signature payload fails to verify; there is no selectable
    // weaker format.
    let Some(task) = state
        .peers
        .get_if_current(owner)
        .and_then(|p| p.endpoint_auth_task_for(owner.worker()))
    else {
        warn!(peer = %device_id, "no endpoint-auth task at hello — dropping");
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    };
    // Whether this Hello is the first one or a retransmission is the task's
    // answer, decided against the contribution it actually bound — never
    // re-derived here from engine state. A conflicting value has already retired
    // this exact task inside `accept_peer_hello` and is terminal, carrying
    // `ConflictingPeerContribution` rather than a currentness cause, so the
    // diagnostic below distinguishes a peer sending a second, different
    // contribution from this endpoint tearing the channel down.
    let accepted = match task.accept_peer_hello(peer_contribution) {
        Ok(accepted) => accepted,
        Err(error) => {
            // Structured, like its sibling profile refusal above: the typed
            // cause is the whole diagnostic value here. Without it the drop
            // reads identically for a conflict, a stale contribution and an
            // ordinary teardown, and the one that indicates a live peer doing
            // something it cannot be doing is the one that gets lost.
            state.log_diag_with(
                crate::events::DiagLevel::Error,
                "handshake",
                format!(
                    "endpoint-auth task refused the contribution from {} — dropping",
                    super::short_peer(device_id)
                ),
                serde_json::json!({
                    "peer": device_id,
                    "error": format!("{error:?}"),
                }),
            );
            warn!(peer = %device_id, "endpoint-auth task refused the peer contribution: {error:?}");
            super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
            return;
        }
    };
    let signature = accepted.proof().as_str().to_owned();

    // Peer-supplied metadata belongs to the Hello that established this
    // attempt. A retransmission carries the same contribution but is otherwise
    // attacker-controlled input, so adopting its label, code, or features would
    // let a late frame rewrite the identity of an attempt that is already bound
    // — or already promoted — while the proof it gets back is the cached one.
    // Only the first binding records cosmetic metadata; the classification is
    // matched, never inferred from retained Hello feature state.
    //
    // What is recorded here is deliberately the smallest set: two cosmetic
    // strings that authorize nothing and gate nothing. The feature list was
    // already checked above as an authentication precondition and is not
    // retained as peer state. Application capability metadata is not among
    // them and cannot be — the frame no longer carries any.
    match accepted {
        crate::endpoint_auth::AcceptedPeerHello::FirstBinding(_) => {
            // `with_current` rather than `get_if_current`, because this write
            // must linearize against registry replacement rather than merely
            // observe that the owner was current a moment ago. There is no
            // await inside, so replacement orders strictly before or after the
            // whole block, and a peer replaced after the task call cannot
            // receive the old frame's metadata.
            state.peers.with_current(owner, |peer| {
                let mut data = peer.state.write();
                data.verification_code_received = Some(hello.verification_code.clone());
                data.label = hello.label.clone();
                data.hello_retention = retention;
            });
            state.log_diag_with(
                crate::events::DiagLevel::Debug,
                "handshake",
                format!(
                    "hello received from {} (label: {:?}, code: {})",
                    super::short_peer(device_id),
                    hello.label,
                    hello.verification_code,
                ),
                serde_json::json!({
                    "peer": device_id,
                    "label": hello.label,
                    "code": hello.verification_code,
                }),
            );
        }
        crate::endpoint_auth::AcceptedPeerHello::ExactDuplicate(_) => {
            debug!(
                peer = %device_id,
                "retransmitted hello: replying from the cached proof without adopting its metadata"
            );
        }
    }
    if let Err(e) = send_to_peer_owner(
        state,
        owner,
        &MeshMessage::AuthResponse(AuthResponseMessage { signature }),
    )
    .await
    {
        state.log_diag_with(
            crate::events::DiagLevel::Error,
            "handshake",
            format!(
                "send auth_response to {} failed: {e}",
                super::short_peer(device_id)
            ),
            serde_json::json!({ "peer": device_id, "error": e.to_string() }),
        );
        warn!(peer = %device_id, "send auth_response failed: {e}");
        return;
    }
    debug!(peer = %device_id, "responded to hello");
}

pub async fn on_auth_response(
    state: &Arc<NetworkState>,
    owner: &PeerOwnerToken,
    resp: AuthResponseMessage,
) {
    let device_id = owner.device_id();
    // Verify both halves of the Arc 04 endpoint-auth transcript. The peer's
    // signature covers `ENDPOINT_AUTH_DOMAIN_TAG` followed by the
    // length-prefixed mesh context, profile, signer role, both Device IDs,
    // both contributions and both certificate fingerprints, ordered by role
    // rather than by which side is local — so both endpoints derive identical
    // bytes. Domain separation makes any signature over a different payload
    // fail here; no alternate format is an accepted fallback.
    // Neither contribution is held in per-peer state. Both belong to the task,
    // which keeps its own draw and its bound peer value for its whole life,
    // including after promotion — so a retransmitted or delayed Hello still
    // finds the attempt it belongs to instead of tearing down a peer whose
    // proof is valid. Single promotion is enforced by the move-only handoff.
    // Idempotence for sequential retransmission, checked before any transport
    // or signing work. Each connector has one event-pump task that awaits an
    // event before taking the next, so a duplicate AuthResponse on this channel
    // runs strictly after the first completed. `has_authenticated_channel` is
    // the right predicate on its own: it is true only for the entry's exact
    // current, unretired connector, because retirement and replacement drop the
    // capability. Without this the duplicate would re-enter promotion, find the
    // handoff already consumed, and tear down a peer whose proof was valid.
    if state
        .peers
        .get_if_current(owner)
        .is_some_and(|peer| peer.has_authenticated_channel())
    {
        debug!(peer = %device_id, "ignoring duplicate auth_response for an already authenticated channel");
        return;
    }
    let (peer_label, verification_code) = {
        let Some(peer) = state.peers.get_if_current(owner) else {
            return;
        };
        let data = peer.state.read();
        (
            data.label.clone(),
            data.verification_code_received.clone().unwrap_or_default(),
        )
    };
    // The endpoint-auth task for the *exact current* connector. A task from a
    // replaced channel cannot promote: because the certificate-fingerprint
    // binding is not session-unique, this ownership check — not the binding —
    // is what distinguishes two channels between the same device pair.
    let Some(auth_task) = state
        .peers
        .get_if_current(owner)
        .and_then(|p| p.endpoint_auth_task_for(owner.worker()))
    else {
        warn!(peer = %device_id, "no current endpoint-auth task at auth_response — dropping");
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    };

    // The task must be the one built for *this* mesh and *this* peer. Ownership
    // of the current connector is not the same fact: a task is created with an
    // immutable context, and this is where the engine states that the entry it
    // is about to promote is the entry that context names. The remote id is
    // derived exactly as task creation derives it, so the comparison is against
    // the same canonical form the context stored rather than a display spelling.
    // Fail closed with no fallback: a task whose context does not match cannot
    // be corrected here, only refused.
    let mesh_context = state.mesh_context_id().to_string();
    if !auth_task.context_matches(&mesh_context, crate::signing::pubkey_part(device_id)) {
        warn!(peer = %device_id, "endpoint-auth task authenticates a different mesh or peer — dropping");
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    }

    // The task owns both halves. It already produced and cached our own proof
    // when it bound the peer's contribution, and it holds the context, the
    // binding, and the transcript, so this path hands it the wire signature and
    // nothing else. There is no fingerprint fetch, no transcript assembly, and
    // no signing here.
    let capability = match auth_task.accept_peer_proof(&resp.signature) {
        // Unboxed here and nowhere else. The box is a size decision on the
        // outcome enum, not a change of custody: what install receives below is
        // the exact capability the promotion built.
        Ok(crate::endpoint_auth::PeerProofAcceptance::Promoted(capability)) => *capability,
        // A retransmission arriving at a task that has already promoted, stated
        // by the task rather than inferred from a terminal cause it never took.
        //
        // What it states is exactly one thing: this *task* moved its channel out
        // already. It is a lifecycle fact and nothing more. It does **not** say
        // the replayed signature verified — once the handoff is gone there is
        // nothing left to verify it against, and the frame's bytes are never
        // examined — and it does **not** say the capability that promotion
        // issued was ever installed.
        //
        // So installation is still corroborated here, and this arm fails closed
        // without it. The caller that wins promotion can move the capability and
        // then fail to install it; treating every `AlreadyPromoted` as benign
        // would leave that peer alive and unauthenticated. Only the
        // corroborated case is benign, and the rest falls through to the drop
        // below.
        //
        // The ordinary sequential retransmission never reaches this arm: it is
        // absorbed by the `has_authenticated_channel` guard above, before any
        // task work at all. What the typed outcome buys is the concurrent case —
        // a caller that loses a race to promote is *told* it lost, instead of
        // reading a terminal currentness cause it must then disambiguate.
        //
        // This arm is also why the conflict cause is separate. A task that a
        // conflicting contribution retired is terminal and answers
        // `Err(ConflictingPeerContribution)`, so it cannot reach this arm at all
        // and falls to the refusal below — a peer that sent a second, different
        // contribution can never present the result here as a retransmission of
        // its first.
        Ok(crate::endpoint_auth::PeerProofAcceptance::AlreadyPromoted) => {
            if state.peers.get_if_current(owner).is_some_and(|peer| {
                peer.has_authenticated_channel() && peer.endpoint_auth_is_current(&auth_task)
            }) {
                debug!(peer = %device_id, "duplicate auth_response after promotion completed");
                return;
            }
            warn!(
                peer = %device_id,
                "endpoint-auth task already promoted with no authenticated channel installed for it — dropping"
            );
            super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
            return;
        }
        // Every remaining outcome is terminal for the attempt: the task recorded
        // this cause and retired itself, so there is nothing left to fall back
        // to and the peer goes with it.
        Err(error) => {
            warn!(peer = %device_id, "endpoint authentication refused: {error:?}");
            super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
            return;
        }
    };

    let Some(peer) = state.peers.get_if_current(owner) else {
        return;
    };
    // Install the capability before any legacy admission state is set, so no
    // window exists in which `authenticated == true` without a live
    // authenticated channel behind it.
    if !peer.install_authenticated_channel(&auth_task, capability) {
        // Refused because one is already installed for this exact current task
        // is a duplicate, not a failure; the capability just dropped, which
        // runs its handoff retention. Any other refusal fails closed.
        if peer.has_authenticated_channel() && peer.endpoint_auth_is_current(&auth_task) {
            debug!(peer = %device_id, "authenticated channel already installed for this connector");
            return;
        }
        warn!(peer = %device_id, "authenticated channel is not installable on the current connector — dropping");
        super::drop_peer_if_current(state, owner, DropReason::AuthFailed).await;
        return;
    }

    // Authentication succeeded.
    //
    // Before ANY admission path runs, the signed-eviction gate: a device
    // this network's governance has evicted is denied here — with the
    // signed log attached as proof so it can verify its own removal and
    // stand down. Without this gate an evicted device that missed the
    // news redialed forever and the flow below RESURRECTED it: pending-
    // approval nudges at best, and on an auto-approve network (every
    // fleet mesh) auto-approve → mutual ACTIVE previously also populated the
    // local roster cache; that cache is not an authority input.
    // straight back into the roster and gossiped it fleet-wide.
    // Mark the exact authenticated installation pending before the governance
    // gate. A denied peer may still receive the signed proof bundle over this
    // owner; it is durable semantic input, not application admission.
    if state
        .peers
        .with_current(owner, |peer| {
            let mut data = peer.state.write();
            data.authenticated = true;
            data.status = PeerStatus::PendingApproval;
        })
        .is_none()
    {
        return;
    }
    // Reconcile every retained durable proof immediately after this exact
    // authenticated owner becomes pending.  A causal regrant makes
    // `log_evicted` false, but it must still fence any stale E0 obligation
    // before the ordinary admission branch can proceed.
    let canonical_eviction_proof = match state.reconcile_durable_eviction_proofs(owner) {
        Ok(record) => record,
        Err(error) => {
            warn!(
                peer = %device_id,
                %error,
                "durable eviction proof reconciliation refused"
            );
            return;
        }
    };
    // A Deny is only a session outcome. When the current signed projection
    // evicts this peer, send the complete canonical graph first so the peer
    // can independently verify the eviction and derive its own stand-down.
    if super::governance::log_evicted(state, device_id) {
        let Some(record) = canonical_eviction_proof else {
            warn!(
                peer = %device_id,
                "evicted authenticated peer has no canonical durable proof"
            );
            return;
        };
        let delivery = match state.materialize_durable_proof_delivery(&record) {
            Ok(delivery) => delivery,
            Err(error) => {
                warn!(
                    peer = %device_id,
                    %error,
                    "durable eviction proof materialization refused"
                );
                return;
            }
        };
        match state.prepare_durable_eviction_proof_send(owner, &record, &delivery) {
            Ok(super::state::DurableProofSendPreparation::Ready(admission)) => {
                if let Err(error) = send_admitted_eviction_proof(state, *admission).await {
                    // Denial is not allowed to outrun the exact proof transfer.
                    // The current owner remains pending so a retry/reconnect
                    // can attempt the same canonical bundle; retiring it here
                    // would leave an offline peer denied without the evidence
                    // needed to stand down.
                    warn!(
                        peer = %device_id,
                        %error,
                        "eviction proof transfer refused; keeping the authenticated peer pending"
                    );
                    return;
                }
            }
            Ok(super::state::DurableProofSendPreparation::Superseded) => {}
            Err(error) => {
                warn!(
                    peer = %device_id,
                    %error,
                    "durable eviction proof send admission refused"
                );
                return;
            }
        }
    } else {
        // A regrant clears the eviction before this new installation is
        // promoted, so it may not enqueue a ReplayCapabilities command yet.
        // Reconcile retained proof obligations at this exact authenticated
        // owner now; the replay helper's publication/owner fence makes this
        // a terminal non-send path and leaves a later transport failure rule
        // unchanged.
        super::replay_pending_durable_proofs(state, owner).await;
    }
    if super::governance::deny_if_evicted(state, owner).await {
        return;
    }
    // Both network-global reads are hoisted above the peer write. Taking the
    // roster and the config while holding a peer's state guard nests a
    // `NetworkState` lock under a per-peer lock, which is the opposite of the
    // order everything else uses, and it makes the policy decision and the
    // policy write two separate atoms for no benefit — neither read depends on
    // this peer's state.
    let rostered = state.is_rostered(device_id);
    let policy_admits = canonical_policy_admits_both(state, device_id);
    let open_participation = is_open_participation(state);
    let auto_approve = !open_participation && policy_admits && state.config.read().auto_approve;
    state.log_diag_with(
        crate::events::DiagLevel::Debug,
        "handshake",
        format!(
            "auth ok with {} ({})",
            super::short_peer(device_id),
            if open_participation && policy_admits {
                "canonical Open participation"
            } else if auto_approve {
                "canonical policy + auto-approve"
            } else {
                "awaiting user approval"
            }
        ),
        serde_json::json!({
            "peer": device_id,
            "rostered": rostered,
            "auto_approve": auto_approve,
            "open_participation": open_participation,
        }),
    );

    state.emit(MeshEvent::Peer(PeerEvent::Authenticated {
        network_id: state.network_id.clone(),
        device_id: device_id.to_string(),
        label: peer_label.clone(),
        verification_code,
        rostered,
    }));

    // Publish authentication before this actor's reevaluation. That helper
    // may synchronously complete promotion and emit Approved; keeping it
    // after this event preserves proof-before-admission ordering for this
    // reviewed actor path.
    reevaluate_after_role_grant(state, owner).await;
}

pub async fn on_approve(state: &Arc<NetworkState>, owner: &PeerOwnerToken) {
    let recorded = state.peers.with_current(owner, |peer| {
        peer.state.write().remote_approve_seen = true;
    });
    if recorded.is_none() {
        return;
    }
    maybe_activate(state, owner).await;
}

/// Re-evaluate one exact authenticated peer after a canonical RoleGrant has
/// become visible. The caller supplies the owner it already holds; this hook
/// never resolves a peer by Device ID or manufactures approval observations.
///
/// Open (including Silent) participation requires no pair permission. Closed
/// retains its configuration and bilateral observations, in addition to the
/// canonical projection. Neither path invents a remote Approve observation.
pub(super) async fn reevaluate_after_role_grant(state: &Arc<NetworkState>, owner: &PeerOwnerToken) {
    let Some(should_reevaluate) = state.peers.with_current(owner, |peer| {
        let data = peer.state.read();
        data.authenticated && matches!(data.status, PeerStatus::PendingApproval)
    }) else {
        return;
    };
    if !should_reevaluate || !canonical_policy_admits_both(state, owner.device_id()) {
        return;
    }
    let auto_approve = state.config.read().auto_approve;
    if is_open_participation(state) {
        maybe_activate(state, owner).await;
    } else if auto_approve {
        send_local_approve_owner(state, owner).await;
    } else {
        maybe_activate(state, owner).await;
    }
}

/// Membership mode comes from the verified, immutable bootstrap, never a UI
/// visibility/dialing preference or a mutable configuration label.
fn is_open_participation(state: &Arc<NetworkState>) -> bool {
    matches!(
        state.verified_bootstrap().policy(),
        crate::semantic::VerifiedProjectPolicy::Open
    )
}

/// Whether the exact local/remote pair is admitted by the canonical policy.
/// Closed bootstrap roots are the initial owner authority; every later
/// member/controller/owner must be the selected, non-conflicting role fact for
/// that device. Open networks use authenticated, ephemeral presence after the
/// exact bootstrap/context and stand-down fences; they do not author durable
/// participation facts. An Evict membership cell remains a refusal even if a
/// stale role grant is present, and stand-down is always fail-closed.
fn canonical_policy_admits_both(state: &Arc<NetworkState>, remote_device_id: &str) -> bool {
    let graph = state.authoritative_fact_graph();
    let graph = graph.read();
    super::governance::canonical_policy_admits_from(
        state.verified_bootstrap(),
        &graph,
        state.identity.public_id(),
        remote_device_id,
    )
}

/// Complete the Active edge from facts already established on the exact peer.
/// Only [`on_approve`] may latch remote approval. Re-evaluating after a local
/// send must never manufacture peer consent. Open bypasses the pair gate, not
/// authentication, canonical admission, or subsequent resource-funded lending.
async fn maybe_activate(state: &Arc<NetworkState>, owner: &PeerOwnerToken) {
    maybe_activate_after_check(state, owner, || {}).await;
}

/// Recheck and commit activation under the exact installation fence.
///
/// `before_commit` is normally empty. The deterministic replacement test uses
/// it to replace the peer after the initial eligibility read but before the
/// roster persistence linearization point.
async fn maybe_activate_after_check(
    state: &Arc<NetworkState>,
    owner: &PeerOwnerToken,
    before_commit: impl FnOnce(),
) {
    maybe_activate_after_check_with_persistence(
        state,
        owner,
        before_commit,
        |state, device_id, label| state.refresh_roster_projection(device_id, label),
    )
    .await;
}

async fn maybe_activate_after_check_with_persistence<F, P>(
    state: &Arc<NetworkState>,
    owner: &PeerOwnerToken,
    before_commit: F,
    persist: P,
) where
    F: FnOnce(),
    P: FnOnce(&Arc<NetworkState>, &str, &str) -> crate::Result<()>,
{
    let device_id = owner.device_id();
    let open_participation = is_open_participation(state);
    let eligible = state.peers.get_if_current(owner).is_some_and(|peer| {
        // Read the channel slot separately from peer state (no nested locks).
        let channel_ready = !open_participation || peer.has_authenticated_channel();
        let data = peer.state.read();
        !matches!(data.status, PeerStatus::Active)
            && data.authenticated
            && channel_ready
            && (open_participation || (data.local_approve_sent && data.remote_approve_seen))
    });
    if !eligible {
        return;
    }

    before_commit();
    let policy_admits = canonical_policy_admits_both(state, device_id);
    if !policy_admits {
        return;
    }

    let Some(result) = state.peers.with_current(owner, |peer| {
        let channel_ready = !open_participation || peer.has_authenticated_channel();
        let data = peer.state.write();
        // Guard the transition edge: a peer that re-sends Approve after
        // we're already ACTIVE shouldn't re-fire the on-active side
        // effects (roster persist, gossip, Approved event).
        let was_active = matches!(data.status, PeerStatus::Active);
        // A peer reaches ACTIVE only once it has proven its ed25519 identity.
        // `remote_approve_seen` can be latched by an `Approve` that arrives
        // before authentication (protocol frames pass the admission gate), and
        // a locally accepted Approve send can be recorded before authentication.
        // Without this `authenticated` conjunct an
        // unauthenticated peer could be promoted to ACTIVE and gain the run of
        // every application and control plane. The early latch is harmless: the
        // transition simply completes the moment authentication lands.
        let active = data.authenticated
            && channel_ready
            && (open_participation || (data.local_approve_sent && data.remote_approve_seen))
            && policy_admits;
        if !active || was_active {
            return None;
        }
        let label = data.label.clone();
        drop(data);

        let channel_ready = !open_participation || peer.has_authenticated_channel();
        let mut data = peer.state.write();
        if !data.authenticated
            || !channel_ready
            || (!open_participation && (!data.local_approve_sent || !data.remote_approve_seen))
            || matches!(data.status, PeerStatus::Active)
        {
            return None;
        }
        data.status = PeerStatus::Active;
        data.tier = ConnectionTier::Steady;
        data.ice_failed_count = 0;
        data.no_turn_diag_emitted = false;
        drop(data);

        // The exact-owner mutation fence is still held; the advisory Hub
        // hook neither re-enters that fence nor decides activation.
        state.note_hub_authenticated_owner_change(owner);

        state.log_diag_with(
            crate::events::DiagLevel::Info,
            "peer",
            format!("{} ACTIVE", super::short_peer(device_id)),
            serde_json::json!({ "peer": device_id }),
        );
        state.emit(MeshEvent::Peer(PeerEvent::Approved {
            network_id: state.network_id.clone(),
            device_id: device_id.to_string(),
            label: label.clone(),
        }));
        state.resolve_authenticated_connect_waiters(owner);
        state.clear_reconnect_intent(device_id);
        Some(label)
    }) else {
        return;
    };
    let Some(label) = result else {
        return;
    };

    // The roster is a compatibility/UI projection, not durable authority.
    // Canonical policy above is the promotion fence, so the exact live owner
    // is published first and a failed cache write is diagnostic only.
    if let Err(error) = persist(state, device_id, &label) {
        state.log_diag(
            crate::events::DiagLevel::Warn,
            "roster",
            format!(
                "refresh compatibility projection for {} after canonical activation failed: {error}",
                super::short_peer(device_id)
            ),
        );
    }

    // Nothing is installed here, and that absence is the design. Real-time work
    // is authorized by the promoted session, which the registry fence mints on
    // demand at the moment of use — so reaching Active is already everything
    // that has to be true, and a separate post-Active step could only be a
    // second copy of the same fact, taken at a different instant, able to drift.

    phase::recompute(state);
    super::reliable::flush_owner(state, owner).await;
    if state.peers.get_if_current(owner).is_none() {
        return;
    }
    // The ordinary first establishment: a peer that reaches Active with a
    // session it can promote is told what this node offers, without waiting for
    // the application to advertise again.
    //
    // This installs nothing and is not the second copy of a fact the note above
    // warns against — it is a send, and it asks the same lender every other
    // application send asks. Nor is it the only place the debt can be paid: if
    // promotion resource-refuses here, nothing is minted, nothing is consumed,
    // and the first later successful promotion still owes it.
    super::replay_local_capabilities_to_owner(state, owner).await;
    if state.peers.get_if_current(owner).is_none() {
        return;
    }
    super::ladder::reevaluate_topology(state).await;
    if state.peers.get_if_current(owner).is_none() {
        return;
    }

    let _ = super::governance::broadcast_fact_inventory_for_owner(state, owner).await;
}

pub async fn on_deny(state: &Arc<NetworkState>, owner: &PeerOwnerToken, deny: DenyMessage) {
    let device_id = owner.device_id();
    state.log_diag_with(
        crate::events::DiagLevel::Warn,
        "auth",
        format!("peer denied us: {device_id} (reason: {:?})", deny.reason),
        serde_json::json!({ "peer": device_id, "reason": format!("{:?}", deny.reason) }),
    );
    // Deny carries no governance proof.
    // Nothing about the DENIER is trusted: the logs go through the same
    // strict-extension verification every adoption takes, so a forged or
    // foreign log changes nothing — but a genuine one finally teaches a
    // device that was evicted while offline that it is out, flipping it
    // to stood-down (and letting the embedding app clear its fleet
    // state) instead of redialing into denials forever.
    // Deny is a channel/session outcome only. Legacy transition/member-log
    // proof is intentionally absent from the wire message; no governance
    // state is adopted from an unauthenticated denial.
    super::drop_peer_if_current(state, owner, DropReason::Denied).await;
}

async fn send_local_approve_owner(state: &Arc<NetworkState>, owner: &PeerOwnerToken) {
    let device_id = owner.device_id();
    let Some(already) = state
        .peers
        .with_current(owner, |peer| peer.state.read().local_approve_sent)
    else {
        return;
    };
    if already {
        // Authentication or remote approval may have completed since the
        // successful local send. Fold the established facts again.
        maybe_activate(state, owner).await;
        return;
    }
    // A user-facing approval request may race the endpoint-auth exchange. An
    // approval frame sent to a carrier is not itself application authority,
    // but accepting it here would let the peer latch consent before this side
    // has verified the signed endpoint proof. Require the exact current peer's
    // authenticated marker and its installed proof capability before sending;
    // the later authenticated path will retry the same approval when these
    // facts become true. The capability check is observation-only and happens
    // after the peer-state guard is released.
    let Some(proof_verified) = state.peers.with_current(owner, |peer| {
        let data = peer.state.read();
        let authenticated = data.authenticated;
        let pending_or_active = matches!(
            data.status,
            PeerStatus::PendingApproval | PeerStatus::Active
        );
        drop(data);
        authenticated && pending_or_active && peer.has_authenticated_channel()
    }) else {
        return;
    };
    if !proof_verified {
        debug!(
            peer = %device_id,
            "deferring approval until signed endpoint authentication is installed"
        );
        return;
    }
    if let Err(e) = send_to_peer_owner(state, owner, &MeshMessage::Approve(ApproveMessage {})).await
    {
        warn!(peer = %device_id, "send approve failed: {e}");
        return;
    }
    let recorded = state.peers.with_current(owner, |peer| {
        peer.state.write().local_approve_sent = true;
    });
    if recorded.is_none() {
        return;
    }
    // This flag means the exact current transport accepted the bytes for
    // transmission. It does not prove remote receipt. Concurrent duplicate
    // Approves are harmless, while a failed send must never erase another
    // successful one.
    // A remote Approve may have arrived before authentication completed.
    // Re-evaluate after local send acceptance without manufacturing the
    // remote-approval fact.
    maybe_activate(state, owner).await;
}

/// Send the local approve frame for a peer. Called from the
/// auto-approve path and from the user-facing
/// [`crate::MeshHandle::approve_peer`] action.
pub async fn send_local_approve(state: &Arc<NetworkState>, device_id: &str) {
    if let Some(owner) = state.peers.owner(device_id) {
        send_local_approve_owner(state, &owner).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Delayed handshake work owns only weak exact identities while its timer
    /// is asleep.  The empty state witness makes both tasks return at their
    /// first wake without waiting for either production delay; dropping the
    /// installation immediately proves that neither scheduled task retained
    /// the peer or its installation marker.
    #[tokio::test]
    async fn v4_handshake_delayed_work_does_not_retain_retired_owner() {
        let state = crate::engine::build_test_state("timer-owner-weak-custody");
        crate::engine::insert_session_less_peer(&state, "timer-owner", None);
        let owner = state
            .peers
            .owner("timer-owner")
            .expect("timer owner exists");
        let weak_owner = owner.downgrade();
        let hello = MeshMessage::Deny(DenyMessage { reason: None });
        let scheduler_policy = state
            .config
            .read()
            .scheduler_policy()
            .expect("test state has a validated scheduler policy");
        schedule_hello_retries(
            &state,
            weak_owner.clone(),
            hello,
            "timer-owner".to_string(),
            scheduler_policy,
        );
        schedule_watchdog(
            &state,
            weak_owner.clone(),
            "timer-owner".to_string(),
            scheduler_policy,
        );

        assert!(weak_owner.upgrade().is_some());
        let removed = state
            .peers
            .remove_if_current(&owner)
            .expect("the authoritative retirement removes the timer owner");
        drop(removed);
        drop(owner);
        state.shutdown().await;
        assert!(
            weak_owner.upgrade().is_none(),
            "scheduled retry/watchdog work retains no retired owner custody"
        );
    }

    fn auth_response(signature: &str) -> AuthResponseMessage {
        AuthResponseMessage {
            signature: signature.to_string(),
        }
    }

    /// Genuine Device proof and capability installation through the handler;
    /// only the connector handoff is a local fixture (no native transport).
    fn signed_pending_auth(state: &Arc<NetworkState>, context: &str) -> (PeerOwnerToken, String) {
        signed_pending_auth_with_signer(
            state,
            context,
            &ed25519_dalek::SigningKey::from_bytes(&[73; 32]),
        )
    }

    fn signed_pending_auth_with_signer(
        state: &Arc<NetworkState>,
        context: &str,
        proof_signer: &ed25519_dalek::SigningKey,
    ) -> (PeerOwnerToken, String) {
        let remote_key = ed25519_dalek::SigningKey::from_bytes(&[73; 32]);
        let remote = data_encoding::BASE32_NOPAD
            .encode(remote_key.verifying_key().as_bytes())
            .to_lowercase();
        let context = crate::endpoint_auth::EndpointAuthContext::new(
            context,
            state.identity.public_id(),
            &remote,
            crate::connector::EndpointAuthBinding::webrtc_certificate_fingerprints(
                "open-admission-local",
                "open-admission-remote",
            )
            .expect("fixture binding"),
        )
        .expect("canonical fixture identities and context");
        let task = Arc::new(crate::endpoint_auth::EndpointAuthTask::begin(
            context,
            crate::connector::handoff_for_test(crate::runtime::runtime_for_test()),
            crate::endpoint_auth::LocalIdentitySigner::for_identity(Arc::clone(&state.identity)),
        ));
        let contribution = crate::endpoint_auth::PeerContribution::from_wire(
            crate::endpoint_auth::LocalContribution::generate().as_str(),
        )
        .expect("canonical peer contribution");
        task.accept_peer_hello(contribution.clone())
            .expect("bind signed transcript");
        let proof = crate::endpoint_auth::peer_proof_for_test(&task, &contribution, proof_signer);
        crate::engine::install_peer(
            &state.peers,
            Arc::new(crate::engine::PeerConnection::with_endpoint_auth_for_test(
                remote.clone(),
                task,
            )),
        );
        (state.peers.owner(&remote).expect("exact auth owner"), proof)
    }

    /// Pre-fix discriminator: the identical signed proof would leave PendingApproval
    /// when auto_approve=false, despite canonical Open admission being true.
    #[tokio::test]
    async fn v4_open_and_silent_authenticate_without_pair_approval() {
        for kind in [
            crate::config::NetworkKind::Open,
            crate::config::NetworkKind::Silent,
        ] {
            let state = crate::engine::build_test_state(&format!("permissionless-{kind:?}"));
            {
                let mut config = state.config.write();
                config.kind = kind;
                config.auto_approve = false;
            }
            assert!(matches!(
                state.verified_bootstrap().policy(),
                crate::semantic::VerifiedProjectPolicy::Open
            ));
            let (owner, proof) = signed_pending_auth(&state, &state.mesh_context_id().to_string());
            assert!(canonical_policy_admits_both(&state, owner.device_id()));
            let before = state
                .authoritative_fact_graph()
                .read()
                .projection_commitment_root();
            let mut events = state.events_tx.subscribe();
            on_auth_response(&state, &owner, auth_response(&proof)).await;
            {
                let peer = state
                    .peers
                    .get_if_current(&owner)
                    .expect("authenticated owner retained");
                assert!(peer.has_authenticated_channel());
                let data = peer.state.read();
                assert!(data.authenticated);
                assert_eq!(data.status, PeerStatus::Active);
                assert!(!data.local_approve_sent);
                assert!(!data.remote_approve_seen, "no fabricated remote consent");
            }
            // Re-evaluation and duplicate proof cannot publish Active twice.
            reevaluate_after_role_grant(&state, &owner).await;
            on_auth_response(&state, &owner, auth_response(&proof)).await;
            let mut activations = 0;
            while let Ok(event) = events.try_recv() {
                if matches!(event, MeshEvent::Peer(PeerEvent::Approved { device_id, .. })
                    if device_id == owner.device_id())
                {
                    activations += 1;
                }
            }
            assert_eq!(activations, 1);
            assert_eq!(
                state
                    .authoritative_fact_graph()
                    .read()
                    .projection_commitment_root(),
                before
            );
            assert_eq!(
                state
                    .authoritative_fact_graph()
                    .read()
                    .admitted_fact_count(),
                0
            );
            state.shutdown().await;
        }
    }

    #[tokio::test]
    async fn v4_open_pair_bypass_refuses_unverified_and_stale_owners() {
        for case in [
            "forged",
            "foreign",
            "unauthenticated",
            "missing-capability",
            "stale",
        ] {
            let state = crate::engine::build_test_state(&format!("permissionless-refuse-{case}"));
            state.config.write().auto_approve = false;
            let context = if case == "foreign" {
                crate::semantic::VerifiedBootstrap::open("foreign-permissionless")
                    .expect("foreign bootstrap")
                    .context_id()
                    .to_string()
            } else {
                state.mesh_context_id().to_string()
            };
            let (owner, proof) = if case == "forged" {
                signed_pending_auth_with_signer(
                    &state,
                    &context,
                    &ed25519_dalek::SigningKey::from_bytes(&[74; 32]),
                )
            } else {
                signed_pending_auth(&state, &context)
            };
            let before = state
                .authoritative_fact_graph()
                .read()
                .projection_commitment_root();
            let mut events = state.events_tx.subscribe();
            match case {
                "forged" => on_auth_response(&state, &owner, auth_response(&proof)).await,
                "foreign" => on_auth_response(&state, &owner, auth_response(&proof)).await,
                "stale" => {
                    crate::engine::insert_session_less_peer(&state, owner.device_id(), None);
                    on_auth_response(&state, &owner, auth_response(&proof)).await;
                    reevaluate_after_role_grant(&state, &owner).await;
                }
                _ => {
                    state.peers.with_current(&owner, |peer| {
                        if case == "unauthenticated" {
                            // Isolate the authenticated-marker fence: a real
                            // capability alone must not complete activation.
                            let task = peer.endpoint_auth_task_for(owner.worker()).expect("fixture task");
                            let crate::endpoint_auth::PeerProofAcceptance::Promoted(capability) =
                                task.accept_peer_proof(&proof).expect("valid fixture proof")
                            else { panic!("first proof must promote"); };
                            assert!(peer.install_authenticated_channel(&task, *capability));
                        }
                        let mut data = peer.state.write();
                        data.status = PeerStatus::PendingApproval;
                        data.authenticated = case == "missing-capability";
                        data.local_approve_sent = true;
                    }).expect("owner current before refused activation");
                    on_approve(&state, &owner).await;
                    reevaluate_after_role_grant(&state, &owner).await;
                }
            }
            assert!(state.peers.get(owner.device_id()).is_none_or(|peer| {
                (case == "unauthenticated" || !peer.has_authenticated_channel())
                    && peer.state.read().status != PeerStatus::Active
            }));
            while let Ok(event) = events.try_recv() {
                assert!(!matches!(
                    event,
                    MeshEvent::Peer(PeerEvent::Approved { .. })
                ));
            }
            assert_eq!(
                state
                    .authoritative_fact_graph()
                    .read()
                    .projection_commitment_root(),
                before
            );
            assert_eq!(
                state
                    .authoritative_fact_graph()
                    .read()
                    .admitted_fact_count(),
                0
            );
            state.shutdown().await;
        }
    }

    #[tokio::test]
    async fn v4_closed_authentication_retains_governance_and_pair_gates() {
        let state = crate::engine::build_test_closed_state("closed-no-open-bypass", [0x73; 32]);
        state.config.write().auto_approve = false;
        let (owner, proof) = signed_pending_auth(&state, &state.mesh_context_id().to_string());
        assert!(!is_open_participation(&state));
        on_auth_response(&state, &owner, auth_response(&proof)).await;
        assert!(state
            .peers
            .get_if_current(&owner)
            .expect("pending authenticated peer")
            .has_authenticated_channel());
        assert!(!canonical_policy_admits_both(&state, owner.device_id()));
        // Model an accepted local send; even both approval flags cannot supply
        // a role. Only on_approve records the remote observation.
        state
            .peers
            .with_current(&owner, |peer| peer.state.write().local_approve_sent = true)
            .expect("authenticated Closed owner remains current");
        on_approve(&state, &owner).await;
        assert_eq!(
            state
                .peers
                .get_if_current(&owner)
                .unwrap()
                .state
                .read()
                .status,
            PeerStatus::PendingApproval
        );
        // A configuration label is not a replacement for the Closed bootstrap.
        state.config.write().kind = crate::config::NetworkKind::Open;
        assert!(!is_open_participation(&state));
        maybe_activate(&state, &owner).await;
        assert_eq!(
            state
                .peers
                .get_if_current(&owner)
                .unwrap()
                .state
                .read()
                .status,
            PeerStatus::PendingApproval
        );
        state.shutdown().await;
    }

    /// A registry peer whose endpoint-auth task has promoted and whose
    /// capability was **not** installed.
    ///
    /// Built against the state's exact `MeshContextId` and the peer's own
    /// Device ID, so the handler's context check passes and the control reaches
    /// the outcome under test rather than stopping at an earlier refusal. The capability the
    /// promotion issues is deliberately dropped: that is the whole scenario —
    /// a caller that won promotion, moved the channel out, and then failed to
    /// install what it was handed.
    fn promoted_peer_without_an_installed_channel(
        state: &Arc<NetworkState>,
    ) -> (
        PeerOwnerToken,
        Arc<crate::endpoint_auth::EndpointAuthTask>,
        String,
    ) {
        fn device_id(key: &ed25519_dalek::SigningKey) -> String {
            data_encoding::BASE32_NOPAD
                .encode(key.verifying_key().as_bytes())
                .to_lowercase()
        }

        let local_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let peer_key = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
        let remote_id = device_id(&peer_key);
        let context = crate::endpoint_auth::EndpointAuthContext::new(
            &state.mesh_context_id().to_string(),
            &device_id(&local_key),
            &remote_id,
            crate::connector::EndpointAuthBinding::webrtc_certificate_fingerprints(
                "arc04g-local-fp",
                "arc04g-remote-fp",
            )
            .expect("both fixture components present"),
        )
        .expect("non-empty fixture identifiers");
        let task = Arc::new(crate::endpoint_auth::EndpointAuthTask::begin(
            context,
            crate::connector::handoff_for_test(crate::runtime::runtime_for_test()),
            crate::endpoint_auth::LocalIdentitySigner::for_identity(Arc::new(
                crate::identity::Identity::from_signing_key(local_key, "arc04g-fixture"),
            )),
        ));

        // Drive the exchange to `Promoted`, then drop the capability on the
        // floor. Nothing installs it.
        let peer_contribution = crate::endpoint_auth::PeerContribution::from_wire(
            crate::endpoint_auth::LocalContribution::generate().as_str(),
        )
        .expect("a generated draw is canonical");
        task.accept_peer_hello(peer_contribution.clone())
            .expect("the first contribution binds");
        let promoted = task
            .accept_peer_proof(&crate::endpoint_auth::peer_proof_for_test(
                &task,
                &peer_contribution,
                &peer_key,
            ))
            .expect("the fixture proof promotes");
        assert!(
            matches!(
                promoted,
                crate::endpoint_auth::PeerProofAcceptance::Promoted(_)
            ),
            "non-vacuity: the task really did promote"
        );
        drop(promoted);

        super::super::install_peer(
            &state.peers,
            Arc::new(
                crate::engine::connection::PeerConnection::with_endpoint_auth_for_test(
                    remote_id.clone(),
                    Arc::clone(&task),
                ),
            ),
        );
        let owner = state.peers.owner(&remote_id).expect("installed peer owner");
        (owner, task, remote_id)
    }

    #[tokio::test]
    async fn v4_arc04g_already_promoted_without_an_installed_channel_drops() {
        // The paired half of the entry guard below, and the reason the typed
        // duplicate outcome is corroborated rather than trusted on its own.
        //
        // `PeerProofAcceptance::AlreadyPromoted` states one thing: the task moved
        // its channel out. It does not state that the capability was installed,
        // and it does not state that this frame's signature verified — the state
        // is read before any verification, so the bytes below are never
        // examined. A handler that read it as "benign duplicate, do nothing"
        // would leave this peer alive and unauthenticated forever.
        let state = crate::engine::build_test_state("arc04g-promoted-not-installed");
        let (owner, task, device_id) = promoted_peer_without_an_installed_channel(&state);

        // Non-vacuity: the entry guard cannot absorb this frame, because there
        // is nothing installed for it to absorb it with, and the task is the
        // entry's current one so the handler reaches the promotion outcome.
        let peer = state.peers.get(&device_id).expect("peer is installed");
        assert!(!peer.has_authenticated_channel());
        assert!(peer.endpoint_auth_is_current(&task));

        on_auth_response(&state, &owner, auth_response("bytes-nobody-verified")).await;

        assert!(
            state.peers.get_if_current(&owner).is_none(),
            "a promoted task with no installed channel behind it must fail closed"
        );
    }

    #[tokio::test]
    async fn v4_arc04_duplicate_auth_response_after_promotion_is_idempotent() {
        // A retransmitted AuthResponse must not re-enter promotion. Before the
        // idempotence guard it would find the handoff already consumed, be
        // refused, and drop a peer whose proof was valid.
        //
        // This is the *entry* guard: an installed authenticated channel absorbs
        // the duplicate before any task work happens, which is where every
        // ordinary sequential retransmission is caught. Its paired half —
        // a task that promoted with nothing installed behind it — is
        // `v4_arc04g_already_promoted_without_an_installed_channel_drops`.
        let state = crate::engine::build_test_state("arc04-duplicate-auth-response");
        crate::engine::insert_session_less_peer(&state, "peer", None);
        let owner = state.peers.owner("peer").expect("installed peer owner");
        let peer = state.peers.get("peer").expect("peer is installed");
        peer.install_authenticated_channel_for_test();
        assert!(
            peer.has_authenticated_channel(),
            "non-vacuity: the channel really is authenticated before the duplicate"
        );

        on_auth_response(&state, &owner, auth_response("replayed-signature")).await;

        assert!(
            state.peers.get_if_current(&owner).is_some(),
            "a duplicate must not tear the peer down"
        );
        assert!(
            state
                .peers
                .get("peer")
                .expect("peer is installed")
                .has_authenticated_channel(),
            "and the exact capability survives untouched"
        );
    }

    // Proof order and the contribution pair belong to the Endpoint Auth Task
    // and are controlled there. What stays here is the engine-owned property,
    // driven against the real handler: what a retransmission is allowed to
    // write.

    /// A Hello carrying an exact contribution plus every field a late frame
    /// could try to rewrite.
    fn hello_carrying(
        device_id: &str,
        contribution: &str,
        label: &str,
        code: &str,
        feature: &str,
    ) -> HelloMessage {
        HelloMessage {
            protocol: PROTOCOL_VERSION,
            device_id: device_id.to_string(),
            label: label.to_string(),
            nonce: contribution.to_string(),
            verification_code: code.to_string(),
            // Every well-formed peer advertises the closed endpoint-auth
            // profile alongside whatever else it supports; without it the
            // handshake now fails closed before any proof work. `feature` is
            // the id each control varies, so both are carried here.
            features: vec![
                crate::protocol::features::Feature::ENDPOINT_AUTH_V1.to_string(),
                feature.to_string(),
            ],
        }
    }

    /// The same fixture with the endpoint-auth profile deliberately absent.
    fn hello_without_endpoint_auth_profile(device_id: &str, contribution: &str) -> HelloMessage {
        HelloMessage {
            protocol: PROTOCOL_VERSION,
            device_id: device_id.to_string(),
            label: "unadvertised".to_string(),
            nonce: contribution.to_string(),
            verification_code: "zzz999".to_string(),
            // An unrelated string is not a compatibility fallback for the one
            // required profile.
            features: vec!["unrelated_profile".to_string()],
        }
    }

    #[test]
    fn v4_arc04c_profile_negotiation_refuses_an_unadvertised_peer() {
        use crate::protocol::features::Feature;

        // Non-vacuity: the advertised set really does resolve, so the refusal
        // below is the absence of the id and not a predicate that never says
        // yes. Both directions are asserted.
        assert_eq!(
            crate::endpoint_auth::negotiate_profile(&[
                Feature::ENDPOINT_AUTH_V1.to_string(),
                "unrelated_profile".to_string(),
            ]),
            Ok(crate::endpoint_auth::EndpointAuthProfile::V1Ed25519Dtls),
            "a peer advertising the profile resolves to the one closed profile"
        );
        assert_eq!(
            crate::endpoint_auth::negotiate_profile(&["unrelated_profile".to_string()]),
            Err(crate::endpoint_auth::EndpointAuthSetupError::IncompatibleProfile),
            "a peer that speaks other features but not this profile is refused"
        );
        assert_eq!(
            crate::endpoint_auth::negotiate_profile(&[]),
            Err(crate::endpoint_auth::EndpointAuthSetupError::IncompatibleProfile),
            "an empty advertisement is refused, not defaulted"
        );
        // Exact-string matching: a near-miss must not resolve, or the id would
        // be an invitation to improvise rather than a closed selector.
        assert_eq!(
            crate::endpoint_auth::negotiate_profile(&["endpoint_auth_v2".to_string()]),
            Err(crate::endpoint_auth::EndpointAuthSetupError::IncompatibleProfile),
            "no forward-compatible guessing: an unknown id is not this profile"
        );
        assert!(
            crate::protocol::features::ADVERTISED_FEATURES.contains(&Feature::ENDPOINT_AUTH_V1),
            "this build must advertise what it requires, or two MyOwnMesh peers \
             could never authenticate each other"
        );
    }

    #[tokio::test]
    async fn v4_arc04c_hello_without_the_profile_is_refused_before_any_proof_work() {
        // The live-handler half. An unadvertised peer must be dropped before a
        // contribution is bound, so no transcript exists and no proof is
        // computed for a peer that could never verify one.
        let state = crate::engine::build_test_state("arc04c-profile-refusal");
        crate::engine::insert_session_less_peer(&state, "peer", None);
        let owner = state.peers.owner("peer").expect("installed peer owner");
        let contribution = crate::endpoint_auth::LocalContribution::generate();

        on_hello(
            &state,
            &owner,
            hello_without_endpoint_auth_profile(owner.device_id(), contribution.as_str()),
        )
        .await;

        assert!(
            state.peers.get_if_current(&owner).is_none(),
            "an unadvertised peer is dropped rather than authenticated"
        );
    }

    #[tokio::test]
    async fn v4_arc04h_malformed_contribution_closes_the_exact_current_peer() {
        // The production half of the setup/terminal split, on the inbound path.
        //
        // A refusal from `PeerContribution::from_wire` is an
        // `EndpointAuthSetupError`: the parser holds no task, so it terminalizes
        // nothing and its value makes no lifecycle claim. That is exactly why
        // this control exists — with the cause no longer able to imply "the
        // attempt is over", the thing that has to fail this closed is the
        // handler's own act on its own state, and it must be asserted rather
        // than inferred from the error type as it was when both senses shared
        // one enum.
        //
        // The twins differ in one field. Both Hellos are otherwise identical
        // and both advertise the closed profile, so the drop below is
        // attributable to the contribution and not to an earlier gate.
        fn fixture(
            suffix: &str,
        ) -> (
            Arc<NetworkState>,
            Arc<crate::endpoint_auth::EndpointAuthTask>,
            PeerOwnerToken,
        ) {
            let state = crate::engine::build_test_state(suffix);
            let task = Arc::new(crate::endpoint_auth::task_for_test(
                crate::connector::handoff_for_test(crate::runtime::runtime_for_test()),
            ));
            crate::engine::install_peer(
                &state.peers,
                Arc::new(crate::engine::PeerConnection::with_endpoint_auth_for_test(
                    "peer".to_string(),
                    Arc::clone(&task),
                )),
            );
            let owner = state.peers.owner("peer").expect("installed peer owner");
            (state, task, owner)
        }

        // Non-vacuity: the canonical twin. The same handler, the same fixture,
        // the same frame — with a contribution the parser accepts — keeps the
        // peer and binds the attempt.
        {
            let (state, task, owner) = fixture("arc04h-canonical-contribution");
            on_hello(
                &state,
                &owner,
                hello_carrying(
                    "peer",
                    crate::endpoint_auth::LocalContribution::generate().as_str(),
                    "label",
                    "aaa111",
                    "feature",
                ),
            )
            .await;

            assert!(
                state.peers.get_if_current(&owner).is_some(),
                "a canonical contribution keeps the exact current peer"
            );
            assert!(
                task.terminal_error().is_none(),
                "and reaches the attempt without terminalizing it"
            );
        }

        let (state, task, owner) = fixture("arc04h-malformed-contribution");
        // The exact value under test, refused by the exact parser the handler
        // calls, with the exact setup cause. Stated here so the drop below is
        // pinned to that refusal rather than assumed to follow from it.
        assert_eq!(
            crate::endpoint_auth::PeerContribution::from_wire("not-base32!"),
            Err(crate::endpoint_auth::EndpointAuthSetupError::ContributionMalformed),
            "non-vacuity: this value really is refused, and as an input rather \
             than as a lifecycle event"
        );

        on_hello(
            &state,
            &owner,
            hello_carrying("peer", "not-base32!", "label", "aaa111", "feature"),
        )
        .await;

        // Fail-closed, and closed on the *exact* current owner: the entry is
        // removed rather than left alive and unauthenticated. This is the
        // synchronous half of the teardown; retiring the connector behind it
        // runs on the peer's own owner path, so this control asserts the
        // registry closure it can observe rather than racing that.
        assert!(
            state.peers.get_if_current(&owner).is_none(),
            "a malformed contribution closes the exact current peer rather than \
             leaving it alive and unauthenticated"
        );
        // And the refusal itself contributed no task-owned cause. A value the
        // parser rejects is a setup cause, so nothing about this frame can be
        // recorded as a reason the *attempt* ended. The one terminalization
        // reachable here is the fail-closed teardown the drop above performs:
        // `finish_drop_peer` spawns `retire_and_close`, which retires the
        // connector, which retires this task with `ChannelNotCurrent`.
        //
        // Stated as the pair rather than as one value, because that spawn is
        // the asynchronous half of the same teardown the comment above names.
        // Whether it has landed by this line is scheduling; what must hold at
        // every instant is that the cause is either absent or the lifecycle
        // one, and never one of the five a task-owned refusal would record.
        assert!(
            matches!(
                task.terminal_error(),
                None | Some(crate::endpoint_auth::EndpointAuthError::ChannelNotCurrent)
            ),
            "a refused input records no task-owned cause of its own; only the \
             fail-closed retirement behind the drop may terminalize this attempt"
        );
    }

    #[tokio::test]
    async fn v4_arc04b_duplicate_hello_replies_without_adopting_its_metadata() {
        // Migrated delayed-Hello control, restated for task-owned contributions.
        // A retransmission carries the bound contribution, so it is answered
        // from the cached proof — but everything else in that frame is still
        // attacker-controlled input. Adopting it would let a late Hello rewrite
        // the identity of an attempt that is already bound while the proof it
        // receives is the one the first Hello earned.
        let state = crate::engine::build_test_state("arc04-duplicate-hello-metadata");
        let task = Arc::new(crate::endpoint_auth::task_for_test(
            crate::connector::handoff_for_test(crate::runtime::runtime_for_test()),
        ));
        crate::engine::install_peer(
            &state.peers,
            Arc::new(crate::engine::PeerConnection::with_endpoint_auth_for_test(
                "peer".to_string(),
                Arc::clone(&task),
            )),
        );
        let owner = state.peers.owner("peer").expect("installed peer owner");

        let contribution = crate::endpoint_auth::LocalContribution::generate();
        on_hello(
            &state,
            &owner,
            hello_carrying(
                "peer",
                contribution.as_str(),
                "settled-label",
                "aaa111",
                "settled-feature",
            ),
        )
        .await;

        {
            let peer = state
                .peers
                .get_if_current(&owner)
                .expect("the first hello keeps the peer");
            let data = peer.state.read();
            assert_eq!(
                data.label, "settled-label",
                "non-vacuity: the first hello really did establish this metadata"
            );
            assert_eq!(data.verification_code_received.as_deref(), Some("aaa111"));
        }
        // The same contribution — so the task classifies this a retransmission —
        // with every other field changed.
        on_hello(
            &state,
            &owner,
            hello_carrying(
                "peer",
                contribution.as_str(),
                "rewritten-label",
                "zzz999",
                "injected-feature",
            ),
        )
        .await;

        let peer = state
            .peers
            .get_if_current(&owner)
            .expect("a retransmitted hello must not tear the peer down");
        let data = peer.state.read();
        assert_eq!(
            data.label, "settled-label",
            "the first hello's label stands"
        );
        assert_eq!(
            data.verification_code_received.as_deref(),
            Some("aaa111"),
            "and its verification code"
        );
        // The changed feature list was an input to the strict profile gate,
        // not retained peer state; the duplicate still preserves only the
        // first Hello's cosmetic metadata.
        drop(data);
        // And the retransmission is still not a lifecycle event: the attempt it
        // was answered from is intact. That a duplicate re-draws and re-signs
        // nothing is the task's own property, controlled where the exchange
        // lives rather than re-proved through the handler.
        assert!(task.terminal_error().is_none());
        assert!(!task.is_retired());
    }

    #[tokio::test]
    async fn v4_arc04b_conflicting_hello_is_terminal_and_writes_no_metadata() {
        // The other classification: a different contribution is not a repeat,
        // so it is terminal for that exact task and must leave the established
        // metadata alone on its way out.
        //
        // The cause is asserted, not merely the retirement. Retirement alone
        // would also hold if this Hello had been refused for some unrelated
        // reason, or if the conflict site went back to reporting a currentness
        // failure — and the diagnostic this path emits carries that cause, so a
        // conflict would become indistinguishable from an ordinary teardown in
        // the one record an operator actually reads.
        let state = crate::engine::build_test_state("arc04-conflicting-hello-metadata");
        let task = Arc::new(crate::endpoint_auth::task_for_test(
            crate::connector::handoff_for_test(crate::runtime::runtime_for_test()),
        ));
        crate::engine::install_peer(
            &state.peers,
            Arc::new(crate::engine::PeerConnection::with_endpoint_auth_for_test(
                "peer".to_string(),
                Arc::clone(&task),
            )),
        );
        let owner = state.peers.owner("peer").expect("installed peer owner");

        on_hello(
            &state,
            &owner,
            hello_carrying(
                "peer",
                crate::endpoint_auth::LocalContribution::generate().as_str(),
                "settled-label",
                "aaa111",
                "settled-feature",
            ),
        )
        .await;
        assert!(
            state.peers.get_if_current(&owner).is_some(),
            "non-vacuity: the first hello bound the attempt"
        );

        on_hello(
            &state,
            &owner,
            hello_carrying(
                "peer",
                crate::endpoint_auth::LocalContribution::generate().as_str(),
                "rewritten-label",
                "zzz999",
                "injected-feature",
            ),
        )
        .await;

        assert!(task.is_retired(), "a conflicting contribution is terminal");
        assert_eq!(
            task.terminal_error(),
            Some(crate::endpoint_auth::EndpointAuthError::ConflictingPeerContribution),
            "and it is terminal for the conflict, not for a currentness failure it never had"
        );
        if let Some(peer) = state.peers.get("peer") {
            let data = peer.state.read();
            assert_eq!(data.label, "settled-label");
            assert_eq!(data.verification_code_received.as_deref(), Some("aaa111"));
        }
    }

    #[tokio::test]
    async fn v4_arc04c_auth_response_for_another_context_is_refused_before_promotion() {
        // The task-context fence at the real handler. Everything else about this
        // attempt is correct: the task binds the peer's contribution and the
        // AuthResponse carries the genuine proof over that task's own transcript,
        // signed by the exact remote key its context expects — so without the
        // context check this promotes and installs. It must be refused because
        // the task authenticates a different mesh and a different remote Device
        // than the entry it is installed on.
        let state = crate::engine::build_test_state("arc04c-auth-response-context-mismatch");
        let task = Arc::new(crate::endpoint_auth::task_for_test(
            crate::connector::handoff_for_test(crate::runtime::runtime_for_test()),
        ));
        crate::engine::install_peer(
            &state.peers,
            Arc::new(crate::engine::PeerConnection::with_endpoint_auth_for_test(
                "peer".to_string(),
                Arc::clone(&task),
            )),
        );
        let owner = state.peers.owner("peer").expect("installed peer owner");
        assert!(
            !task.context_matches(
                &state.mesh_context_id().to_string(),
                crate::signing::pubkey_part("peer"),
            ),
            "non-vacuity: the fixture task really does authenticate another mesh and peer"
        );

        // The peer's half, over the task's own bound attempt.
        let peer_contribution = crate::endpoint_auth::PeerContribution::from_wire(
            crate::endpoint_auth::LocalContribution::generate().as_str(),
        )
        .expect("a generated draw is canonical");
        task.accept_peer_hello(peer_contribution.clone())
            .expect("the first canonical contribution binds this attempt");
        let proof = crate::endpoint_auth::peer_proof_for_test(
            &task,
            &peer_contribution,
            &ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]),
        );

        on_auth_response(&state, &owner, auth_response(&proof)).await;

        assert!(
            state
                .peers
                .get("peer")
                .is_none_or(|peer| !peer.has_authenticated_channel()),
            "a task built for another context must not promote this entry"
        );
    }

    #[tokio::test]
    async fn v4_arc04_auth_response_before_our_hello_is_refused() {
        // No endpoint-auth task exists for this peer, so there is no attempt to
        // complete and nothing can be promoted.
        let state = crate::engine::build_test_state("arc04-auth-response-before-hello");
        crate::engine::insert_session_less_peer(&state, "peer", None);
        let owner = state.peers.owner("peer").expect("installed peer owner");

        on_auth_response(&state, &owner, auth_response("unsolicited")).await;

        assert!(
            state
                .peers
                .get("peer")
                .is_none_or(|peer| !peer.has_authenticated_channel()),
            "an unsolicited auth_response must never promote"
        );
    }

    #[tokio::test]
    async fn v4_arc03_remote_approve_before_local_send_acceptance_converges() {
        let state =
            crate::engine::build_test_closed_state("arc03-approve-remote-first", [0x74; 32]);
        state.config.write().auto_approve = false;
        let (owner, proof) = signed_pending_auth(&state, &state.mesh_context_id().to_string());
        let remote_device = owner.device_id().to_string();
        super::super::governance::propose_role_grant(
            &state,
            &remote_device,
            crate::semantic::Role::Member,
            None,
        )
        .await
        .expect("Closed peer has canonical authority before pair gating");
        assert!(
            canonical_policy_admits_both(&state, &remote_device),
            "this control exercises the preserved Closed bilateral gate"
        );
        on_auth_response(&state, &owner, auth_response(&proof)).await;
        {
            let peer = state
                .peers
                .get_if_current(&owner)
                .expect("exact peer remains installed");
            assert!(peer.has_authenticated_channel());
            let data = peer.state.read();
            assert!(data.authenticated);
            assert_eq!(data.status, PeerStatus::PendingApproval);
        }

        on_approve(&state, &owner).await;
        {
            let peer = state
                .peers
                .get_if_current(&owner)
                .expect("exact peer remains installed");
            let data = peer.state.read();
            assert!(data.remote_approve_seen);
            assert!(!data.local_approve_sent);
            assert_eq!(data.status, PeerStatus::PendingApproval);
        }

        state
            .peers
            .get_if_current(&owner)
            .expect("exact peer remains installed")
            .state
            .write()
            .local_approve_sent = true;
        send_local_approve_owner(&state, &owner).await;

        {
            let peer = state
                .peers
                .get_if_current(&owner)
                .expect("exact peer remains installed");
            let data = peer.state.read();
            assert!(data.remote_approve_seen);
            assert!(data.local_approve_sent);
            assert_eq!(data.status, PeerStatus::Active);
        }
        state.shutdown().await;
    }

    #[tokio::test]
    async fn v4_open_policy_requires_exact_context() {
        let remote_identity = crate::identity::Identity::ephemeral();
        let remote_device = remote_identity.public_id().to_string();
        let state = crate::engine::build_test_state(&format!("open-context-fence-{remote_device}"));

        assert!(
            matches!(
                state.verified_bootstrap().policy(),
                crate::semantic::VerifiedProjectPolicy::Open
            ),
            "the control must exercise the founderless Open bootstrap"
        );
        assert_eq!(
            state.verified_bootstrap().context_id(),
            state.mesh_context_id(),
            "the engine boundary retains the bootstrap's exact context identity"
        );
        assert!(
            canonical_policy_admits_both(&state, &remote_device),
            "matching exact Open bootstrap and authenticated presence authorize the peer"
        );

        let foreign_context = crate::semantic::VerifiedBootstrap::open(format!(
            "foreign-open-context-{remote_device}"
        ))
        .expect("the foreign Open bootstrap is valid")
        .context_id();
        let foreign_bootstrap = crate::semantic::VerifiedBootstrap::open(format!(
            "foreign-open-bootstrap-{remote_device}"
        ))
        .expect("the foreign Open bootstrap is valid");
        let foreign_graph = crate::semantic::FactGraph::from_bootstrap(&foreign_bootstrap);
        let local = crate::semantic::DeviceId::from_canonical_str(state.identity.public_id())
            .expect("the local fixture identity is canonical");
        let remote = crate::semantic::DeviceId::from_canonical_str(&remote_device)
            .expect("the remote fixture identity is canonical");
        assert_ne!(foreign_context, state.mesh_context_id());
        assert!(
            !super::super::governance::canonical_policy_admits_from(
                state.verified_bootstrap(),
                &foreign_graph,
                &local.to_string(),
                &remote.to_string(),
            ),
            "a graph from a foreign Open context cannot authorize this network"
        );

        state.shutdown().await;
    }

    #[tokio::test]
    async fn v4_open_policy_recheck_cannot_cross_a_replaced_owner() {
        let state = crate::engine::build_test_state("open-fact-owner-recheck");
        state.config.write().auto_approve = true;
        let remote_identity = crate::identity::Identity::ephemeral();
        let remote_device = remote_identity.public_id().to_string();

        crate::engine::insert_session_less_peer(&state, &remote_device, None);
        let stale_owner = state
            .peers
            .owner(&remote_device)
            .expect("stale owner exists");
        state
            .peers
            .with_current(&stale_owner, |peer| {
                let mut data = peer.state.write();
                data.authenticated = true;
                data.status = PeerStatus::PendingApproval;
            })
            .expect("stale owner is current before replacement");

        crate::engine::insert_session_less_peer(&state, &remote_device, None);
        reevaluate_after_role_grant(&state, &stale_owner).await;

        let replacement = state
            .peers
            .get(&remote_device)
            .expect("replacement remains installed");
        {
            let data = replacement.state.read();
            assert!(!data.authenticated);
            assert!(!data.local_approve_sent);
            assert_eq!(data.status, PeerStatus::Sighted);
        }
        state.shutdown().await;
    }

    #[tokio::test]
    async fn v4_arc03_local_approve_without_remote_consent_stays_pending() {
        let state = crate::engine::build_test_closed_state("arc03-approve-local-only", [0x75; 32]);
        state.config.write().auto_approve = false;
        let (owner, proof) = signed_pending_auth(&state, &state.mesh_context_id().to_string());
        let remote_device = owner.device_id().to_string();
        super::super::governance::propose_role_grant(
            &state,
            &remote_device,
            crate::semantic::Role::Member,
            None,
        )
        .await
        .expect("Closed peer is canonically admitted");
        assert!(canonical_policy_admits_both(&state, &remote_device));
        on_auth_response(&state, &owner, auth_response(&proof)).await;
        {
            let peer = state
                .peers
                .get_if_current(&owner)
                .expect("exact peer remains installed");
            let mut data = peer.state.write();
            assert!(data.authenticated);
            data.local_approve_sent = true;
            assert_eq!(data.status, PeerStatus::PendingApproval);
        }

        send_local_approve_owner(&state, &owner).await;

        {
            let peer = state
                .peers
                .get_if_current(&owner)
                .expect("exact peer remains installed");
            let data = peer.state.read();
            assert!(!data.remote_approve_seen);
            assert_eq!(data.status, PeerStatus::PendingApproval);
        }
        state.shutdown().await;
    }

    #[tokio::test]
    async fn v4_activation_save_refusal_does_not_suppress_canonical_promotion() {
        let remote_identity = crate::identity::Identity::ephemeral();
        let remote_device = remote_identity.public_id().to_string();
        let state =
            crate::engine::build_test_state(&format!("approve-save-refusal-{remote_device}"));
        assert!(
            canonical_policy_admits_both(&state, &remote_device),
            "ephemeral presence admission does not create durable semantic state"
        );

        crate::engine::insert_session_less_peer(&state, &remote_device, None);
        let owner = state.peers.owner(&remote_device).expect("peer owner");
        state
            .peers
            .with_current(&owner, |peer| {
                peer.install_authenticated_channel_for_test();
                let mut data = peer.state.write();
                data.authenticated = true;
                data.local_approve_sent = true;
                data.remote_approve_seen = true;
                data.status = PeerStatus::PendingApproval;
            })
            .expect("peer remains current");
        let mut events = state.events_tx.subscribe();
        let attempted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let attempted_by_persist = Arc::clone(&attempted);

        maybe_activate_after_check_with_persistence(
            &state,
            &owner,
            || {},
            move |_, _, _| {
                attempted_by_persist.store(true, std::sync::atomic::Ordering::SeqCst);
                Err(crate::Error::Roster(
                    "injected approval projection failure".into(),
                ))
            },
        )
        .await;

        assert!(attempted.load(std::sync::atomic::Ordering::SeqCst));
        let peer = state
            .peers
            .get_if_current(&owner)
            .expect("peer remains current");
        assert_eq!(peer.state.read().status, PeerStatus::Active);
        let mut approved = false;
        while let Ok(event) = events.try_recv() {
            if matches!(
                event,
                MeshEvent::Peer(PeerEvent::Approved { device_id, .. })
                    if device_id == remote_device
            ) {
                approved = true;
                break;
            }
        }
        assert!(approved, "canonical promotion must publish approval");
        state.shutdown().await;
    }

    #[tokio::test]
    async fn v4_arc03_replacement_before_roster_persistence_cancels_activation_commit() {
        let state = crate::engine::build_test_state("arc03-approve-stale-owner");
        state.config.write().auto_approve = false;
        let (stale_owner, proof) =
            signed_pending_auth(&state, &state.mesh_context_id().to_string());
        let remote_device = stale_owner.device_id().to_string();
        assert!(canonical_policy_admits_both(&state, &remote_device));
        // This compatibility query is canonical Open admission, not presence
        // in the persisted UI roster. It is already true before activation.
        assert!(state.is_rostered(&remote_device));
        let roster_before = {
            let roster = state.roster.read();
            assert!(!roster
                .authorized_devices
                .iter()
                .any(|peer| peer.device_id == remote_device));
            (
                roster.version,
                roster.network_id.clone(),
                roster.authorized_devices.clone(),
            )
        };
        let mut events = state.events_tx.subscribe();
        let (waiter_tx, mut waiter_rx) = tokio::sync::oneshot::channel();
        let (registration, cancellation) =
            state.connect_waiter_registration_for_test(&remote_device, 1, waiter_tx);
        state.register_connect_waiter(&remote_device, registration);
        state.record_reconnect_intent(&remote_device, false);
        {
            let peer = state
                .peers
                .get_if_current(&stale_owner)
                .expect("first peer remains installed");
            let task = peer
                .endpoint_auth_task_for(stale_owner.worker())
                .expect("current task");
            let crate::endpoint_auth::PeerProofAcceptance::Promoted(capability) =
                task.accept_peer_proof(&proof).expect("valid proof")
            else {
                panic!("first proof must promote");
            };
            assert!(peer.install_authenticated_channel(&task, *capability));
            let mut data = peer.state.write();
            data.authenticated = true;
            data.status = PeerStatus::PendingApproval;
        }

        let replacement_state = Arc::clone(&state);
        let replacement_device = remote_device.clone();
        let persistence_attempted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let attempted_by_persist = Arc::clone(&persistence_attempted);
        maybe_activate_after_check_with_persistence(
            &state,
            &stale_owner,
            move || {
                crate::engine::insert_session_less_peer(
                    &replacement_state,
                    &replacement_device,
                    None,
                );
            },
            move |state, device_id, label| {
                attempted_by_persist.store(true, std::sync::atomic::Ordering::SeqCst);
                state.refresh_roster_projection(device_id, label)
            },
        )
        .await;

        {
            let replacement = state.peers.get(&remote_device).expect("replacement peer");
            let data = replacement.state.read();
            assert!(!data.authenticated);
            assert!(!data.local_approve_sent);
            assert!(!data.remote_approve_seen);
            assert_ne!(data.status, PeerStatus::Active);
        }
        assert!(matches!(
            events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
        assert!(matches!(
            waiter_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        assert!(state.has_reconnect_intent(&remote_device));
        assert!(
            !persistence_attempted.load(std::sync::atomic::Ordering::SeqCst),
            "a replaced owner must never reach roster persistence"
        );
        {
            let roster = state.roster.read();
            assert_eq!(roster.version, roster_before.0);
            assert_eq!(roster.network_id, roster_before.1);
            assert_eq!(roster.authorized_devices, roster_before.2);
            assert!(
                !roster
                    .authorized_devices
                    .iter()
                    .any(|peer| peer.device_id == remote_device),
                "a peer replaced before the persistence fence must not enter the UI roster"
            );
        }
        state.shutdown().await;
        drop(waiter_rx);
        drop(cancellation);
    }

    /// A Hello cannot carry application capability metadata.
    ///
    /// This is the pre-promotion half of the capability boundary, and it is a
    /// wire claim rather than a type claim: deleting the field from
    /// `HelloMessage` stops *this* build from producing one, but says nothing
    /// about what a peer may put on the wire. A sender that still emits the old
    /// frame — or an attacker that emits it deliberately — must be refused
    /// before it can place application metadata into this node. The retired
    /// shape is not accepted and silently stripped, so a caller cannot mistake
    /// a mixed-profile Hello for a current one.
    #[test]
    fn a_hello_carrying_retired_application_metadata_is_refused() {
        use crate::protocol::features::Feature;

        let with_advert = serde_json::json!({
            "protocol": PROTOCOL_VERSION,
            "device_id": "peer",
            "label": "Phone",
            "nonce": "noncexyz",
            "verification_code": "aaa111",
            "features": [Feature::ENDPOINT_AUTH_V1.to_string()],
            // Retired pre-session application metadata.
            "capabilities": { "tags": ["transcribe"], "app_version": "9.9.9" },
            "max_connections": 8,
            "app_version": "9.9.9",
        });

        assert!(serde_json::from_value::<HelloMessage>(with_advert).is_err());
    }
}
