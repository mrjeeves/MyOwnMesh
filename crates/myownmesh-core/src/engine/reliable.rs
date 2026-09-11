//! Acknowledged channel delivery — the engine's drive loop over state a
//! promoted session owns.
//!
//! The plain send path ([`super::send_to_peer`]) is best-effort: "send now or
//! error". This is the acknowledged contract: a frame is retained until the
//! peer's engine says it arrived, and the caller's wait resolves on that rather
//! than on a local write succeeding.
//!
//! **This module is a driver and holds no state.** Everything retained lives in
//! [`PeerSessionState`](peer_session::PeerSessionState), a field of the peer's
//! promoted session. Each operation resolves an owner, enters the registry
//! fence, and acts on the record the fence lends it.
//!
//! The contract that follows:
//!
//! * **Submission acquires the current session first.** A caller whose peer has
//!   no live session, or whose frame the provider will not fund retaining, is
//!   refused with that reason. A frame is retained under a session or not at
//!   all.
//! * **A frame ends on acknowledgement, with its caller, or with its session.**
//!   A caller that stops waiting takes its frame with it wherever dropping the
//!   frame leaves the wire contiguous — the session record's own
//!   `release_abandoned` decides where that is, because it is the only thing
//!   that knows what the peer has already been shown. Session end
//!   resolves the caller with the truth and the application decides whether the
//!   payload still means anything — which it is in a position to know and this
//!   layer is not.
//! * **Revocation and replacement need no code here.** Both drop the promoted
//!   session; the record goes with it and answers every wait on the way out.
//!
//! Delivery is exactly-once within a session: frames ride a `(stream, seq)`
//! pair, the receiver drops seqs at or below its high-water mark and
//! acknowledges cumulatively, so a retransmit cannot double-deliver. `stream` is
//! minted per session, which is what lets a late acknowledgement for a replaced
//! session be recognised and discarded rather than applied to the replacement's
//! frames.
//!
//! **This module is not the record's only writer, and nothing here may assume
//! it is.** Submission and flushing run on the engine driver task, through the
//! command queue and the state-watch tick. Inbound frames do not: each peer's
//! connector events are pumped by their own spawned task, which reaches
//! [`super::handle_inbound_frame_from`] and from there this session's
//! acknowledgement path. The two are concurrent.
//!
//! What orders them is the registry fence, per entry — and only per entry.
//! [`flush_owner`] deliberately releases it for the write, so the record can be
//! entered and mutated by the inbound task while a frame of this one's is on
//! the wire. That interval is real and is the reason `sent` is not a safe proxy
//! for "the peer has not seen this": it is set on a later acquisition than the
//! write it describes. An earlier version of the retention sweep read it that
//! way and could roll back a sequence the peer already held.

use std::sync::Arc;

use tokio::sync::oneshot;
use tracing::trace;

use crate::error::Result;
use crate::protocol::MeshMessage;
use crate::runtime::peer_session;

use super::peer_registry::PeerOwnerToken;
use super::state::NetworkState;
use super::traffic;

/// Retain one frame for acknowledged delivery to `peer`, or tell the caller why
/// not, then try once to put it on the wire.
///
/// The caller's wait is answered by exactly one place: the session record it is
/// handed to. Every refusal here happens *before* that hand-off and answers it
/// directly, so there is no arm on which a caller is answered twice or not at
/// all.
///
/// Nothing here asks whether the peer speaks the acknowledged contract. It is
/// current-profile behaviour of every build that can promote a session, so there
/// is no negotiated fact to read and no advertisement to be stale, wrong, or
/// withheld. Every fact that authorizes the retention is read inside the fence,
/// at the moment of use.
pub(crate) async fn submit(
    state: &Arc<NetworkState>,
    peer: &str,
    channel: &str,
    payload: serde_json::Value,
    reply: oneshot::Sender<Result<()>>,
) {
    let Some(owner) = state.peers.owner(peer) else {
        let _ = reply.send(Err(peer_session::no_session_error(peer)));
        return;
    };
    // Both the payload and the caller's wait are lent to the closure through
    // `Option`s rather than moved into it. A fence that refuses never runs the
    // closure, and a `oneshot::Sender` that is merely dropped resolves its
    // caller with a bare receive error that names nothing — so the values have
    // to come back out on that arm to be answered here. The closure runs at most
    // once, so each `take` is unconditional when it does.
    let mut handoff = Some((payload, reply));
    state.peers.with_live_session_state(
        &owner,
        state.session_broker.as_ref(),
        &state.mesh_context_id().to_string(),
        |session, record| {
            let (payload, reply) = handoff
                .take()
                .expect("the fence runs this closure at most once");
            record.submit(session, channel, payload, reply);
        },
    );
    if let Some((_payload, reply)) = handoff {
        let _ = reply.send(Err(peer_session::no_session_error(peer)));
        return;
    }
    flush_owner(state, &owner).await;
}

/// Drain the frames the peer's live session still owes the wire, in order.
///
/// One frame per fence entry, deliberately. The write leaves the fence, so a
/// batch collected under one acquisition would be a list of frames authorized by
/// a session that may not be current by the time the second one goes out.
/// Re-entering per frame re-proves the session per frame, and the cost of that
/// is a mutex acquisition against a write that already crosses the network.
///
/// Stops at the first failure rather than skipping ahead: the receiver's
/// contract is in-order, and a gap would stall its high-water mark behind a
/// frame that never arrives. Whatever is left stays retained until the peer
/// acknowledges it or the session ends.
pub(super) async fn flush_owner(state: &Arc<NetworkState>, owner: &PeerOwnerToken) {
    loop {
        let next = state
            .peers
            .with_live_session_state(
                owner,
                state.session_broker.as_ref(),
                &state.mesh_context_id().to_string(),
                |session, record| record.next_unsent(session),
            )
            .flatten();
        // `None` is either "nothing owed" or "the provider would not fund the
        // copy this write needs". Both stop the flush and neither loses
        // anything: the frame stays retained and unsent, and the next tick asks
        // again.
        let Some(unsent) = next else {
            return;
        };
        let seq = unsent.seq;
        if let Err(e) = super::send_application_bytes(
            state,
            owner,
            unsent.bytes.clone(),
            traffic::FrameClass::App,
        )
        .await
        {
            trace!(
                peer = %super::short_peer(owner.device_id()),
                "reliable flush paused: {e}"
            );
            return;
        }
        // Recorded through the fence again rather than on a handle held across
        // the send: if the session was replaced during the write, there is no
        // record to mark, and the frame that was written belonged to a session
        // that has since resolved its callers. Marking through a stale handle
        // would set `sent` on a replacement's frame that was never sent.
        state.peers.with_live_session_state(
            owner,
            state.session_broker.as_ref(),
            &state.mesh_context_id().to_string(),
            |_session, record| record.mark_sent(seq),
        );
        // The copy and the lease that funded it die together, here, once the
        // write that borrowed them has returned.
        drop(unsent);
    }
}

/// Settle the frames one inbound acknowledgement covers, **inside the registry
/// admission fence** and through the logical-session lender.
///
/// Called from the fence rather than after it because an acknowledgement
/// admitted for installation A and applied after A was replaced would settle
/// frames installation B retained. It cannot do that now — B's session has a
/// different stream and the record is not shared — but the ordering is what
/// makes the acknowledgement and the release one act, so no reader observes
/// frames released for an acknowledgement that was refused.
///
/// The caller waits are resolved **here**, inside the fence, rather than carried
/// out to be answered later. Each is answered while its frame and that frame's
/// entry lease are still together, so the oneshot the retained claim paid for
/// never outlives the lease that paid for it. That is safe under the locks the
/// fence holds for the same reason the abandon-drop is: sending on a oneshot
/// stores the value and wakes the waiting task, it does not run the caller's
/// continuation and it re-enters neither the registry nor the session record.
///
/// A `ChannelSeq` is deliberately not handled here. Its receive-side effect is
/// two things that must be indivisible — advancing the high-water mark and
/// handing the payload to the subscribers — and the payload leaves this fence
/// with the frame, so the dispatch side runs both, together, under its own
/// fence.
pub(super) fn admit_inbound_reliable(
    admitted: &super::peer_registry::LogicalSessionOperation,
    msg: &MeshMessage,
) {
    if let MeshMessage::ChannelAck { stream, up_to } = msg {
        admitted.with_logical_state(|operation| {
            operation.state().acknowledge(*stream, *up_to);
        });
    }
}

/// The four fields one decoded `ChannelSeq` carries, kept together.
///
/// One value rather than four parameters because they are one frame. The mark
/// and the delivery below are only truthful about parts that arrived together:
/// a caller that could pass the sequence of one frame with the payload of
/// another would be describing a frame no peer sent, and this side would record
/// having received it.
pub(super) struct InboundChannelSeq {
    pub(super) stream: u64,
    pub(super) seq: u64,
    pub(super) channel: String,
    pub(super) payload: serde_json::Value,
}

/// Receive one inbound `channel_seq`: move the high-water mark, deliver,
/// acknowledge.
///
/// The first two are one fenced step, and now one *borrow*: the mark lives in
/// the same record the delivery is authorized by, so they are reached together
/// or not at all. Combined with
/// [`PeerSessionState::receive`](peer_session::PeerSessionState::receive)'s
/// own biconditional, this session's mark records a seq exactly when its payload
/// was handed to the subscribers.
///
/// Both sides of the ordering against replacement are truthful:
///
/// * A replacement landing **before** the fence refuses the closure outright.
///   Nothing is marked, delivered or acknowledged — so the sender retransmits
///   and the frame is still fresh when it arrives.
/// * A replacement landing **after** it may make the owner-bound acknowledgement
///   fail, since the send refuses to go through a replacement under the same
///   device id. The sender then retransmits, and that retransmit really is a
///   duplicate: the payload was already delivered under the installation it was
///   admitted for.
///
/// A duplicate is re-acknowledged and not re-delivered, which is what stops a
/// sender whose earlier acknowledgement was lost. A gap is neither delivered nor
/// advanced, and answers the current contiguous mark, which tells the sender
/// exactly how far this side actually is. A frame on an unbound stream is
/// answered with nothing at all.
pub(super) async fn on_channel_seq_admitted(
    state: &Arc<NetworkState>,
    dispatch: &super::peer_registry::AdmittedInboundDispatch,
    claim: crate::resource::ResourceClaim,
    retention: crate::resource::ResourceLease,
    frame: InboundChannelSeq,
) {
    let InboundChannelSeq {
        stream,
        seq,
        channel,
        payload,
    } = frame;
    let owner = dispatch.owner();
    // Delivery is an application effect whose escape is visible outside the
    // engine: a subscriber reads `from` as a device identity, so a payload
    // admitted for one installation and delivered after that installation was
    // replaced is attributed to whoever holds the id now. Both the attribution
    // and the mark are therefore settled inside the fence.
    //
    // Gateway acceptance is a resource-backed fan-out: it never blocks on a
    // subscriber and never re-enters the registry, so it is safe under the
    // mutation lock.
    let Some(outcome) = dispatch.with_captured_logical_state(&state.peers, |operation| {
        // Keep the logical funding witness independent of the mutable state
        // borrow held by `try_receive`; the witness is the retention authority
        // for this admitted effect and does not select a carrying channel.
        let validity = operation.validity().clone();
        let outcome = operation
            .state()
            .try_receive(stream, seq, payload, |payload| {
                state
                    .application_gateway
                    .accept_channel(
                        &validity,
                        claim,
                        retention,
                        &channel,
                        owner.device_id(),
                        payload,
                    )
                    .map(|_accepted| ())
            });
        outcome
    }) else {
        // Superseded installation, or one holding no live session: the frame
        // moved nothing and reached nobody, so there is nothing to acknowledge
        // either. Acknowledging here would tell the sender a payload had been
        // received that no subscriber ever saw.
        return;
    };
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(refusal) => {
            // The same two refusals that end a session on the unreliable path,
            // for the same reason: they are facts about this session that will
            // hold for the next frame too. `NoReceiver` is not one of them —
            // nobody having subscribed yet is an ordinary state of a healthy
            // session. Nothing is acknowledged on any of these arms, so a
            // refused frame is never reported to the sender as received.
            let terminal = match refusal {
                crate::application_gateway::GatewayRefusal::Pressure(_) => {
                    Some("would not fund the reliable frame it delivered")
                }
                crate::application_gateway::GatewayRefusal::Malformed => {
                    Some("delivered a reliable frame that is not representable")
                }
                _ => None,
            };
            // Reached only on the arms that are about to retire. The dispatch's
            // logical operation names the session admitted for this frame, so a
            // replacement promoted in the interval fails the identity check and
            // remains untouched.
            if terminal.is_some() {
                state.reach_exact_retirement_barrier();
            }
            match terminal {
                Some(reason)
                    if state
                        .peers
                        .retire_exact_session(dispatch.logical_reply_operation()) =>
                {
                    trace!(
                        peer = %super::short_peer(owner.device_id()),
                        channel,
                        %reason,
                        "retiring a session whose reliable frame could not be admitted"
                    );
                }
                _ => trace!(
                    peer = %super::short_peer(owner.device_id()),
                    channel,
                    "reliable frame refused by Application Gateway"
                ),
            }
            return;
        }
    };
    let Some(ack_up_to) = outcome.acknowledge() else {
        // A stream this session is not bound to. Answering would put a mark on
        // *our* bound stream in reply to a frame that was never part of it,
        // which is the sender-visible half of letting a peer reset our state.
        trace!(
            peer = %super::short_peer(owner.device_id()),
            "reliable frame on an unbound stream refused"
        );
        return;
    };
    let msg = MeshMessage::ChannelAck {
        stream,
        up_to: ack_up_to,
    };
    // Test observation only, taken here because this is the point past every
    // refusal above: reaching it *is* the decision to acknowledge, whatever the
    // wire then does with it. See `NetworkState::channel_ack_attempts`.
    #[cfg(test)]
    state
        .channel_ack_attempts
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if let Err(e) = super::send_to_peer_owner(state, owner, &msg).await {
        trace!(
            peer = %super::short_peer(owner.device_id()),
            "channel_ack send failed: {e}"
        );
    }
}

/// State-watch tick: re-attempt flushes for peers whose session still holds
/// unsent frames.
///
/// Flush only, and there is nothing here to expire against: a retained frame
/// ends when the peer acknowledges it or when the session retaining it ends, and
/// this loop is the arbiter of neither. A deadline enforced here would report a
/// choice this process made as though it were a fact about the peer.
pub(crate) async fn tick(state: &Arc<NetworkState>) {
    for owner in state.peers.owners_with_unsent_reliable_frames() {
        flush_owner(state, &owner).await;
    }
}

/// The exact encoded frame one submission retains, for controls that must send
/// or size a frame the record would actually accept.
#[cfg(all(test, feature = "transport-lab"))]
pub(super) fn encoded_frame_for_test(
    stream: u64,
    seq: u64,
    channel: &str,
    payload: &str,
) -> bytes::Bytes {
    bytes::Bytes::from(
        serde_json::to_vec(&MeshMessage::ChannelSeq {
            stream,
            seq,
            channel: channel.to_string(),
            payload: serde_json::json!(payload),
        })
        .expect("a control frame of owned strings serializes"),
    )
}
