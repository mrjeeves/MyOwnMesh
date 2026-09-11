//! Local RPC operations: handler registration, in-flight resolution, the
//! outbound call, and the streaming call with the frame builders that forward
//! it without constructing anything the writer mailbox has not admitted.
//!
//! Four of these carry a `client_id` and the capability that proves it, and
//! every one of those checks it first — before a network lookup, before a
//! reply is measured, before anything is claimed. Registration is the reason
//! this matters most: a method claim is process-wide state, so an
//! unauthenticated caller must not be able to reach the point where one is
//! taken and then released.
//!
//! Like every operation module here, nothing writes. Each function answers
//! with an [`Answer`]: the reply, and the line capacity it was admitted under.
//! The connection loop encodes and writes.

use std::sync::Arc;

use anyhow::{Context, Result};

use super::{funded, refused, refused_text, unknown_network, Answer};
use crate::control::framing::{AdmittedLineOut, FrameAdmission};
use crate::control::handoff::ProvisionalHandoff;
use crate::control::reply::{
    prepare_reply_then, ControlOut, FundedVariableReply, OperationReplyData, PreparedReply,
    ResponseOwner,
};
use crate::control::{ConnectionCancel, ControlState};

/// The refusal shared by every client-scoped operation here.
const BAD_CLIENT: &str = "invalid local client authority";

/// The five coordinates that name one filed inbound call.
///
/// They travel together because they are one thing: `network`, `peer`,
/// `method` and `request_id` are the [`PendingKey`](crate::ipc::clients::PendingKey)
/// the entry was filed under, and `operation_id` is the process-local
/// ownership token for that exact entry. Answering, pushing a chunk, and
/// closing all need the whole set and none of them needs part of it.
pub(in crate::control) struct FiledCall {
    pub network: String,
    pub peer: String,
    pub method: String,
    pub request_id: String,
    pub operation_id: u64,
}

/// Register a local handler for one method on one network.
///
/// The order is the whole operation: the response line is funded, then a
/// generation is taken, then the core-side handler is prepared, and only then
/// is the method claimed. Each step that fails releases the funding it has not
/// used before building its refusal, so a refused registration leaves the
/// connection holding exactly what it held before.
pub(in crate::control) async fn register(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    client_id: crate::ipc::ClientId,
    client_capability: String,
    network: String,
    method: String,
    streaming: bool,
) -> Result<Answer> {
    if state
        .clients
        .authenticate(client_id, &client_capability)
        .is_none()
    {
        return refused(BAD_CLIENT, admission);
    }
    let Some(net) = state.registry.get(&network) else {
        return unknown_network(&network, admission);
    };
    let success = PreparedReply::Bool {
        key: "registered",
        value: true,
    };
    let output = AdmittedLineOut::prepare(&ControlOut::Prepared(&success), admission)
        .context("RPC-register response capacity was not admitted")?;
    let mode = if streaming {
        crate::ipc::clients::HandlerMode::Stream
    } else {
        crate::ipc::clients::HandlerMode::Single
    };
    let key = (network, method);
    let generation = state.clients.next_handler_generation();
    let prepared = match crate::ipc::bridge::prepare_handler_for_mode(
        &net.rpc(),
        &key,
        generation,
        mode,
        &state.clients,
    ) {
        Ok(prepared) => prepared,
        Err(refusal) => {
            drop(output);
            return refused_text(format!("rpc register refused: {refusal}"), admission);
        }
    };
    let previous = match state
        .clients
        .claim_method_committing_with_key(key, client_id, mode, generation, prepared)
    {
        Ok(previous) => previous,
        Err(refusal) => {
            drop(output);
            return refused_text(format!("rpc register refused: {refusal}"), admission);
        }
    };
    if let Some((previous, key)) = previous {
        crate::ipc::bridge::notify_displaced(&state.clients, previous, client_id, key.0, key.1);
    }
    Ok((success, output))
}

/// Release a method claim this client holds.
pub(in crate::control) async fn unregister(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    client_id: crate::ipc::ClientId,
    client_capability: String,
    network: String,
    method: String,
) -> Result<Answer> {
    if state
        .clients
        .authenticate(client_id, &client_capability)
        .is_none()
    {
        return refused(BAD_CLIENT, admission);
    }
    // Funded against the widest boolean the line can carry, so the real answer
    // encodes into capacity taken before the release happened.
    let ceiling = PreparedReply::Bool {
        key: "released",
        value: false,
    };
    let output = AdmittedLineOut::prepare(&ControlOut::Prepared(&ceiling), admission)
        .context("RpcUnregister response capacity was not admitted")?;
    let key = (network, method);
    let release = state.clients.release_method(&key, client_id);
    let released = release.released;
    // Releasing the core registration is the local commit. Output capacity is
    // already held, and cancellation only races the later write.
    drop(release);
    Ok((
        PreparedReply::Bool {
            key: "released",
            value: released,
        },
        output,
    ))
}

/// Build the identity of one in-flight inbound request.
fn pending_key(
    network: String,
    method: String,
    peer: String,
    request_id: String,
    class: crate::ipc::clients::HandlerMode,
) -> crate::ipc::clients::PendingKey {
    crate::ipc::clients::PendingKey {
        network,
        method,
        remote_peer: peer,
        remote_request_id: request_id,
        class,
    }
}

/// Resolve one in-flight single-response request.
pub(in crate::control) async fn respond(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    client_id: crate::ipc::ClientId,
    client_capability: String,
    call: FiledCall,
    ok: Option<serde_json::Value>,
    error: Option<String>,
) -> Result<Answer> {
    let FiledCall {
        network,
        peer,
        method,
        request_id,
        operation_id,
    } = call;
    if state
        .clients
        .authenticate(client_id, &client_capability)
        .is_none()
    {
        return refused(BAD_CLIENT, admission);
    }
    let success = PreparedReply::Bool {
        key: "resolved",
        value: true,
    };
    let key = pending_key(
        network,
        method,
        peer,
        request_id,
        crate::ipc::clients::HandlerMode::Single,
    );
    let result = error.map_or_else(|| Ok(ok.unwrap_or(serde_json::Value::Null)), Err);
    let (resolved, output) = prepare_reply_then(&success, admission, || {
        state
            .clients
            .resolve_exact_single(&key, client_id, operation_id, result)
    })
    .context("RPC-resolve response capacity was not admitted")?;
    if resolved {
        return Ok((success, output));
    }
    drop(output);
    refused_text(
        format!("no in-flight inbound RPC for '{}'", key.remote_request_id),
        admission,
    )
}

/// Push one chunk onto an in-flight streaming response.
pub(in crate::control) async fn stream_chunk(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    client_id: crate::ipc::ClientId,
    client_capability: String,
    call: FiledCall,
    payload: serde_json::Value,
) -> Result<Answer> {
    let FiledCall {
        network,
        peer,
        method,
        request_id,
        operation_id,
    } = call;
    if state
        .clients
        .authenticate(client_id, &client_capability)
        .is_none()
    {
        return refused(BAD_CLIENT, admission);
    }
    let success = PreparedReply::Bool {
        key: "delivered",
        value: true,
    };
    let key = pending_key(
        network,
        method,
        peer,
        request_id,
        crate::ipc::clients::HandlerMode::Stream,
    );
    let (accepted, output) = prepare_reply_then(&success, admission, || {
        state
            .clients
            .push_exact_stream(&key, client_id, operation_id, payload)
    })
    .context("stream-chunk response capacity was not admitted")?;
    if accepted {
        return Ok((success, output));
    }
    drop(output);
    refused_text(
        format!(
            "no in-flight inbound stream for '{}'",
            key.remote_request_id
        ),
        admission,
    )
}

/// Close an in-flight streaming response, cleanly or with an error.
///
/// Unlike the chunk push, "there was no such stream" is not a refusal here: a
/// close that finds nothing to close answers `closed: false`. The line is
/// funded against the widest boolean before the close is attempted, so both
/// answers encode into the same admitted capacity.
pub(in crate::control) async fn stream_end(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    client_id: crate::ipc::ClientId,
    client_capability: String,
    call: FiledCall,
    error: Option<String>,
) -> Result<Answer> {
    let FiledCall {
        network,
        peer,
        method,
        request_id,
        operation_id,
    } = call;
    if state
        .clients
        .authenticate(client_id, &client_capability)
        .is_none()
    {
        return refused(BAD_CLIENT, admission);
    }
    let ceiling = PreparedReply::Bool {
        key: "closed",
        value: false,
    };
    let key = pending_key(
        network,
        method,
        peer,
        request_id,
        crate::ipc::clients::HandlerMode::Stream,
    );
    let (closed, output) = prepare_reply_then(&ceiling, admission, || {
        state
            .clients
            .close_exact_stream(&key, client_id, operation_id, error)
    })
    .context("stream-close response capacity was not admitted")?;
    Ok((
        PreparedReply::Bool {
            key: "closed",
            value: closed,
        },
        output,
    ))
}

/// Call a method on a remote peer and answer with whatever came back.
///
/// This is the one operation here that can end the connection rather than
/// answer it, and the `Option` says so in the type: a call cancelled by the
/// connection draining has no reply, because the daemon never learned what the
/// answer would have been. Every other outcome — including a remote error — is
/// a reply. Returning `Answer` and inventing a refusal for the cancelled case
/// would claim a result that was never obtained.
pub(in crate::control) async fn call(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    cancel: &ConnectionCancel,
    network: String,
    peer: String,
    method: String,
    payload: serde_json::Value,
) -> Result<Option<Answer>> {
    let Some(joined) = state.registry.get(&network) else {
        return unknown_network(&network, admission).map(Some);
    };
    // The result's size is not known until it arrives, so the right to answer is
    // taken before the call is made rather than after it returns.
    let owner =
        ResponseOwner::acquire(admission).context("RpcCall result operation was not admitted")?;
    let rpc = joined.rpc();
    let result = tokio::select! {
        biased;
        () = cancel.cancelled() => return Ok(None),
        result = rpc.call_funded(&peer, &method, payload) => result,
    };
    funded(
        PreparedReply::Variable(FundedVariableReply::rpc_call(result, owner)),
        admission,
    )
    .context("RpcCall response line was not admitted")
    .map(Some)
}

/// One client-requested streaming call, exactly as the request stated it.
///
/// A carrier for the fields the `RpcCallStream` arm destructured. The payload
/// travels by value because the call consumes it; nothing here copies it.
pub(in crate::control) struct StreamCall {
    pub network: String,
    pub peer: String,
    pub method: String,
    pub payload: serde_json::Value,
}

/// One forwarded stream chunk, measured before the frame exists.
///
/// The payload is *moved* into the frame rather than copied, so unlike the
/// inbound-RPC and channel builders this one does not exist to avoid a clone.
/// It exists to keep the outer queue from charging the process grant a second
/// time for a graph core is already holding a reservation on. See
/// [`Self::measured_claim`].
struct StreamChunkBuilder<'a> {
    /// Borrowed from the forwarding task, which owns it for the whole stream.
    /// The frame's owned copy is made by [`Self::build`], past admission.
    request_id: &'a str,
    chunk: myownmesh_core::rpc::RpcStreamChunk,
}

unsafe impl myownmesh_core::ResourceMailboxItemBuilder<crate::ipc::ServerOut>
    for StreamChunkBuilder<'_>
{
    fn measured_claim(
        &self,
    ) -> Result<
        myownmesh_core::MailboxMeasurement<crate::ipc::ServerOut>,
        myownmesh_core::ResourceMailboxItemError,
    > {
        myownmesh_core::measure_serialized_mailbox_item_after_funded::<crate::ipc::ServerOut>(
            &crate::ipc::wire::ServerOutView::RpcCallStreamChunk {
                request_id: self.request_id,
                payload: self.chunk.value(),
            },
            self.chunk.funded_claim()?,
        )
    }

    fn build(self) -> crate::ipc::ServerOut {
        crate::ipc::ServerOut::RpcCallStreamChunk {
            request_id: self.request_id.to_owned(),
            payload: self.chunk,
        }
    }
}

/// One end-of-stream marker, measured before the frame exists.
///
/// Both kinds of reason are held as something that already exists rather than
/// as a `String`: a remote terminal is peer-sized text core is still funding,
/// and a local refusal has no business being formatted before the writer
/// mailbox has agreed to hold it. Either way the owned field is made by
/// [`Self::build`], past admission.
struct StreamEndBuilder<'a> {
    request_id: &'a str,
    reason: crate::ipc::wire::TerminalReasonView<'a>,
}

unsafe impl myownmesh_core::ResourceMailboxItemBuilder<crate::ipc::ServerOut>
    for StreamEndBuilder<'_>
{
    fn measured_claim(
        &self,
    ) -> Result<
        myownmesh_core::MailboxMeasurement<crate::ipc::ServerOut>,
        myownmesh_core::ResourceMailboxItemError,
    > {
        myownmesh_core::measure_serialized_mailbox_item::<crate::ipc::ServerOut>(
            &crate::ipc::wire::ServerOutView::RpcCallStreamEnd {
                request_id: self.request_id,
                error: self.reason,
            },
        )
    }

    fn build(self) -> crate::ipc::ServerOut {
        crate::ipc::ServerOut::RpcCallStreamEnd {
            request_id: self.request_id.to_owned(),
            error: self.reason.into_owned(),
        }
    }
}

/// End one forwarded stream: land the terminal, or disconnect the exact client.
///
/// A started stream owes its client exactly one ending. The writer mailbox can
/// refuse the terminal — it is admitted like any other frame — and a refusal
/// discarded here leaves the client registered, connected, and waiting on an
/// operation that will never produce another frame.
///
/// So the refusal is not discarded. The exact client is unregistered through
/// the same seam a disconnect uses, and that is what ends the operation: its
/// `connected` flag falls, the connection's own cancellation observes it, the
/// connection loop returns, and the socket reaches end of file. Nothing is
/// retried, no capacity is reserved ahead for a terminal, and no duration is
/// consulted.
async fn end_stream(
    state: &Arc<ControlState>,
    client_id: crate::ipc::ClientId,
    writer_tx: &myownmesh_core::ResourceMailboxSender<crate::ipc::ServerOut>,
    request_id: &str,
    reason: crate::ipc::wire::TerminalReasonView<'_>,
) {
    if writer_tx
        .send_building(StreamEndBuilder { request_id, reason })
        .is_ok()
    {
        return;
    }
    disconnect_exact(state, client_id).await;
}

/// Unregister exactly this client and settle everything it owned.
///
/// The exact id, never a successor: `unregister` answers `None` for an id the
/// table no longer holds, so a client that has already gone — or one displaced
/// by a reconnect under a new id — is not torn down by a late stream ending.
async fn disconnect_exact(state: &Arc<ControlState>, client_id: crate::ipc::ClientId) {
    if let Some(removed) = state.clients.unregister(client_id) {
        crate::control::realtime_pipe::release_owned_registrations(state, removed).await;
    }
}

/// Start a streaming RPC call and hand back the forwarding that has not begun.
///
/// The call's coordinates arrive as [`StreamCall`] rather than as a `Request`,
/// so the signature is the claim about who may call this, checked, rather than
/// a runtime `unreachable!`.
///
/// Nothing is spawned here. The request id in the reply is the client's only
/// handle on this stream, and only the connection loop knows whether the line
/// carrying it was written, so the started stream travels back as a
/// [`ProvisionalHandoff`] and begins forwarding — or is withdrawn — there.
pub(in crate::control) async fn call_stream_funded(
    state: &Arc<ControlState>,
    cancel: &ConnectionCancel,
    owner: ResponseOwner,
    call: StreamCall,
    client_id: crate::ipc::ClientId,
    client_capability: String,
) -> (FundedVariableReply, ProvisionalHandoff) {
    let StreamCall {
        network,
        peer,
        method,
        payload,
    } = call;
    let Some(client) = state.clients.authenticate(client_id, &client_capability) else {
        return (
            owner.finish(Err("invalid local client authority".to_owned())),
            ProvisionalHandoff::None,
        );
    };
    let Some(net) = state.registry.get(&network) else {
        return (
            owner.finish(Err(format!("unknown network: {network}"))),
            ProvisionalHandoff::None,
        );
    };
    let request_id = format!("ipc-stream-{}", state.clients.next_call_stream_id());
    let task = match state.clients.lease_task_retaining(request_id.len()) {
        Ok(task) => task,
        Err(refusal) => {
            return (
                owner.finish(Err(format!("rpc call stream refused: {refusal}"))),
                ProvisionalHandoff::None,
            )
        }
    };
    let rpc = net.rpc();
    let started = tokio::select! {
        biased;
        () = cancel.cancelled() => {
            return (
                owner.finish(Err("control connection closing".to_owned())),
                ProvisionalHandoff::None,
            )
        }
        result = rpc.call_stream(&peer, &method, payload) => result,
    };
    let rx = match started {
        Ok(rx) => rx,
        Err(error) => {
            return (
                owner.finish(Err(error.to_string())),
                ProvisionalHandoff::None,
            )
        }
    };
    let pending = PendingStreamForward {
        task,
        rx,
        writer_tx: client.writer_tx.clone(),
        stream_owner: client.clone(),
        request_id: request_id.clone(),
        // The registry, for the one thing the forward may have to do to its own
        // client: end it. Cloned rather than borrowed because the task outlives
        // this call.
        ending_state: Arc::clone(state),
        client_id,
        #[cfg(test)]
        panic_after_start: false,
    };
    (
        owner.finish(Ok(OperationReplyData::RpcStreamStarted(request_id))),
        ProvisionalHandoff::RpcStream(pending),
    )
}

/// One started remote stream and the forwarding that has not been spawned.
///
/// Everything the forwarding loop needs, held rather than running. Dropping it
/// drops the receiver, which withdraws the filed stream at core's own seam, and
/// releases the task admission the setup took — the whole rollback, with no
/// cancellation to observe because nothing was started.
///
/// The exact client id and the exact client handle are both carried: the handle
/// is what the loop waits on and forwards through, the id is what a terminal
/// refusal unregisters. Neither is re-resolved later, so a client that
/// reconnected under a new id is never mistaken for this one.
pub(in crate::control) struct PendingStreamForward {
    task: crate::ipc::TaskAdmission,
    rx: myownmesh_core::rpc::RpcStream,
    writer_tx: myownmesh_core::ResourceMailboxSender<crate::ipc::ServerOut>,
    stream_owner: myownmesh_core::FundedArc<crate::ipc::ClientHandle>,
    request_id: String,
    ending_state: Arc<ControlState>,
    client_id: crate::ipc::ClientId,
    #[cfg(test)]
    panic_after_start: bool,
}

impl PendingStreamForward {
    /// Begin forwarding, now that the client holds the request id that names
    /// what will arrive.
    pub(in crate::control) fn spawn(self) {
        let Self {
            task,
            mut rx,
            writer_tx,
            stream_owner,
            request_id: req_id_for_task,
            ending_state,
            client_id,
            #[cfg(test)]
            panic_after_start,
        } = self;
        let ending_clients = ending_state.clients.clone();
        let forwarding = async move {
            #[cfg(test)]
            if panic_after_start {
                panic!("injected RPC stream forwarder panic");
            }
            loop {
                // `recv_funded`, not `recv`: the ordinary public `recv` converts a
                // terminal into an application-owned `String` and releases core's
                // lease in the same expression. The daemon is not at that boundary
                // until it has forwarded the value, so it takes the funded form and
                // reads the text by borrow.
                let chunk = tokio::select! {
                    () = stream_owner.wait_disconnected() => return,
                    chunk = rx.recv_funded() => chunk,
                };
                let Some(chunk) = chunk else { break };
                match chunk {
                    Ok(payload) => {
                        if let Err(refusal) = writer_tx.send_building(StreamChunkBuilder {
                            request_id: &req_id_for_task,
                            chunk: payload,
                        }) {
                            // Still only a cause. It becomes a message inside
                            // `build`, past this second admission. One substitute
                            // attempt is enough: if the writer will not take the
                            // terminal either, the client is disconnected instead
                            // of left holding a started operation.
                            end_stream(
                                &ending_state,
                                client_id,
                                &writer_tx,
                                &req_id_for_task,
                                crate::ipc::wire::TerminalReasonView::LocalChunkRefusal(&refusal),
                            )
                            .await;
                            return;
                        }
                    }
                    Err(terminal) => {
                        // `terminal` is alive across measurement, admission and the
                        // build, so core's session lease is paying for the
                        // peer-sized text for the whole time the daemon is deciding
                        // whether it may forward it. It is dropped only once the
                        // write-side owner exists.
                        end_stream(
                            &ending_state,
                            client_id,
                            &writer_tx,
                            &req_id_for_task,
                            crate::ipc::wire::TerminalReasonView::Remote(&terminal),
                        )
                        .await;
                        return;
                    }
                }
            }
            end_stream(
                &ending_state,
                client_id,
                &writer_tx,
                &req_id_for_task,
                crate::ipc::wire::TerminalReasonView::Clean,
            )
            .await;
        };
        if let Err((_task, _forwarding, refusal)) =
            ending_clients.spawn_retained_task(task, forwarding)
        {
            // Retention and spawn are one fenced operation. A refusal returns
            // both owned inputs before a JoinHandle exists, so there is no
            // unowned task to abort or await and no detached cleanup path.
            tracing::warn!("RPC stream forwarder refused: {refusal}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myownmesh_core::ResourceMailboxItemBuilder;

    /// The borrowed mirrors must encode byte-for-byte as the frames they stand
    /// in for. If they ever diverge the mailbox admitted one frame and queued a
    /// different one, and every measurement in this module would be about
    /// something that never gets sent.
    ///
    /// All three arms are covered, including `Remote` — that is the one whose
    /// width a peer chooses, so it is the one a mirror is most likely to get
    /// wrong and the one that matters most. Its terminal comes from a real
    /// stream that ends rather than a fabricated value.
    #[tokio::test]
    async fn v4_r5_daemon_a_measured_stream_frame_matches_the_frame_it_becomes() {
        let refusal = myownmesh_core::ResourceMailboxAdmissionError::Closed;
        let scope = crate::test_application_scope();
        let inbox = myownmesh_core::rpc::TransportLabStreamInbox::new();
        inbox
            .finish_owned(&scope, "w".repeat(4096))
            .expect("the fixture scope funds one terminal of this width");
        let terminal = match inbox.recv_funded().await {
            Some(Err(terminal)) => terminal,
            _ => panic!("the stream ends with the terminal it was finished with"),
        };
        for reason in [
            crate::ipc::wire::TerminalReasonView::Clean,
            crate::ipc::wire::TerminalReasonView::LocalChunkRefusal(&refusal),
            crate::ipc::wire::TerminalReasonView::Remote(&terminal),
        ] {
            let builder = StreamEndBuilder {
                request_id: "ipc-stream-7",
                reason,
            };
            let measured = serde_json::to_vec(&crate::ipc::wire::ServerOutView::RpcCallStreamEnd {
                request_id: builder.request_id,
                error: builder.reason,
            })
            .expect("the mirror encodes");
            let measured_claim =
                myownmesh_core::ResourceMailboxSender::<crate::ipc::ServerOut>::
                    building_item_planning_charge(&builder)
                .expect("the mirror's claim is representable");

            let built = builder.build();
            let built_bytes = serde_json::to_vec(&built).expect("the frame encodes");
            let built_claim =
                myownmesh_core::ResourceMailboxSender::<crate::ipc::ServerOut>::
                    accepted_item_planning_charge(&built)
                .expect("the frame's claim is representable");

            assert_eq!(
                String::from_utf8(measured).expect("JSON is UTF-8"),
                String::from_utf8(built_bytes).expect("JSON is UTF-8"),
                "the borrowed mirror must encode exactly as the frame it measured"
            );
            assert_eq!(
                measured_claim, built_claim,
                "the admitted claim must be the claim the queued frame retains"
            );
        }
    }

    /// What opening one writer costs, plus what the frames a control queues
    /// actually consume.
    ///
    /// **Both halves are priced by production, and neither is a list of
    /// classes.** [`starved_grant`] is the mailbox's own opening charge, from
    /// `root_claim` and the provider's planning prices. The addend is
    /// `accepted_item_planning_charge`, which is the mailbox's own answer to
    /// "what does accepting this value cost" — both reservations it makes per
    /// item, and the provider's record of each.
    ///
    /// A hand-written list was wrong twice, in the same way each time, which is
    /// why there is no list here any more. It named no `CallbackOrScheduledWork`
    /// and the *open* was refused for one unit against zero; it then named no
    /// [`QueuedBytes`](myownmesh_core::ResourceClass::QueuedBytes) and the first
    /// *queued frame* was refused, because that is a dimension every accepted
    /// item charges and no amount of generosity in the other three supplies it.
    /// A fixture that enumerates dimensions is a second, silently drifting copy
    /// of the admission shape; this one asks the shape.
    ///
    /// The representative frame is far wider than anything these controls
    /// actually send — a 4 KiB terminal reason against real request ids of about
    /// twenty bytes and a five-byte chunk payload — and it is scaled for several
    /// frames, so the amounts are headroom while the dimensions are exact.
    ///
    /// Nothing here weakens the two pressure controls beside it: both still open
    /// over `starved_grant` alone, so their refusal is still the first admission
    /// after an open that consumed the whole grant.
    fn unpressured_grant() -> myownmesh_core::ResourceClaim {
        let representative = crate::ipc::ServerOut::RpcCallStreamEnd {
            request_id: "ipc-stream-fixture".to_owned(),
            error: Some("x".repeat(4096)),
        };
        let per_frame = myownmesh_core::ResourceMailboxSender::<crate::ipc::ServerOut>::accepted_item_planning_charge(
            &representative,
        )
        .expect("the representative frame is priceable");
        starved_grant()
            .checked_add(
                per_frame
                    .checked_scale(16)
                    .expect("sixteen such frames are representable"),
            )
            .expect("the fixture grant is representable")
    }

    /// One started stream, held exactly as `call_stream_funded` hands it back.
    ///
    /// Built here rather than through `call_stream_funded` because that function
    /// needs a joined network and a reachable peer to start a stream at all,
    /// and what is under test is what happens to the stream *after* it started —
    /// which is this value and the settle that consumes it.
    fn pending_forward(
        state: &Arc<ControlState>,
        client: &myownmesh_core::FundedArc<crate::ipc::ClientHandle>,
        writer_tx: &myownmesh_core::ResourceMailboxSender<crate::ipc::ServerOut>,
        rx: myownmesh_core::rpc::RpcStream,
        request_id: &str,
    ) -> PendingStreamForward {
        PendingStreamForward {
            task: state
                .clients
                .lease_task_retaining(request_id.len())
                .expect("the fixture registry funds one forwarding task"),
            rx,
            writer_tx: writer_tx.clone(),
            stream_owner: client.clone(),
            request_id: request_id.to_owned(),
            ending_state: Arc::clone(state),
            client_id: client.id,
            panic_after_start: false,
        }
    }

    /// A stream setup response that was never written forwards nothing, ever.
    ///
    /// The discriminating case for A1's RPC-stream arm. The request id in the
    /// setup response is the client's only handle on the stream; if the line is
    /// refused or the socket ends first, a forwarding task started before the
    /// answer would be writing frames for an operation the client was never told
    /// about. Nothing is spawned until the settle, so this is true by
    /// construction rather than by cancelling a task afterwards — and the chunk
    /// waiting in the stream is what makes the absence meaningful: there is
    /// something to forward, and it is not forwarded.
    ///
    /// The stream is production's, over the fixture inbox's own real inbox; see
    /// [`myownmesh_core::rpc::TransportLabStreamInbox::stream`]. Its
    /// cancellation is inert, so what this proves is the forwarding half —
    /// the gateway-side withdrawal a dropped receiver performs is core's and is
    /// tested there.
    #[test]
    fn v4_r6_daemon_a1_an_unhanded_stream_setup_forwards_nothing() {
        crate::services::with_service_cleanup(
            crate::services::test_cleanup_scope(),
            |cleanup_port| async move {
                let state = crate::control::joinless_control_state(cleanup_port.clone()).await;
                let (tx, mut rx, _provider, _port) = writer_over_grant(unpressured_grant());
                let client = state
                    .clients
                    .register(tx.clone())
                    .expect("the fixture registry admits one client");

                let inbox = myownmesh_core::rpc::TransportLabStreamInbox::new();
                let scope = crate::test_application_scope();
                inbox
                    .push(&scope, serde_json::json!("chunk"))
                    .expect("the fixture scope funds one chunk");
                let pending =
                    pending_forward(&state, &client, &tx, inbox.stream(), "ipc-stream-unhanded");

                ProvisionalHandoff::RpcStream(pending)
                    .settle(&state, false)
                    .await;

                // Driven as far as the runtime will go. A task that had been spawned
                // would have had every opportunity to run; the negative is that the
                // writer is still empty after that, not that a duration elapsed.
                for _ in 0..1_000 {
                    tokio::task::yield_now().await;
                }
                assert!(
                    rx.try_recv().is_none(),
                    "no frame was ever written for a stream the client was never told \
             about"
                );
            },
        );
    }

    /// The positive twin: a delivered setup response starts the forwarding.
    ///
    /// Without this the control above would be satisfied by a build that never
    /// forwarded anything. The chunk that was waiting arrives, under the exact
    /// request id the client was answered with.
    #[test]
    fn v4_r6_daemon_a1_a_delivered_stream_setup_starts_forwarding() {
        crate::services::with_service_cleanup(
            crate::services::test_cleanup_scope(),
            |cleanup_port| async move {
                let state = crate::control::joinless_control_state(cleanup_port.clone()).await;
                let (tx, mut rx, provider, port) = writer_over_grant(unpressured_grant());
                let setup_baseline = provider.in_use();
                assert_ne!(
                    setup_baseline,
                    myownmesh_core::ResourceClaim::ZERO,
                    "the private writer setup must hold its funded root before forwarding"
                );
                let client = state
                    .clients
                    .register(tx.clone())
                    .expect("the fixture registry admits one client");

                let inbox = myownmesh_core::rpc::TransportLabStreamInbox::new();
                let scope = crate::test_application_scope();
                inbox
                    .push(&scope, serde_json::json!("chunk"))
                    .expect("the fixture scope funds one chunk");
                let pending =
                    pending_forward(&state, &client, &tx, inbox.stream(), "ipc-stream-handed");

                ProvisionalHandoff::RpcStream(pending)
                    .settle(&state, true)
                    .await;

                let delivered = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
                    .await
                    .expect("hang guard: the forwarding task writes the waiting chunk")
                    .expect("the writer mailbox is open, so the chunk is delivered");
                match delivered.value() {
                    crate::ipc::ServerOut::RpcCallStreamChunk { request_id, .. } => {
                        assert_eq!(request_id.as_str(), "ipc-stream-handed");
                    }
                    _ => panic!("the forwarded frame is this stream's chunk"),
                }

                inbox.finish_clean();
                let terminal = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
                    .await
                    .expect("hang guard: the forwarding task writes the natural terminal")
                    .expect("the writer mailbox remains open for the natural terminal");
                assert!(
                    matches!(
                        terminal.value(),
                        crate::ipc::ServerOut::RpcCallStreamEnd { error: None, .. }
                    ),
                    "natural completion is forwarded as a clean stream ending"
                );
                drop(delivered);
                drop(terminal);
                drop(
                    state
                        .clients
                        .unregister(client.id)
                        .expect("the exact client remains registered after natural completion"),
                );
                assert!(state.clients.begin_closing());
                assert_eq!(state.clients.drain_watchdogs().await, 0);
                state.clients.wait_for_tasks().await;
                assert_eq!(state.clients.finish_closed(), crate::ipc::Lifecycle::Closed);
                drop(client);
                drop(tx);
                drop(rx);
                drop(port);
                assert_eq!(
                    provider.in_use(),
                    myownmesh_core::ResourceClaim::ZERO,
                    "all private writer owners, including its process scope, are released"
                );
                assert_eq!(
                    state.clients.residue(),
                    crate::ipc::RegistryResidue::empty(crate::ipc::Lifecycle::Closed)
                );
            },
        );
    }

    /// A delivered setup response retains the forwarding handle, and a panic
    /// is observed by the same shutdown drain as every other watchdog.
    #[test]
    fn v4_r6_daemon_a_delivered_stream_panic_is_joined_and_classified() {
        crate::services::with_service_cleanup(
            crate::services::test_cleanup_scope(),
            |cleanup_port| async move {
                let state = crate::control::joinless_control_state(cleanup_port.clone()).await;
                let (tx, rx, provider, port) = writer_over_grant(unpressured_grant());
                let setup_baseline = provider.in_use();
                assert_ne!(
                    setup_baseline,
                    myownmesh_core::ResourceClaim::ZERO,
                    "the private writer setup must hold its funded root before forwarding"
                );
                let client = state
                    .clients
                    .register(tx.clone())
                    .expect("the fixture registry admits one client");
                let inbox = myownmesh_core::rpc::TransportLabStreamInbox::new();
                let mut pending =
                    pending_forward(&state, &client, &tx, inbox.stream(), "ipc-stream-panic");
                pending.panic_after_start = true;

                ProvisionalHandoff::RpcStream(pending)
                    .settle(&state, true)
                    .await;
                assert_eq!(
                    state.clients.residue().watchdogs,
                    1,
                    "a delivered stream is retained before shutdown observes it"
                );
                assert_eq!(
                    state.clients.residue().live_tasks,
                    1,
                    "the retained forward still owns its task admission"
                );

                drop(
                    state
                        .clients
                        .unregister(client.id)
                        .expect("the exact client is still registered before shutdown"),
                );
                assert!(state.clients.begin_closing());
                assert_eq!(
                    state.clients.drain_watchdogs().await,
                    1,
                    "the injected forwarder panic is observed exactly once"
                );
                state.clients.wait_for_tasks().await;
                assert_eq!(state.clients.residue().watchdogs, 0);
                assert_eq!(state.clients.residue().live_tasks, 0);
                assert_eq!(state.clients.finish_closed(), crate::ipc::Lifecycle::Closed);
                drop(client);
                drop(tx);
                drop(rx);
                drop(port);
                assert_eq!(
                    provider.in_use(),
                    myownmesh_core::ResourceClaim::ZERO,
                    "all private writer owners, including its process scope, are released"
                );
                assert_eq!(
                    state.clients.residue(),
                    crate::ipc::RegistryResidue::empty(crate::ipc::Lifecycle::Closed)
                );
            },
        );
    }

    /// The production `before_provisional_settle` race: the setup response has
    /// been delivered, shutdown enters Closing, and commit then refuses before
    /// creating a forwarding handle. A queued chunk proves that no forwarder
    /// ran, and the whole registry still reaches the exact empty terminal.
    #[test]
    fn v4_r6_daemon_a_delivered_stream_loses_to_closing_before_settle() {
        crate::services::with_service_cleanup(
            crate::services::test_cleanup_scope(),
            |cleanup_port| async move {
                let state = crate::control::joinless_control_state(cleanup_port.clone()).await;
                let (tx, mut rx, provider, port) = writer_over_grant(unpressured_grant());
                let setup_baseline = provider.in_use();
                assert_ne!(
                    setup_baseline,
                    myownmesh_core::ResourceClaim::ZERO,
                    "the private writer setup must hold its funded root before forwarding"
                );
                let client = state
                    .clients
                    .register(tx.clone())
                    .expect("the fixture registry admits one client");
                let inbox = myownmesh_core::rpc::TransportLabStreamInbox::new();
                let scope = crate::test_application_scope();
                inbox
                    .push(&scope, serde_json::json!("must-not-forward"))
                    .expect("the fixture scope funds one queued chunk");
                let pending = pending_forward(
                    &state,
                    &client,
                    &tx,
                    inbox.stream(),
                    "ipc-stream-closing-race",
                );

                assert!(state.clients.begin_closing());
                ProvisionalHandoff::RpcStream(pending)
                    .settle(&state, true)
                    .await;
                assert!(
                    rx.try_recv().is_none(),
                    "the Closing fence refuses before any forwarder can write"
                );
                drop(
                    state
                        .clients
                        .unregister(client.id)
                        .expect("the exact client is still registered during the race"),
                );
                state.clients.wait_for_tasks().await;
                assert_eq!(state.clients.drain_watchdogs().await, 0);
                assert_eq!(state.clients.finish_closed(), crate::ipc::Lifecycle::Closed);
                assert_eq!(
                    state.clients.residue(),
                    crate::ipc::RegistryResidue::empty(crate::ipc::Lifecycle::Closed),
                    "Closing-before-settle leaves no client, stream, watchdog, or task residue"
                );
                drop(client);
                drop(tx);
                drop(rx);
                drop(port);
                assert_eq!(
                    provider.in_use(),
                    myownmesh_core::ResourceClaim::ZERO,
                    "all private writer owners, including its process scope, are released"
                );
            },
        );
    }

    /// A normal open stream is stopped by the exact client disconnect and its
    /// retained handle is then joined before the registry can become Closed.
    #[test]
    fn v4_r6_daemon_a_open_stream_shutdown_is_joined_cleanly() {
        crate::services::with_service_cleanup(
            crate::services::test_cleanup_scope(),
            |cleanup_port| async move {
                let state = crate::control::joinless_control_state(cleanup_port.clone()).await;
                let (tx, rx, provider, port) = writer_over_grant(unpressured_grant());
                let setup_baseline = provider.in_use();
                assert_ne!(
                    setup_baseline,
                    myownmesh_core::ResourceClaim::ZERO,
                    "the private writer setup must hold its funded root before forwarding"
                );
                let client = state
                    .clients
                    .register(tx.clone())
                    .expect("the fixture registry admits one client");
                let inbox = myownmesh_core::rpc::TransportLabStreamInbox::new();
                let pending =
                    pending_forward(&state, &client, &tx, inbox.stream(), "ipc-stream-shutdown");
                ProvisionalHandoff::RpcStream(pending)
                    .settle(&state, true)
                    .await;
                assert_eq!(state.clients.residue().watchdogs, 1);

                let client_id = client.id;
                drop(
                    state
                        .clients
                        .unregister(client_id)
                        .expect("the exact open-stream client is still registered"),
                );
                assert!(state.clients.begin_closing());
                assert_eq!(state.clients.drain_watchdogs().await, 0);
                state.clients.wait_for_tasks().await;
                assert_eq!(state.clients.residue().watchdogs, 0);
                assert_eq!(state.clients.residue().live_tasks, 0);
                assert_eq!(state.clients.finish_closed(), crate::ipc::Lifecycle::Closed);
                drop(client);
                drop(tx);
                drop(rx);
                drop(port);
                assert_eq!(
                    provider.in_use(),
                    myownmesh_core::ResourceClaim::ZERO,
                    "all private writer owners, including its process scope, are released"
                );
                assert_eq!(
                    state.clients.residue(),
                    crate::ipc::RegistryResidue::empty(crate::ipc::Lifecycle::Closed),
                    "the normal open-stream shutdown leaves no registry residue"
                );
            },
        );
    }

    /// A late disconnect for an old id cannot tear down a successor client;
    /// the forwarding task remains bound to the original exact handle.
    #[test]
    fn v4_r6_daemon_a_forward_disconnect_is_exact_to_the_original_client() {
        crate::services::with_service_cleanup(
            crate::services::test_cleanup_scope(),
            |cleanup_port| async move {
                let state = crate::control::joinless_control_state(cleanup_port.clone()).await;
                let (tx, rx, provider, port) = writer_over_grant(unpressured_grant());
                let setup_baseline = provider.in_use();
                assert_ne!(
                    setup_baseline,
                    myownmesh_core::ResourceClaim::ZERO,
                    "the private writer setup must hold its funded root before forwarding"
                );
                let first = state
                    .clients
                    .register(tx.clone())
                    .expect("the fixture registry admits the first client");
                let first_id = first.id;
                let inbox = myownmesh_core::rpc::TransportLabStreamInbox::new();
                let pending =
                    pending_forward(&state, &first, &tx, inbox.stream(), "ipc-stream-exact");
                ProvisionalHandoff::RpcStream(pending)
                    .settle(&state, true)
                    .await;

                drop(
                    state
                        .clients
                        .unregister(first_id)
                        .expect("the first exact client is registered"),
                );
                let successor = state
                    .clients
                    .register(tx.clone())
                    .expect("the successor client is independently admitted");
                assert_ne!(first_id, successor.id, "client ids are never reused");
                assert!(state.clients.client(successor.id).is_some());
                assert!(
                    state.clients.unregister(first_id).is_none(),
                    "a late old-id disconnect cannot remove the successor"
                );

                assert!(state.clients.begin_closing());
                assert_eq!(state.clients.drain_watchdogs().await, 0);
                state.clients.wait_for_tasks().await;
                drop(
                    state
                        .clients
                        .unregister(successor.id)
                        .expect("the successor is still registered at shutdown"),
                );
                assert_eq!(state.clients.finish_closed(), crate::ipc::Lifecycle::Closed);
                drop(first);
                drop(successor);
                drop(tx);
                drop(rx);
                drop(port);
                assert_eq!(
                    provider.in_use(),
                    myownmesh_core::ResourceClaim::ZERO,
                    "all private writer owners, including its process scope, are released"
                );
                assert_eq!(
                    state.clients.residue(),
                    crate::ipc::RegistryResidue::empty(crate::ipc::Lifecycle::Closed)
                );
            },
        );
    }

    /// A stream whose chunk *and* whose substitute terminal are both refused
    /// ends its client, rather than leaving it holding a started operation.
    ///
    /// The discriminating case. A started stream owes its client exactly one
    /// ending, and the writer mailbox can refuse that ending like any other
    /// frame — a refusal discarded here left the client registered, connected,
    /// and waiting on an operation that would never produce another frame. There
    /// is no second attempt and no reserved capacity: the client is unregistered
    /// through the same seam a disconnect uses, and that ending is what ends the
    /// operation.
    ///
    /// The refusal is real capacity pressure over a private grant, and the
    /// terminal is a peer-sized one from a stream that genuinely ended, so what
    /// the writer refuses is a frame worth refusing.
    #[test]
    fn v4_r6_daemon_a2_a_client_whose_terminal_is_refused_is_disconnected() {
        crate::services::with_service_cleanup(
            crate::services::test_cleanup_scope(),
            |cleanup_port| async move {
                let state = crate::control::joinless_control_state(cleanup_port.clone()).await;
                let scope = crate::test_application_scope();
                let inbox = myownmesh_core::rpc::TransportLabStreamInbox::new();
                inbox
                    .finish_owned(&scope, "z".repeat(32 * 1024))
                    .expect("the fixture scope funds one terminal of this width");
                let terminal = match inbox.recv_funded().await {
                    Some(Err(terminal)) => terminal,
                    _ => panic!("the stream ends with the terminal it was finished with"),
                };

                let (tx, _rx, _provider, _port) = writer_over_grant(starved_grant());
                let client = state
                    .clients
                    .register(tx.clone())
                    .expect("the fixture registry admits one client");
                let client_id = client.id;
                assert!(
                    state.clients.client(client_id).is_some(),
                    "non-vacuity: the client is registered before the ending"
                );

                // The chunk was already refused; this is the substitute terminal, and
                // the writer will not take it either.
                end_stream(
                    &state,
                    client_id,
                    &tx,
                    "ipc-stream-refused",
                    crate::ipc::wire::TerminalReasonView::Remote(&terminal),
                )
                .await;

                assert!(
                    state.clients.client(client_id).is_none(),
                    "the exact client is unregistered, which is what ends its connection \
             and with it the operation nothing could settle"
                );
                // Its own record says so too, which is what the connection loop observes
                // on its way to end of file. The bound is a failure detector and nothing
                // else: the wait returns because the record was marked disconnected, and
                // a regression fails here by name rather than as a suite that timed out
                // with nothing named.
                tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    client.wait_disconnected(),
                )
                .await
                .expect("the unregistered client's own record is marked disconnected");
            },
        );
    }

    /// The positive twin: a terminal the writer accepts ends the stream and
    /// leaves the client exactly where it was.
    ///
    /// Without this the control above would be satisfied by a build that
    /// disconnected on every ending, which is strictly worse than the discarded
    /// refusal it replaces. The queued frame is read back, so this is also the
    /// statement that the client was told *about this stream* rather than merely
    /// left alone.
    #[test]
    fn v4_r6_daemon_a2_a_client_whose_terminal_lands_stays_connected() {
        crate::services::with_service_cleanup(
            crate::services::test_cleanup_scope(),
            |cleanup_port| async move {
                let state = crate::control::joinless_control_state(cleanup_port.clone()).await;
                let (tx, mut rx, _provider, _port) = writer_over_grant(unpressured_grant());
                let client = state
                    .clients
                    .register(tx.clone())
                    .expect("the fixture registry admits one client");
                let client_id = client.id;

                end_stream(
                    &state,
                    client_id,
                    &tx,
                    "ipc-stream-clean",
                    crate::ipc::wire::TerminalReasonView::Clean,
                )
                .await;

                assert!(
                    state.clients.client(client_id).is_some(),
                    "a landed terminal disconnects nobody"
                );
                match rx.recv().await {
                    Some(item) => match item.value() {
                        crate::ipc::ServerOut::RpcCallStreamEnd { request_id, error } => {
                            assert_eq!(request_id.as_str(), "ipc-stream-clean");
                            assert!(error.is_none(), "a clean ending carries no error");
                        }
                        _ => panic!("the queued frame is this stream's ending"),
                    },
                    None => panic!("the terminal was admitted, so it is queued"),
                }
            },
        );
    }

    /// A writer mailbox over a grant of exactly `grant`, and the provider that
    /// answers for it.
    ///
    /// The shared `test_application_scope` cannot be used for pressure: it
    /// draws on the binary-wide provider every other daemon test spends from,
    /// so exhausting it would starve them rather than this control. This builds
    /// a private provider and issues a local-application scope under its own
    /// port, which is the only shape a mailbox can be opened over.
    fn writer_over_grant(
        grant: myownmesh_core::ResourceClaim,
    ) -> (
        myownmesh_core::ResourceMailboxSender<crate::ipc::ServerOut>,
        myownmesh_core::ResourceMailboxReceiver<crate::ipc::ServerOut>,
        myownmesh_core::FiniteResourceProvider,
        myownmesh_core::ResourceProviderPort,
    ) {
        let provider = myownmesh_core::FiniteResourceProvider::new(grant);
        let port = myownmesh_core::ResourceProviderPort::new(provider.clone())
            .expect("the fixture grant funds its own process scope");
        let mailbox_scope =
            myownmesh_core::LocalApplicationResourceScope::transport_lab_child_of(&port)
                .expect("the fixture port issues the mailbox's own scope");
        let (tx, rx) = myownmesh_core::resource_mailbox(mailbox_scope)
            .expect("the fixture grant opens one mailbox");
        // The port is returned, not dropped here: the scope the mailbox spends
        // through is a child of it, and a fixture that let the port go would be
        // measuring a provider nothing is still attached to.
        (tx, rx, provider, port)
    }

    /// A pressured writer builds no replacement terminal buffer.
    ///
    /// This is the capacity arm, not the closure arm: the mailbox opens over a
    /// private grant with nothing left after its own planning charge, so
    /// `send_building` gets past the closed check and is refused by the
    /// provider. The terminal is long and real, so what is being refused is a
    /// frame worth refusing.
    ///
    /// What proves the refusal is the ledger, which is what the provider
    /// already exposes to its owner: a refusal that had built its replacement
    /// buffer first would have to charge for it, and the exact return to
    /// baseline says nothing was taken. The grant is private to this control,
    /// so that reading is this call's and no one else's.
    #[tokio::test]
    async fn v4_r5_daemon_a_pressured_writer_builds_no_replacement_terminal_buffer() {
        let scope = crate::test_application_scope();
        let inbox = myownmesh_core::rpc::TransportLabStreamInbox::new();
        let reason = "y".repeat(64 * 1024);
        inbox
            .finish_owned(&scope, reason.clone())
            .expect("the fixture scope funds one terminal of this width");
        let terminal = match inbox.recv_funded().await {
            Some(Err(terminal)) => terminal,
            _ => panic!("the stream ends with the terminal it was finished with"),
        };

        let (tx, _rx, provider, _port) = writer_over_grant(starved_grant());
        let baseline = provider.in_use();
        let refusal = tx
            .send_building(StreamEndBuilder {
                request_id: "ipc-stream-pressured",
                reason: crate::ipc::wire::TerminalReasonView::Remote(&terminal),
            })
            .expect_err("a writer with no remaining capacity refuses the long terminal");
        assert!(
            matches!(
                refusal,
                myownmesh_core::ResourceMailboxAdmissionError::Pressure(_)
            ),
            "the refusal is capacity, not closure: {refusal:?}"
        );
        assert_eq!(
            provider.in_use(),
            baseline,
            "a refused admission builds no replacement buffer and returns the exact baseline"
        );
        assert_eq!(
            terminal.reason(),
            reason,
            "core's charge still owns the peer's text after the daemon was refused"
        );
    }

    /// The session charge for a long peer-supplied terminal stays live from the
    /// inbox pop, through writer admission and serialization, and is released
    /// only when the write-side owner lets go.
    ///
    /// On a real two-peer link: the terminal is funded by a real
    /// `SessionCapability` because a real session produced it, not by an
    /// application scope standing in for one.
    ///
    /// `#[ignore]` is load-bearing. The readings are deltas on the daemon test
    /// binary's process-wide provider, which every other daemon control also
    /// spends from, so they are only exact when this runs alone. CI selects it
    /// by exact name with `--ignored`; a full workspace run skips it. An
    /// accounting control whose arithmetic is only usually right is worse than
    /// none, because it fails intermittently and gets dismissed as flake.
    ///
    /// The assertions are deltas rather than a return to an absolute baseline,
    /// deliberately: the link itself is still up at the end, so the ledger does
    /// not go back to where it started and a control claiming it did would be
    /// asserting something false that happened to pass.
    ///
    /// Unix-only, because [`crate::test_resource_ledger`] is. The ledger is the
    /// concrete provider rather than the capability port, and the port erases
    /// it deliberately — there is no reading `in_use` through the port, and a
    /// privately built provider would compile while observing an accounting
    /// nothing under test spends from. The gate belongs on the control rather
    /// than on the helper's caller side so that an all-targets Windows build
    /// still compiles this module.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "reads the process-wide daemon ledger; exact only when run alone"]
    async fn v4_r5_daemon_a_session_funded_long_terminal_stays_live_through_writer_ownership() {
        use myownmesh_core::ResourceClass::AccountedMemoryBytes as Amb;

        let _fixture = crate::exclusive_connector_fixture().await;
        let (alice_state, _bob_state, _alice_rpc, bob_rpc, alice_id, _bob_id, drivers) =
            crate::test_link::two_peer_rpc("control-dispatch-terminal").await;

        // Peer-chosen width. The charge under control is text the far end
        // sizes, so a short reason would leave nothing to observe.
        //
        // 32 KiB rather than 64: the data channel's `max_message_size` is
        // 65,536 bytes, and the terminal does not travel bare — it rides
        // inside an RPC envelope. A 64 KiB reason plus that framing exceeds
        // the ceiling, so the link could not carry it and no answer would
        // arrive. Half the ceiling leaves the envelope room while staying far
        // wider than anything a short-string bug could hide behind.
        let reason = "q".repeat(32 * 1024);
        let handler_reason = reason.clone();
        myownmesh_core::engine::transport_lab::rpc(&alice_state)
            .expect("the fixture network's application gateway admits an Rpc")
            .serve_stream("terminal_only", move |_call| {
                let reason = handler_reason.clone();
                async move { Err(reason) }
            })
            .expect("the fixture handler claims its method");

        // The ledger, not the port. `in_use` is a figure the concrete provider
        // keeps; the port is the capability and erases it. This is also the
        // instance the engines under test spend through, because
        // `test_application_scope` installs it into the process root.
        let provider = crate::test_resource_ledger();
        let baseline = provider.in_use().amount(Amb);

        // The three link-facing awaits in this control are bounded separately,
        // each with its own message. Unbounded, a stall here does not fail the
        // control — it hangs the CI step that selects this test by exact name,
        // and because those exact-name helpers deliberately run without
        // `--nocapture`, the hang produces no output at all to diagnose from.
        // A named panic per stage is the difference between a silent job that
        // burns its whole limit and one line saying where the link stopped.
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            bob_rpc.call_stream(
                alice_id.public_id(),
                "terminal_only",
                serde_json::json!("go"),
            ),
        )
        .await
        .expect("the peer's stream opens within ten seconds")
        .expect("the real link opens the stream");
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(10), stream.recv_funded())
                .await
                .expect("the peer's terminal arrives within ten seconds");
        let terminal = match received {
            Some(Err(terminal)) => terminal,
            _ => panic!("the handler ends this stream with its error text"),
        };

        // 1. Live after the pop. This is the assertion that fails against the
        //    old shape, where `recv` released the session lease in the same
        //    expression that produced the owned `String`.
        let after_pop = provider.in_use().amount(Amb);
        assert!(
            after_pop >= baseline + reason.len() as u64,
            "the session still funds the peer's text after the inbox pop: \
             {after_pop} < {baseline} + {}",
            reason.len()
        );
        assert_eq!(
            terminal.reason(),
            reason,
            "non-vacuity: the text read by borrow is the one the peer sent"
        );

        // 2. Live through writer admission and serialization.
        let (tx, mut rx) = myownmesh_core::resource_mailbox::<crate::ipc::ServerOut>(
            crate::test_application_scope(),
        )
        .expect("the daemon test grant opens one writer mailbox");
        tx.send_building(StreamEndBuilder {
            request_id: "ipc-stream-session",
            reason: crate::ipc::wire::TerminalReasonView::Remote(&terminal),
        })
        .expect("the writer admits the long terminal");
        let admitted = provider.in_use().amount(Amb);
        assert!(
            admitted >= baseline + reason.len() as u64,
            "the session charge is still live once the frame is admitted and encoded"
        );

        let frame = rx.recv().await.expect("the admitted frame is queued");
        match frame.value() {
            crate::ipc::ServerOut::RpcCallStreamEnd { error, .. } => assert_eq!(
                error.as_deref(),
                Some(reason.as_str()),
                "the forwarded frame carries the peer's text unchanged"
            ),
            other => panic!("the queued frame is the terminal: {other:?}"),
        }

        // 3. The handoff, and the two owners are released one at a time on
        //    purpose. Dropping both together and asserting one combined delta
        //    would pass on the outer frame's own claim alone -- so a session
        //    charge that had leaked, or one that vanished early, would look
        //    exactly like a correct handoff. Separated, each owner has to
        //    account for itself.
        //
        //    First the session terminal, while the queued frame is still alive
        //    and still readable. What comes back here is core's charge for the
        //    peer's text and nothing else.
        let before_terminal = provider.in_use().amount(Amb);
        drop(terminal);
        let after_terminal = provider.in_use().amount(Amb);
        assert!(
            before_terminal.saturating_sub(after_terminal) >= reason.len() as u64,
            "releasing the session terminal returns at least the peer-chosen width: \
             {before_terminal} -> {after_terminal}"
        );
        // The frame is untouched by that release: it owns its own copy, funded
        // by its own claim, and it is still the text the peer sent.
        match frame.value() {
            crate::ipc::ServerOut::RpcCallStreamEnd { error, .. } => assert_eq!(
                error.as_deref(),
                Some(reason.as_str()),
                "the queued frame outlives the session charge that carried its text here"
            ),
            other => panic!("the queued frame is the terminal: {other:?}"),
        }

        //    Then the write-side owner, which must account for its own claim
        //    separately. If this delta were zero the frame had been funded by
        //    the terminal all along, which is the double-ownership the
        //    forwarding seam exists to prevent.
        let before_frame = provider.in_use().amount(Amb);
        drop(frame);
        let after_frame = provider.in_use().amount(Amb);
        assert!(
            before_frame.saturating_sub(after_frame) >= reason.len() as u64,
            "releasing the write-side owner returns its own copy of the text: \
             {before_frame} -> {after_frame}"
        );

        drop((tx, rx, stream));
        tokio::time::timeout(std::time::Duration::from_secs(10), drivers.shutdown())
            .await
            .expect("both engine drivers end within ten seconds");
    }

    /// A grant large enough for the mailbox and nothing else.
    /// Exactly enough to open the writer, and not one item's worth more.
    ///
    /// Three things must fit, and they are the three the fixture builds before
    /// it sends anything:
    ///
    /// - two `scope_planning_charge`s — one for the process scope
    ///   [`myownmesh_core::ResourceProviderPort::new`] opens, one for the child
    ///   scope `transport_lab_child_of` issues. A finite provider retains a
    ///   bookkeeping record per scope, and there are two scopes, not one;
    /// - the mailbox's shared root, priced through
    ///   `reservation_planning_charge` rather than as a bare claim, because the
    ///   provider also keeps a record of holding that reservation. Comparing or
    ///   funding against the bare `root_claim` would be short by exactly that
    ///   record.
    ///
    /// What is deliberately absent is capacity for a single queued item. That
    /// is the whole point of the control: the mailbox opens, and then the first
    /// `send_building` finds nothing left, so it refuses with real `Pressure`
    /// before `build` runs. Any terminal or item slack here would turn the
    /// control into one that proves a frame can be queued.
    fn starved_grant() -> myownmesh_core::ResourceClaim {
        let scopes = myownmesh_core::FiniteResourceProvider::scope_planning_charge()
            .checked_scale(2)
            .expect("two scope bookkeeping records are representable");
        let root = myownmesh_core::FiniteResourceProvider::reservation_planning_charge(
            myownmesh_core::ResourceMailboxSender::<crate::ipc::ServerOut>::root_claim()
                .expect("the mailbox root claim is representable"),
        )
        .expect("the mailbox root reservation is priceable");
        scopes
            .checked_add(root)
            .expect("the fixture grant is representable")
    }
}
