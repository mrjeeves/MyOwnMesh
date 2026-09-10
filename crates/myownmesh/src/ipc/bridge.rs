//! Engine ↔ IPC bridge: synthetic `Rpc::serve` / `serve_stream`
//! handlers that route inbound peer RPCs to whichever IPC
//! client currently holds the matching method claim, plus the
//! per-channel pump task that fans `Channel::subscribe()`
//! frames out to subscribed IPC clients.
//!
//! Lifetime model:
//!
//! - **Handlers** are installed lazily on first claim of a
//!   `(network, method)` pair and forgotten on the last unclaim —
//!   whether that unclaim is an explicit `RpcUnregister` or the
//!   disconnect of the client that held it. Installing is an
//!   admission the engine can refuse, and the refusal is answered
//!   to the claiming client rather than swallowed: a claim whose
//!   handler was never installed would route nothing.
//!
//!   Each installed handler holds retention in the network's gateway scope,
//!   so the last unclaim removes it. A handler invoked during removal still
//!   answers "no claim" truthfully.
//!
//! - **Channel pumps** are owned by a route, not by a subscriber count. The
//!   first subscribe creates the route and installs the pump; the last
//!   unsubscribe retires the route, which cancels the pump and *joins* it, so
//!   the unsubscribe returns only once the task has actually stopped.
//!
//!   Cancellation cannot depend on another published frame: a quiet channel
//!   may have no next receive on which the pump could notice retirement.

use myownmesh_core::application_gateway::GatewayRefusal;
use myownmesh_core::channels::ChannelSubscription;
use myownmesh_core::{JoinedNetwork, ResourceMailboxAdmissionError};
use serde_json::Value;
use tracing::{debug, warn};

use super::clients::{
    ClaimKey, ClientRegistry, HandlerGeneration, HandlerMode, IpcAdmissionError, WeakClientRegistry,
};
use super::wire::ServerOut;
use myownmesh_core::rpc::PreparedRegistration;
use myownmesh_core::{ResourceClaim, ResourceClass};

/// Drop the synthetic handler for one method from a network's dispatcher.
///
/// Called on the last unclaim — an explicit `RpcUnregister`, or the disconnect
/// of the client that held the claim. Idempotent in the engine, so a caller that
/// cannot tell whether it was the last claimant is free to ask anyway; the
/// registry answers that question exactly, and both of its answers are honoured
/// here without a second check.
///
/// Lives beside the installs rather than at the call sites so that what is
/// installed and what is removed stay one decision. The engine's own `forget`
/// takes only the method name because a dispatcher belongs to one network
/// already — the `(network, method)` pair is this crate's key, not core's.
/// What one installed handler knows about itself, in one funded allocation.
///
/// One `Arc`, cloned by pointer, once per invocation. The client-chosen key is
/// retained here rather than copied for every inbound call. A pointer clone is
/// a scalar in the future's own layout, which core measures and funds itself.
///
/// **And the funding follows the last clone, not the registration.** A clone of
/// this context can still be in flight after the method has been displaced and
/// the registration released — that is the whole subject of the exactness work
/// on this path — so the lease lives here, in the allocation every invocation
/// shares, and is returned when the last of them goes. Core's per-closure
/// retention claim is correspondingly zero: what its handler entry holds beyond
/// its own callable is one pointer into an allocation the daemon has already
/// funded for a longer life than the entry has.
pub(crate) struct HandlerContext {
    key: ClaimKey,
    generation: HandlerGeneration,
}

impl HandlerContext {
    /// Fund the allocation, then build it.
    fn admit(
        key: &ClaimKey,
        generation: HandlerGeneration,
        registry: &ClientRegistry,
    ) -> Result<myownmesh_core::FundedArc<Self>, GatewayRefusal> {
        // The visible record and the two name buffers it owns. One broad
        // residual covers dependency-private allocation metadata rather than
        // exposing Arc control-block or String allocator details as protocol
        // invariants.
        let bytes = std::mem::size_of::<Self>()
            .checked_add(key.0.len())
            .and_then(|bytes| bytes.checked_add(key.1.len()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(GatewayRefusal::Malformed)?;
        let claim = ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, bytes),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
        .map_err(|_| GatewayRefusal::Malformed)?;
        let retained = match registry.acquire_claim(claim) {
            Ok(retained) => retained,
            Err(IpcAdmissionError::Resources(refusal)) => {
                return Err(GatewayRefusal::Pressure(refusal))
            }
            Err(_) => return Err(GatewayRefusal::Malformed),
        };
        Ok(myownmesh_core::FundedArc::new(
            Self {
                key: key.clone(),
                generation,
            },
            retained,
        )
        .unwrap_or_else(|_| unreachable!("an admitted handler lease may be shared")))
    }
}

/// Why one channel pump could not be started.
///
/// Kept as two arms because the caller's remedy is the same but the operator's
/// reading of them is not: a refused subscription means the gateway is closed
/// or under pressure for that channel, while a refused task means this daemon
/// is at its accounted concurrency. Collapsing them into one string would make
/// a capacity problem look like a channel problem.
#[derive(Debug, thiserror::Error)]
pub enum ChannelPumpError {
    #[error("channel subscription was refused: {0}")]
    Subscribe(myownmesh_core::ChannelError),
    #[error("channel pump task could not be accounted: {0}")]
    Task(IpcAdmissionError),
}

/// One inbound RPC frame, measured before it exists and built only if it was
/// admitted.
///
/// The writer mailbox's own admission is the exact owner of this allocation: it
/// lives from the instant the frame is assembled until the writer has drained
/// it, and nothing shorter or longer is the truth. What this type adds is the
/// ability to answer *what will this cost* without building it — every field of
/// the frame is either a borrow of the inbound call or a scalar, so the question
/// can be asked of [`ServerOutView`] and the answer acted on before a byte is
/// copied.
///
/// Building the frame first would mean cloning the peer id, the request id,
/// the method and the peer-chosen payload before offering any of it to the
/// mailbox, so a client that had stopped reading, or a full grant, would refuse
/// *after* the daemon had copied whatever the peer sent, at whatever rate the
/// peer chose to call.
///
/// [`ServerOutView`]: crate::ipc::wire::ServerOutView
struct RpcInboundBuilder<'a> {
    /// Borrowed from the handler context, which outlives every call it routes.
    /// Cloned by [`Self::build`] and by nothing else.
    network: &'a str,
    operation_id: u64,
    /// Moved in, and moved out again field by field. Core funded these buffers
    /// when it funded the call; the frame is the same bytes under another name.
    call: myownmesh_core::rpc::RpcCall,
}

impl RpcInboundBuilder<'_> {
    fn view(&self) -> crate::ipc::wire::ServerOutView<'_> {
        crate::ipc::wire::ServerOutView::RpcInbound {
            network: self.network,
            from: &self.call.from,
            request_id: &self.call.request_id,
            operation_id: self.operation_id,
            method: &self.call.method,
            payload: &self.call.payload,
            streaming: self.call.streaming,
        }
    }
}

unsafe impl myownmesh_core::ResourceMailboxItemBuilder<ServerOut> for RpcInboundBuilder<'_> {
    fn measured_claim(
        &self,
    ) -> Result<
        myownmesh_core::MailboxMeasurement<ServerOut>,
        myownmesh_core::ResourceMailboxItemError,
    > {
        // Two halves from two places, and both are the real one. The bytes and
        // the JSON tree are measured over a mirror that encodes byte-for-byte as
        // the frame; the inline layout is taken from `ServerOut`, the type that
        // will actually sit in the queue, because the mirror is a row of borrows
        // and pricing its own size would understate what is stored by the
        // difference between a reference and the buffer it points at.
        myownmesh_core::measure_serialized_mailbox_item::<ServerOut>(&self.view())
    }

    fn build(self) -> ServerOut {
        ServerOut::RpcInbound {
            // The one copy assembling this frame makes, and it is made past
            // every refusal.
            network: self.network.to_string(),
            from: self.call.from,
            request_id: self.call.request_id,
            operation_id: self.operation_id,
            method: self.call.method,
            payload: self.call.payload,
            streaming: self.call.streaming,
        }
    }
}

/// One subscriber's `ChannelInbound` frame, measured before it exists.
///
/// The fan-out is where build-before-admission costs the most: one inbound
/// frame becomes one owned `ServerOut` per subscriber, and the payload is a
/// JSON tree whose size a remote peer chose. Building each copy and *then*
/// offering it to that subscriber's mailbox meant a full or disconnected
/// subscriber refused an allocation that had already happened, once per
/// subscriber, at whatever rate the peer sent.
///
/// Every field here is a borrow of the funded delivery the pump is holding, so
/// [`Self::measured_claim`] can answer what the frame will cost without any of
/// it existing yet, and [`Self::build`] runs only for a subscriber the mailbox
/// has already admitted.
struct ChannelInboundBuilder<'a> {
    /// Borrowed from the pump's route key, which outlives the fan-out.
    network: &'a str,
    channel: &'a str,
    /// Borrowed from the funded `ChannelMessage`, which stays whole for the
    /// whole fan-out and is not taken apart to make these frames.
    from: &'a str,
    payload: &'a Value,
    /// Incremented by [`Self::build`] and by nothing else, so a control can say
    /// "a refused subscriber built none" and "an admitted one built exactly
    /// one" about the production pump rather than about a fixture.
    #[cfg(test)]
    builds: &'a std::sync::atomic::AtomicUsize,
}

impl ChannelInboundBuilder<'_> {
    fn view(&self) -> crate::ipc::wire::ServerOutView<'_> {
        crate::ipc::wire::ServerOutView::ChannelInbound {
            network: self.network,
            from: self.from,
            channel: self.channel,
            payload: self.payload,
        }
    }
}

unsafe impl myownmesh_core::ResourceMailboxItemBuilder<ServerOut> for ChannelInboundBuilder<'_> {
    fn measured_claim(
        &self,
    ) -> Result<
        myownmesh_core::MailboxMeasurement<ServerOut>,
        myownmesh_core::ResourceMailboxItemError,
    > {
        // Measured over the mirror, priced as the `ServerOut` that will sit in
        // the queue — the same split, and for the same reason, as
        // [`RpcInboundBuilder`]: the mirror is a row of references and its own
        // size would understate the buffers those references point at.
        myownmesh_core::measure_serialized_mailbox_item::<ServerOut>(&self.view())
    }

    fn build(self) -> ServerOut {
        #[cfg(test)]
        self.builds
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        ServerOut::ChannelInbound {
            // The four copies this fan-out makes for this subscriber, all of
            // them past the admission that agreed to pay for them.
            network: self.network.to_string(),
            from: self.from.to_string(),
            channel: self.channel.to_string(),
            payload: self.payload.clone(),
        }
    }
}

/// Install (or re-install) a synthetic single-shot RPC handler
/// for `(network_id, method)` on this network's `Rpc`
/// dispatcher. The handler emits `RpcInbound` to whichever
/// client currently owns the claim and awaits an `RpcRespond`
/// to resolve.
///
/// Installing is an admission: the engine funds the handler's retention out of
/// the network's gateway scope and can refuse. The refusal is returned rather
/// than discarded, because a claim recorded against a handler that was never
/// installed is a client told it is serving a method that will never reach it.
pub fn prepare_single_handler(
    rpc: &myownmesh_core::rpc::Rpc,
    key: &ClaimKey,
    generation: HandlerGeneration,
    registry: &ClientRegistry,
) -> Result<PreparedRegistration, GatewayRefusal> {
    let context = HandlerContext::admit(key, generation, registry)?;
    // The closure's own pointer clone. `context` itself stays here so the method
    // name can be *borrowed* into core below: core's prepare seam takes a `&str`
    // and funds the copy it keeps, so a `String` clone made here would be a
    // third buffer that neither side's admission covers -- small, but sized by a
    // name a client chose, and made before either party had agreed to it.
    let closure_context = context.clone();
    // Weak, always. See [`WeakClientRegistry`]: a network owns its handler
    // entries and an entry owns this closure, so a strong clone here would make
    // the network an owner of the daemon's whole client registry.
    let registry = registry.downgrade();
    // Zero, and truthfully so: see [`HandlerContext`]. What core's handler entry
    // retains beyond its own callable is one pointer, into an allocation this
    // daemon has funded for a life that outlasts the entry.
    rpc.prepare_serve_with_retention_claim(&context.key.1, ResourceClaim::ZERO, move |call| {
        single_handler_call(registry.clone(), closure_context.clone(), call)
    })
}

/// One inbound single-shot call, as the installed closure runs it.
///
/// A named function rather than an anonymous body, and the difference is what
/// can be *observed*. Core clones this closure per call, so a call that began
/// under one installation can still be running when another replaces it — and
/// the whole exactness argument is about what that in-flight clone does next.
/// Anonymous, there is no way for a control to hold one and drive it across a
/// displacement; named, a control builds a clone carrying the same generation
/// and runs the same code core would.
async fn single_handler_call(
    registry: WeakClientRegistry,
    context: myownmesh_core::FundedArc<HandlerContext>,
    call: myownmesh_core::rpc::RpcCall,
) -> Result<myownmesh_core::rpc::RpcResponse, String> {
    let Some(registry) = registry.upgrade() else {
        return Err("the control runtime that installed this handler is gone".to_string());
    };
    let key = &context.key;
    // This closure's own generation and class, not the method name. A
    // clone of an *earlier* installation can still be in flight while a
    // successor holds the name, and asking by name would hand it the
    // successor's owner -- dispatching a call in one client's shape to
    // another client that never agreed to serve it.
    let Some(owner_id) = registry.handler_owner_for(key, context.generation, HandlerMode::Single)
    else {
        return Err(format!(
            "no IPC client holds method '{}' on '{}'",
            key.1, key.0
        ));
    };
    let Some(client) = registry.client(owner_id) else {
        return Err("handler owner client disconnected".into());
    };
    // Funded from borrowed coordinates, before a byte of this call's own state
    // exists. Nothing below this line is built unless it was admitted first --
    // not the four coordinate copies of the pending key, and not the channel the
    // peer's answer travels back on.
    let prepared = match registry.prepare_exact_pending(
        key,
        &call.from,
        &call.request_id,
        HandlerMode::Single,
        owner_id,
    ) {
        Ok(prepared) => prepared,
        Err(reason) => return Err(reason.to_string()),
    };
    // The oneshot is built *inside* the commit, past its last refusal and under
    // the lock it inserts with. Nothing but the prepared retention covers a
    // `oneshot`'s allocation, so one built out here and handed into a refusal
    // would outlive the very lease that was paying for it.
    let (ticket, rx) =
        match registry.commit_exact_single_pending(prepared, &call.from, &call.request_id) {
            Ok(filed) => filed,
            // The reason reaches the peer. Colliding coordinates, an owner
            // that left, and a daemon out of capacity are distinct failures.
            Err(reason) => return Err(reason.to_string()),
        };
    // A frame the owner's mailbox will not admit is reported to the
    // peer here rather than dropped. Dropping it would leave the
    // pending entry installed and the caller waiting on a request no
    // client was ever told about, which resolves only as a timeout —
    // an outcome indistinguishable from a peer that went away.
    // Returning drops the ticket, which removes the pending entry.
    //
    // Nothing of the frame is built before this call: the mailbox measures it
    // from borrowed coordinates, acquires its retention and its queue node, and
    // only then invokes the builder. See [`RpcInboundBuilder`].
    if let Err(refusal) = client.writer_tx.send_building(RpcInboundBuilder {
        network: &context.key.0,
        operation_id: ticket.operation_id(),
        call,
    }) {
        return Err(format!(
            "IPC handler owner could not be given the inbound call: {refusal}"
        ));
    }
    // Await this owner's `RpcRespond`. Disconnect and displacement
    // remove this exact operation and settle the oneshot with a
    // truthful error; a later claimant cannot answer it.
    let result = match rx.await {
        Ok(Ok(payload)) => Ok(value_to_response(payload)),
        Ok(Err(e)) => Err(e),
        Err(_) => Err("IPC handler dropped without responding".into()),
    };
    drop(ticket);
    result
}

/// Install (or re-install) a synthetic streaming RPC handler.
/// Mirrors [`prepare_single_handler`] but stashes a resource-funded
/// `ResourceMailboxSender<RpcStreamItem>` in the pending table instead
/// of a `oneshot`; chunks land via `RpcStreamChunk`, and
/// `RpcStreamEnd` terminates the stream with an explicit
/// `RpcStreamItem::End` carrying clean completion or the
/// client's error.
///
/// Fallible for the same reason [`prepare_single_handler`] is.
pub fn prepare_stream_handler(
    rpc: &myownmesh_core::rpc::Rpc,
    key: &ClaimKey,
    generation: HandlerGeneration,
    registry: &ClientRegistry,
) -> Result<PreparedRegistration, GatewayRefusal> {
    let context = HandlerContext::admit(key, generation, registry)?;
    // Borrowed into core, cloned only as a pointer for the closure — see
    // [`prepare_single_handler`].
    let closure_context = context.clone();
    let registry = registry.downgrade();
    // Zero for the same reason [`prepare_single_handler`] gives.
    rpc.prepare_serve_stream_with_retention_claim(
        &context.key.1,
        ResourceClaim::ZERO,
        move |call| stream_handler_call(registry.clone(), closure_context.clone(), call),
    )
}

/// One inbound streaming call, as the installed closure runs it. Named for the
/// same reason [`single_handler_call`] is.
async fn stream_handler_call(
    registry: WeakClientRegistry,
    context: myownmesh_core::FundedArc<HandlerContext>,
    call: myownmesh_core::rpc::RpcCall,
) -> Result<myownmesh_core::ResourceMailboxReceiver<myownmesh_core::rpc::RpcStreamItem>, String> {
    let Some(registry) = registry.upgrade() else {
        return Err("the control runtime that installed this handler is gone".to_string());
    };
    let key = &context.key;
    let Some(owner_id) = registry.handler_owner_for(key, context.generation, HandlerMode::Stream)
    else {
        return Err(format!(
            "no IPC client holds streaming method '{}' on '{}'",
            key.1, key.0
        ));
    };
    let Some(client) = registry.client(owner_id) else {
        return Err("handler owner client disconnected".into());
    };
    // No item count. This queue is bounded by what the process owner
    // funded, measured per chunk, rather than by a number of chunks —
    // which is the only bound that is true of a stream whose items have
    // no fixed size. A capacity of N said nothing about how much memory
    // N chunks would hold.
    //
    // Its own subtree, so everything one stream retains is released as
    // a unit when the stream ends rather than lingering in the
    // registry's scope for the daemon's lifetime.
    //
    // The send side is stashed in `exact_pending_inbound` by the commit that
    // builds it; chunks land via `RpcStreamChunk`. The stream ends with an explicit terminal
    // item: `RpcStreamEnd` sends `RpcStreamItem::End` carrying either
    // clean completion or the client's own error, so that distinction
    // survives to the peer instead of being flattened into a silent
    // close. A sender that disappears without one is a failure rather
    // than an end, which is what makes the watchdog below necessary.
    let resources = match registry.child_resources() {
        Ok(resources) => resources,
        Err(refusal) => {
            return Err(format!(
                "inbound streaming RPC queue could not be scoped: {refusal}"
            ))
        }
    };
    // Funded here, built later. This is the only part of a streaming call whose
    // funding can be refused *and* reaches core's provider to ask, and the
    // provider must never be entered while this daemon holds a table lock — so
    // the acquisition happens out here and what it bought is carried, inert,
    // into the commit's infallible section. Nothing of the queue exists yet: no
    // `Arc`, no node, no sender for a client to be handed.
    let prepared_mailbox = match myownmesh_core::prepare_resource_mailbox::<
        myownmesh_core::rpc::RpcStreamItem,
    >(resources)
    {
        Ok(prepared) => prepared,
        Err(refusal) => {
            return Err(format!(
                "inbound streaming RPC queue could not be funded: {refusal}"
            ))
        }
    };
    // And the pending call's own funding, from borrowed coordinates, before this
    // call's four coordinate copies exist. Same seam as the single-shot handler.
    let prepared = match registry.prepare_exact_pending(
        key,
        &call.from,
        &call.request_id,
        HandlerMode::Stream,
        owner_id,
    ) {
        Ok(prepared) => prepared,
        Err(reason) => return Err(reason.to_string()),
    };
    // Past the last refusal, under the lock the entry is inserted with, and
    // infallible: the queue's two halves and the probe that watches them come
    // into existence together with the record that owns them, so there is no
    // interval in which a stream exists that no pending entry points at.
    let (ticket, rx, close_probe) = match registry.commit_exact_stream_pending(
        prepared,
        &call.from,
        &call.request_id,
        prepared_mailbox,
    ) {
        Ok(filed) => filed,
        // Same three outcomes as the single-shot handler, reported
        // apart for the same reason.
        Err(reason) => return Err(reason.to_string()),
    };
    // Same reasoning as the single-shot handler, and the same builder: a frame
    // the owner's mailbox refuses is reported to the peer rather than dropped,
    // and nothing of it is built before the mailbox has admitted it.
    // Returning here drops `ticket` and `close_probe` before the
    // watchdog below is spawned, so the pending entry leaves with them
    // and no stream is left waiting for chunks nothing will send.
    if let Err(refusal) = client.writer_tx.send_building(RpcInboundBuilder {
        network: &context.key.0,
        operation_id: ticket.operation_id(),
        call,
    }) {
        return Err(format!(
            "IPC handler owner could not be given the inbound streaming call: {refusal}"
        ));
    }
    // The watchdog is what eventually drops the ticket and its pending
    // entry, so it is funded before it is spawned and the refusal is
    // reported to the peer. An unfunded watchdog would mean either no
    // watchdog — leaving the pending entry installed with nothing left
    // to remove it — or one running unaccounted. Returning here drops
    // `ticket` and `close_probe` together, which removes the entry and
    // settles the stream, so the refusal path needs no separate
    // cleanup.
    let task = match registry.lease_task() {
        Ok(task) => task,
        Err(refusal) => {
            return Err(format!(
                "inbound streaming RPC could not be accounted: {refusal}"
            ))
        }
    };
    let watchdog_registry = registry.downgrade();
    let watchdog = async move {
        tokio::select! {
            () = close_probe.closed() => {}
            () = ticket.cancelled() => {}
            // Third arm because `serve` waits for this task, and the
            // other two are both events a peer controls. A stream nobody
            // ever closes would otherwise hold the daemon open for as
            // long as the peer chose. Every arm below drops the ticket
            // and the probe, so shutting down settles the pending entry
            // exactly as a close would.
            () = async move {
                if let Some(registry) = watchdog_registry.upgrade() {
                    registry.closing().await;
                }
            } => {}
        }
        drop(close_probe);
        drop(ticket);
    };
    if let Err((_task, _watchdog, reason)) = registry.spawn_retained_task(task, watchdog) {
        return Err(format!(
            "inbound streaming RPC watchdog could not be retained: {reason}"
        ));
    }
    Ok(rx)
}

/// Spawn the per-channel fan-out task for an IPC subscription on
/// `(network_id, channel)`. The caller spawns this only when
/// `subscribe_channel(...)` hands it a [`ChannelJoin::Install`],
/// and publishes the result -- pump or refusal -- back into that
/// exact generation through `finish_channel_install`. On the last
/// `unsubscribe_channel(...)`, the [`RetiredRoute`] that comes
/// back retires this task through the handles returned here.
///
/// [`ChannelJoin::Install`]: crate::ipc::ChannelJoin::Install
/// [`RetiredRoute`]: crate::ipc::RetiredRoute
///
/// The task lives by polling the channel's broadcast receiver,
/// raced against its own cancellation and the control runtime's
/// shutdown. It exits on any of the three: retirement, shutdown,
/// or the network being torn down under it.
/// Subscription is a resource admission and can be refused, so this reports
/// rather than starts a pump that would never receive anything. The caller
/// answers the requesting client with the refusal instead of recording a
/// subscription the daemon does not actually hold.
#[expect(
    clippy::result_large_err,
    reason = "the `Err` is `ChannelPumpError`, sized by the `ChannelError` its \
              `Subscribe` arm carries inline for the funding reason stated on \
              that enum. Boxing the error here would charge an allocation to the \
              path taken when an admission has just been refused, and the \
              success path -- which returns the cancellation handle and the join \
              handle -- would pay the wider `Result` for nothing. This function \
              is called once per channel install, not per frame"
)]
pub(crate) fn spawn_channel_pump(
    network: &JoinedNetwork,
    key: &ClaimKey,
    registry: ClientRegistry,
) -> std::result::Result<
    (
        myownmesh_core::FundedArc<crate::ipc::RouteCancellation>,
        tokio::task::JoinHandle<()>,
    ),
    ChannelPumpError,
> {
    let channel = network.channel::<Value>(&key.1);
    let sub = channel.subscribe().map_err(ChannelPumpError::Subscribe)?;
    // Funded before the pump exists, and for the same reason the subscription
    // is checked first: this reports rather than starting a pump the daemon
    // cannot account for.
    //
    // Neither refusal unwinds anything *here*, and that is not because nothing
    // has been recorded — the caller has already taken the subscription, so a
    // route exists under this key with at least this client in it. It is
    // because the unwind is all-or-nothing and belongs to the one place that
    // can see every member: the caller answers a refusal by calling
    // `finish_channel_install` with no pump, which removes the route, releases
    // every member's subscription and settles each of their waiters as failed.
    // A route that never published a pump has told nobody it succeeded, so
    // removing it takes nothing back.
    // The pump keeps its own copies of both coordinates for its whole life —
    // it re-reads them on every frame it forwards and on every log line — so
    // the admission that funds the task funds those bytes too. A bare
    // `lease_task` prices one worker obligation and one bookkeeping object and
    // would call two client-chosen strings free. Checked before the clones
    // exist, on the same pattern as `RpcCallStream`'s request id.
    let captured = key
        .0
        .len()
        .checked_add(key.1.len())
        .ok_or(ChannelPumpError::Task(IpcAdmissionError::Claim(
            myownmesh_core::ResourceClaimArithmeticError::Overflow {
                dimension: myownmesh_core::ResourceClass::AccountedMemoryBytes,
            },
        )))?;
    let task = registry
        .lease_task_retaining(captured)
        .map_err(ChannelPumpError::Task)?;
    let key = key.clone();
    // Handed back to the route, which is the only thing entitled to stop this
    // task. Retiring the route cancels and joins through these two, so a quiet
    // channel does not keep the pump alive.
    let cancel = registry
        .route_cancellation()
        .map_err(ChannelPumpError::Task)?;
    let cancelled = cancel.clone();
    let join = tokio::spawn(run_channel_pump(sub, key, registry, cancelled, task));
    Ok((cancel, join))
}

/// One channel pump's whole life, as its own function.
///
/// Everything in [`spawn_channel_pump`] resolves the channel, funds the task,
/// and mints the route cancellation. This function owns the running fan-out.
async fn run_channel_pump(
    mut sub: ChannelSubscription<Value>,
    key: ClaimKey,
    registry: ClientRegistry,
    cancelled: myownmesh_core::FundedArc<crate::ipc::RouteCancellation>,
    task: crate::ipc::TaskAdmission,
) {
    let _task = task;
    loop {
        // Raced against the shutdown signal, biased to it. Without this the
        // pump's only exits are the channel closing or its last subscriber
        // leaving, and neither is something the daemon can bring about while
        // shutting down -- so `serve`, which waits for every accepted task,
        // would wait for a receive on a quiet channel indefinitely.
        let next = tokio::select! {
            biased;
            () = cancelled.cancelled() => {
                debug!(
                    network = %key.0,
                    channel = %key.1,
                    "channel pump exiting (route retired)"
                );
                break;
            }
            () = registry.closing() => {
                debug!(
                    network = %key.0,
                    channel = %key.1,
                    "channel pump exiting (control runtime closing)"
                );
                break;
            }
            next = sub.recv() => next,
        };
        let Some(next) = next else {
            debug!(
                network = %key.0,
                channel = %key.1,
                "channel pump exiting (channel closed)"
            );
            break;
        };
        match next {
            Ok(msg) => {
                // One subscriber at a time, and the registry lock is held
                // only for the step that names the next one. Everything
                // below -- the deep clone of a peer-controlled payload, the
                // serialized measurement `send` takes, the provider
                // acquisition and the mailbox insertion -- happens with no
                // daemon lock held at all. Holding it for the whole fan-out
                // would make the lock duration depend on peer-controlled work
                // and block disconnect, settlement, retirement and shutdown.
                //
                // No snapshot vector either: `subscriber_after` resumes by
                // client identity, so there is nothing to allocate per frame
                // and nothing to fund. A monotonic id also means a
                // subscriber removed mid-fan-out is skipped rather than
                // re-resolved into whoever came after it.
                let mut position = crate::ipc::ChannelFanout::frame();
                let route_gone = loop {
                    // The exact route this pump belongs to, matched by the
                    // cancellation it was given. A route removed and
                    // reinstalled under this key belongs to a successor
                    // pump, and this one stops rather than delivering into
                    // it.
                    let owner = crate::ipc::RouteOwner::Pump(&cancelled);
                    match registry.subscriber_after(&key, owner, &mut position) {
                        crate::ipc::ChannelFanoutStep::Gone => break true,
                        crate::ipc::ChannelFanoutStep::End => break false,
                        crate::ipc::ChannelFanoutStep::Next { client, .. } => {
                            // The tables are released and the frame does not
                            // exist yet. A control parks here and asks the
                            // registry to record a disconnect and begin
                            // closing while it is parked. See
                            // [`ClientRegistry::park_fanout_after_selection`].
                            #[cfg(test)]
                            registry.pass_fanout_barrier().await;
                            let client_id = client.id;
                            // Read through the accessors: `msg` is a funded
                            // owner and stays whole for the entire fan-out, so
                            // every subscriber's frame is copied *from* it
                            // rather than assembled out of its parts. Nothing
                            // is copied here at all — this is a row of borrows
                            // the subscriber's own mailbox will price, and the
                            // copies happen inside `build`, past the admission
                            // that agreed to them.
                            let builder = ChannelInboundBuilder {
                                network: &key.0,
                                channel: &key.1,
                                from: msg.from(),
                                payload: msg.body(),
                                #[cfg(test)]
                                builds: registry.channel_frame_build_counter(),
                            };
                            // Fan-out has nobody to answer: the frame came
                            // off a broadcast and no peer is waiting on this
                            // subscriber in particular. A refusal is
                            // therefore logged rather than propagated — but
                            // it is logged, because a subscriber silently
                            // missing a channel message is the failure this
                            // pump exists to make visible. `Closed` is the
                            // ordinary disconnect race and stays at debug.
                            match client.send_building(builder) {
                                Ok(()) => {}
                                Err(ResourceMailboxAdmissionError::Closed) => debug!(
                                    network = %key.0,
                                    channel = %key.1,
                                    client = %client_id,
                                    "channel frame dropped: subscriber disconnected"
                                ),
                                Err(refusal) => warn!(
                                    network = %key.0,
                                    channel = %key.1,
                                    client = %client_id,
                                    "channel frame refused for a connected subscriber: {refusal}"
                                ),
                            }
                        }
                    }
                };
                if route_gone {
                    debug!(
                        network = %key.0,
                        channel = %key.1,
                        "channel pump exiting (route gone)"
                    );
                    break;
                }
            }
            Err(e) => {
                warn!(
                    network = %key.0,
                    channel = %key.1,
                    "channel deserialize error: {e}"
                );
            }
        }
    }
}

/// `myownmesh-core`'s `Rpc::serve` wants an
/// `Ok(RpcResponse)` — wrap a raw `Value` so callers don't
/// reach across crate-private types.
pub fn value_to_response(v: Value) -> myownmesh_core::rpc::RpcResponse {
    myownmesh_core::rpc::RpcResponse::from_value(v)
}

struct HandlerDisplacedBuilder {
    network: String,
    method: String,
    by: super::clients::ClientId,
}

impl HandlerDisplacedBuilder {
    fn view(&self) -> crate::ipc::wire::ServerOutView<'_> {
        crate::ipc::wire::ServerOutView::HandlerDisplaced {
            network: &self.network,
            method: &self.method,
            by: self.by,
        }
    }
}

unsafe impl myownmesh_core::ResourceMailboxItemBuilder<ServerOut> for HandlerDisplacedBuilder {
    fn measured_claim(
        &self,
    ) -> Result<
        myownmesh_core::MailboxMeasurement<ServerOut>,
        myownmesh_core::ResourceMailboxItemError,
    > {
        myownmesh_core::measure_serialized_mailbox_item::<ServerOut>(&self.view())
    }

    fn build(self) -> ServerOut {
        ServerOut::HandlerDisplaced {
            network: self.network,
            method: self.method,
            by: self.by.to_string(),
        }
    }
}

/// Helper used by `dispatch` when an IPC client releases or
/// has been disconnected: notify the now-displaced client.
pub fn notify_displaced(
    registry: &ClientRegistry,
    prev_owner: super::clients::ClientId,
    by: super::clients::ClientId,
    network: String,
    method: String,
) {
    if let Some(client) = registry.client(prev_owner) {
        // The displacement has already happened in the registry; this frame
        // only tells the loser about it. There is no caller to refuse and no
        // way to undo the claim transfer, so a refusal is recorded and the
        // displaced client is left to notice through its own failing calls.
        match client.send_building(HandlerDisplacedBuilder {
            network,
            method,
            by,
        }) {
            Ok(()) => {}
            Err(ResourceMailboxAdmissionError::Closed) => debug!(client = %prev_owner,
                "displacement notice dropped: displaced client had already disconnected"),
            Err(refusal) => warn!(client = %prev_owner, %refusal,
                "connected client was displaced but could not be told"),
        }
    }
}

/// Fund whichever handler shape matches the requested mode, without publishing
/// it.
///
/// The first half of one transaction: every acquisition happens here, and what
/// comes back publishes only if the daemon's own claim succeeds under the same
/// lock. Nothing is installed on the network by calling this, so dropping the
/// result installs nothing.
///
/// Takes the dispatcher rather than the `JoinedNetwork` it hangs off, because
/// the dispatcher is all any of this needs. Narrowing it is what lets a control
/// drive the real seam — `Rpc::attach` gives a genuine dispatcher over one
/// engine, where reaching a `JoinedNetwork` would mean standing up the whole
/// join path to observe a transaction that has nothing to do with peers.
pub fn prepare_handler_for_mode(
    rpc: &myownmesh_core::rpc::Rpc,
    key: &ClaimKey,
    generation: HandlerGeneration,
    mode: HandlerMode,
    registry: &ClientRegistry,
) -> Result<PreparedRegistration, GatewayRefusal> {
    match mode {
        HandlerMode::Single => prepare_single_handler(rpc, key, generation, registry),
        HandlerMode::Stream => prepare_stream_handler(rpc, key, generation, registry),
    }
}

#[cfg(test)]
mod tests {
    //! End-to-end engine-bridge tests. Two engines wired
    //! through `LocalBroker`; one side simulates an IPC client
    //! by holding the receiver end of a `ClientHandle` and
    //! manually feeding `RpcRespond`s back through the
    //! registry — same path the dispatch layer takes when a
    //! real socket client posts `RpcRespond`.

    // The three production items the F3 control drives directly. Named rather
    // than glob-imported so it is visible that the control runs the same
    // handler body core runs, not a copy of it.
    use super::{
        prepare_handler_for_mode, run_channel_pump, single_handler_call, stream_handler_call,
        ChannelInboundBuilder, HandlerContext, HandlerDisplacedBuilder, RpcInboundBuilder,
    };
    use crate::ipc::clients::{ClientRegistry, HandlerMode, PendingKey, RegistrationError};
    use crate::ipc::wire::ServerOut;
    use myownmesh_core::ResourceMailboxItemBuilder;
    // The shared real link, at the crate root because the control
    // dispatcher's streaming controls need the same one: two copies of a
    // two-peer handshake are two things free to drift, and a control passing
    // against a link its sibling does not build is exactly the failure that
    // would hide.
    use crate::test_link::{fresh_network, test_transport, two_peer_rpc};
    use myownmesh_core::engine::transport_lab::spawn_network;
    use myownmesh_core::identity::Identity;
    use serde_json::Value;
    use std::sync::Arc;
    use std::time::Duration;

    // Serialization lives on `crate::exclusive_connector_fixture`, which every
    // connector-consuming family in this binary shares. A mutex local to this
    // module would only stop these three tests racing each other; they draw on
    // one process-global connector budget that `embedded` and `registry` draw
    // on too.

    /// One engine and its real dispatcher, for the controls that need core to
    /// actually publish something rather than a stand-in.
    ///
    /// No peer and no approval wait: the transaction under test is entirely
    /// local — funding a registration, claiming a method, publishing both under
    /// one lock — and a second engine would only add a connector budget and a
    /// handshake to observe none of it. The exclusive fixture is still taken,
    /// because building a `Transport` at all draws on the one process-global
    /// connector budget every family in this binary shares.
    async fn one_engine_rpc(
        wire_id: &str,
    ) -> (
        Arc<myownmesh_core::engine::transport_lab::NetworkState>,
        myownmesh_core::rpc::Rpc,
        tokio::task::JoinHandle<()>,
    ) {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::env::set_var("MYOWNMESH_HOME", tmp.path());
        std::mem::forget(tmp); // leak — test scope only
                               // This is intentionally an unjoined Open state: the control is
                               // entirely local and exercises no peer promotion or carrier path.
        let (state, driver) = spawn_network(
            fresh_network("solo", wire_id),
            Arc::new(Identity::ephemeral()),
            test_transport(),
        )
        .await
        .expect("the solo engine starts");
        let rpc = myownmesh_core::engine::transport_lab::rpc(&state)
            .expect("the live gateway admits its RPC owner");
        (state, rpc, driver)
    }

    /// One inbound call, in flight across a displacement, through core's real
    /// two-phase registration.
    ///
    /// The registry controls prove the *predicate* — that an old generation
    /// resolves to nobody. This one proves the behaviour that predicate exists
    /// to produce, by running the handler body core runs, on a call that is
    /// genuinely parked mid-flight when the method changes hands.
    ///
    /// The sequence, and why each step is there:
    ///
    /// 1. `A` publishes single-shot through the production path: a real
    ///    `PreparedRegistration`, a real `commit_with` running the daemon's
    ///    claim under core's handlers lock, a real `OwnedMethodRegistration`.
    /// 2. A newcomer the daemon refuses publishes nothing, and `A` keeps its
    ///    owner, its class *and* its generation. Under an install-then-claim
    ///    order the incumbent's handler would already be overwritten by the
    ///    time the refusal was discovered.
    /// 3. A call is started under `A`'s generation and parks at the real park
    ///    point — awaiting `A`'s `RpcRespond`. The barrier is `A`'s own mailbox
    ///    receiving the inbound frame, which cannot happen until the call has
    ///    resolved its owner, filed its pending entry and handed the frame over.
    ///    No timer decides anything.
    /// 4. `B` takes the method as a stream, for real, while that call is parked.
    /// 5. The parked call comes back *displaced*, not answered by `B`. This is
    ///    the observation the predicate alone cannot make: the in-flight call is
    ///    settled truthfully by the displacement rather than left to resolve
    ///    against whoever holds the name when it wakes.
    /// 6. `B` was never told about `A`'s call — its mailbox is empty. A stale
    ///    clone re-run afterwards refuses truthfully and still tells `B`
    ///    nothing.
    /// 7. The installation that *is* published reaches `B`, in the stream shape
    ///    it claimed.
    ///
    /// What this does not observe is core cloning the closure itself: the body
    /// is invoked directly, one call away from where core invokes it, because
    /// reaching core's own dispatch would need a second engine and a peer
    /// handshake to watch a transaction that has nothing to do with peers. The
    /// closure passed to core is this same function and nothing else.
    #[tokio::test]
    async fn v4_f3_daemon_an_in_flight_call_cannot_follow_the_method_to_its_new_owner() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let (state, rpc, driver) = one_engine_rpc("f3-exact").await;
        let registry = ClientRegistry::default();
        let (a, mut a_rx) = fresh_ipc_client(&registry);
        let (b, mut b_rx) = fresh_ipc_client(&registry);
        let (gone, _gone_rx) = fresh_ipc_client(&registry);
        let key = ("solo".to_string(), "infer".to_string());

        // ---- 1. A claims it single-shot, through the production path -------
        let first = registry.next_handler_generation();
        let prepared = prepare_handler_for_mode(&rpc, &key, first, HandlerMode::Single, &registry)
            .expect("the live gateway funds one synthetic handler");
        let displaced = registry
            .claim_method_committing(key.clone(), a.id, HandlerMode::Single, first, prepared)
            .expect("the claim and the handler publish together");
        assert!(displaced.is_none(), "there was no incumbent to displace");

        // ---- 2. a newcomer the daemon refuses changes nothing --------------
        let gone_id = gone.id;
        drop(registry.unregister(gone_id).expect("registered client"));
        let refused = registry.next_handler_generation();
        let prepared =
            prepare_handler_for_mode(&rpc, &key, refused, HandlerMode::Stream, &registry)
                .expect("funding a registration is not publishing it");
        let refusal = registry.claim_method_committing(
            key.clone(),
            gone_id,
            HandlerMode::Stream,
            refused,
            prepared,
        );
        assert!(
            matches!(refusal, Err(RegistrationError::ClientGone)),
            "the refusal names the real cause"
        );
        assert_eq!(
            registry.handler_owner_for(&key, first, HandlerMode::Single),
            Some(a.id),
            "core published nothing, so the incumbent's own generation still routes"
        );
        assert_eq!(
            registry.handler_mode(&key),
            Some(HandlerMode::Single),
            "in the class it claimed, not the one that was refused"
        );
        assert!(
            a.holds_method_for_test(&key),
            "the incumbent's own record of its claim is intact"
        );

        // ---- 3. park a real call under A's generation ----------------------
        let parked = tokio::spawn(single_handler_call(
            registry.downgrade(),
            handler_context(key.clone(), first, &registry),
            fixture_call("peer-one", "req-one", false),
        ));
        // The barrier, and it is a state and not a duration: this frame does not
        // exist until the call has resolved its owner, filed its pending entry
        // and handed the frame to A. Past it, the call is parked on A's
        // response and nothing else.
        let inbound = a_rx
            .recv()
            .await
            .expect("A is given the inbound call it owns");
        assert!(
            matches!(inbound.value(), ServerOut::RpcInbound { request_id, .. } if request_id == "req-one"),
            "and it is the call this control started"
        );

        // ---- 4. B takes the method as a stream, mid-flight ------------------
        let second = registry.next_handler_generation();
        let prepared = prepare_handler_for_mode(&rpc, &key, second, HandlerMode::Stream, &registry)
            .expect("the live gateway funds the displacing handler");
        let displaced = registry
            .claim_method_committing(key.clone(), b.id, HandlerMode::Stream, second, prepared)
            .expect("the displacing claim and its handler publish together");
        assert_eq!(displaced, Some(a.id), "and it says whose method it took");

        // ---- 5. the parked call is displaced, not answered by B -------------
        let outcome = parked.await.expect("the parked call's task completes");
        let reason = outcome.expect_err("a displaced call does not return a response");
        assert!(
            reason.contains("displaced"),
            "the peer is told the handler was displaced, not that it timed out: {reason}"
        );

        // ---- 6. B never heard about A's call, and a stale clone gets nowhere
        assert!(
            b_rx.try_recv().is_none(),
            "the displacing client was never handed a call that began under A"
        );
        let stale = single_handler_call(
            registry.downgrade(),
            handler_context(key.clone(), first, &registry),
            fixture_call("peer-two", "req-two", false),
        )
        .await
        .expect_err("a clone of A's installation cannot route once A is displaced");
        assert!(
            stale.contains("no IPC client holds method"),
            "and it says so truthfully rather than reaching the newcomer: {stale}"
        );
        assert!(
            b_rx.try_recv().is_none(),
            "still nothing: a stale generation cannot reach B by any path"
        );

        // ---- 7. the published installation reaches B, in its own shape ------
        let stream = stream_handler_call(
            registry.downgrade(),
            handler_context(key.clone(), second, &registry),
            fixture_call("peer-three", "req-three", true),
        )
        .await
        .expect("the installation core published routes to its owner");
        let inbound = b_rx
            .recv()
            .await
            .expect("B is given the streaming call it owns");
        match inbound.value() {
            ServerOut::RpcInbound {
                request_id,
                streaming,
                ..
            } => {
                assert_eq!(request_id, "req-three");
                assert!(*streaming, "and in the stream shape B claimed it as");
            }
            other => panic!("B was given something other than its inbound call: {other:?}"),
        }
        drop(stream);

        state.request_shutdown();
        let _ = driver.await;
    }

    /// What an installed handler holds about itself, for controls that drive one
    /// handler call directly rather than through core's dispatcher.
    ///
    /// Built through the production admission, not around it: a context minted
    /// some other way would let these controls pass while the funded one they
    /// stand for could not be acquired at all.
    fn handler_context(
        key: crate::ipc::clients::ClaimKey,
        generation: crate::ipc::HandlerGeneration,
        registry: &ClientRegistry,
    ) -> myownmesh_core::FundedArc<HandlerContext> {
        HandlerContext::admit(&key, generation, registry)
            .expect("the daemon test grant funds one handler context")
    }

    /// What the mailbox was told a frame would cost is what the frame costs.
    ///
    /// The whole prepare-before-construct shape on this path rests on one
    /// substitution: a borrowed [`ServerOutView`] stands in for a
    /// [`ServerOut::RpcInbound`] that does not exist yet. If the mirror ever
    /// stopped encoding as the thing it mirrors -- a renamed field, a reordered
    /// one, a `serde` attribute added to one and not the other -- the admission
    /// would keep succeeding and would simply be measuring a different frame,
    /// which is the kind of drift that shows up as an over-full daemon months
    /// later rather than as a failure here.
    ///
    /// Two assertions, and the second is the one that matters. Equal bytes is
    /// the property the mirror promises; equal *claims* is what the mailbox
    /// acts on, and it is derived from the encoded length, the JSON tree and the
    /// inline size of the queued type. A mirror that encoded identically but was
    /// priced against its own layout would pass the first and fail the second,
    /// and that is exactly the mistake this builder was written wrong once
    /// already.
    ///
    /// The payload is nested and the coordinates are non-empty on purpose: a
    /// flat frame of empty strings encodes the same under most ways of getting
    /// it wrong.
    ///
    /// The same question for the fan-out mirror, and it has to be asked
    /// separately.
    ///
    /// A hand-written mirror is only as good as the check that it still matches,
    /// and there are now two of them beside one enum. The RPC control proves
    /// nothing about this variant: they share a tag style and nothing else, and
    /// a field reordered or renamed here would encode differently while the RPC
    /// control stayed green. Measured against the encoded bytes rather than the
    /// fields, because equal fields that encode differently is the failure a
    /// mirror actually has.
    #[test]
    fn v4_r3_daemon_a_measured_channel_frame_matches_the_frame_it_becomes() {
        use myownmesh_core::ResourceMailboxSender;

        let builds = std::sync::atomic::AtomicUsize::new(0);
        let payload = serde_json::json!({
            "text": "a body a peer chose the size of",
            "meta": { "seq": 7, "tags": ["a", "b"] },
        });
        let builder = ChannelInboundBuilder {
            network: "solo/mesh",
            channel: "transcripts",
            from: "peer-with-a-name",
            payload: &payload,
            builds: &builds,
        };
        let measured_bytes = serde_json::to_vec(&builder.view()).expect("the mirror encodes");
        let measured_claim =
            ResourceMailboxSender::<ServerOut>::building_item_planning_charge(&builder)
                .expect("the mirror's claim is representable");

        let built = builder.build();
        let built_bytes = serde_json::to_vec(&built).expect("the frame encodes");
        let built_claim = ResourceMailboxSender::<ServerOut>::accepted_item_planning_charge(&built)
            .expect("the frame's claim is representable");

        assert_eq!(
            String::from_utf8(measured_bytes).expect("JSON is UTF-8"),
            String::from_utf8(built_bytes).expect("JSON is UTF-8"),
            "the mirror must encode byte-for-byte as the frame it prices, or the \
             admission was taken for a different value than the one queued"
        );
        assert_eq!(
            measured_claim, built_claim,
            "and the claim answered before the frame existed is the claim the \
             frame itself answers"
        );
        assert_eq!(
            builds.load(std::sync::atomic::Ordering::Acquire),
            1,
            "non-vacuity: the counter this control's pressure sibling reads moves \
             exactly once per built frame, and it moved here"
        );
    }

    /// [`ServerOutView`]: crate::ipc::wire::ServerOutView
    #[test]
    fn v4_r2_daemon_a_measured_inbound_frame_matches_the_frame_it_becomes() {
        use myownmesh_core::ResourceMailboxSender;

        let builder = RpcInboundBuilder {
            network: "solo/mesh",
            operation_id: 9,
            call: myownmesh_core::rpc::RpcCall {
                from: "peer-with-a-name".to_string(),
                request_id: "req-42".to_string(),
                method: "transcribe".to_string(),
                payload: serde_json::json!({
                    "audio": [1, 2, 3],
                    "opts": { "lang": "en", "diarize": true },
                }),
                streaming: true,
            },
        };
        let measured_bytes = serde_json::to_vec(&builder.view()).expect("the mirror encodes");
        let measured_claim =
            ResourceMailboxSender::<ServerOut>::building_item_planning_charge(&builder)
                .expect("the mirror's claim is representable");

        let built = builder.build();
        let built_bytes = serde_json::to_vec(&built).expect("the frame encodes");
        let built_claim = ResourceMailboxSender::<ServerOut>::accepted_item_planning_charge(&built)
            .expect("the frame's claim is representable");

        assert_eq!(
            String::from_utf8(measured_bytes).expect("JSON is UTF-8"),
            String::from_utf8(built_bytes).expect("JSON is UTF-8"),
            "the borrowed mirror must encode byte-for-byte as the frame it stands \
             in for, or the mailbox admitted a different frame than it queued"
        );
        assert_eq!(
            measured_claim, built_claim,
            "and must be priced as the frame it stands in for: the mirror is a \
             row of borrows, so a claim taken against the mirror's own layout \
             would understate every queued frame by the difference between a \
             reference and the buffer behind it"
        );
        // Non-vacuity: a frame of nothing would satisfy both of the above.
        assert!(
            built_claim.amount(myownmesh_core::ResourceClass::QueuedBytes) > 0,
            "and this control measured a frame with something in it"
        );
    }

    #[test]
    fn v4_r2_daemon_a_displacement_frame_is_measured_before_its_id_string_exists() {
        use myownmesh_core::ResourceMailboxSender;

        let builder = HandlerDisplacedBuilder {
            network: "network-with-owned-coordinate".to_string(),
            method: "handler.with.owned.coordinate".to_string(),
            by: crate::ipc::clients::ClientId(42),
        };
        let measured_bytes = serde_json::to_vec(&builder.view()).expect("the mirror encodes");
        let measured_claim =
            ResourceMailboxSender::<ServerOut>::building_item_planning_charge(&builder)
                .expect("the mirror is measurable");
        let built = builder.build();
        let built_bytes = serde_json::to_vec(&built).expect("the frame encodes");
        let built_claim = ResourceMailboxSender::<ServerOut>::accepted_item_planning_charge(&built)
            .expect("the frame is measurable");

        assert_eq!(
            measured_bytes, built_bytes,
            "the borrowed ClientId display and the constructed String have the same wire form"
        );
        assert_eq!(
            measured_claim, built_claim,
            "the admitted claim is the finished frame's exact claim"
        );
    }

    /// One inbound call, as a peer would have made it.
    fn fixture_call(from: &str, request_id: &str, streaming: bool) -> myownmesh_core::rpc::RpcCall {
        myownmesh_core::rpc::RpcCall {
            from: from.to_string(),
            request_id: request_id.to_string(),
            method: "infer".to_string(),
            payload: serde_json::json!({ "q": 1 }),
            streaming,
        }
    }

    /// One IPC client with a funded writer mailbox.
    fn fresh_ipc_client(
        registry: &ClientRegistry,
    ) -> (
        myownmesh_core::FundedArc<crate::ipc::ClientHandle>,
        myownmesh_core::ResourceMailboxReceiver<ServerOut>,
    ) {
        let (tx, rx) = myownmesh_core::resource_mailbox(crate::test_application_scope())
            .expect("the daemon test grant funds one client writer mailbox");
        let handle = registry
            .register(tx)
            .expect("the daemon test grant funds one client record");
        (handle, rx)
    }

    /// Single-shot RPC routed via the IPC bridge. Alice's
    /// network registers a synthetic handler bound to a
    /// simulated IPC client; Bob calls the method; the
    /// "client" receives `RpcInbound`, posts `RpcRespond` back
    /// via the registry, and Bob's call resolves with the
    /// returned payload.
    #[tokio::test]
    async fn single_shot_rpc_round_trip_through_bridge() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let (alice_state, _bob_state, _alice_rpc, bob_rpc, alice_id, _bob_id, drivers) =
            two_peer_rpc("ipc-bridge-single").await;

        // Simulate an IPC client on Alice's side.
        let registry = ClientRegistry::default();
        let (tx, mut rx) =
            myownmesh_core::resource_mailbox::<ServerOut>(crate::test_application_scope())
                .expect("the daemon test grant funds this fixture client's writer mailbox");
        let client = registry
            .register(tx)
            .expect("the daemon test grant funds this fixture client record");
        let net_key = "alice".to_string();
        let method = "echo".to_string();
        let key = (net_key.clone(), method.clone());
        registry
            .claim_method(key.clone(), client.id, HandlerMode::Single)
            .expect("the daemon test grant funds this fixture's method claim");

        // Inlined rather than calling `prepare_single_handler`,
        // because this fixture drives the *routing* half of the
        // handler against two live engines and does not need the
        // claim transaction that production wraps it in. The
        // control that does drive that transaction against a real
        // registration is
        // `v4_f3_daemon_an_in_flight_call_cannot_follow_the_method_to_its_new_owner`.
        //
        // Both admissions are asserted rather than discarded. This fixture is
        // pointless if the handler is not actually installed, and a discarded
        // refusal would have turned that into a mysteriously silent peer.
        let registry_for_handler = registry.clone();
        let key_for_handler = key.clone();
        myownmesh_core::engine::transport_lab::rpc(&alice_state)
            .expect("the fixture network's application gateway admits an Rpc")
            .serve("echo", move |call| {
                let registry = registry_for_handler.clone();
                let key = key_for_handler.clone();
                async move {
                    let owner = registry
                        .handler_owner(&key)
                        .ok_or_else(|| "no claim".to_string())?;
                    let client = registry
                        .client(owner)
                        .ok_or_else(|| "owner gone".to_string())?;
                    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                    let pending_key = PendingKey {
                        network: key.0.clone(),
                        method: key.1.clone(),
                        remote_peer: call.from.clone(),
                        remote_request_id: call.request_id.clone(),
                        class: HandlerMode::Single,
                    };
                    let Ok(ticket) = registry.insert_exact_pending(
                        pending_key,
                        owner,
                        crate::ipc::clients::PendingInbound::Single(resp_tx),
                    ) else {
                        return Err("duplicate".into());
                    };
                    // Reported rather than asserted: this runs inside the engine's
                    // handler task, where a panic would surface as a caller that
                    // never settles. An error reaches the assertion in the test
                    // body carrying its own reason.
                    if let Err(refusal) = client.send(ServerOut::RpcInbound {
                        network: key.0.clone(),
                        from: call.from.clone(),
                        request_id: call.request_id.clone(),
                        operation_id: ticket.operation_id(),
                        method: call.method.clone(),
                        payload: call.payload.clone(),
                        streaming: call.streaming,
                    }) {
                        return Err(format!("fixture client mailbox refused inbound: {refusal}"));
                    }
                    let result = match resp_rx.await {
                        Ok(Ok(p)) => Ok(myownmesh_core::rpc::RpcResponse::from_value(p)),
                        Ok(Err(e)) => Err(e),
                        Err(_) => Err("handler dropped".into()),
                    };
                    drop(ticket);
                    result
                }
            })
            .expect("the fixture network admits one single-shot handler");

        // Bob calls the method.
        let alice_did = alice_id.public_id().to_string();
        let call_handle = tokio::spawn(async move {
            bob_rpc
                .call(&alice_did, "echo", serde_json::json!({"n": 7}))
                .await
        });

        // Pull the RpcInbound off the simulated client's writer mailbox.
        let inbound = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("inbound timeout")
            .expect("inbound recv");
        // The delivery is held whole for the rest of this control, and the
        // frame is read through it. The coordinates the registry needs are
        // owned copies of borrowed fields, not the frame taken apart.
        let (pending_key, operation_id) = match inbound.value() {
            ServerOut::RpcInbound {
                network,
                from,
                request_id,
                operation_id,
                payload,
                method,
                ..
            } => {
                assert_eq!(method, "echo");
                assert_eq!(payload, &serde_json::json!({"n": 7}));
                (
                    // Respond via the registry (same path dispatch takes).
                    PendingKey {
                        network: network.clone(),
                        method: method.clone(),
                        remote_peer: from.clone(),
                        remote_request_id: request_id.clone(),
                        class: HandlerMode::Single,
                    },
                    *operation_id,
                )
            }
            other => panic!("expected RpcInbound, got {other:?}"),
        };
        let resolved = registry.resolve_exact_single(
            &pending_key,
            client.id,
            operation_id,
            Ok(serde_json::json!({"n_squared": 49})),
        );
        assert!(resolved);

        let bob_response = tokio::time::timeout(Duration::from_secs(5), call_handle)
            .await
            .expect("call timeout")
            .expect("join")
            .expect("rpc ok");
        assert_eq!(bob_response.body, serde_json::json!({"n_squared": 49}));
        drivers.shutdown().await;
    }

    /// Streaming RPC: Alice's "client" pushes three chunks
    /// via `push_exact_stream` + closes via
    /// `close_exact_stream`; Bob's `call_stream` drains the
    /// receiver and sees all three plus the end-of-stream.
    #[tokio::test]
    async fn streaming_rpc_round_trip_through_bridge() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let (alice_state, _bob_state, _alice_rpc, bob_rpc, alice_id, _bob_id, drivers) =
            two_peer_rpc("ipc-bridge-stream").await;

        let registry = ClientRegistry::default();
        let (tx, mut rx) =
            myownmesh_core::resource_mailbox::<ServerOut>(crate::test_application_scope())
                .expect("the daemon test grant funds this fixture client's writer mailbox");
        let client = registry
            .register(tx)
            .expect("the daemon test grant funds this fixture client record");
        let key = ("alice".to_string(), "stream_echo".to_string());
        registry
            .claim_method(key.clone(), client.id, HandlerMode::Stream)
            .expect("the daemon test grant funds this fixture's method claim");

        // Wire the synthetic stream handler. Identical to the
        // single-shot test but uses `serve_stream` + the
        // `PendingInbound::Stream` arm — including asserting both
        // admissions rather than discarding them.
        let registry_for_handler = registry.clone();
        let key_for_handler = key.clone();
        myownmesh_core::engine::transport_lab::rpc(&alice_state)
            .expect("the fixture network's application gateway admits an Rpc")
            .serve_stream("stream_echo", move |call| {
                let registry = registry_for_handler.clone();
                let key = key_for_handler.clone();
                async move {
                    let owner = registry
                        .handler_owner(&key)
                        .ok_or_else(|| "no claim".to_string())?;
                    let client = registry
                        .client(owner)
                        .ok_or_else(|| "owner gone".to_string())?;
                    let (tx, rx) =
                        myownmesh_core::resource_mailbox::<myownmesh_core::rpc::RpcStreamItem>(
                            registry
                                .child_resources()
                                .expect("the daemon test grant scopes one stream queue"),
                        )
                        .expect("the daemon test grant funds one stream queue");
                    let close_probe = tx.clone();
                    let pending_key = PendingKey {
                        network: key.0.clone(),
                        method: key.1.clone(),
                        remote_peer: call.from.clone(),
                        remote_request_id: call.request_id.clone(),
                        class: HandlerMode::Stream,
                    };
                    let Ok(ticket) = registry.insert_exact_pending(
                        pending_key,
                        owner,
                        crate::ipc::clients::PendingInbound::Stream(tx),
                    ) else {
                        return Err("duplicate".into());
                    };
                    // Same reason as the single-shot fixture above: reported, not
                    // asserted, so the failure arrives at the caller's assertion.
                    if let Err(refusal) = client.send(ServerOut::RpcInbound {
                        network: key.0.clone(),
                        from: call.from.clone(),
                        request_id: call.request_id.clone(),
                        operation_id: ticket.operation_id(),
                        method: call.method.clone(),
                        payload: call.payload.clone(),
                        streaming: call.streaming,
                    }) {
                        return Err(format!("fixture client mailbox refused inbound: {refusal}"));
                    }
                    tokio::spawn(async move {
                        tokio::select! {
                            () = close_probe.closed() => {}
                            () = ticket.cancelled() => {}
                        }
                        drop(close_probe);
                        drop(ticket);
                    });
                    Ok(rx)
                }
            })
            .expect("the fixture network admits one streaming handler");

        let alice_did = alice_id.public_id().to_string();
        let bob_rpc_clone = bob_rpc.clone();
        let stream_handle = tokio::spawn(async move {
            bob_rpc_clone
                .call_stream(&alice_did, "stream_echo", serde_json::json!("start"))
                .await
        });

        // Pull RpcInbound to get the request_id.
        let inbound = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("inbound timeout")
            .expect("inbound recv");
        // Same shape as the single-shot control: the delivery stays whole and
        // the pending coordinates are copied out of the borrowed frame.
        let (pending_key, operation_id) = match inbound.value() {
            ServerOut::RpcInbound {
                network,
                from,
                request_id,
                operation_id,
                method,
                ..
            } => (
                // Push three chunks then close.
                PendingKey {
                    network: network.clone(),
                    method: method.clone(),
                    remote_peer: from.clone(),
                    remote_request_id: request_id.clone(),
                    class: HandlerMode::Stream,
                },
                *operation_id,
            ),
            other => panic!("expected RpcInbound, got {other:?}"),
        };
        for n in 1..=3 {
            assert!(
                registry.push_exact_stream(
                    &pending_key,
                    client.id,
                    operation_id,
                    serde_json::json!(n)
                ),
                "chunk {n} push"
            );
        }
        assert!(registry.close_exact_stream(&pending_key, client.id, operation_id, None));

        // Bob drains his receiver — three chunks then close.
        let mut bob_rx = tokio::time::timeout(Duration::from_secs(5), stream_handle)
            .await
            .expect("stream timeout")
            .expect("join")
            .expect("call_stream ok");
        for n in 1..=3 {
            let chunk = tokio::time::timeout(Duration::from_secs(5), bob_rx.recv())
                .await
                .expect("chunk timeout")
                .expect("chunk recv")
                .expect("chunk ok");
            assert_eq!(chunk, serde_json::json!(n));
        }
        // End-of-stream: receiver returns None.
        let end = tokio::time::timeout(Duration::from_secs(5), bob_rx.recv())
            .await
            .expect("end timeout");
        assert!(end.is_none(), "expected stream end, got {end:?}");
        drivers.shutdown().await;
    }

    /// Channel pub/sub: subscribe Alice's "IPC client" to a
    /// channel, Bob sends a frame on the same name, the
    /// client receives a `ChannelInbound` event with the
    /// correct payload and sender.
    #[tokio::test]
    async fn channel_inbound_round_trip_through_bridge() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let (alice_state, bob_state, _alice_rpc, _bob_rpc, _alice_id, bob_id, drivers) =
            two_peer_rpc("ipc-bridge-channel").await;

        let registry = ClientRegistry::default();
        let (tx, mut rx) =
            myownmesh_core::resource_mailbox::<ServerOut>(crate::test_application_scope())
                .expect("the daemon test grant funds this fixture client's writer mailbox");
        let client = registry
            .register(tx)
            .expect("the daemon test grant funds this fixture client record");
        let net_key = "alice".to_string();
        let chan_key = "catalog".to_string();
        let key = (net_key.clone(), chan_key.clone());

        // Subscribe and spawn the pump. The pump only needs
        // the engine state to build a `Channel<Value>`, so the
        // `JoinedNetwork` facade `spawn_channel_pump` takes in
        // production is bypassed here.
        let joined = registry
            .subscribe_channel(key.clone(), client.id)
            .expect("the daemon test grant funds this fixture's subscription");
        let crate::ipc::ChannelJoin::Install(installing) = joined else {
            panic!("the fixture's first subscriber owns the install")
        };
        // This fixture is its own installer, so it publishes its own outcome
        // into its own generation: without this the route stays `Installing`
        // and `for_each_subscriber` below would be visiting members of a route
        // nothing had made live.
        assert!(registry
            .finish_channel_install(&key, &installing, None)
            .is_none());
        let joined = registry
            .subscribe_channel(key.clone(), client.id)
            .expect("re-recording the fixture's own subscription");
        assert!(matches!(joined, crate::ipc::ChannelJoin::Install(_)));

        // Spawn a pump that mirrors `bridge::spawn_channel_pump`
        // but uses the engine state directly.
        let chan: myownmesh_core::Channel<serde_json::Value> =
            myownmesh_core::engine::transport_lab::channel(chan_key.clone(), alice_state.clone());
        let mut sub = chan.subscribe().expect("subscription admitted");
        let registry_for_pump = registry.clone();
        let key_for_pump = key.clone();
        tokio::spawn(async move {
            loop {
                let Some(next) = sub.recv().await else {
                    break;
                };
                let Ok(msg) = next else {
                    continue;
                };
                // The assertion this fixture exists for is on the frame
                // arriving, so a refusal here is left to fail as the receive
                // timeout it causes rather than being reported twice.
                //
                // Mirrors production: `msg` is the funded owner and stays
                // whole across the fan-out, and each subscriber's frame is
                // built here from borrows of it. A `ServerOut` owns what it
                // carries, so one per subscriber is what a fan-out costs --
                // but it is copied out of the live owner rather than out of a
                // frame that was assembled once and cloned.
                let live = registry_for_pump.for_each_subscriber(&key_for_pump, |c| {
                    let _ = c.send(ServerOut::ChannelInbound {
                        network: key_for_pump.0.clone(),
                        from: msg.from().to_string(),
                        channel: key_for_pump.1.clone(),
                        payload: msg.body().clone(),
                    });
                });
                if !live {
                    break;
                }
            }
        });

        // Bob sends to Alice on the channel.
        let bob_chan: myownmesh_core::Channel<serde_json::Value> =
            myownmesh_core::engine::transport_lab::channel(chan_key.clone(), bob_state.clone());
        bob_chan
            .send_to(
                _alice_id_arg(&alice_state),
                &serde_json::json!({"hello": "from bob"}),
            )
            .await
            .expect("bob send");

        let frame = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("inbound timeout")
            .expect("inbound recv");
        match frame.value() {
            ServerOut::ChannelInbound {
                network,
                from,
                channel,
                payload,
            } => {
                assert_eq!(network, &net_key);
                assert_eq!(channel, &chan_key);
                assert_eq!(from, bob_id.public_id());
                assert_eq!(payload, &serde_json::json!({"hello": "from bob"}));
            }
            other => panic!("expected ChannelInbound, got {other:?}"),
        }
        drivers.shutdown().await;
    }

    /// A subscriber whose writer mailbox refuses
    /// costs no copy of the peer's payload; an admitted one costs exactly one.
    ///
    /// The defect this holds down is multiplication. One inbound frame becomes
    /// one owned `ServerOut` per subscriber, and the payload is a JSON tree a
    /// remote peer chose the size of, so building each copy before offering it
    /// would mean a full or disconnected subscriber refusing an allocation
    /// already made — once per subscriber, at the peer's chosen rate. Keeping
    /// the fan-out off the registry lock answers contention, not this.
    ///
    /// Driven through the real pump rather than by calling the builder, because
    /// the property is about *where in the pump* the copy happens. A control
    /// that invoked `build` itself would be asserting something about its own
    /// call.
    ///
    /// **Two arms, positive first.** The positive is what stops the negative
    /// passing vacuously: a pump that had stopped delivering entirely would
    /// satisfy "the refused subscriber built nothing" perfectly. The second
    /// fan-out is the discriminating one — one pressured subscriber and one
    /// healthy one, in a single walk, so the healthy subscriber's frame
    /// arriving is itself the proof that the pump reached and passed the
    /// pressured one. No sleep and no deadline is doing any work here.
    #[tokio::test]
    async fn v4_r3_daemon_a_refused_channel_subscriber_costs_no_copy_of_the_payload() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let (alice_state, bob_state, _alice_rpc, _bob_rpc, _alice_id, bob_id, drivers) =
            two_peer_rpc("ipc-bridge-refused-fanout").await;

        let registry = ClientRegistry::default();
        let net_key = "alice".to_string();
        let chan_key = "catalog".to_string();
        let key = (net_key.clone(), chan_key.clone());
        let payload = serde_json::json!({ "entries": "x".repeat(4096) });

        // **The pressured subscriber is funded privately, and it subscribes
        // first.** Both halves of that are load-bearing.
        //
        // Privately, because the first version of this control filled a mailbox
        // on `test_application_scope()` — the grant the whole daemon test binary
        // shares, and the one the real publisher below draws on. The fill
        // starved `send_to` itself, which was refused for
        // `CallbackOrScheduledWork` before the fan-out ran, so the walk this
        // control is about never happened and the discriminating assertion
        // never executed.
        //
        // First, because `subscriber_after` resumes by ascending membership id.
        // If the healthy member held the lower id, its frame arriving would
        // prove only that the walk started — not that it had reached the
        // pressured member at all, which is the entire claim. Do not reorder
        // these subscriptions for tidiness: the order *is* the proof.
        let sizing_builds = std::sync::atomic::AtomicUsize::new(0);
        let sizing = ChannelInboundBuilder {
            network: &net_key,
            channel: &chan_key,
            from: bob_id.public_id(),
            payload: &payload,
            builds: &sizing_builds,
        };
        // Every term production's own, and exactly the terms this mailbox will
        // spend: the port's process scope and the lab child issued under it,
        // the mailbox root's reservation, and one frame of the size the
        // positive arm is about to deliver. No slack, so "one item fits and the
        // next does not" is arithmetic rather than a guessed bound.
        let grant = myownmesh_core::FiniteResourceProvider::scope_planning_charge()
            .checked_scale(2)
            .expect("two scope planning charges compose")
            .checked_add(
                myownmesh_core::FiniteResourceProvider::reservation_planning_charge(
                    myownmesh_core::ResourceMailboxSender::<ServerOut>::root_claim()
                        .expect("the writer mailbox root claim is representable"),
                )
                .expect("the mailbox root's reservation is representable"),
            )
            .expect("the root joins the scope charges")
            .checked_add(
                myownmesh_core::ResourceMailboxSender::<ServerOut>::building_item_planning_charge(
                    &sizing,
                )
                .expect("one planned channel frame is representable"),
            )
            .expect("the private writer grant composes");
        assert_eq!(
            sizing_builds.load(std::sync::atomic::Ordering::Acquire),
            0,
            "non-vacuity: planning the grant costs no built frame, so the \
             counter this control reads still starts at zero"
        );

        let port = myownmesh_core::ResourceProviderPort::new(
            myownmesh_core::FiniteResourceProvider::new(grant),
        )
        .expect("the private grant accounts for its own process scope");
        let pressured_scope =
            myownmesh_core::LocalApplicationResourceScope::transport_lab_child_of(&port)
                .expect("the private grant issues one local application scope");
        let (pressured_tx, mut first_rx) =
            myownmesh_core::resource_mailbox::<ServerOut>(pressured_scope)
                .expect("the private grant funds exactly one writer mailbox");
        let first = registry
            .register(pressured_tx)
            .expect("the daemon test grant funds one client record");

        let crate::ipc::ChannelJoin::Install(installing) = registry
            .subscribe_channel(key.clone(), first.id)
            .expect("the daemon test grant funds this fixture's subscription")
        else {
            panic!("the first subscriber owns the install")
        };

        let channel: myownmesh_core::Channel<Value> =
            myownmesh_core::engine::transport_lab::channel(chan_key.clone(), alice_state.clone());
        let sub = channel
            .subscribe()
            .expect("the fixture's channel admits a subscription");
        let cancel = registry
            .route_cancellation()
            .expect("the daemon test grant funds one pump cancellation");
        let task = registry
            .lease_task()
            .expect("the daemon test grant funds one pump task");
        let pump = tokio::spawn(run_channel_pump(
            sub,
            key.clone(),
            registry.clone(),
            cancel.clone(),
            task,
        ));
        assert!(
            registry
                .finish_channel_install(&key, &installing, Some((cancel, pump)))
                .is_none(),
            "the installer publishes its own pump into its own route"
        );
        assert!(
            installing.wait().await,
            "and its followers are told it worked"
        );

        let bob_channel: myownmesh_core::Channel<Value> =
            myownmesh_core::engine::transport_lab::channel(chan_key.clone(), bob_state.clone());

        // Positive. The isolated subscriber is the only member, its grant funds
        // exactly this frame, and one publish costs exactly one build.
        let built_before = registry.channel_frames_built();
        bob_channel
            .send_to(_alice_id_arg(&alice_state), &payload)
            .await
            .expect("bob publishes on the channel");
        let frame = tokio::time::timeout(Duration::from_secs(10), first_rx.recv())
            .await
            .expect("hang guard: an admitted subscriber is delivered to")
            .expect("the subscriber's mailbox is live");
        assert!(
            matches!(frame.value(), ServerOut::ChannelInbound { .. }),
            "the admitted subscriber receives the channel frame it subscribed for"
        );
        assert_eq!(
            registry.channel_frames_built(),
            built_before + 1,
            "non-vacuity: an admitted subscriber costs exactly one built frame, \
             so the counter the negative arm reads is one that genuinely moves"
        );

        // Hand the item charge back, so the private grant is once again worth
        // exactly one frame and the fill below has somewhere to start.
        drop(frame);

        // Fill that same isolated writer, with the one frame whose charge the
        // grant was sized from. Two sends, no loop and no constant: the grant is
        // exactly one such item wide, so the first must be admitted and the
        // second must not, and both directions are arithmetic rather than a
        // search.
        //
        // Deliberately this frame rather than a small `Lagged` one. A filler of
        // a different size class would make "how many fit" depend on which
        // dimension binds first, which is the guessed bound this control had
        // once and should not have again. Sending it directly costs no build:
        // the counter lives inside the builder, and nothing here goes through
        // one.
        let filler = || ServerOut::ChannelInbound {
            network: net_key.clone(),
            from: bob_id.public_id().to_string(),
            channel: chan_key.clone(),
            payload: payload.clone(),
        };
        first.send(filler()).expect(
            "the grant was sized for exactly one frame of this shape, so the \
             first one fits — if it does not, the sizing above is wrong and \
             every assertion after it would be measuring the wrong mailbox",
        );
        assert!(
            first.send(filler()).is_err(),
            "and the second does not, so the mailbox the fan-out is about to \
             reach is genuinely full rather than merely small"
        );

        // Only now the healthy member, which therefore takes the higher
        // membership id and is reached second.
        let (second, mut second_rx) = fresh_ipc_client(&registry);
        registry
            .subscribe_channel(key.clone(), second.id)
            .expect("the daemon test grant funds a second subscription");

        let built_before = registry.channel_frames_built();
        bob_channel
            .send_to(_alice_id_arg(&alice_state), &payload)
            .await
            .expect("bob publishes a second frame on the channel");
        let frame = tokio::time::timeout(Duration::from_secs(10), second_rx.recv())
            .await
            .expect("hang guard: the healthy subscriber is still delivered to")
            .expect("the healthy subscriber's mailbox is live");
        assert!(
            matches!(frame.value(), ServerOut::ChannelInbound { .. }),
            "a subscriber the walk reaches after a refused one is still served"
        );
        assert_eq!(
            registry.channel_frames_built(),
            built_before + 1,
            "and that whole fan-out built exactly one frame: the pressured \
             subscriber was reached first, measured, and refused without the \
             payload ever being copied for it, which is the allocation this \
             control exists to forbid"
        );

        // Shut the pump down before returning, cooperatively, rather than
        // dropping it and hoping.
        //
        // The pump holds a `WorkerOrTask` lease drawn from the binary-wide
        // daemon grant for as long as it is alive, and that grant is nine tasks
        // wide for the whole test binary. A control that returns while its pump
        // is still running therefore lends that lease to whatever runs next,
        // which fails the neighbouring fan-out control at nine of nine for
        // `WorkerOrTask` rather than for anything to do with fan-out.
        // `begin_closing` is the pump's own
        // cooperative exit, the same one production uses, and the driver
        // shutdown is awaited the way the neighbouring control awaits its own.
        registry.begin_closing();
        drivers.shutdown().await;
        // Last, and after the shutdown: the private provider funds the
        // pressured mailbox, so releasing it any earlier would release the
        // pressure the assertions above depend on.
        drop(port);
    }

    /// A large channel frame parks the *production* pump, and the registry
    /// answers anyway.
    ///
    /// It drives [`run_channel_pump`] itself rather than a copy of it, because a
    /// control that mirrors the loop can go green against its own copy while the
    /// production loop still holds the registry lock.
    ///
    /// The barrier is installed on the registry and passed by the pump at the
    /// line that matters: after `subscriber_after` has selected a subscriber and
    /// released the tables, and before `ServerOut::ChannelInbound` exists. While
    /// the pump is parked there — mid-frame, with a second subscriber still
    /// unvisited — a disconnect is recorded and a shutdown begins.
    ///
    /// No duration is authority here; the two `timeout`s are failure detectors
    /// only. The pump says when it has reached the line, the control says when
    /// it may leave it, and the frame that then goes out is read off a real
    /// mailbox. The payload is large so that the interval being asserted across
    /// is a real clone and a real serialized measurement.
    #[tokio::test]
    async fn v4_r2_daemon_a_large_channel_frame_does_not_hold_the_registry_while_it_fans_out() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let (alice_state, bob_state, _alice_rpc, _bob_rpc, _alice_id, _bob_id, drivers) =
            two_peer_rpc("ipc-bridge-parked-fanout").await;

        let registry = ClientRegistry::default();
        let (first, mut first_rx) = fresh_ipc_client(&registry);
        let (second, _second_rx) = fresh_ipc_client(&registry);
        let net_key = "alice".to_string();
        let chan_key = "catalog".to_string();
        let key = (net_key.clone(), chan_key.clone());

        // Two subscribers, so the walk has somewhere to be when it is parked.
        let crate::ipc::ChannelJoin::Install(installing) = registry
            .subscribe_channel(key.clone(), first.id)
            .expect("the daemon test grant funds this fixture's subscription")
        else {
            panic!("the first subscriber owns the install")
        };
        registry
            .subscribe_channel(key.clone(), second.id)
            .expect("the daemon test grant funds a second subscription");

        // The production pump, over a subscription this control owns. Everything
        // `spawn_channel_pump` does above this line is resolving the channel,
        // funding the task and minting the cancellation; all three are done here
        // the same way it does them.
        let channel: myownmesh_core::Channel<Value> =
            myownmesh_core::engine::transport_lab::channel(chan_key.clone(), alice_state.clone());
        let sub = channel
            .subscribe()
            .expect("the fixture's channel admits a subscription");
        let cancel = registry
            .route_cancellation()
            .expect("the daemon test grant funds one pump cancellation");
        let task = registry
            .lease_task()
            .expect("the daemon test grant funds one pump task");
        let (barrier, parked, release) = crate::ipc::FanoutBarrier::paired();
        registry.park_fanout_after_selection(barrier);
        let pump = tokio::spawn(run_channel_pump(
            sub,
            key.clone(),
            registry.clone(),
            cancel.clone(),
            task,
        ));
        assert!(
            registry
                .finish_channel_install(&key, &installing, Some((cancel, pump)))
                .is_none(),
            "the installer publishes its own pump into its own route"
        );
        assert!(
            installing.wait().await,
            "and its followers are told it worked"
        );

        // A frame whose payload a publisher chose the size of.
        let payload = serde_json::json!({
            "entries": (0..512)
                .map(|n| serde_json::json!({ "id": n, "name": "x".repeat(64) }))
                .collect::<Vec<_>>(),
        });
        assert!(
            serde_json::to_vec(&payload)
                .expect("the frame encodes")
                .len()
                > 16 * 1024,
            "non-vacuity: this is a large frame, so the interval below is a real \
             clone and a real measurement rather than a formality"
        );
        let bob_channel: myownmesh_core::Channel<Value> =
            myownmesh_core::engine::transport_lab::channel(chan_key.clone(), bob_state.clone());
        bob_channel
            .send_to(_alice_id_arg(&alice_state), &payload)
            .await
            .expect("bob publishes on the channel");

        // The pump itself says when it is at the line.
        tokio::time::timeout(Duration::from_secs(10), parked)
            .await
            .expect("hang guard: the pump reaches its first subscriber")
            .expect("the pump signals from the fan-out barrier");

        // Parked mid-frame, with the frame not yet built.
        let removed = registry
            .unregister(second.id)
            .expect("a disconnect is recorded while a frame is mid-fan-out");
        assert_eq!(removed.handle.id, second.id);
        registry.begin_closing();
        assert_eq!(
            registry.lifecycle(),
            crate::ipc::Lifecycle::Closing,
            "and a shutdown begins while a frame is mid-fan-out, rather than \
             waiting for a payload the publisher chose the size of"
        );

        // Released, the frame still goes out to the subscriber that stayed.
        release.send(()).expect("the pump is still parked");
        let frame = tokio::time::timeout(Duration::from_secs(10), first_rx.recv())
            .await
            .expect("hang guard: the parked frame is delivered")
            .expect("the remaining subscriber is delivered to");
        match frame.value() {
            ServerOut::ChannelInbound {
                network,
                channel,
                payload: delivered,
                ..
            } => {
                assert_eq!(network, &net_key);
                assert_eq!(channel, &chan_key);
                assert_eq!(
                    delivered, &payload,
                    "and it is the frame that was published"
                );
            }
            other => panic!("expected the parked ChannelInbound, got {other:?}"),
        }

        drivers.shutdown().await;
    }

    fn _alice_id_arg(state: &Arc<myownmesh_core::engine::transport_lab::NetworkState>) -> &str {
        state.identity.public_id()
    }
}
