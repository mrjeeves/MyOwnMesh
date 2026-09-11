//! The binary `realtime_pipe` connections: what one is bound to, and the two
//! pumps that move units across it.
//!
//! Frame-shaped work only. Admission is settled before either pump starts —
//! the binding is resolved and checked against its direction first — and every
//! refusal these can meet is core's, forwarded rather than interpreted. The
//! frame layout itself is not defined here; these read and write it.

use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};

use myownmesh_core::realtime as core_realtime;
use myownmesh_core::transport as core_webrtc;

// The two codec helpers are named where they are defined, not through the
// parent. `control` binds `ControlState` (its own item), `RealtimePipeDirection`
// (`pub use wire::…`) and `FrameAdmission` + `REALTIME_FRAME_HEADER` (its own
// `use framing::…`, which a child module can see even though it is private) —
// but it binds neither of these two, so `super::` has no name to resolve. They
// are `pub(super)` in `framing`, which makes them visible throughout `control`
// and every descendant of it, this module included. Importing them from their
// real location is therefore the whole fix; re-exporting them from `control`
// would widen their reach for no reason.
use super::framing::{encode_realtime_recv_fields_with_ceiling, inspect_realtime_send_unit};
use super::{ControlState, FrameAdmission, RealtimePipeDirection, REALTIME_FRAME_HEADER};

const REALTIME_BUFFER_ALLOCATIONS: u64 = 1;

/// What one realtime pipe is bound to, once its fields have been checked
/// against its direction.
///
/// The two directions carry different bindings because they are bound to
/// different things: an outbound pipe to one exact flow, an inbound pipe to one
/// session's whole unit stream. A single struct with optional fields would make
/// "which of these is authority here" a question every reader has to re-derive.
pub(super) enum RealtimePipeBinding {
    /// Writes to the one flow `flow_capability` names, on the client that owns
    /// it. No peer: there is nothing left to resolve.
    Outbound {
        network: String,
        flow_capability: String,
    },
    /// Claims the whole inbound unit stream of the session `peer` currently
    /// resolves to. The claim is the authority and it is taken once.
    Inbound { network: String, peer: String },
}

pub(super) enum RealtimePipeBindingPlan<'a> {
    Outbound {
        network: &'a str,
        flow_capability: &'a str,
    },
    Inbound {
        network: &'a str,
        peer: &'a str,
    },
}

impl RealtimePipeBindingPlan<'_> {
    pub(super) fn retained_lengths(&self) -> [usize; 2] {
        match self {
            Self::Outbound {
                network,
                flow_capability,
            } => [network.len(), flow_capability.len()],
            Self::Inbound { network, peer } => [network.len(), peer.len()],
        }
    }

    pub(super) fn build(self) -> RealtimePipeBinding {
        match self {
            Self::Outbound {
                network,
                flow_capability,
            } => RealtimePipeBinding::Outbound {
                network: network.to_string(),
                flow_capability: flow_capability.to_string(),
            },
            Self::Inbound { network, peer } => RealtimePipeBinding::Inbound {
                network: network.to_string(),
                peer: peer.to_string(),
            },
        }
    }
}

impl RealtimePipeBinding {
    /// The network both directions are bound through.
    ///
    /// Borrowed rather than cloned, and the caller reads it that way. The pipe
    /// path used to take a third copy of this client-chosen name purely to look
    /// the network up; removing the allocation is a better answer than pricing
    /// it.
    pub(super) fn network(&self) -> &str {
        match self {
            Self::Outbound { network, .. } | Self::Inbound { network, .. } => network,
        }
    }
}

/// Validate a [`Request::RealtimePipe`]'s fields against its direction.
///
/// Every field is required or refused; none is accepted and ignored. A pipe
/// that took a field and dropped it would read, from the client's side, exactly
/// like one that honoured it — and for `peer` on an outbound pipe that
/// misreading is the finding itself, a client believing its units are bound to
/// a peer when what actually binds them is a flow.
///
/// The plan-and-build pair collapsed into one call, for controls that assert on
/// the *rule* rather than on when the retention is taken. Production never uses
/// this: it holds the plan across its admission and builds inside it — see
/// `serve`'s `RealtimePipe` arm, which answers a refusal with
/// `PreparedReply::StaticError(message)` and only calls `plan.build()` under
/// `Retained::admit_building`.
///
/// The error is the plan's own `&'static str`, forwarded rather than copied.
/// Allocating a `String` here would be a second error shape for the same
/// refusal, and it would put an allocation on a path whose entire point is that
/// the refusal text is already static and costs nothing to answer with.
///
/// `cfg(test)` because its only consumer is: `control`'s import of it is
/// `#[cfg(test)]` too, so without this gate the item is unused in a release
/// build. Nothing is gated that production reaches —
/// [`realtime_pipe_binding_plan`] and [`RealtimePipeBindingPlan::build`], the
/// two halves this composes, both stay ungated and are what `serve` calls.
#[cfg(test)]
pub(super) fn realtime_pipe_binding(
    direction: RealtimePipeDirection,
    network: &str,
    peer: Option<&str>,
    flow_capability: Option<&str>,
) -> std::result::Result<RealtimePipeBinding, &'static str> {
    realtime_pipe_binding_plan(direction, network, peer, flow_capability)
        .map(RealtimePipeBindingPlan::build)
}

pub(super) fn realtime_pipe_binding_plan<'a>(
    direction: RealtimePipeDirection,
    network: &'a str,
    peer: Option<&'a str>,
    flow_capability: Option<&'a str>,
) -> std::result::Result<RealtimePipeBindingPlan<'a>, &'static str> {
    if network.trim().is_empty() {
        return Err("realtime_pipe requires a network");
    }
    match direction {
        RealtimePipeDirection::Outbound => {
            if peer.is_some() {
                return Err(
                    "realtime_pipe outbound takes no peer: it writes to the exact flow \
                     its flow_capability names, and a peer selector here would be \
                     re-resolved per unit — which is how a pipe outliving its session \
                     ended up writing into the replacement's flow of the same name",
                );
            }
            let Some(flow_capability) = flow_capability else {
                return Err(
                    "realtime_pipe outbound requires a flow_capability: the value \
                     realtime_flow_open issued is the only thing that authorizes a write",
                );
            };
            Ok(RealtimePipeBindingPlan::Outbound {
                network,
                flow_capability,
            })
        }
        RealtimePipeDirection::Inbound => {
            if flow_capability.is_some() {
                return Err(
                    "realtime_pipe inbound takes no flow_capability: it claims a \
                     session's whole unit stream rather than one flow, and every unit \
                     carries the name of the flow it arrived on",
                );
            }
            let Some(peer) = peer.filter(|peer| !peer.trim().is_empty()) else {
                return Err(
                    "realtime_pipe inbound requires a peer: the stream it claims \
                     belongs to one session",
                );
            };
            Ok(RealtimePipeBindingPlan::Inbound { network, peer })
        }
    }
}

/// Read length-prefixed units off an outbound [`Request::RealtimePipe`] and hand
/// each to the **one flow this pipe is bound to**.
///
/// Sends nothing back per unit: errors are logged rather than answered, which is
/// the whole latency win — a per-unit acknowledgement would put a round trip on
/// the media path. Returns when the client disconnects.
///
/// **Nothing here resolves a selector, and nothing here re-resolves anything.**
/// The pipe holds a flow capability, the capability names one move-only handle
/// the owning client stored at open, and that handle names one exact session and
/// one exact flow record. This is the correction: the version this replaces kept
/// `network + peer` and re-resolved them for every unit, so a pipe whose session
/// had ended went on writing until the peer's next session came up and then
/// delivered into *that* one, under labels chosen for a session that no longer
/// existed — with nothing to notice, because nothing on this path is
/// acknowledged.
///
/// The frame's `flow_label` survives as a wire coordinate and is checked, not
/// obeyed: a unit naming a different flow than this pipe is bound to is dropped
/// rather than rerouted. A client with two flows open has two pipes.
pub(super) async fn run_realtime_outbound_pipe<R>(
    net: &myownmesh_core::JoinedNetwork,
    owner: &crate::ipc::ClientHandle,
    flow_capability: &str,
    network: &str,
    mut reader: R,
    admission: &FrameAdmission,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt as _;

    loop {
        let mut len_buf = [0u8; 4];
        // A clean EOF (the client closed the pipe) ends the loop; a short read
        // is a torn frame and ends it too — the stream is no longer framed, so
        // nothing after this point can be trusted to be a unit boundary.
        if reader.read_exact(&mut len_buf).await.is_err() {
            return Ok(());
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        // Admitted before a single byte of it is allocated, which is what makes
        // the length prefix safe to believe: a client that announces a frame
        // this daemon was not granted the memory for gets no allocation at all.
        // The lease is held for this iteration, which spans the body, the
        // decoded unit and the send — everything the frame's bytes live in — and
        // is released when the iteration ends, by any exit.
        let _frame = match admission.admit(len) {
            Ok(frame) => frame,
            Err(refusal) => {
                warn!("realtime frame of {len} bytes not admitted: {refusal} — dropping pipe");
                return Ok(());
            }
        };
        let _allocation = match admission.admit_allocator_residual(REALTIME_BUFFER_ALLOCATIONS) {
            Ok(allocation) => allocation,
            Err(refusal) => {
                warn!("realtime frame allocation not admitted: {refusal} â€” dropping pipe");
                return Ok(());
            }
        };
        let mut body = vec![0u8; len];
        if reader.read_exact(&mut body).await.is_err() {
            return Ok(());
        }
        let Some(unit) = inspect_realtime_send_unit(&body) else {
            warn!("malformed realtime send unit ({len} bytes) — skipped");
            continue;
        };
        // Two forms of the same name, and only one of them is authority: the
        // bytes go to core, and the lossy rendering exists solely so a refusal
        // can name the flow in a log line. A label is opaque application bytes,
        // so it has no guaranteed text form and none is invented for the wire.
        let label_range = unit.flow_label.clone();
        let payload_range = unit.payload.clone();
        let duration_us = unit.duration_us;
        let body = bytes::Bytes::from(body);
        let label = &body[label_range];
        // No marker: an outbound unit does not carry one, at any layer. The
        // marker bit states something about packetization that the flow's
        // framing policy decides and the packetizer alone is positioned to get
        // right, so a value supplied from here could only contradict it. The
        // wire byte that would have held it is reserved zero and refused
        // otherwise, which is what stops a client from believing it still has a
        // say.
        let outbound = core_webrtc::WebRtcRealtimeOutboundUnit {
            duration: std::time::Duration::from_micros(u64::from(duration_us)),
            data: body.slice(payload_range),
        };
        // Lent for exactly this unit and never held: the borrow ends with the
        // closure, so the daemon's stored handle stays the only one and a close
        // arriving on another connection is not racing a copy.
        //
        // Synchronous by design: the unit is authorized against the session and
        // enqueued before this returns, so a refusal is attributable to the unit
        // that caused it rather than surfacing later against an unrelated one.
        let sent = owner.with_realtime_flow(flow_capability, network, |flow| {
            // The label is compared, not resolved. It grants nothing — the flow
            // is already chosen — so a mismatch is a client naming one of its
            // own flows on the wrong pipe, which is worth telling it about and
            // is never worth guessing at.
            if flow.label() != label {
                return Err(None);
            }
            net.send_webrtc_realtime(flow, outbound).map_err(Some)
        });
        let Some(sent) = sent else {
            // The flow was closed while this pipe was running — by this client
            // on another connection, or by its disconnect drain. There is
            // nothing left to write to, and the pipe ends rather than idling
            // against a capability that will never resolve again.
            debug!(
                label = %label_for_log(label),
                "realtime outbound pipe closing: its flow is no longer held by this client"
            );
            return Ok(());
        };
        match sent {
            Ok(()) => {}
            Err(None) => {
                debug!(
                    label = %label_for_log(label),
                    "realtime unit names a different flow than this pipe is bound to — dropped"
                );
            }
            // `SessionNotCurrent` ENDS THE PIPE. Every other refusal is about
            // one unit and the next one may well succeed, but this one says the
            // session this pipe's flow belonged to is gone — and because the
            // flow handle is exact, that is now the *only* thing it can mean.
            // It can no longer be a peer that has been replaced under a name
            // this pipe kept resolving.
            //
            // Closing hands the failure to the one party that can resolve it:
            // the client sees its pipe drop, and reopening a flow forces a
            // fresh binding against whatever session is current now.
            Err(Some(refusal)) => {
                if matches!(refusal, core_realtime::RealtimeRefusal::SessionNotCurrent) {
                    warn!(
                        label = %label_for_log(label),
                        code = refusal.code(),
                        "realtime outbound pipe closing: its session is no longer current"
                    );
                    return Ok(());
                }
                debug!(label = %label_for_log(label), code = refusal.code(), "realtime send refused");
            }
        }
    }
}

/// Release everything a removed client still holds in its networks: every
/// realtime flow it had open, and every synthetic handler it was the last
/// claimant of.
///
/// Called when that client's event stream ends, however it ended. Both halves
/// are here because both have the same shape — the registry can say *what* is
/// outstanding but not release it, since releasing needs a `JoinedNetwork` and
/// an await, and the registry holds neither.
///
/// Each flow is *closed* rather than dropped, and the reason is no longer that
/// dropping releases nothing. A `RealtimeFlowHandle`'s own Drop removes the flow
/// from its set and hands the native half back as remains that retire when they
/// drop, so an abandoned handle is cleaned up rather than leaked. What an
/// explicit close still buys is the acknowledgement: it awaits that retirement,
/// so this path can say the client's flows are down and be telling the truth,
/// where a drop has nobody to tell and returns before the native half is gone.
/// Drop is the backstop for the paths that cannot await one; this one can.
///
/// Each flow is taken out of the client's table before its close runs, so a
/// close racing this drain reaches core at most once for a given flow.
///
/// A handler left installed is the quieter version of the same leak: it holds
/// the retention the engine funded for it and answers "no claim" to every
/// caller. `forget` names only the claims nothing else took over, so a method a
/// displacing client now owns is not removed from under it.
///
/// Refusals are ignored rather than reported: there is nobody left to report to,
/// and every refusal this can produce means the thing was already gone.
/// Taken by value, not borrowed: the retired routes have to be *consumed* to be
/// retired — a pump is joined and an unfinished install is answered, and both
/// move out of the record. Everything else here is read through the record while
/// it is still alive, so its leases outlive the buffers they fund.
struct RouteRetirementBatch(Option<crate::ipc::LeasedList<crate::ipc::RetiredRoute>>);

impl RouteRetirementBatch {
    fn pop(&mut self) -> Option<crate::ipc::RetiredRoute> {
        self.0.as_mut().and_then(|routes| routes.pop())
    }
}

pub(super) async fn release_owned_registrations(
    state: &ControlState,
    removed: crate::ipc::UnregisteredClient,
) {
    // The lease is bound rather than discarded: it funds this flow's capability
    // and network-name buffers, and dropping it at the top of the body would
    // unfund the very `network` string the lookup below reads. It goes at the
    // end of the iteration, with the strings it paid for.
    let mut flows = removed.handle.drain_realtime_flows();
    while let Some(flow) = flows.pop() {
        let Some(net) = state.registry.get(flow.network()) else {
            continue;
        };
        let _ = flow.close_through(&net).await;
    }
    // Methods next, and *before* the routes -- which is the order this comment
    // used to claim while the code did the opposite. Each `ForgottenMethod`
    // carries the core registration that removes its own handler, so dropping
    // one forgets it from the dispatcher it was installed on, whether or not
    // this daemon still has that network in its map, and only if a successor has
    // not legitimately taken the name in the meantime.
    //
    // Dropping them here rather than letting `removed` fall out of scope is two
    // things at once. It makes the stated ordering true: a handler that is still
    // installed can be re-entered by an inbound call, and a call that arrives
    // while this client's channel routes are mid-retirement is a call routed
    // into a fan-out being taken apart. And it releases each method's list node
    // one at a time, as the F2 storage shape requires, rather than holding every
    // node until the last route has been awaited.
    let mut forget = removed.forget;
    while let Some(forgotten) = forget.pop() {
        drop(forgotten);
    }
    // Last, and awaited. Each of these is either a pump that has not been told
    // to stop yet or an install whose followers have not been answered, and
    // `serve` counts the pumps among the tasks it will not return without. A
    // disconnect that skipped this would leave a fan-out task delivering into a
    // channel whose only subscriber is gone.
    // `RetiredRoute::retire` keeps an external bounded join owner armed across
    // this await, so cancellation of this cleanup task cannot detach the pump.
    let mut routes = RouteRetirementBatch(Some(removed.routes));
    while let Some(route) = routes.pop() {
        route.retire().await;
    }
}

/// Render a flow label for a log line, and for nothing else.
///
/// A label is opaque application bytes with no guaranteed text form, so this is
/// lossy by construction and its output must never reach the wire, a response,
/// or a lookup: two distinct labels can render identically, which is harmless in
/// a diagnostic and would be a routing bug anywhere else.
fn label_for_log(label: &[u8]) -> String {
    String::from_utf8_lossy(label).into_owned()
}

/// Push units for the bound session's inbound flows to a client's binary pipe.
///
/// One-way (daemon → client) apart from EOF, which ends the loop. Each unit goes
/// out as `[u32 len][body]`, and the body's `flow_label` — delivered alongside
/// the unit rather than looked up — names which flow it belongs to. The session
/// is already fixed by the pipe's binding, which is what lets the body stay
/// this small.
///
/// The two exits are the only two things that can happen: the client leaves, or
/// the session ends. `None` from the stream is terminal and means the latter;
/// there is no retirement flag to check and nothing to distinguish, because a
/// session that ended has taken every flow with it.
pub(super) async fn run_realtime_inbound_pipe<R, W>(
    net: &myownmesh_core::JoinedNetwork,
    peer: &str,
    inbound: &core_realtime::RealtimeInboundStream,
    mut reader: R,
    writer: &mut W,
    admission: &FrameAdmission,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt as _;

    let mut probe = [0u8; 1];
    loop {
        let arrival = match tokio::select! {
            biased;
            // The client never writes on an inbound pipe, so any completed read
            // — a stray byte, or normally EOF — means it is gone. Biased first
            // so a departure is noticed on the same poll rather than waiting out
            // an idle session that may never produce another unit.
            _ = reader.read(&mut probe) => return Ok(()),
            arrival = net.recv_webrtc_realtime_any(inbound) => arrival,
        } {
            Ok(arrival) => arrival,
            Err(refusal) => {
                warn!(%peer, code = refusal.code(), "realtime inbound head is not RTP; closing pipe");
                return Err(anyhow::anyhow!(
                    "realtime inbound receive refused by core: {}",
                    refusal.code()
                ));
            }
        };
        let Some(arrival) = arrival else {
            debug!(%peer, "realtime inbound stream ended (session over)");
            return Ok(());
        };
        let framed_len = REALTIME_FRAME_HEADER
            .checked_add(arrival.label.len())
            .and_then(|length| length.checked_add(arrival.unit.data.len()));
        let Some(framed_len) = framed_len else {
            warn!(%peer, bytes = arrival.unit.data.len(), "realtime unit cannot be framed — dropped");
            continue;
        };
        // Funded for this iteration, which covers the one encoded output body.
        // The arrival's label and payload are borrowed directly while encoding;
        // there is no intermediate unit or payload copy. Inbound units are core's to produce and
        // this daemon's to hold on their way out, so they are accounted here
        // even though no local client chose their size — a session sending
        // faster than a client reads is exactly when this has to hold.
        let _frame = match admission.admit(framed_len) {
            Ok(frame) => frame,
            Err(refusal) => {
                warn!(%peer, bytes = arrival.unit.data.len(), "realtime unit not admitted: {refusal} — dropped");
                continue;
            }
        };
        let _allocation = match admission.admit_allocator_residual(REALTIME_BUFFER_ALLOCATIONS) {
            Ok(allocation) => allocation,
            Err(refusal) => {
                warn!(%peer, "realtime output allocation not admitted: {refusal} â€” dropped");
                continue;
            }
        };
        let Some(body) = encode_realtime_recv_fields_with_ceiling(
            &arrival.label,
            arrival.unit.marker,
            arrival.unit.rtp_timestamp,
            &arrival.unit.data,
            admission.framing_ceiling(),
        ) else {
            // Larger than the framing can express. Dropped here, and the pipe
            // continues: the alternative is writing a frame whose length prefix
            // or inner length is wrong, which the client cannot interpret and
            // cannot resynchronise from — one unit it could not have used
            // becomes every unit after it. One flow's oversized unit is not a
            // reason to take down a session's whole inbound path.
            warn!(
                %peer,
                label = %label_for_log(&arrival.label),
                bytes = arrival.unit.data.len(),
                "realtime unit too large to frame — dropped"
            );
            continue;
        };
        // Cannot truncate: `encode_realtime_recv_unit` returned `Some`, so the
        // body is within the owner-selected ceiling and the u32 wire length.
        let len = (body.len() as u32).to_le_bytes();
        if writer.write_all(&len).await.is_err()
            || writer.write_all(&body).await.is_err()
            || writer.flush().await.is_err()
        {
            return Ok(());
        }
    }
}
