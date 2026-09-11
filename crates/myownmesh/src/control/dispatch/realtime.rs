//! The two funded realtime-flow operations.
//!
//! Opening a flow and closing one are the only realtime work the control
//! surface performs: everything after the open travels as opaque frames on the
//! pipe connection, which `framing` owns. Both check the client's capability
//! first, and both answer through the response owner the connection loop
//! acquired before the operation began, so neither can write and neither can
//! decide its own line width.

use std::sync::Arc;

use myownmesh_core::{realtime::RealtimeRefusal, transport as core_webrtc};

use crate::control::handoff::ProvisionalHandoff;
use crate::control::reply::{FundedVariableReply, OperationReplyData, ResponseOwner};
use crate::control::ControlState;

/// One client-requested realtime flow, exactly as the request stated it.
///
/// A carrier for the fields the `RealtimeFlowOpen` arm destructured, and
/// nothing more: it applies no default and no validation, so what reaches
/// [`core_webrtc::WebRtcRealtimeFlowOpen`] is what the client sent.
pub(in crate::control) struct FlowOpen {
    pub network: String,
    pub peer: String,
    pub flow_label: String,
    pub direction: myownmesh_core::realtime::RealtimeFlowDirection,
    pub rtp_kind: core_webrtc::WebRtcRtpKind,
    pub mime: String,
    pub clock_rate: u32,
    pub channels: u16,
}

fn refused_flow(owner: ResponseOwner, refusal: RealtimeRefusal) -> FundedVariableReply {
    owner.finish(Ok(OperationReplyData::RealtimeRefused {
        error: refusal.to_string(),
        code: refusal.code().to_owned(),
    }))
}

/// Open one realtime flow to a peer and issue the capability that names it.
///
/// The request's fields arrive as [`FlowOpen`] rather than as a `Request`, so
/// a caller that gets the variant wrong cannot compile rather than reaching a
/// runtime panic.
/// The installed flow travels back with the reply rather than being kept here:
/// the capability naming it is the client's only copy, and only the connection
/// loop knows whether that copy was delivered. See [`ProvisionalHandoff`].
pub(in crate::control) async fn flow_open(
    state: &Arc<ControlState>,
    owner: ResponseOwner,
    open: FlowOpen,
    client_id: crate::ipc::ClientId,
    client_capability: String,
) -> (FundedVariableReply, ProvisionalHandoff) {
    let FlowOpen {
        network,
        peer,
        flow_label,
        direction,
        rtp_kind,
        mime,
        clock_rate,
        channels,
    } = open;
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
    let chosen = flow_label.clone();
    let requested = core_webrtc::WebRtcRealtimeFlowOpen {
        label: flow_label.into_bytes(),
        direction,
        kind: rtp_kind,
        mime,
        clock_rate,
        channels,
    };
    match net.open_webrtc_realtime(&peer, requested).await {
        Ok(flow) => match state.clients.install_realtime_flow(&client, network, flow) {
            Ok(capability) => {
                let capability = capability.expose().to_owned();
                (
                    owner.finish(Ok(OperationReplyData::RealtimeOpened {
                        flow_label: chosen,
                        capability: capability.clone(),
                    })),
                    ProvisionalHandoff::RealtimeFlow { client, capability },
                )
            }
            Err(rejected) => {
                let reason = rejected.reason.to_string();
                let _ = net.close_realtime(rejected.flow).await;
                (
                    owner.finish(Err(format!("realtime flow open refused: {reason}"))),
                    ProvisionalHandoff::None,
                )
            }
        },
        Err(refusal) => (refused_flow(owner, refusal), ProvisionalHandoff::None),
    }
}

/// Close a realtime flow the client still holds a capability for.
pub(in crate::control) async fn flow_close(
    state: &Arc<ControlState>,
    owner: ResponseOwner,
    client_id: crate::ipc::ClientId,
    client_capability: String,
    flow_capability: String,
) -> FundedVariableReply {
    let Some(client) = state.clients.authenticate(client_id, &client_capability) else {
        return owner.finish(Err("invalid local client authority".to_owned()));
    };
    let Some(flow) = client.take_realtime_flow(&flow_capability) else {
        return owner.finish(Err("unknown flow_capability: it was never issued to this client, or the flow it named has already been closed".to_owned()));
    };
    let Some(net) = state.registry.get(flow.network()) else {
        return owner.finish(Err(format!("unknown network: {}", flow.network())));
    };
    match flow.close_through(&net).await {
        Ok(()) => owner.finish(Ok(OperationReplyData::Closed)),
        Err(refusal) => refused_flow(owner, refusal),
    }
}
