//! Dispatch for codec-opaque application flow capabilities.
//!
//! This module only performs the JSON-side open/change/close transactions.  Opaque
//! bodies never enter this path: after the capability is issued they travel on
//! [`super::super::opaque_pipe`] as length-prefixed binary frames.

use std::sync::Arc;

use myownmesh_core::realtime::{OpaqueFlowOpen, RealtimeRefusal};

use crate::control::handoff::ProvisionalHandoff;
use crate::control::reply::{FundedVariableReply, OperationReplyData, ResponseOwner};
use crate::control::ControlState;

pub(in crate::control) struct FlowOpen {
    pub network: String,
    pub peer: String,
    pub label: Vec<u8>,
    pub direction: myownmesh_core::realtime::RealtimeFlowDirection,
    pub mode: myownmesh_core::realtime::OpaqueFlowMode,
    pub max_unit_bytes: u32,
}

pub(in crate::control) struct FlowChange {
    pub network: String,
    pub label: Vec<u8>,
    pub direction: myownmesh_core::realtime::RealtimeFlowDirection,
    pub mode: myownmesh_core::realtime::OpaqueFlowMode,
    pub max_unit_bytes: u32,
}

fn refused_flow(owner: ResponseOwner, refusal: RealtimeRefusal) -> FundedVariableReply {
    owner.finish(Ok(OperationReplyData::RealtimeRefused {
        error: refusal.to_string(),
        code: refusal.code().to_owned(),
    }))
}

/// Open one exact opaque flow and file its move-only handle under the
/// authenticated client that will own the later binary pipe.
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
        label,
        direction,
        mode,
        max_unit_bytes,
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
    let Some(requested) = OpaqueFlowOpen::new(label, direction, mode, max_unit_bytes) else {
        return (
            owner.finish(Ok(OperationReplyData::RealtimeRefused {
                error: "opaque flow request is outside the representable label or body bounds"
                    .to_owned(),
                code: "provider_configuration_invalid".to_owned(),
            })),
            ProvisionalHandoff::None,
        );
    };
    let response_label = String::from_utf8_lossy(&requested.label).into_owned();
    match net.open_opaque_flow(&peer, &requested).await {
        Ok(flow) => match state.clients.install_realtime_flow(&client, network, flow) {
            Ok(capability) => {
                let capability = capability.expose().to_owned();
                (
                    owner.finish(Ok(OperationReplyData::RealtimeOpened {
                        // The operation response predates raw-byte labels and
                        // exposes only a descriptive string.  The capability,
                        // not this lossy display value, authorizes the pipe.
                        flow_label: response_label,
                        capability: capability.clone(),
                    })),
                    ProvisionalHandoff::RealtimeFlow { client, capability },
                )
            }
            Err(rejected) => {
                let reason = rejected.reason.to_string();
                let _ = net.close_realtime(rejected.flow).await;
                (
                    owner.finish(Err(format!("opaque flow open refused: {reason}"))),
                    ProvisionalHandoff::None,
                )
            }
        },
        Err(refusal) => (refused_flow(owner, refusal), ProvisionalHandoff::None),
    }
}

/// Change the ceiling of one exact installed flow.  The slot is captured
/// under the authenticated client's table lock, then its funded async mutex
/// is held across the core transaction while that table lock is released.
pub(in crate::control) async fn flow_change(
    state: &Arc<ControlState>,
    owner: ResponseOwner,
    open: FlowChange,
    client_id: crate::ipc::ClientId,
    client_capability: String,
    flow_capability: String,
) -> FundedVariableReply {
    let FlowChange {
        network,
        label,
        direction,
        mode,
        max_unit_bytes,
    } = open;
    let Some(client) = state.clients.authenticate(client_id, &client_capability) else {
        return owner.finish(Err("invalid local client authority".to_owned()));
    };
    if !client.is_connected() {
        return refused_flow(owner, RealtimeRefusal::SessionNotCurrent);
    }
    let Some(slot) = client.realtime_flow_slot(&flow_capability, &network) else {
        return owner.finish(Err(
            "unknown flow_capability, network mismatch, or flow already closed".to_owned(),
        ));
    };
    let Some(net) = state.registry.get(&network) else {
        return owner.finish(Err(format!("unknown network: {network}")));
    };
    let Some(requested) = OpaqueFlowOpen::new(label, direction, mode, max_unit_bytes) else {
        return owner.finish(Ok(OperationReplyData::RealtimeRefused {
            error: "opaque flow request is outside the representable label or body bounds"
                .to_owned(),
            code: "provider_configuration_invalid".to_owned(),
        }));
    };
    let result = tokio::select! {
        result = slot.change_opaque(&net, &requested) => result,
        _ = client.wait_disconnected() => Err(RealtimeRefusal::SessionNotCurrent),
    };
    match result {
        Ok(()) => owner.finish(Ok(OperationReplyData::OpaqueChanged {
            flow_capability,
            max_unit_bytes,
        })),
        Err(refusal) => refused_flow(owner, refusal),
    }
}

/// Close uses the same exact client capability and move-only flow retirement
/// path as RTP.  Keeping one close implementation prevents a second registry
/// or a close-by-peer/label fallback from appearing in the opaque branch.
pub(in crate::control) async fn flow_close(
    state: &Arc<ControlState>,
    owner: ResponseOwner,
    client_id: crate::ipc::ClientId,
    client_capability: String,
    flow_capability: String,
) -> FundedVariableReply {
    super::realtime::flow_close(state, owner, client_id, client_capability, flow_capability).await
}
