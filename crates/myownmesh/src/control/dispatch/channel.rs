//! Typed-channel operations: subscribe, release, send to one peer, broadcast.
//!
//! Each function answers with an [`Answer`] — the reply it produced and the
//! line capacity that reply was admitted under. That pairing is the point
//! rather than a convenience: these operations fund their response line
//! *before* the send or the subscription is committed, so a client cannot be
//! told "sent" by a daemon that then discovers it has nowhere to put the
//! answer. Returning the reply alone would have left the capacity to be
//! acquired afterwards, which is the ordering the funding work removed.
//!
//! Nothing here writes. The connection loop is the only encoder and the only
//! writer; what it gets back is already measured and already paid for.

use std::sync::Arc;

use anyhow::{Context, Result};

use super::{refused, refused_text, unknown_network, Answer};
use crate::control::framing::{AdmittedLineOut, FrameAdmission};
use crate::control::reply::{prepare_reply_then, ControlOut, PreparedReply};
use crate::control::{ConnectionCancel, ControlState};

/// Join a typed channel, installing the network-to-client pump if this is the
/// first subscriber.
pub(in crate::control) async fn subscribe(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    client_id: crate::ipc::ClientId,
    client_capability: String,
    network: String,
    channel: String,
) -> Result<Answer> {
    if state
        .clients
        .authenticate(client_id, &client_capability)
        .is_none()
    {
        return refused("invalid local client authority", admission);
    }
    let Some(net) = state.registry.get(&network) else {
        return unknown_network(&network, admission);
    };
    let success = PreparedReply::Bool {
        key: "subscribed",
        value: true,
    };
    let output = AdmittedLineOut::prepare(&ControlOut::Prepared(&success), admission)
        .context("channel-subscribe response capacity was not admitted")?;
    let key = (network, channel);
    let join = match state.clients.subscribe_channel_borrowed(&key, client_id) {
        Ok(join) => join,
        Err(refusal) => {
            // The success line's funding goes back before the refusal's is
            // taken, so the two are never both outstanding.
            drop(output);
            return refused_text(format!("channel subscribe refused: {refusal}"), admission);
        }
    };
    match join {
        crate::ipc::ChannelJoin::Install(ready) => {
            let pump = crate::ipc::bridge::spawn_channel_pump(&net, &key, state.clients.clone());
            let orphan = match pump {
                Ok(pump) => state
                    .clients
                    .finish_channel_install(&key, &ready, Some(pump)),
                Err(error) => {
                    if let Some(orphan) = state.clients.finish_channel_install(&key, &ready, None) {
                        orphan.retire().await;
                    }
                    drop(output);
                    return refused_text(format!("channel subscribe refused: {error}"), admission);
                }
            };
            if let Some(orphan) = orphan {
                orphan.retire().await;
            }
        }
        crate::ipc::ChannelJoin::Pending(ready) => {
            if !ready.wait().await {
                drop(output);
                return refused(
                    "channel subscribe refused: the route this subscription joined could not be installed",
                    admission,
                );
            }
        }
        crate::ipc::ChannelJoin::Live => {}
    }
    Ok((success, output))
}

/// Release a channel subscription. A no-op for a client that does not hold one.
pub(in crate::control) async fn unsubscribe(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    client_id: crate::ipc::ClientId,
    client_capability: String,
    network: String,
    channel: String,
) -> Result<Answer> {
    if state
        .clients
        .authenticate(client_id, &client_capability)
        .is_none()
    {
        return refused("invalid local client authority", admission);
    }
    let reply = PreparedReply::Bool {
        key: "unsubscribed",
        value: true,
    };
    let output = AdmittedLineOut::prepare(&ControlOut::Prepared(&reply), admission)
        .context("ChannelUnsubscribe response capacity was not admitted")?;
    let key = (network, channel);
    // Route retirement is the local commit and intentionally is not cancelled
    // with the socket. Success means the pump has stopped; only the subsequent
    // pre-funded response write races connection shutdown.
    if let Some(route) = state.clients.unsubscribe_channel(&key, client_id) {
        route.retire().await;
    }
    Ok((reply, output))
}

/// Send one payload to one peer on one channel.
pub(in crate::control) async fn send_to(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    channel: String,
    peer: String,
    payload: serde_json::Value,
) -> Result<Answer> {
    let Some(net) = state.registry.get(&network) else {
        return unknown_network(&network, admission);
    };
    let reply = PreparedReply::Bool {
        key: "sent",
        value: true,
    };
    let channel = net.channel::<serde_json::Value>(&channel);
    let (send, output) = prepare_reply_then(&reply, admission, || channel.send_to(&peer, &payload))
        .context("channel-send response capacity was not admitted")?;
    match send.await {
        Ok(()) => Ok((reply, output)),
        Err(error) => {
            drop(output);
            refused_text(error.to_string(), admission)
        }
    }
}

/// Broadcast one payload to every subscriber on one channel.
pub(in crate::control) async fn send_all(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    network: String,
    channel: String,
    payload: serde_json::Value,
) -> Result<Answer> {
    let Some(net) = state.registry.get(&network) else {
        return unknown_network(&network, admission);
    };
    // The count is not known until the broadcast returns, so the line is funded
    // against the widest scalar it could carry and the real count is encoded
    // into that same funding.
    let ceiling = PreparedReply::Usize {
        key: "dispatched_to",
        value: usize::MAX,
    };
    let channel = net.channel::<serde_json::Value>(&channel);
    let (broadcast, output) =
        prepare_reply_then(&ceiling, admission, || channel.broadcast(&payload))
            .context("channel-broadcast response capacity was not admitted")?;
    match broadcast.await {
        Ok(count) => Ok((
            PreparedReply::Usize {
                key: "dispatched_to",
                value: count,
            },
            output,
        )),
        Err(error) => {
            drop(output);
            refused_text(error.to_string(), admission)
        }
    }
}

/// Send one frame under the acknowledged-delivery contract.
///
/// This is the one channel operation that can outlive the client's interest in
/// the answer, so it is also the one that takes the connection's cancellation:
/// a caller that is going away is told so rather than being made to wait for a
/// delivery acknowledgement no one will read. Cancellation is polled first,
/// because a connection already draining should not start a fresh reliable
/// submission.
pub(in crate::control) async fn send_reliable(
    state: &Arc<ControlState>,
    admission: &FrameAdmission,
    cancel: &ConnectionCancel,
    network: String,
    channel: String,
    peer: String,
    payload: serde_json::Value,
) -> Result<Answer> {
    let Some(net) = state.registry.get(&network) else {
        return unknown_network(&network, admission);
    };
    let reply = PreparedReply::Bool {
        key: "delivered",
        value: true,
    };
    let output = AdmittedLineOut::prepare(&ControlOut::Prepared(&reply), admission)
        .context("reliable-send response capacity was not admitted")?;
    let result = tokio::select! {
        biased;
        () = cancel.cancelled() => {
            drop(output);
            return refused("control connection closing", admission);
        }
        result = net.send_reliable(&peer, &channel, payload) => result,
    };
    match result {
        Ok(()) => Ok((reply, output)),
        Err(error) => {
            drop(output);
            refused_text(error.to_string(), admission)
        }
    }
}
