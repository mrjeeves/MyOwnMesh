//! Small production API patterns for an embedding application.
//!
//! The functions here are reusable snippets, not a runnable two-peer fixture:
//! callers provide an already-started [`JoinedNetwork`], exact peer id, and
//! their own payload/resource policy. No test broker or synthetic grant is
//! selected here.

use std::future::Future;

use bytes::Bytes;
use myownmesh_core::application_gateway::GatewayRefusal;
use myownmesh_core::realtime::{
    OpaqueFlowOpen, RealtimeFlowHandle, RealtimeInboundStream, RealtimeRefusal,
};
use myownmesh_core::rpc::RpcStreamItem;
use myownmesh_core::{
    Channel, ChannelError, JoinedNetwork, ResourceClaim, ResourceMailboxReceiver, Rpc, RpcError,
    WebRtcRealtimeFlowOpen, WebRtcRealtimeInboundArrival,
};
use serde::{de::DeserializeOwned, Serialize};

/// Send one typed message under the acknowledged-delivery contract.
pub async fn send_acked<T>(channel: &Channel<T>, peer: &str, body: &T) -> Result<(), ChannelError>
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    channel.send_to_acked(peer, body).await
}

/// Register a streaming handler whose returned mailbox is funded by the
/// application's local resource scope.
pub fn register_stream_handler<F, Fut>(
    rpc: &Rpc,
    method: &str,
    handler: F,
) -> std::result::Result<(), GatewayRefusal>
where
    F: Fn(myownmesh_core::RpcCall) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = std::result::Result<ResourceMailboxReceiver<RpcStreamItem>, String>>
        + Send
        + 'static,
{
    rpc.serve_stream(method, handler)
}

/// Register the same streaming shape while stating the handler's retained
/// capture claim explicitly. The claim must be derived from the application's
/// actual captures; `ResourceClaim::ZERO` is valid only for a truly empty
/// capture set.
pub fn register_funded_stream_handler<F, Fut>(
    rpc: &Rpc,
    method: &str,
    captures: ResourceClaim,
    handler: F,
) -> std::result::Result<(), GatewayRefusal>
where
    F: Fn(myownmesh_core::RpcCall) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = std::result::Result<ResourceMailboxReceiver<RpcStreamItem>, String>>
        + Send
        + 'static,
{
    rpc.serve_stream_with_retention_claim(method, captures, handler)
}

/// Prepare and publish a unary handler while retaining the exact owned
/// registration. Dropping the returned value removes only the installation it
/// created; call `detach` deliberately when lifetime is owned elsewhere.
pub fn prepare_owned_handler<F, Fut>(
    rpc: &Rpc,
    method: &str,
    handler: F,
) -> std::result::Result<myownmesh_core::rpc::OwnedMethodRegistration, GatewayRefusal>
where
    F: Fn(myownmesh_core::RpcCall) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = std::result::Result<myownmesh_core::RpcResponse, String>> + Send + 'static,
{
    rpc.prepare_serve(method, handler)?
        .commit()
        .into_result()
        .map_err(|refused| refused.into_refusal())
}

/// Register a minimal real streaming producer. The explicit `End(Ok(()))`
/// item is required: dropping the sender without a terminal item is a failed
/// stream, not successful EOF. The mailbox root and item are funded by the
/// caller's local application scope.
pub fn register_empty_stream_handler(
    rpc: &Rpc,
    method: &str,
    owner: myownmesh_core::LocalApplicationResourceScope,
) -> std::result::Result<(), GatewayRefusal> {
    rpc.serve_stream(method, move |_call| {
        let owner = owner.clone();
        async move {
            let (sender, receiver) = myownmesh_core::resource_mailbox::<RpcStreamItem>(owner)
                .map_err(|error| format!("stream mailbox setup: {error}"))?;
            sender
                .send(RpcStreamItem::End(Ok(())))
                .map_err(|error| format!("stream terminal admission: {error:?}"))?;
            drop(sender);
            Ok(receiver)
        }
    })
}

/// Consume a streaming response incrementally under a caller-owned item
/// bound. Each funded chunk is borrowed by `visit` and then released before
/// the next receive; this helper never accumulates an unbounded application
/// buffer. `None` from the stream is the terminal condition, while an item or
/// callback error remains an error rather than implicit success.
pub async fn consume_stream_bounded(
    rpc: &Rpc,
    peer: &str,
    method: &str,
    payload: serde_json::Value,
    max_items: usize,
    mut visit: impl FnMut(&serde_json::Value) -> std::result::Result<(), String>,
) -> std::result::Result<usize, String> {
    let mut stream = rpc
        .call_stream(peer, method, payload)
        .await
        .map_err(|error: RpcError| error.to_string())?;
    let mut count = 0usize;
    while let Some(item) = stream.recv().await {
        let item = item.map_err(|error| error.to_string())?;
        if count == max_items {
            return Err("stream exceeded the caller's item bound".into());
        }
        visit(item.value())?;
        count += 1;
    }
    Ok(count)
}

/// Use the funded unary result when the caller must encode/write the response
/// before releasing its retention lease. This is an advanced, currently
/// `doc(hidden)` retention seam rather than the ordinary supported facade;
/// ordinary callers should use `Rpc::call` and take ownership of its body.
pub async fn call_funded(
    rpc: &Rpc,
    peer: &str,
    method: &str,
    payload: serde_json::Value,
) -> std::result::Result<myownmesh_core::rpc::FundedRpcCallResult, RpcError> {
    rpc.call_funded(peer, method, payload).await
}

/// Open, send once, and close one exact opaque flow. Cleanup is awaited even
/// when the send refuses; callers must not retry an ambiguous flow change or
/// substitute a peer/label lookup for the returned move-only handle.
pub async fn send_and_close_opaque(
    network: &JoinedNetwork,
    peer: &str,
    open: &OpaqueFlowOpen,
    body: Bytes,
) -> std::result::Result<(), OpaqueLifecycleError> {
    let flow = network
        .open_opaque_flow(peer, open)
        .await
        .map_err(OpaqueLifecycleError::Open)?;
    let send = network.send_opaque_flow(&flow, body);
    let close = network.close_realtime(flow).await;
    match (send, close) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(send), Ok(())) => Err(OpaqueLifecycleError::Send { send, close: None }),
        (Ok(()), Err(close)) => Err(OpaqueLifecycleError::Close { close }),
        (Err(send), Err(close)) => Err(OpaqueLifecycleError::Send {
            send,
            close: Some(close),
        }),
    }
}

/// Open one exact opaque flow, publish a caller-supplied change, and always
/// await close. The replacement must describe the same label, direction, and
/// mode; callers must not retry an ambiguous change result.
pub async fn change_and_close_opaque(
    network: &JoinedNetwork,
    peer: &str,
    open: &OpaqueFlowOpen,
    replacement: &OpaqueFlowOpen,
) -> std::result::Result<(), OpaqueLifecycleError> {
    let flow = network
        .open_opaque_flow(peer, open)
        .await
        .map_err(OpaqueLifecycleError::Open)?;
    let changed = network.change_opaque_flow(&flow, replacement).await;
    let close = network.close_realtime(flow).await;
    match (changed, close) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(change), Ok(())) => Err(OpaqueLifecycleError::Change {
            change,
            close: None,
        }),
        (Ok(()), Err(close)) => Err(OpaqueLifecycleError::Close { close }),
        (Err(change), Err(close)) => Err(OpaqueLifecycleError::Change {
            change,
            close: Some(close),
        }),
    }
}

/// Open a provider-specific RTP flow using the exact encoding selected by the
/// caller's preinstalled real-time profile.
pub async fn open_rtp_flow(
    network: &JoinedNetwork,
    peer: &str,
    open: WebRtcRealtimeFlowOpen,
) -> std::result::Result<RealtimeFlowHandle, RealtimeRefusal> {
    network.open_webrtc_realtime(peer, open).await
}

/// Receive one tagged RTP arrival from a previously claimed single-consumer
/// inbound stream. `None` is the terminal session condition.
pub async fn receive_one_rtp(
    network: &JoinedNetwork,
    inbound: &RealtimeInboundStream,
) -> std::result::Result<Option<WebRtcRealtimeInboundArrival>, RealtimeRefusal> {
    network.recv_webrtc_realtime_any(inbound).await
}

/// The send result and awaited close result are kept separately so a failed
/// cleanup is never hidden by an earlier operation error.
#[derive(Debug)]
pub enum OpaqueLifecycleError {
    Open(RealtimeRefusal),
    Send {
        send: RealtimeRefusal,
        close: Option<RealtimeRefusal>,
    },
    Close {
        close: RealtimeRefusal,
    },
    Change {
        change: RealtimeRefusal,
        close: Option<RealtimeRefusal>,
    },
}

fn main() {
    println!("application_patterns provides reusable channel, RPC, and opaque-flow functions");
}
