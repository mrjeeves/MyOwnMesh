//! Generic request/response RPC over the mesh data channels.
//!
//! Embedders register a handler by `method` name; callers invoke
//! it on a peer via [`Rpc::call`]. Single-shot responses use a
//! `oneshot` round-trip; streaming responses use
//! `tokio::sync::mpsc` plus the
//! [`crate::protocol::rpc::RpcStreamChunkMessage`] /
//! [`crate::protocol::rpc::RpcStreamEndMessage`] frames so a
//! single request can yield many ordered chunks.
//!
//! In-flight requests are tracked per-network in a `DashMap`
//! keyed by the caller-generated request id. Each entry holds the
//! sender side of a `oneshot` (or `mpsc` for streams) so the
//! receive path can route the matching response directly without
//! a global mutex.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot};

use crate::engine::state::NetworkState;
use crate::identity::DeviceId;
use crate::protocol::CapabilityAdvert;

#[derive(thiserror::Error, Debug)]
pub enum RpcError {
    #[error("network down")]
    NetworkDown,
    #[error("peer {0} not in active set")]
    PeerNotFound(String),
    #[error("timeout")]
    Timeout,
    #[error("handler returned error: {0}")]
    Remote(String),
    #[error("no handler registered for method '{0}'")]
    NoHandler(String),
    #[error("serialize: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("transport: {0}")]
    Transport(String),
}

/// A single inbound RPC the local handler receives.
#[derive(Debug, Clone)]
pub struct RpcCall {
    pub from: DeviceId,
    pub request_id: String,
    pub method: String,
    pub payload: serde_json::Value,
    pub streaming: bool,
}

/// Response a handler emits for a single-shot RPC. Streaming
/// handlers use [`Rpc::serve_stream`] and emit chunks on the
/// returned sender directly.
#[derive(Debug, Clone)]
pub struct RpcResponse {
    pub body: serde_json::Value,
}

impl RpcResponse {
    pub fn from_value(body: serde_json::Value) -> Self {
        Self { body }
    }

    pub fn from_serialize<T: serde::Serialize>(body: &T) -> Result<Self, serde_json::Error> {
        Ok(Self {
            body: serde_json::to_value(body)?,
        })
    }
}

/// Boxed future returned by an RPC handler.
pub type RpcHandlerFuture =
    Pin<Box<dyn Future<Output = Result<RpcResponse, String>> + Send + 'static>>;

pub type RpcHandler = Arc<dyn Fn(RpcCall) -> RpcHandlerFuture + Send + Sync + 'static>;

/// Streaming-handler signature. Returns a stream of chunk
/// payloads; the engine wraps each into an
/// [`crate::protocol::rpc::RpcStreamChunkMessage`] and ships an
/// [`crate::protocol::rpc::RpcStreamEndMessage`] when the stream
/// closes.
pub type RpcStreamHandlerFuture = Pin<
    Box<dyn Future<Output = Result<mpsc::Receiver<serde_json::Value>, String>> + Send + 'static>,
>;

pub type RpcStreamHandler = Arc<dyn Fn(RpcCall) -> RpcStreamHandlerFuture + Send + Sync + 'static>;

/// RPC dispatcher. One per joined network; cheap to clone.
#[derive(Clone)]
pub struct Rpc {
    pub(crate) inner: Arc<RpcInner>,
}

/// Internal RPC state shared between the [`Rpc`] facade and the
/// engine's frame-dispatch path. Public so `NetworkState` can
/// stash it; embedders never construct these directly.
pub struct RpcInner {
    pub(crate) network: Arc<NetworkState>,
    pub(crate) handlers: DashMap<String, HandlerEntry>,
    pub(crate) pending: DashMap<String, PendingEntry>,
    pub(crate) capability: Mutex<CapabilityAdvert>,
}

#[allow(clippy::large_enum_variant)]
pub enum HandlerEntry {
    Single(RpcHandler),
    Stream(RpcStreamHandler),
}

pub enum PendingEntry {
    Single(oneshot::Sender<Result<RpcResponse, String>>),
    Stream(mpsc::UnboundedSender<Result<serde_json::Value, String>>),
}

impl Rpc {
    pub(crate) fn new(network: Arc<NetworkState>) -> Self {
        Self {
            inner: Arc::new(RpcInner {
                network,
                handlers: DashMap::new(),
                pending: DashMap::new(),
                capability: Mutex::new(CapabilityAdvert::default()),
            }),
        }
    }

    /// Register a single-shot handler under `method`. Replaces any
    /// previous handler for the same name.
    pub fn serve<F, Fut>(&self, method: &str, handler: F)
    where
        F: Fn(RpcCall) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<RpcResponse, String>> + Send + 'static,
    {
        let h: RpcHandler = Arc::new(move |call| {
            let fut = handler(call);
            Box::pin(fut)
        });
        self.inner
            .handlers
            .insert(method.to_string(), HandlerEntry::Single(h));
    }

    /// Register a streaming handler under `method`. The handler
    /// returns an `mpsc::Receiver<Value>`; each value becomes one
    /// `rpc_stream_chunk` on the wire and a final
    /// `rpc_stream_end` is sent when the receiver closes.
    pub fn serve_stream<F, Fut>(&self, method: &str, handler: F)
    where
        F: Fn(RpcCall) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<mpsc::Receiver<serde_json::Value>, String>> + Send + 'static,
    {
        let h: RpcStreamHandler = Arc::new(move |call| {
            let fut = handler(call);
            Box::pin(fut)
        });
        self.inner
            .handlers
            .insert(method.to_string(), HandlerEntry::Stream(h));
    }

    /// Drop the handler registered under `method`. Idempotent —
    /// no-op if nothing was registered.
    pub fn forget(&self, method: &str) {
        self.inner.handlers.remove(method);
    }

    /// Single-shot RPC call.
    pub async fn call(
        &self,
        peer: &str,
        method: &str,
        payload: serde_json::Value,
    ) -> Result<RpcResponse, RpcError> {
        let request_id = new_request_id();
        let (tx, rx) = oneshot::channel();
        self.inner
            .pending
            .insert(request_id.clone(), PendingEntry::Single(tx));
        let frame = crate::protocol::RpcRequestMessage {
            request_id: request_id.clone(),
            method: method.to_string(),
            payload,
            streaming: false,
        };
        let send_res = self
            .inner
            .network
            .send_rpc_request(peer, frame)
            .await
            .map_err(map_engine_err);
        if let Err(e) = send_res {
            self.inner.pending.remove(&request_id);
            return Err(e);
        }
        match rx.await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(msg)) => Err(RpcError::Remote(msg)),
            Err(_) => Err(RpcError::NetworkDown),
        }
    }

    /// Streaming RPC call. The returned receiver yields each chunk
    /// as it arrives; a `None` signals end-of-stream.
    pub async fn call_stream(
        &self,
        peer: &str,
        method: &str,
        payload: serde_json::Value,
    ) -> Result<mpsc::UnboundedReceiver<Result<serde_json::Value, String>>, RpcError> {
        let request_id = new_request_id();
        let (tx, rx) = mpsc::unbounded_channel();
        self.inner
            .pending
            .insert(request_id.clone(), PendingEntry::Stream(tx));
        let frame = crate::protocol::RpcRequestMessage {
            request_id: request_id.clone(),
            method: method.to_string(),
            payload,
            streaming: true,
        };
        let send_res = self
            .inner
            .network
            .send_rpc_request(peer, frame)
            .await
            .map_err(map_engine_err);
        if let Err(e) = send_res {
            self.inner.pending.remove(&request_id);
            return Err(e);
        }
        Ok(rx)
    }

    /// Advertise capabilities to the mesh. Sent in every outgoing
    /// `hello` and re-broadcast via
    /// [`crate::protocol::CapabilitiesUpdateMessage`] on change.
    pub fn advertise(&self, caps: CapabilityAdvert) {
        *self.inner.capability.lock() = caps.clone();
        // Fire and forget — the engine's broadcast picks up the
        // update on its next tick.
        let net = self.inner.network.clone();
        tokio::spawn(async move {
            let _ = net.broadcast_capabilities(caps).await;
        });
    }

    /// Snapshot of the currently-advertised capabilities.
    pub fn capabilities(&self) -> CapabilityAdvert {
        self.inner.capability.lock().clone()
    }

    #[allow(dead_code)]
    pub(crate) fn handler_entries(&self) -> &DashMap<String, HandlerEntry> {
        &self.inner.handlers
    }

    #[allow(dead_code)]
    pub(crate) fn take_pending(&self, request_id: &str) -> Option<PendingEntry> {
        self.inner
            .pending
            .remove(request_id)
            .map(|(_, entry)| entry)
    }

    /// Track which handlers are currently registered. Used by the
    /// engine to surface "this peer doesn't speak method X" without
    /// shipping a full advertisement on every call.
    pub fn registered_methods(&self) -> Vec<String> {
        self.inner
            .handlers
            .iter()
            .map(|e| e.key().clone())
            .collect()
    }
}

fn new_request_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 12] = rng.gen();
    data_encoding::BASE32_NOPAD.encode(&bytes).to_lowercase()
}

fn map_engine_err(e: crate::error::Error) -> RpcError {
    use crate::error::Error as E;
    match e {
        E::Network(msg) if msg.contains("not found") => RpcError::PeerNotFound(msg),
        E::Transport(msg) => RpcError::Transport(msg),
        other => RpcError::Transport(other.to_string()),
    }
}

/// Build a flat snapshot of currently-registered method names —
/// used by the engine to populate hello.capabilities.
pub fn methods_snapshot(rpc: &Rpc) -> HashMap<String, ()> {
    rpc.inner
        .handlers
        .iter()
        .map(|e| (e.key().clone(), ()))
        .collect()
}
