//! Typed publish/subscribe channels between peers.
//!
//! Embedders register a [`Channel`] by name; both ends use the
//! same name to bind their senders to their receivers. Messages
//! are serialized as JSON on the wire (the
//! [`crate::protocol::MeshMessage::Channel`] variant carries the
//! channel name + JSON payload), so any `Serialize +
//! DeserializeOwned` type works.
//!
//! Delivery is best-effort: if no peer with the named channel is
//! connected, the send still succeeds but reaches nobody. The
//! engine's per-peer queue applies its own backpressure; the
//! channel layer never holds bytes for a peer that isn't yet up.

use std::marker::PhantomData;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::engine::state::NetworkState;
use crate::identity::DeviceId;

#[derive(thiserror::Error, Debug)]
pub enum ChannelError {
    #[error("network has been torn down")]
    NetworkDown,
    #[error("peer {0} not found in active set")]
    PeerNotFound(String),
    #[error("serialize: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("transport: {0}")]
    Transport(String),
}

/// One inbound message on a channel, paired with the peer that
/// sent it.
pub struct ChannelMessage<T> {
    pub from: DeviceId,
    pub body: T,
}

/// Typed handle to a named channel. Cheap to clone — multiple
/// holders can `subscribe` independently; the underlying receive
/// stream is a `tokio::sync::broadcast` so missed-while-lagging
/// is observable (matches the broader event stream's policy).
pub struct Channel<T> {
    pub(crate) name: Arc<String>,
    pub(crate) network: Arc<NetworkState>,
    _phantom: PhantomData<T>,
}

impl<T> Clone for Channel<T> {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            network: self.network.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<T> Channel<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    /// Build a channel handle bound to the given network's
    /// engine state. Most embedders should use
    /// [`crate::JoinedNetwork::channel`] instead — this is the
    /// raw constructor for advanced callers that hold the
    /// engine state directly (e.g. integration tests).
    pub fn new(name: String, network: Arc<NetworkState>) -> Self {
        Self {
            name: Arc::new(name),
            network,
            _phantom: PhantomData,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Send a message to one specific peer. Returns `PeerNotFound`
    /// when the peer isn't currently in the active set —
    /// embedders that want to queue-until-available need to
    /// observe [`crate::MeshEvent::Peer`] events first.
    pub async fn send_to(&self, peer: &str, body: &T) -> Result<(), ChannelError> {
        let payload = serde_json::to_value(body)?;
        self.network
            .send_channel_frame(peer, &self.name, payload)
            .await
            .map_err(|e| match e {
                crate::error::Error::Network(msg) if msg.contains("not found") => {
                    ChannelError::PeerNotFound(peer.to_string())
                }
                crate::error::Error::Transport(msg) => ChannelError::Transport(msg),
                other => ChannelError::Transport(other.to_string()),
            })
    }

    /// Send under the acknowledged-delivery contract: parked until the
    /// peer's link is up, retransmitted across session rebuilds, and
    /// resolved when the peer's engine has handed the frame to its
    /// application layer (or with an error at TTL / terminal failure).
    /// Unlike [`Self::send_to`], a peer that isn't connected *yet* is a
    /// reason to queue, not an error — this is the primitive that
    /// replaces application-level retransmit loops.
    pub async fn send_to_acked(
        &self,
        peer: &str,
        body: &T,
        ttl: Option<std::time::Duration>,
    ) -> Result<(), ChannelError> {
        let payload = serde_json::to_value(body)?;
        self.network
            .send_channel_reliable(peer, &self.name, payload, ttl.map(|d| d.as_millis() as u64))
            .await
            .map_err(|e| match e {
                crate::error::Error::Transport(msg) => ChannelError::Transport(msg),
                other => ChannelError::Transport(other.to_string()),
            })
    }

    /// Broadcast to every active peer. Returns the count of peers
    /// the send was dispatched to (a send-success count, not a
    /// delivery-success count — the underlying data channel is
    /// reliable but the peer may have left between dispatch and
    /// the WebRTC stack actually flushing).
    pub async fn broadcast(&self, body: &T) -> Result<usize, ChannelError> {
        let payload = serde_json::to_value(body)?;
        Ok(self
            .network
            .broadcast_channel_frame(&self.name, payload)
            .await)
    }

    /// Subscribe to inbound messages on this channel. The returned
    /// receiver lives until dropped; missed messages while a
    /// receiver is lagging are signaled by the underlying
    /// broadcast channel (matches the event stream's contract).
    pub fn subscribe(&self) -> ChannelSubscription<T> {
        let rx = self.network.subscribe_channel(&self.name);
        ChannelSubscription {
            rx,
            _phantom: PhantomData,
        }
    }
}

/// Inbound side of a channel. Wraps a tokio broadcast Receiver
/// and deserializes each frame into `T` on demand.
pub struct ChannelSubscription<T> {
    rx: tokio::sync::broadcast::Receiver<RawChannelFrame>,
    _phantom: PhantomData<T>,
}

impl<T> ChannelSubscription<T>
where
    T: DeserializeOwned,
{
    /// Await the next message. Returns `None` if the channel has
    /// been torn down (network closed). Surfaces deserialization
    /// failures as `Err`.
    pub async fn recv(&mut self) -> Option<Result<ChannelMessage<T>, ChannelError>> {
        loop {
            match self.rx.recv().await {
                Ok(frame) => {
                    let body = match serde_json::from_value::<T>(frame.payload) {
                        Ok(v) => v,
                        Err(e) => return Some(Err(ChannelError::Serialize(e))),
                    };
                    return Some(Ok(ChannelMessage {
                        from: frame.from,
                        body,
                    }));
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    // Skip the gap and keep going. Embedders that
                    // need explicit lag visibility can observe
                    // `MeshEvent::Diag` for the matching warning.
                    continue;
                }
            }
        }
    }
}

/// The internal frame the engine's channel router stores in its
/// per-channel broadcast queue. Public so `NetworkState` can
/// expose typed accessors that return it; embedders shouldn't
/// construct these directly.
#[derive(Clone, Debug)]
pub struct RawChannelFrame {
    pub from: DeviceId,
    pub payload: serde_json::Value,
}
