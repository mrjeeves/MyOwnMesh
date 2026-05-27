//! Daemon-side IPC plumbing for typed channels and RPC.
//!
//! The existing `control.rs` request/response model covers
//! control-plane ops (network lifecycle, peers, roster,
//! governance, status). What it doesn't cover are the parts of
//! `myownmesh-core` that are inherently bidirectional and
//! stateful per client:
//!
//! - **RPC handler registration.** A client claims a method
//!   name (`infer`, `transcribe`, ...) and the daemon installs a
//!   synthetic `Rpc::serve` that routes inbound peer calls to
//!   the claiming client's event socket as `RpcInbound` events.
//!   The client posts `RpcRespond` / `RpcStreamChunk` /
//!   `RpcStreamEnd` requests back over the same connection;
//!   those resolve the engine-side `oneshot` / `mpsc` the
//!   library handler returned.
//!
//! - **Typed channel subscriptions.** A client subscribes to a
//!   channel name (`catalog/announce`, `permissions/snapshot`,
//!   ...) and the daemon spins up a forwarder that drains the
//!   network's `Channel::subscribe()` broadcast and emits
//!   `ChannelInbound` events to every currently-subscribed
//!   client.
//!
//! - **Capability advertisement updates.** Clients call
//!   `CapabilitiesSet` to replace the network's advertised caps;
//!   the daemon forwards to `JoinedNetwork::advertise(...)`,
//!   which broadcasts a `capabilities_update` frame to peers.
//!
//! All of this is layered on top of the existing
//! request/response wire — see [`crate::control`] for the
//! existing variants. The new ops are additive; no breaking
//! change to clients that don't speak them.
//!
//! Per-client state lives in [`clients::ClientRegistry`]; the
//! engine-side glue (synthetic `Rpc::serve` handlers, channel
//! pump tasks) lives in [`bridge`].

pub mod bridge;
pub mod clients;
pub mod wire;

#[allow(unused_imports)]
pub use clients::{ClientHandle, ClientId, ClientRegistry};
pub use wire::ServerOut;
