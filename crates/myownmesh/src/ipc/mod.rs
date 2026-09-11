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
//!   `RpcStreamEnd` requests over command connections carrying the exact
//!   capability minted for that event connection;
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
/// Cleanup storage whose funding and whose allocation are the same value's.
///
/// Crate-private: nothing outside this daemon hands a caller a funded
/// collection, and an embedder that could build one could push into it
/// without a lease.
mod leased;
pub mod wire;

#[cfg(test)]
pub use clients::{FanoutBarrier, RegistryResidue};
/// Channel-route lifecycle machinery, which is this daemon's own and not an
/// embedder's authority.
///
/// Crate-visible rather than public, and the distinction is real: an embedder
/// that could name a [`clients::RouteReady`] could wait on an install it does
/// not own, and one that could name a [`clients::RouteCancellation`] could stop
/// a pump the daemon is accounting for. Nothing outside this crate has a reason
/// to hold either. Their owners -- [`clients::ChannelJoin`] and
/// [`clients::RetiredRoute`] -- travel with them for the same reason and to keep
/// their effective visibility matched, which is what stops a public signature
/// naming a crate-private type.
pub(crate) use leased::LeasedList;

#[allow(unused_imports)]
pub(crate) use clients::{
    ChannelFanout, ChannelFanoutStep, ChannelJoin, RetiredRoute, RouteCancellation, RouteOwner,
    RouteReady,
};
#[allow(unused_imports)]
pub use clients::{
    ClientHandle, ClientId, ClientRegistry, ForgottenMethod, HandlerGeneration, Lifecycle,
    MethodRelease, RealtimeFlowCapability, TaskAdmission, UnregisteredClient, WeakClientRegistry,
};
pub use wire::ServerOut;
