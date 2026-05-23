//! MyOwnMesh — peer-to-peer mesh networking runtime.
//!
//! `myownmesh-core` is the only crate embedding apps need to depend on.
//! It exposes:
//!
//! - [`Identity`] — long-lived ed25519 device identity persisted at
//!   `~/.myownmesh/.secrets/identity.json` (mode 0600 on Unix). The
//!   public key is the Device ID surfaced on the wire.
//! - [`Roster`] — per-network list of approved peer Device IDs.
//!   Reconnects from rostered peers auto-allow without re-prompting
//!   the user.
//! - The wire [`protocol`] — `hello` / `auth_response` / `approve` /
//!   `deny` / `ping` / `pong` / `shelve` / `unshelve` /
//!   `capabilities_update` / generic RPC frames.
//! - Pluggable [`topology`] selectors — Ring (default), Star, FullMesh.
//!
//! The connection engine, transport, channels, RPC, and high-level
//! [`MeshHandle`] facade build on top of these primitives.
//!
//! Trust model: each device owns a long-lived ed25519 keypair. The
//! `hello` handshake commits both sides to a shared nonce; the
//! `auth_response` is an ed25519 signature over
//! `SIGN_DOMAIN_TAG || nonce || my_device_id || their_device_id` —
//! domain separation prevents a signature obtained for one protocol
//! step from being replayed in another. A user-visible 6-char
//! verification code lets a human eyeball-confirm the handshake over
//! voice/video at first-meeting time; thereafter the peer's pubkey is
//! in the roster and auto-approved on reconnect.

pub mod channels;
pub mod config;
pub mod dirs;
pub mod engine;
pub mod error;
pub mod events;
pub mod handle;
pub mod identity;
pub mod protocol;
pub mod roster;
pub mod rpc;
pub mod signing;
pub mod topology;
pub mod transport;
pub mod verification;

pub use channels::{Channel, ChannelError, ChannelMessage};
pub use config::{
    AutoUpdateConfig, MeshConfig, NetworkConfig, StunServer, TopologyMode, TurnServer,
};
pub use engine::ladder::ConnectionTier;
pub use error::{Error, Result};
pub use events::{DiagEntry, DiagLevel, MeshEvent, MeshPhase, PeerEvent};
pub use handle::{JoinedNetwork, Mesh, MeshHandle, PeerInfo};
pub use identity::{generate_network_id, normalize_network_id, DeviceId, Identity};
pub use protocol::CapabilityAdvert;
pub use roster::{AuthorizedPeer, Roster};
pub use rpc::{Rpc, RpcCall, RpcError, RpcResponse};
pub use topology::Topology;

/// Domain-separation tag prefixed to every signed handshake payload.
/// A signature obtained for one protocol step cannot be replayed in
/// another (e.g. a different version of MyOwnMesh, or any other product
/// that signs ed25519 challenges).
pub const SIGN_DOMAIN_TAG: &str = "myownmesh-mesh-auth-v1:";

/// App-id used to derive the Trystero room handle. Two MyOwnMesh peers
/// with the same `network_id` and the same app-id meet in the same
/// signaling room; peers with mismatching app-ids never see each
/// other. Overridable via the `MYOWNMESH_TRYSTERO_APP_ID` env var so
/// downstream forks can isolate their fleet.
pub const TRYSTERO_APP_ID: &str = "myownmesh-cloud-mesh-v1";

/// Wire-protocol version. Stays at 1 across additive changes (new
/// optional fields, new message kinds); a v1 receiver getting an
/// unknown message kind silently drops it. Bump only when an existing
/// message's wire shape changes incompatibly — finer-grained
/// capability negotiation happens in [`protocol::features`].
pub const PROTOCOL_VERSION: u32 = 1;
