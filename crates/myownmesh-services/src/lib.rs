//! Self-hosted STUN / TURN servers for MyOwnMesh.
//!
//! These let a device become an ICE infrastructure provider for the
//! rest of the mesh: a [`stun::StunServer`] answers RFC 5389 Binding
//! requests so peers can learn their reflexive address without a public
//! provider, and a [`turn::TurnServer`] relays media / data via RFC 5766
//! allocations for peers stuck behind symmetric NAT. Together with the
//! self-hosted signaling relay in `myownmesh-signaling::server`, they
//! make a fully internet-isolated network practical — no Google STUN,
//! no Cloudflare TURN, no public Nostr relay required.
//!
//! Both servers are thin, async wrappers over the webrtc-rs `stun` /
//! `turn` crates (the same versions the mesh transport already links),
//! driven by the [`myownmesh_core::config`] service config. They live in
//! their own crate so embedders that only want the mesh runtime don't
//! pull the TURN server's dependency tree.
//!
//! ```no_run
//! # async fn _ex() -> Result<(), Box<dyn std::error::Error>> {
//! use myownmesh_services::{ServiceCleanupPort, StunServer, TurnServer};
//! use myownmesh_core::config::{StunServiceConfig, TurnServiceConfig};
//!
//! # let scope: myownmesh_core::LocalApplicationResourceScope = todo!();
//! // Supplied by a ServiceCleanupOwner outside this runtime. The owner joins
//! // only after the service/runtime has completed its cleanup handoff.
//! # let cleanup: ServiceCleanupPort = todo!();
//! let stun = StunServer::start_with_resource_scope(
//!     &StunServiceConfig { enabled: true, ..Default::default() },
//!     scope,
//!     cleanup,
//! ).await?;
//! println!("STUN listening on {}", stun.local_addr());
//! # let _ = stun;
//! # Ok(()) }
//! ```

mod cleanup;
pub mod stun;
pub mod turn;

pub use cleanup::{
    ServiceCleanupError, ServiceCleanupOwner, ServiceCleanupPort, ServiceCleanupReport,
};
pub use stun::{StunServer, StunServerHandle};
pub use turn::{TurnServer, TurnServerHandle};

/// Errors starting or running a self-hosted service.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Outside-owner admission, funding, or worker failure.
    #[error("service cleanup: {0}")]
    Cleanup(#[from] ServiceCleanupError),
    /// The bind address was malformed or the port couldn't be bound
    /// (already in use, privileged, etc.).
    #[error("bind {0}: {1}")]
    Bind(String, #[source] std::io::Error),
    /// A STUN packet failed to decode.
    #[error("decode: {0}")]
    Decode(String),
    /// A STUN response failed to encode.
    #[error("encode: {0}")]
    Encode(String),
    /// The TURN server config was rejected (e.g. no public IP, no
    /// credentials).
    #[error("turn config: {0}")]
    TurnConfig(String),
    /// The owner-selected resource provider refused service custody.
    #[error("resource custody: {0}")]
    Resource(String),
    /// The underlying `turn` crate returned an error.
    #[error("turn: {0}")]
    Turn(String),
    /// A service listener task terminated unexpectedly while being joined.
    #[error("service task: {0}")]
    TaskJoin(String),
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, Error>;
