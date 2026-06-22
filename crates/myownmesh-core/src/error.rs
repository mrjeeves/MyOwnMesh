//! Crate-wide error type. Embedders match on these variants instead of
//! the stringly-typed `anyhow::Error` so applications can react
//! programmatically to specific failures (e.g. surface a "key file is
//! locked" message vs. "ICE failed without TURN").

use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("io: {0}")]
    IoBare(#[from] std::io::Error),

    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("base32 decode: {0}")]
    Base32(String),

    #[error("identity: {0}")]
    Identity(String),

    #[error("roster: {0}")]
    Roster(String),

    #[error("signing: {0}")]
    Signing(String),

    #[error("verification: {0}")]
    Verification(String),

    #[error("config: {0}")]
    Config(String),

    #[error("protocol: {0}")]
    Protocol(String),

    #[error("topology: {0}")]
    Topology(String),

    #[error("transport: {0}")]
    Transport(String),

    #[error("network: {0}")]
    Network(String),

    /// Per-device custody MFA: enrollment, verification, or a gate
    /// refusal (a custody-affecting governance change attempted without
    /// a valid second factor). See [`crate::custody`].
    #[error("custody: {0}")]
    Custody(String),

    /// The peer signature didn't verify under its claimed Device ID.
    /// Treated as a hard auth failure — the connection is torn down
    /// and the peer goes back to PendingApproval the next time it
    /// reconnects.
    #[error("signature did not verify")]
    SignatureInvalid,

    /// User denied or explicitly removed the peer; we should not
    /// reconnect to it until the user approves again.
    #[error("peer denied")]
    PeerDenied,

    /// Generic catch-all for context attached to ad-hoc errors. New
    /// call sites should prefer a typed variant where one exists.
    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }
}
