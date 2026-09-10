//! Filesystem layout for MyOwnMesh's persistent state. Single source
//! of truth for "where do we put the identity anchor, rosters, config,
//! and updater staging area"; all other modules go through here so a
//! future migration to e.g. XDG state-dir is a one-file change.
//!
//! Default layout (Unix):
//!
//! ```text
//! ~/.myownmesh/
//!   ├── config.json
//!   ├── .secrets/
//!   │   └── identity.json          (0600)
//!   ├── mesh/
//!   │   └── rosters/
//!   │       └── {network_id}.json  (0600)
//!   └── updates/
//!       ├── pending.json
//!       └── {version}/
//! ```
//!
//! The directory is also used on Windows and macOS; we don't follow
//! `%APPDATA%` / `~/Library/Application Support` conventions yet
//! because the on-disk shape is meant to be portable across machines
//! (a user copying their `~/.myownmesh/` between hosts gets the same
//! identity + rosters without surgery).

use std::path::PathBuf;

use crate::error::{Error, Result};

/// Root directory for MyOwnMesh state. Resolves to `$MYOWNMESH_HOME` if
/// set, otherwise `$HOME/.myownmesh` (Unix) or `%USERPROFILE%\.myownmesh`
/// (Windows). The directory is created lazily by the first writer; this
/// function only returns the path.
pub fn data_dir() -> Result<PathBuf> {
    if let Ok(custom) = std::env::var("MYOWNMESH_HOME") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    let home = dirs::home_dir().ok_or_else(|| {
        Error::Other(
            "could not resolve user home directory (set MYOWNMESH_HOME to override)".to_string(),
        )
    })?;
    Ok(home.join(".myownmesh"))
}

/// Directory holding per-network roster files.
pub fn rosters_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join("mesh").join("rosters"))
}

/// Directory holding the identity anchor and any other secret-key
/// material. Mode 0700 on Unix.
pub fn secrets_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join(".secrets"))
}

/// Directory the updater stages downloaded releases into before
/// applying them on next launch.
pub fn updates_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join("updates"))
}

/// Path to the user-editable config file. Missing file is treated as
/// "use defaults" — the file only needs to exist when the user has
/// customised something.
pub fn config_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("config.json"))
}
