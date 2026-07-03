//! Crash-safe persistence primitives for MyOwnMesh's state files.
//!
//! Every durable file the engine owns (config, rosters, governance
//! state, custody store, identity anchor) used to be written with a
//! plain truncate-and-write. On an appliance that loses power — or a
//! daemon killed mid-write — that leaves a 0-byte file behind, and a
//! file that *exists but doesn't parse* used to fail hard forever:
//! a KVM was found bricked off its fleet by exactly this (an empty
//! roster file failing every subsequent join). Two primitives close
//! both halves:
//!
//! * [`write_atomic`] — write-to-temp + fsync + rename, so a file is
//!   only ever its previous complete contents or its next complete
//!   contents, never a truncation. The fsync before the rename
//!   matters on the FAT-style filesystems small devices keep state
//!   on; without it the rename can land before the data does.
//! * [`quarantine`] — shove a corrupt file aside (`{name}.corrupt`)
//!   instead of deleting it, so loaders can fall back to a fresh
//!   default *without destroying the evidence* (or a hand-editor's
//!   work). Loaders that fall back this way must log loudly.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Atomically replace `path` with `bytes`.
///
/// The temp file lives in the same directory (rename must not cross a
/// filesystem) and is created `0600` on Unix so secret-bearing files
/// (identity anchor, custody store) are never readable mid-write —
/// callers that want looser permissions relax them afterwards, as
/// before. `std::fs::rename` replaces the destination on every
/// platform we ship (on Windows it maps to `MOVEFILE_REPLACE_EXISTING`).
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = temp_path(path)?;
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        // Data must be on disk before the rename publishes it, or a
        // power cut can leave the *new* name pointing at unwritten
        // blocks — the exact corruption this module exists to end.
        f.sync_all()?;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // Best-effort: persist the rename itself. A missed dir-fsync can
    // only resurface the previous complete file, which is safe.
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Move a corrupt state file aside as `{file_name}.corrupt` (replacing
/// any earlier quarantine — the freshest failure is the interesting
/// one) and return where it went. `None` means the rename itself
/// failed and the caller should leave the file alone rather than risk
/// looping on it.
pub(crate) fn quarantine(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?;
    let mut quarantined = name.to_os_string();
    quarantined.push(".corrupt");
    let dest = path.with_file_name(quarantined);
    std::fs::rename(path, &dest).ok()?;
    Some(dest)
}

fn temp_path(path: &Path) -> std::io::Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("no file name in {}", path.display()),
        )
    })?;
    let mut tmp = name.to_os_string();
    tmp.push(".tmp");
    Ok(path.with_file_name(tmp))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mom-persist-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn write_atomic_replaces_and_leaves_no_temp() {
        let dir = tmpdir("write");
        let path = dir.join("state.json");
        write_atomic(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        write_atomic(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert!(
            !path.with_file_name("state.json.tmp").exists(),
            "temp file must not survive a successful write"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_creates_files_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("mode");
        let path = dir.join("secret.json");
        write_atomic(&path, b"{}").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "fresh state files must be owner-only");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn quarantine_moves_the_file_aside() {
        let dir = tmpdir("quarantine");
        let path = dir.join("roster.json");
        std::fs::write(&path, b"").unwrap();
        let dest = quarantine(&path).expect("quarantine succeeds");
        assert!(!path.exists(), "original must be gone");
        assert_eq!(dest, dir.join("roster.json.corrupt"));
        assert_eq!(std::fs::read(&dest).unwrap(), b"", "bytes preserved");
        // A second corruption replaces the first quarantine.
        std::fs::write(&path, b"worse").unwrap();
        let dest2 = quarantine(&path).expect("re-quarantine succeeds");
        assert_eq!(std::fs::read(&dest2).unwrap(), b"worse");
        let _ = std::fs::remove_dir_all(dir);
    }
}
