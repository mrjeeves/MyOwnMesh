//! Persistent roster of authorized peers.
//!
//! When the user approves a peer, that peer's Device ID is added to
//! the roster. On subsequent connections the auth handshake auto-allows
//! known IDs without going back to the user — that's the "low friction
//! after attachment" half of the bidirectional-auth contract.
//!
//! The roster is scoped to a single Network ID. Each saved network
//! gets its own roster file under `~/.myownmesh/mesh/rosters/`, so
//! switching the active network swaps to that network's roster intact
//! rather than wiping it. The user can keep their home-mesh peers
//! approved separately from their office-mesh peers without
//! re-authenticating on every switch.
//!
//! Stored at `~/.myownmesh/mesh/rosters/{network_id}.json` (mode 0600
//! on Unix). Schema is v1.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const ROSTER_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct AuthorizedPeer {
    /// Canonical pubkey portion of the Device ID — base32-lowercase,
    /// no display suffix. Roster compares peers by this value.
    pub device_id: String,
    /// Label the peer self-reported at handshake time. Cosmetic only
    /// — peers can lie about labels, so don't trust this for
    /// anything but UI presentation.
    pub label: String,
    /// Unix-seconds timestamp of approval. Informational.
    pub approved_at: u64,
    /// Authority tier within this network's governance. Defaults to
    /// [`Role::Member`] so rosters written before the
    /// `network_state_v1` feature shipped keep loading cleanly — and
    /// so open networks (where the field is cosmetic) don't need to
    /// stamp every entry.
    ///
    /// Source of truth for *enforced* authority on a closed network
    /// is the `roles` map on [`crate::NetworkState`] — this field is
    /// the locally-cached projection for fast peer-row rendering.
    /// They are kept in sync by the engine on every signed transition.
    #[serde(default)]
    pub role: crate::network_state::Role,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Roster {
    pub version: u32,
    /// Network ID the roster is scoped to. Empty when the roster has
    /// never been populated; mismatch with the current config's
    /// network_id triggers a wipe on next load.
    pub network_id: String,
    pub authorized_devices: Vec<AuthorizedPeer>,
}

/// Per-network roster filename. We use the canonical network_id
/// directly — it's already a string of `[a-z0-9_-]` chars (validated
/// by `identity::normalize_network_id`), so it's safe as a filename
/// without further encoding. Hashes / pathological inputs can't reach
/// here without bypassing the normalizer.
fn roster_path(network_id: &str) -> Result<PathBuf> {
    Ok(crate::dirs::rosters_dir()?.join(format!("{network_id}.json")))
}

fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---- pure (in-memory) ops -----------------------------------------------
//
// Filesystem-free so unit tests can exercise the logic without
// touching the user's data dir. The high-level helpers below
// (`load`/`save`) wrap these.

pub fn empty_for(network_id: &str) -> Roster {
    Roster {
        version: ROSTER_VERSION,
        network_id: network_id.to_string(),
        authorized_devices: Vec::new(),
    }
}

/// Add or refresh a peer in the roster. Idempotent — re-approving an
/// existing peer updates their label but doesn't bump `approved_at`,
/// so the user-facing "approved on …" reflects the original moment
/// of trust. The existing peer's `role` is preserved through a
/// re-approval (use [`set_role_in`] or
/// [`crate::network_state::apply_transition`] to change it).
pub fn add_peer_in(roster: &mut Roster, device_id: &str, label: &str) {
    let pubkey = crate::signing::pubkey_part(device_id).to_string();
    if let Some(existing) = roster
        .authorized_devices
        .iter_mut()
        .find(|p| p.device_id == pubkey)
    {
        existing.label = label.to_string();
    } else {
        roster.authorized_devices.push(AuthorizedPeer {
            device_id: pubkey,
            label: label.to_string(),
            approved_at: now_unix(),
            role: crate::network_state::Role::default(),
        });
    }
}

/// Update a roster entry's role tag. No-op if the peer isn't in the
/// roster (callers should add first). Returns whether a row was
/// changed so the caller can short-circuit a no-op disk write.
pub fn set_role_in(roster: &mut Roster, device_id: &str, role: crate::network_state::Role) -> bool {
    let pubkey = crate::signing::pubkey_part(device_id);
    if let Some(existing) = roster
        .authorized_devices
        .iter_mut()
        .find(|p| p.device_id == pubkey)
    {
        if existing.role != role {
            existing.role = role;
            return true;
        }
    }
    false
}

pub fn remove_peer_in(roster: &mut Roster, device_id: &str) {
    let pubkey = crate::signing::pubkey_part(device_id);
    roster.authorized_devices.retain(|p| p.device_id != pubkey);
}

/// Membership test. Compares by pubkey (strips display suffixes from
/// both sides), so a caller can pass either the raw pubkey or the
/// display form.
pub fn is_authorized(roster: &Roster, device_id: &str) -> bool {
    let pubkey = crate::signing::pubkey_part(device_id);
    roster
        .authorized_devices
        .iter()
        .any(|p| p.device_id == pubkey)
}

// ---- filesystem wrappers ------------------------------------------------

/// Load the roster scoped to the given Network ID. If the on-disk
/// roster is missing returns a fresh empty roster — the caller is
/// the first to add a peer for this network. Each saved network gets
/// its own file, so switching the active network preserves other
/// networks' rosters untouched. The returned roster is in-memory;
/// nothing is written until a caller invokes `save`.
pub fn load(current_network_id: &str) -> Result<Roster> {
    let path = roster_path(current_network_id)?;
    if !path.exists() {
        return Ok(empty_for(current_network_id));
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| Error::Roster(format!("read roster at {}: {e}", path.display())))?;
    let roster: Roster = serde_json::from_str(&raw)
        .map_err(|e| Error::Roster(format!("parse roster at {}: {e}", path.display())))?;
    if roster.version != ROSTER_VERSION {
        return Err(Error::Roster(format!(
            "roster version {} unsupported (this build expects v{})",
            roster.version, ROSTER_VERSION
        )));
    }
    if roster.network_id != current_network_id {
        // Defensive: a per-network file should always match its
        // filename. If it doesn't (manual edit, mid-rename crash,
        // etc.) trust the filename — it's the index we're keyed on.
        return Ok(empty_for(current_network_id));
    }
    Ok(roster)
}

pub fn save(roster: &Roster) -> Result<()> {
    let path = roster_path(&roster.network_id)?;
    let parent = path
        .parent()
        .ok_or_else(|| Error::Roster(format!("roster path has no parent: {}", path.display())))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| Error::Roster(format!("create rosters dir at {}: {e}", parent.display())))?;
    let serialized = serde_json::to_string_pretty(roster)?;
    std::fs::write(&path, serialized)
        .map_err(|e| Error::Roster(format!("write roster to {}: {e}", path.display())))?;
    restrict_file_permissions(&path)?;
    Ok(())
}

/// Remove the roster file for `network_id`. Used by the "Forget
/// Network" UX so a removed network doesn't leave its peer approvals
/// lingering on disk. Idempotent — missing file is fine.
pub fn delete(network_id: &str) -> Result<()> {
    let path = roster_path(network_id)?;
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| Error::Roster(format!("remove roster at {}: {e}", path.display())))?;
    }
    Ok(())
}

pub fn add_peer(current_network_id: &str, device_id: &str, label: &str) -> Result<Roster> {
    let mut roster = load(current_network_id)?;
    add_peer_in(&mut roster, device_id, label);
    save(&roster)?;
    Ok(roster)
}

pub fn remove_peer(current_network_id: &str, device_id: &str) -> Result<Roster> {
    let mut roster = load(current_network_id)?;
    remove_peer_in(&mut roster, device_id);
    save(&roster)?;
    Ok(roster)
}

#[cfg(unix)]
fn restrict_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .map_err(|e| Error::io(path.to_path_buf(), e))?
        .permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms).map_err(|e| Error::io(path.to_path_buf(), e))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_query() {
        let mut r = empty_for("network-a");
        add_peer_in(&mut r, "peerpubkeyone", "Laptop");
        assert_eq!(r.authorized_devices.len(), 1);
        assert!(is_authorized(&r, "peerpubkeyone"));
        assert!(is_authorized(&r, "peerpubkeyone-xyz12")); // display form
        assert!(!is_authorized(&r, "peerpubkeytwo"));
    }

    #[test]
    fn add_is_idempotent_and_refreshes_label() {
        let mut r = empty_for("network-a");
        add_peer_in(&mut r, "peer1", "Laptop");
        let original_ts = r.authorized_devices[0].approved_at;
        add_peer_in(&mut r, "peer1", "Laptop-renamed");
        assert_eq!(r.authorized_devices.len(), 1);
        assert_eq!(r.authorized_devices[0].label, "Laptop-renamed");
        // approved_at preserved across the re-add — the "approved on
        // …" UI label should reflect the original moment of trust.
        assert_eq!(r.authorized_devices[0].approved_at, original_ts);
    }

    #[test]
    fn remove_works() {
        let mut r = empty_for("network-a");
        add_peer_in(&mut r, "peer1", "X");
        add_peer_in(&mut r, "peer2", "Y");
        remove_peer_in(&mut r, "peer1");
        assert_eq!(r.authorized_devices.len(), 1);
        assert_eq!(r.authorized_devices[0].device_id, "peer2");
    }

    #[test]
    fn remove_accepts_display_form() {
        let mut r = empty_for("network-a");
        add_peer_in(&mut r, "peerone", "X");
        remove_peer_in(&mut r, "peerone-abc12");
        assert!(r.authorized_devices.is_empty());
    }

    #[test]
    fn empty_for_initialises_clean() {
        let r = empty_for("net-x");
        assert_eq!(r.version, ROSTER_VERSION);
        assert_eq!(r.network_id, "net-x");
        assert!(r.authorized_devices.is_empty());
    }

    #[test]
    fn default_role_is_member() {
        let mut r = empty_for("net-a");
        add_peer_in(&mut r, "peer1", "Laptop");
        assert_eq!(
            r.authorized_devices[0].role,
            crate::network_state::Role::Member
        );
    }

    #[test]
    fn old_roster_without_role_field_parses_with_member_default() {
        // Schema before `network_state_v1` shipped. Loading it must
        // keep working — `role` defaults to Member via #[serde(default)]
        // and the existing peer keeps its `approved_at` intact.
        let old_json = r#"{
            "version": 1,
            "network_id": "net-a",
            "authorized_devices": [
                { "device_id": "peer1", "label": "Old laptop", "approved_at": 1700000000 }
            ]
        }"#;
        let r: Roster = serde_json::from_str(old_json).unwrap();
        assert_eq!(r.authorized_devices.len(), 1);
        let p = &r.authorized_devices[0];
        assert_eq!(p.device_id, "peer1");
        assert_eq!(p.label, "Old laptop");
        assert_eq!(p.approved_at, 1700000000);
        assert_eq!(p.role, crate::network_state::Role::Member);
    }

    #[test]
    fn set_role_changes_existing_entry() {
        let mut r = empty_for("net-a");
        add_peer_in(&mut r, "peer1", "Laptop");
        assert!(set_role_in(
            &mut r,
            "peer1",
            crate::network_state::Role::Controller
        ));
        assert_eq!(
            r.authorized_devices[0].role,
            crate::network_state::Role::Controller
        );
        // Idempotent — same role is a no-op.
        assert!(!set_role_in(
            &mut r,
            "peer1",
            crate::network_state::Role::Controller
        ));
    }

    #[test]
    fn set_role_is_noop_on_missing_peer() {
        let mut r = empty_for("net-a");
        assert!(!set_role_in(
            &mut r,
            "ghost",
            crate::network_state::Role::Owner
        ));
        assert!(r.authorized_devices.is_empty());
    }

    #[test]
    fn add_peer_preserves_existing_role() {
        let mut r = empty_for("net-a");
        add_peer_in(&mut r, "peer1", "Laptop");
        set_role_in(&mut r, "peer1", crate::network_state::Role::Owner);
        // Re-add with a new label — role stays.
        add_peer_in(&mut r, "peer1", "Laptop-renamed");
        assert_eq!(r.authorized_devices[0].label, "Laptop-renamed");
        assert_eq!(
            r.authorized_devices[0].role,
            crate::network_state::Role::Owner
        );
    }
}
