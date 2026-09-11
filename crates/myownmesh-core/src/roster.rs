//! Persistent local/UI projection of canonical peer admission state.
//!
//! When canonical policy admits a peer, its Device ID and display metadata
//! may be written to this projection. Persisted rows never authorize a
//! session; admission still requires the exact canonical policy and the
//! explicit network `auto_approve` setting.
//!
//! The roster is scoped to a single Network ID. Cosmetic metadata is stored
//! in keyed records under `~/.myownmesh/mesh/rosters/{network_id}/`; switching
//! networks therefore keeps labels and approval timestamps separate without
//! making those bytes an authority source.

#[cfg(test)]
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::persist::DirectoryCapability;

#[cfg(test)]
thread_local! {
    static AUTHORIZED_DEVICES_LINEAR_SCAN_COUNT: Cell<usize> = const { Cell::new(0) };
    static AUTHORIZED_DEVICES_REBUILD_COUNT: Cell<usize> = const { Cell::new(0) };
}

/// Version of the keyed, non-authoritative projection records.  The former
/// v1 whole-roster JSON document is deliberately not accepted by the loader.
pub const ROSTER_VERSION: u32 = 2;

// These are metadata custody limits, not governance limits.  They bound the
// work this advisory projection can request before any filesystem allocation
// or write; canonical authority remains owned by the semantic store.
const ROSTER_MAX_ENTRIES: usize = 4_096;
const ROSTER_MAX_KEY_BYTES: usize = 128;
const ROSTER_MAX_LABEL_BYTES: usize = 4_096;
const ROSTER_MAX_RECORD_BYTES: usize = 16 * 1024;
const ROSTER_MAX_TRANSACTION_OPERATIONS: usize = ROSTER_MAX_ENTRIES;
const ROSTER_MAX_TRANSACTION_BYTES: usize = 8 * 1024 * 1024;
const ROSTER_MAX_LOAD_BYTES: usize = 32 * 1024 * 1024;

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
    /// Authority tier within this network's governance. Current-profile roster
    /// entries derive it from the canonical graph; it is never serialized.
    ///
    /// This role is a non-authoritative projection/UI cache derived from the
    /// canonical semantic `FactGraph`; admission and authorization must use
    /// the verified facts rather than this locally stored field.
    #[serde(skip_serializing, default = "default_member_role")]
    pub role: crate::semantic::Role,
}

fn default_member_role() -> crate::semantic::Role {
    crate::semantic::Role::Member
}

/// Public values view backed by a keyed in-memory index.
///
/// The slice-shaped view keeps existing read-only UI callers source-compatible
/// while the projection mutators use the index instead of scanning the whole
/// vector for every subject. Mutations go through the named keyed methods
/// below so the index cannot silently drift.
#[derive(Debug, Clone, Default)]
pub struct AuthorizedDevices {
    entries: Vec<AuthorizedPeer>,
    positions: BTreeMap<String, usize>,
}

impl PartialEq for AuthorizedDevices {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}

impl Eq for AuthorizedDevices {}

impl Deref for AuthorizedDevices {
    type Target = [AuthorizedPeer];

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

impl IntoIterator for AuthorizedDevices {
    type Item = AuthorizedPeer;
    type IntoIter = std::vec::IntoIter<AuthorizedPeer>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl<'a> IntoIterator for &'a AuthorizedDevices {
    type Item = &'a AuthorizedPeer;
    type IntoIter = std::slice::Iter<'a, AuthorizedPeer>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

impl Serialize for AuthorizedDevices {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.entries.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AuthorizedDevices {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let entries = Vec::<AuthorizedPeer>::deserialize(deserializer)?;
        Ok(Self::from_entries(entries))
    }
}

impl AuthorizedDevices {
    fn from_entries(entries: Vec<AuthorizedPeer>) -> Self {
        let mut devices = Self {
            entries,
            positions: BTreeMap::new(),
        };
        devices.rebuild_index();
        devices
    }

    fn rebuild_index(&mut self) {
        #[cfg(test)]
        AUTHORIZED_DEVICES_REBUILD_COUNT.with(|count| count.set(count.get().saturating_add(1)));
        self.entries
            .sort_by(|left, right| left.device_id.cmp(&right.device_id));
        self.positions.clear();
        for (index, peer) in self.entries.iter().enumerate() {
            self.positions.insert(peer.device_id.clone(), index);
        }
    }

    fn position(&self, device_id: &str) -> Option<usize> {
        self.positions.get(device_id).copied()
    }

    pub(crate) fn iter(&self) -> std::slice::Iter<'_, AuthorizedPeer> {
        #[cfg(test)]
        AUTHORIZED_DEVICES_LINEAR_SCAN_COUNT.with(|count| {
            count.set(count.get().saturating_add(1));
        });
        self.entries.iter()
    }

    pub(crate) fn snapshot_keys(
        &self,
        keys: &std::collections::BTreeSet<String>,
    ) -> BTreeMap<String, (usize, AuthorizedPeer)> {
        keys.iter()
            .filter_map(|key| {
                let index = self.position(key)?;
                Some((key.clone(), (index, self.entries.get(index)?.clone())))
            })
            .collect()
    }

    /// Restore only the keyed rows captured by `snapshot`. Existing rows keep
    /// their positions and therefore restore without scanning or rebuilding;
    /// additions/removals use indexed operations and rebuild once to restore
    /// the deterministic position map.
    pub(crate) fn restore_snapshot(
        &mut self,
        keys: &std::collections::BTreeSet<String>,
        snapshot: &BTreeMap<String, (usize, AuthorizedPeer)>,
    ) {
        let structural = keys
            .iter()
            .any(|key| snapshot.contains_key(key) != self.position(key).is_some());
        if !structural {
            for (key, (index, peer)) in snapshot {
                if self
                    .entries
                    .get(*index)
                    .is_some_and(|current| current.device_id == *key)
                {
                    self.entries[*index] = peer.clone();
                }
            }
            return;
        }

        let mut removals = keys
            .iter()
            .filter(|key| !snapshot.contains_key(*key))
            .filter_map(|key| self.position(key))
            .collect::<Vec<_>>();
        removals.sort_unstable_by(|left, right| right.cmp(left));
        for index in removals {
            self.entries.remove(index);
        }
        let mut insertions = snapshot
            .values()
            .filter(|(_, peer)| self.position(&peer.device_id).is_none())
            .cloned()
            .collect::<Vec<_>>();
        insertions.sort_unstable_by_key(|(index, _)| *index);
        for (index, peer) in insertions {
            self.entries.insert(index.min(self.entries.len()), peer);
        }
        self.rebuild_index();
        for (key, (index, peer)) in snapshot {
            if self
                .entries
                .get(*index)
                .is_some_and(|current| current.device_id == *key)
            {
                self.entries[*index] = peer.clone();
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn reset_test_counters() {
        AUTHORIZED_DEVICES_LINEAR_SCAN_COUNT.with(|count| count.set(0));
        AUTHORIZED_DEVICES_REBUILD_COUNT.with(|count| count.set(0));
    }

    #[cfg(test)]
    pub(crate) fn test_counters() -> (usize, usize) {
        (
            AUTHORIZED_DEVICES_LINEAR_SCAN_COUNT.with(Cell::get),
            AUTHORIZED_DEVICES_REBUILD_COUNT.with(Cell::get),
        )
    }

    fn get_mut_by_key(&mut self, device_id: &str) -> Option<&mut AuthorizedPeer> {
        let index = self.position(device_id)?;
        self.entries.get_mut(index)
    }

    fn get_by_key(&self, device_id: &str) -> Option<&AuthorizedPeer> {
        let index = self.position(device_id)?;
        self.entries.get(index)
    }

    fn push_keyed(&mut self, peer: AuthorizedPeer) {
        if let Some(index) = self.position(&peer.device_id) {
            self.entries[index] = peer;
        } else {
            self.entries.push(peer);
        }
        self.rebuild_index();
    }

    /// Apply one committed semantic projection batch and rebuild the ordered
    /// position index at most once. Existing role-only updates stay in place;
    /// structural additions and removals are staged against the old index and
    /// published together.
    fn apply_projected_roles(
        &mut self,
        desired: &BTreeMap<String, Option<crate::semantic::Role>>,
    ) -> bool {
        let approved_at = now_unix();
        let mut removals = BTreeSet::new();
        let mut structural = false;
        let mut changed = false;

        for (device_id, role) in desired {
            match (self.position(device_id), role) {
                (Some(index), Some(role)) => {
                    let peer = self
                        .entries
                        .get_mut(index)
                        .expect("the keyed roster index points at an entry");
                    if peer.role != *role {
                        peer.role = *role;
                        changed = true;
                    }
                }
                (None, Some(role)) => {
                    self.entries.push(AuthorizedPeer {
                        device_id: device_id.clone(),
                        label: String::new(),
                        approved_at,
                        role: *role,
                    });
                    structural = true;
                    changed = true;
                }
                (Some(_), None) => {
                    removals.insert(device_id.clone());
                    structural = true;
                    changed = true;
                }
                (None, None) => {}
            }
        }

        if !removals.is_empty() {
            self.entries
                .retain(|peer| !removals.contains(&peer.device_id));
        }
        if structural {
            self.rebuild_index();
        }
        changed
    }

    pub fn push(&mut self, peer: AuthorizedPeer) {
        self.push_keyed(peer);
    }

    fn insert_at(&mut self, index: usize, peer: AuthorizedPeer) {
        self.entries.insert(index.min(self.entries.len()), peer);
        self.rebuild_index();
    }

    pub fn insert(&mut self, index: usize, peer: AuthorizedPeer) {
        self.insert_at(index, peer);
    }

    fn retain_keyed<F>(&mut self, keep: F)
    where
        F: FnMut(&AuthorizedPeer) -> bool,
    {
        self.entries.retain(keep);
        self.rebuild_index();
    }

    pub fn retain<F>(&mut self, keep: F)
    where
        F: FnMut(&AuthorizedPeer) -> bool,
    {
        self.retain_keyed(keep);
    }

    fn clear_keyed(&mut self) {
        self.entries.clear();
        self.positions.clear();
    }

    pub fn clear(&mut self) {
        self.clear_keyed();
    }

    fn remove_keyed(&mut self, device_id: &str) -> Option<AuthorizedPeer> {
        let index = self.position(device_id)?;
        let removed = self.entries.remove(index);
        self.rebuild_index();
        Some(removed)
    }

    pub fn remove(&mut self, index: usize) -> AuthorizedPeer {
        let removed = self.entries.remove(index);
        self.rebuild_index();
        removed
    }
}

/// Apply an already-validated, committed semantic role projection as one
/// keyed roster batch. The roster remains a disposable UI cache; authority is
/// still evaluated exclusively from the semantic graph.
pub(crate) fn apply_projected_roles_in(
    roster: &mut Roster,
    desired: &BTreeMap<String, Option<crate::semantic::Role>>,
) -> bool {
    roster.authorized_devices.apply_projected_roles(desired)
}

/// Compare only the fields represented by [`RosterEntryRecord`].  A semantic
/// role change is deliberately absent from that record, so callers can update
/// the in-memory role projection without rewriting the advisory metadata.
/// The comparison remains keyed and bounded by the supplied affected set.
pub(crate) fn persisted_metadata_equal(
    before: &Roster,
    after: &Roster,
    affected_keys: &std::collections::BTreeSet<String>,
) -> bool {
    if before.version != after.version || before.network_id != after.network_id {
        return false;
    }
    persisted_metadata_matches_snapshot(
        &before.authorized_devices.snapshot_keys(affected_keys),
        after,
        affected_keys,
    )
}

/// Compare the persisted fields against an already captured keyed snapshot.
/// This is the delta-path variant: it avoids cloning or read-locking the whole
/// roster while its write lock is held.
pub(crate) fn persisted_metadata_matches_snapshot(
    before: &BTreeMap<String, (usize, AuthorizedPeer)>,
    after: &Roster,
    affected_keys: &std::collections::BTreeSet<String>,
) -> bool {
    affected_keys.iter().all(|key| {
        let before = before
            .get(key)
            .map(|(_, peer)| (&peer.device_id, &peer.label, peer.approved_at));
        let after = after
            .authorized_devices
            .get_by_key(key)
            .map(|peer| (&peer.device_id, &peer.label, peer.approved_at));
        before == after
    })
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Roster {
    #[serde(deserialize_with = "deserialize_current_version")]
    pub version: u32,
    /// Network ID the roster is scoped to. Empty when the roster has
    /// never been populated; mismatch with the current config's
    /// network_id triggers a wipe on next load.
    pub network_id: String,
    pub authorized_devices: AuthorizedDevices,
    /// Instance-owned persistence root. This is local custody, not wire or
    /// roster identity, so it is intentionally omitted from serialization.
    #[serde(skip)]
    persistence_root: Option<PathBuf>,
}

fn deserialize_current_version<'de, D>(deserializer: D) -> std::result::Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let version = u32::deserialize(deserializer)?;
    if version == ROSTER_VERSION {
        Ok(version)
    } else {
        Err(serde::de::Error::custom(format!(
            "roster version {version} is retired; expected v{ROSTER_VERSION}"
        )))
    }
}

fn roster_store(root: Option<&Path>, create: bool) -> Result<DirectoryCapability> {
    let path = match root {
        Some(root) => root.to_path_buf(),
        None => crate::dirs::data_dir()?,
    };
    open_roster_store(&path, root.is_none(), create).map_err(|error| {
        Error::Roster(format!(
            "open roster capability at {}: {error}",
            path.display()
        ))
    })
}

/// Only the application/instance root is caller-selected. All managed
/// components stay relative to retained no-follow capabilities. Keep the raw
/// I/O result so deletion can distinguish missing storage from refusal.
fn open_roster_store(
    selected_root: &Path,
    append_mesh: bool,
    create: bool,
) -> std::io::Result<DirectoryCapability> {
    let root = DirectoryCapability::open_selected_root(selected_root, create)?;
    let parent = if append_mesh {
        root.open_dir("mesh", create)?
    } else {
        root
    };
    parent.open_dir("rosters", create)
}

fn roster_io(error: std::io::Error, action: &str) -> Error {
    Error::Roster(format!("{action}: {error}"))
}

fn random_roster_component(prefix: &str) -> Result<String> {
    let mut random = [0u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|error| Error::Roster(format!("secure roster temp name unavailable: {error}")))?;
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!(".{prefix}.tmp-{suffix}"))
}

fn write_roster_new(directory: &DirectoryCapability, name: &str, bytes: &[u8]) -> Result<()> {
    if bytes.len() > ROSTER_MAX_TRANSACTION_BYTES {
        return Err(Error::Roster(
            "roster write exceeds transaction byte limit".into(),
        ));
    }
    directory
        .write_new(name, bytes, 0o600)
        .map_err(|error| roster_io(error, "write roster capability file"))
}

fn replace_roster_file(
    staging: &DirectoryCapability,
    name: &str,
    bytes: &[u8],
    destination: &DirectoryCapability,
) -> Result<()> {
    let temp = random_roster_component(name)?;
    write_roster_new(staging, &temp, bytes)?;
    if let Err(error) = staging.rename_to(&temp, destination, name) {
        let _ = staging.remove_file(&temp);
        return Err(roster_io(error, "publish roster capability file"));
    }
    Ok(())
}

fn network_file_name(network_id: &str) -> Result<String> {
    let network_id = canonical_network_id(network_id)?;
    Ok(format!("{network_id}.json"))
}

fn validate_device_key(device_id: &str) -> Result<()> {
    if device_id.is_empty()
        || device_id.len() > ROSTER_MAX_KEY_BYTES
        || !device_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(Error::Roster(format!(
            "noncanonical roster DeviceId key: {device_id}"
        )));
    }
    Ok(())
}

fn entry_file_name(device_id: &str) -> Result<String> {
    validate_device_key(device_id)?;
    Ok(format!("{device_id}.json"))
}

fn canonical_network_id(network_id: &str) -> Result<String> {
    crate::identity::normalize_network_id(network_id)
        .map_err(|error| Error::Roster(format!("invalid roster network id: {error}")))
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
        authorized_devices: AuthorizedDevices::default(),
        persistence_root: None,
    }
}

/// Construct an empty projection retaining the instance-owned persistence
/// root.  The root is metadata custody only; canonical authority is rebuilt
/// from the semantic store after startup.
pub(crate) fn empty_for_at(root: Option<&Path>, network_id: &str) -> Roster {
    with_persistence_root(empty_for(network_id), root)
}

fn with_persistence_root(mut roster: Roster, root: Option<&Path>) -> Roster {
    roster.persistence_root = root.map(Path::to_path_buf);
    roster
}

/// Add or refresh a peer in the roster. Idempotent — re-approving an
/// existing peer updates their label but doesn't bump `approved_at`,
/// so the user-facing "approved on …" reflects the original moment
/// of trust. The existing role projection is preserved through a
/// re-approval; canonical role changes arrive through the semantic
/// `FactGraph`, while [`set_role_in`] only updates this local UI cache.
pub fn add_peer_in(roster: &mut Roster, device_id: &str, label: &str) {
    let pubkey = crate::signing::pubkey_part(device_id).to_string();
    if let Some(existing) = roster.authorized_devices.get_mut_by_key(&pubkey) {
        existing.label = label.to_string();
    } else {
        roster.authorized_devices.push_keyed(AuthorizedPeer {
            device_id: pubkey,
            label: label.to_string(),
            approved_at: now_unix(),
            role: crate::semantic::Role::Member,
        });
    }
}

/// Update a roster entry's role tag. No-op if the peer isn't in the
/// roster (callers should add first). Returns whether a row was
/// changed so the caller can short-circuit a no-op disk write.
pub fn set_role_in<R>(roster: &mut Roster, device_id: &str, role: R) -> bool
where
    R: Into<crate::semantic::Role>,
{
    let role = role.into();
    let pubkey = crate::signing::pubkey_part(device_id);
    if let Some(existing) = roster.authorized_devices.get_mut_by_key(pubkey) {
        if existing.role != role {
            existing.role = role;
            return true;
        }
    }
    false
}

pub fn remove_peer_in(roster: &mut Roster, device_id: &str) {
    let pubkey = crate::signing::pubkey_part(device_id);
    roster.authorized_devices.remove_keyed(pubkey);
}

/// Membership test. Compares by pubkey (strips display suffixes from
/// both sides), so a caller can pass either the raw pubkey or the
/// display form.
pub fn is_authorized(roster: &Roster, device_id: &str) -> bool {
    let pubkey = crate::signing::pubkey_part(device_id);
    roster.authorized_devices.position(pubkey).is_some()
}

// ---- filesystem wrappers ------------------------------------------------

/// Load the advisory projection for a network. Missing, malformed,
/// mismatched, legacy, or unreadable metadata is quarantined/diagnosed and
/// becomes an empty projection. This function never supplies authority and
/// never blocks canonical semantic startup.
pub fn load(current_network_id: &str) -> Result<Roster> {
    load_at(None, current_network_id)
}

/// Load keyed advisory metadata from an instance-owned root. `None` keeps the
/// production default. The v1 whole-roster document is a retired format.
pub fn load_at(root: Option<&Path>, current_network_id: &str) -> Result<Roster> {
    canonical_network_id(current_network_id)?;
    Ok(load_advisory_at(root, current_network_id))
}

/// Non-blocking advisory loader used by canonical-first engine startup.
pub(crate) fn load_advisory_at(root: Option<&Path>, current_network_id: &str) -> Roster {
    let current_network_id = match canonical_network_id(current_network_id) {
        Ok(network_id) => network_id,
        Err(error) => {
            tracing::warn!(%error, "invalid roster network id; using empty projection");
            return empty_for_at(root, current_network_id);
        }
    };
    let mut roster = empty_for_at(root, &current_network_id);
    let store = match roster_store(root, false) {
        Ok(store) => store,
        Err(error) => {
            tracing::warn!(network = %current_network_id, %error, "roster metadata capability unavailable; using empty projection");
            return roster;
        }
    };
    let legacy = match network_file_name(&current_network_id) {
        Ok(name) => name,
        Err(error) => {
            tracing::warn!(network = %current_network_id, %error, "roster legacy name unavailable; using empty projection");
            return roster;
        }
    };
    match store.quarantine(&legacy) {
        Ok(()) => tracing::warn!(
            network = %current_network_id,
            "retired v1 whole-roster metadata quarantined"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!(
            network = %current_network_id,
            %error,
            "retired v1 whole-roster metadata could not be quarantined"
        ),
    }
    let directory = match store.open_dir(&current_network_id, false) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return roster,
        Err(error) => {
            tracing::warn!(network = %current_network_id, %error, "roster metadata directory unavailable; using empty projection");
            return roster;
        }
    };
    if let Err(error) = recover_roster_transaction(&directory, &current_network_id) {
        tracing::warn!(
            network = %current_network_id,
            %error,
            "roster transaction recovery failed; using empty projection"
        );
        return roster;
    }
    let entries = match directory.read_names_bounded(ROSTER_MAX_ENTRIES, ROSTER_MAX_KEY_BYTES + 16)
    {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!(network = %current_network_id, %error, "roster metadata directory unreadable; using empty projection");
            return roster;
        }
    };
    let mut loaded_bytes = 0usize;
    let mut scanned_entries = 0usize;
    for file_name in entries {
        scanned_entries += 1;
        if scanned_entries > ROSTER_MAX_ENTRIES {
            tracing::warn!(network = %current_network_id, "roster entry limit exceeded; using empty projection");
            return empty_for_at(root, &current_network_id);
        }
        if file_name == ".txn" || !file_name.ends_with(".json") || file_name.len() <= ".json".len()
        {
            continue;
        }
        let file_key = file_name.trim_end_matches(".json");
        if validate_device_key(file_key).is_err() {
            let _ = directory.quarantine(&file_name);
            continue;
        }
        let raw = match directory.read_file(&file_name, ROSTER_MAX_RECORD_BYTES) {
            Ok(raw) => raw,
            Err(error) => {
                tracing::warn!(file = %file_name, %error, "roster metadata unreadable; quarantining");
                let _ = directory.quarantine(&file_name);
                continue;
            }
        };
        loaded_bytes = match loaded_bytes.checked_add(raw.len()) {
            Some(bytes) if bytes <= ROSTER_MAX_LOAD_BYTES => bytes,
            _ => {
                tracing::warn!(network = %current_network_id, "roster load byte limit exceeded; using empty projection");
                return empty_for_at(root, &current_network_id);
            }
        };
        let record: RosterEntryRecord = match serde_json::from_slice(&raw) {
            Ok(record) => record,
            Err(error) => {
                tracing::warn!(file = %file_name, %error, "roster metadata corrupt; quarantining");
                let _ = directory.quarantine(&file_name);
                continue;
            }
        };
        if record.version != ROSTER_VERSION
            || record.network_id != current_network_id
            || record.device_id != file_key
            || entry_file_name(&record.device_id)
                .map(|expected| expected != file_name)
                .unwrap_or(true)
        {
            tracing::warn!(file = %file_name, "roster metadata identity/version mismatch; quarantining");
            let _ = directory.quarantine(&file_name);
            continue;
        }
        roster.authorized_devices.push_keyed(AuthorizedPeer {
            device_id: record.device_id,
            label: record.label,
            approved_at: record.approved_at,
            role: crate::semantic::Role::Member,
        });
    }
    roster
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RosterEntryRecord {
    version: u32,
    network_id: String,
    device_id: String,
    label: String,
    approved_at: u64,
}

const ROSTER_TRANSACTION_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
enum RosterTransactionState {
    Prepared,
    Committed,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RosterTransactionOperation {
    device_id: String,
    existed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RosterTransaction {
    version: u32,
    network_id: String,
    state: RosterTransactionState,
    operations: Vec<RosterTransactionOperation>,
}

struct PreparedRosterOperation {
    device_id: String,
    target_name: String,
    previous: Option<Vec<u8>>,
    desired: Option<Vec<u8>>,
    backup_name: String,
    stage_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostCommitDurability {
    Proven,
    Unproved,
}

fn observe_post_commit_sync<F>(label: &str, sync: F) -> PostCommitDurability
where
    F: FnOnce() -> std::io::Result<()>,
{
    match sync() {
        Ok(()) => PostCommitDurability::Proven,
        Err(error) => {
            tracing::warn!(%error, "{label} durability is unproved after atomic publication");
            PostCommitDurability::Unproved
        }
    }
}

fn write_roster_transaction_manifest(
    transaction_directory: &DirectoryCapability,
    transaction: &RosterTransaction,
    replace: bool,
) -> Result<()> {
    if transaction.operations.len() > ROSTER_MAX_TRANSACTION_OPERATIONS {
        return Err(Error::Roster(
            "roster transaction operation limit exceeded".into(),
        ));
    }
    let bytes = serde_json::to_vec(transaction)?;
    if bytes.len() > ROSTER_MAX_TRANSACTION_BYTES {
        return Err(Error::Roster(
            "roster transaction manifest exceeds byte limit".into(),
        ));
    }
    if replace {
        replace_roster_file(
            transaction_directory,
            "manifest.json",
            &bytes,
            transaction_directory,
        )
    } else {
        write_roster_new(transaction_directory, "manifest.json", &bytes)
    }
}

fn cleanup_roster_transaction(directory: &DirectoryCapability) -> Result<()> {
    directory
        .remove_tree(".txn")
        .map_err(|error| roster_io(error, "remove roster transaction capability"))
}

fn restore_roster_transaction(
    directory: &DirectoryCapability,
    transaction_directory: &DirectoryCapability,
    network_id: &str,
    transaction: &RosterTransaction,
) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for (index, operation) in transaction.operations.iter().enumerate() {
        if !seen.insert(operation.device_id.clone()) {
            return Err(Error::Roster(format!(
                "duplicate roster transaction key: {}",
                operation.device_id
            )));
        }
        let target = entry_file_name(&operation.device_id)?;
        let backup = format!("backup-{index}.bin");
        if operation.existed {
            if transaction_directory
                .read_file(&backup, ROSTER_MAX_RECORD_BYTES)
                .is_err()
            {
                return Err(Error::Roster(format!(
                    "missing roster transaction backup for {network_id}: {}",
                    operation.device_id
                )));
            }
            transaction_directory
                .rename_to(&backup, directory, &target)
                .map_err(|error| roster_io(error, "restore roster transaction backup"))?;
        } else {
            directory
                .remove_file(&target)
                .map_err(|error| roster_io(error, "remove new roster transaction target"))?;
        }
    }
    Ok(())
}

fn recover_roster_transaction(directory: &DirectoryCapability, network_id: &str) -> Result<()> {
    let transaction_directory = match directory.open_dir(".txn", false) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(roster_io(error, "open roster transaction capability")),
    };
    let raw = transaction_directory
        .read_file("manifest.json", ROSTER_MAX_TRANSACTION_BYTES)
        .map_err(|error| roster_io(error, "read roster transaction manifest"))?;
    let transaction: RosterTransaction = serde_json::from_slice(&raw)
        .map_err(|error| Error::Roster(format!("decode roster transaction manifest: {error}")))?;
    if transaction.operations.len() > ROSTER_MAX_TRANSACTION_OPERATIONS {
        return Err(Error::Roster(
            "roster transaction operation limit exceeded".into(),
        ));
    }
    if transaction.version != ROSTER_TRANSACTION_VERSION
        || transaction.network_id != canonical_network_id(network_id)?
    {
        return Err(Error::Roster(
            "roster transaction identity/version mismatch".into(),
        ));
    }
    match transaction.state {
        RosterTransactionState::Prepared => {
            restore_roster_transaction(
                directory,
                &transaction_directory,
                network_id,
                &transaction,
            )?;
        }
        RosterTransactionState::Committed => {}
    }
    cleanup_roster_transaction(directory)
}

fn rollback_prepared_roster_operations(
    directory: &DirectoryCapability,
    transaction_directory: &DirectoryCapability,
    operations: &[PreparedRosterOperation],
) -> Result<()> {
    let mut first_error = None;
    for operation in operations.iter().rev() {
        let result = if operation.previous.is_some() {
            transaction_directory.rename_to(
                &operation.backup_name,
                directory,
                &operation.target_name,
            )
        } else {
            directory.remove_file(&operation.target_name)
        };
        if let Err(error) = result {
            if first_error.is_none() {
                first_error = Some(roster_io(error, "rollback roster transaction"));
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn save_affected_with_publisher<F>(
    roster: &Roster,
    affected_keys: &std::collections::BTreeSet<String>,
    publish: F,
) -> Result<()>
where
    F: FnMut(&Path, Option<&[u8]>) -> Result<()>,
{
    save_affected_with_publisher_and_sync(
        roster,
        affected_keys,
        publish,
        |directory| directory.sync(),
        |store| store.sync(),
    )
}

fn save_affected_with_publisher_and_sync<F, D, S>(
    roster: &Roster,
    affected_keys: &std::collections::BTreeSet<String>,
    mut _publish: F,
    sync_directory: D,
    sync_store: S,
) -> Result<()>
where
    F: FnMut(&Path, Option<&[u8]>) -> Result<()>,
    D: FnOnce(&DirectoryCapability) -> std::io::Result<()>,
    S: FnOnce(&DirectoryCapability) -> std::io::Result<()>,
{
    let network_id = canonical_network_id(&roster.network_id)?;
    if affected_keys.len() > ROSTER_MAX_TRANSACTION_OPERATIONS {
        return Err(Error::Roster(
            "roster transaction operation limit exceeded".into(),
        ));
    }

    // Complete the pure portion of the admission check before opening a
    // create-capable directory. This makes count, key, label, and serialized
    // byte refusals side-effect free even when the projection root is absent.
    let mut desired_by_key = std::collections::BTreeMap::new();
    let mut desired_bytes = 0usize;
    for key in affected_keys {
        let _target_name = entry_file_name(key)?;
        if let Some(peer) = roster.authorized_devices.get_by_key(key) {
            if peer.label.len() > ROSTER_MAX_LABEL_BYTES {
                return Err(Error::Roster("roster label exceeds byte limit".into()));
            }
        }
        let desired = roster
            .authorized_devices
            .get_by_key(key)
            .map(|peer| {
                serde_json::to_vec(&RosterEntryRecord {
                    version: ROSTER_VERSION,
                    network_id: network_id.clone(),
                    device_id: peer.device_id.clone(),
                    label: peer.label.clone(),
                    approved_at: peer.approved_at,
                })
            })
            .transpose()?;
        if let Some(bytes) = &desired {
            if bytes.len() > ROSTER_MAX_RECORD_BYTES {
                return Err(Error::Roster("roster record exceeds byte limit".into()));
            }
            desired_bytes = desired_bytes
                .checked_add(bytes.len())
                .ok_or_else(|| Error::Roster("roster serialized byte count overflow".into()))?;
        }
        desired_by_key.insert(key.clone(), desired);
    }
    if desired_bytes > ROSTER_MAX_TRANSACTION_BYTES {
        return Err(Error::Roster(
            "roster transaction byte limit exceeded".into(),
        ));
    }

    let store = roster_store(roster.persistence_root.as_deref(), true)?;
    let directory = store
        .open_dir(&network_id, true)
        .map_err(|error| roster_io(error, "open keyed roster capability"))?;
    recover_roster_transaction(&directory, &network_id)?;

    // Validate every key and serialize every desired row before any writer,
    // directory creation, or replacement can occur.
    let mut operations = Vec::with_capacity(affected_keys.len());
    let mut transaction_bytes = 0usize;
    for key in affected_keys {
        let target_name = entry_file_name(key)?;
        let previous = match directory.read_file(&target_name, ROSTER_MAX_RECORD_BYTES) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(roster_io(error, "read previous roster entry")),
        };
        let desired = desired_by_key
            .get(key)
            .cloned()
            .expect("desired roster row was preflighted for every affected key");
        transaction_bytes = transaction_bytes
            .checked_add(previous.as_ref().map_or(0, Vec::len))
            .and_then(|bytes| bytes.checked_add(desired.as_ref().map_or(0, Vec::len)))
            .ok_or_else(|| Error::Roster("roster transaction byte count overflow".into()))?;
        if transaction_bytes > ROSTER_MAX_TRANSACTION_BYTES {
            return Err(Error::Roster(
                "roster transaction byte limit exceeded".into(),
            ));
        }
        if previous.as_deref() != desired.as_deref() {
            operations.push(PreparedRosterOperation {
                device_id: key.clone(),
                target_name,
                previous,
                desired,
                backup_name: format!("backup-{}.bin", operations.len()),
                stage_name: format!("stage-{}.bin", operations.len()),
            });
        }
    }
    if operations.is_empty() {
        return Ok(());
    }

    if directory.open_dir(".txn", false).is_ok() {
        return Err(Error::Roster("roster transaction directory remains".into()));
    }
    let transaction_directory = directory
        .open_dir(".txn", true)
        .map_err(|error| roster_io(error, "create roster transaction capability"))?;

    let transaction = RosterTransaction {
        version: ROSTER_TRANSACTION_VERSION,
        network_id: network_id.clone(),
        state: RosterTransactionState::Prepared,
        operations: operations
            .iter()
            .map(|operation| RosterTransactionOperation {
                device_id: operation.device_id.clone(),
                existed: operation.previous.is_some(),
            })
            .collect(),
    };
    let stage_result = (|| -> Result<()> {
        for (index, operation) in operations.iter().enumerate() {
            if let Some(previous) = &operation.previous {
                debug_assert_eq!(operation.backup_name, format!("backup-{index}.bin"));
                write_roster_new(&transaction_directory, &operation.backup_name, previous)?;
            }
            if let Some(desired) = &operation.desired {
                debug_assert_eq!(operation.stage_name, format!("stage-{index}.bin"));
                write_roster_new(&transaction_directory, &operation.stage_name, desired)?;
            }
        }
        write_roster_transaction_manifest(&transaction_directory, &transaction, false)
    })();
    if let Err(error) = stage_result {
        let _ = cleanup_roster_transaction(&directory);
        return Err(error);
    }

    for operation in &operations {
        let result = _publish(
            Path::new(&operation.target_name),
            operation.desired.as_deref(),
        )
        .and_then(|()| {
            let publish = if operation.desired.is_some() {
                transaction_directory.rename_to(
                    &operation.stage_name,
                    &directory,
                    &operation.target_name,
                )
            } else {
                directory.remove_file(&operation.target_name)
            };
            publish.map_err(|error| roster_io(error, "publish roster capability file"))
        });
        if let Err(error) = result {
            let rollback = rollback_prepared_roster_operations(
                &directory,
                &transaction_directory,
                &operations,
            );
            if rollback.is_ok() {
                let _ = cleanup_roster_transaction(&directory);
            }
            return match rollback {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(Error::Roster(format!(
                    "roster batch failed: {error}; rollback failed: {rollback_error}"
                ))),
            };
        }
    }
    let committed = RosterTransaction {
        state: RosterTransactionState::Committed,
        ..transaction
    };
    if let Err(error) = write_roster_transaction_manifest(&transaction_directory, &committed, true)
    {
        let rollback =
            rollback_prepared_roster_operations(&directory, &transaction_directory, &operations);
        if rollback.is_ok() {
            let _ = cleanup_roster_transaction(&directory);
        }
        return match rollback {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(Error::Roster(format!(
                "roster commit marker failed: {error}; rollback failed: {rollback_error}"
            ))),
        };
    }
    // The committed manifest is the atomic publication fence. Directory
    // durability cannot be proven on Windows, where these callbacks return
    // Unsupported; neither that outcome nor a post-publication sync failure
    // may make the caller roll back already-published live state.
    let _directory_durability =
        observe_post_commit_sync("roster directory", || sync_directory(&directory));
    let _store_durability = observe_post_commit_sync("roster store", || sync_store(&store));
    if let Err(error) = cleanup_roster_transaction(&directory) {
        tracing::warn!(%error, "roster batch committed; transaction cleanup deferred to recovery");
    }
    Ok(())
}

/// Persist only the supplied canonical keys. Each file contains cosmetic
/// metadata; projected role is intentionally excluded and must be rebuilt
/// from the semantic graph.
pub fn save_affected(
    roster: &Roster,
    affected_keys: &std::collections::BTreeSet<String>,
) -> Result<()> {
    save_affected_with_publisher(roster, affected_keys, |_path, _desired| Ok(()))
}

/// Explicit full reconciliation for standalone callers. Production semantic
/// delta callers should pass their affected key set to `save_affected`.
pub fn save(roster: &Roster) -> Result<()> {
    let keys = roster
        .authorized_devices
        .iter()
        .map(|peer| peer.device_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    save_affected(roster, &keys)
}

/// Remove keyed advisory metadata for `network_id`. Used by the "Forget
/// Network" UX so a removed network doesn't leave its projection metadata
/// lingering on disk. Idempotent: missing files are fine.
pub fn delete(network_id: &str) -> Result<()> {
    let network_id = canonical_network_id(network_id)?;
    let store_path = crate::dirs::data_dir()?;
    let store = match open_roster_store(&store_path, true, false) {
        Ok(store) => store,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(roster_io(error, "open roster store capability")),
    };
    store
        .remove_tree(&network_id)
        .map_err(|error| roster_io(error, "remove keyed roster capability"))?;
    store
        .remove_file(&network_file_name(&network_id)?)
        .map_err(|error| roster_io(error, "remove retired roster capability"))?;
    store
        .sync()
        .map_err(|error| roster_io(error, "sync roster store directory"))?;
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
        assert_eq!(r.authorized_devices[0].role, crate::semantic::Role::Member);
    }

    #[test]
    fn projected_role_batch_rebuilds_the_key_index_once() {
        let mut roster = empty_for("net-batch");
        AuthorizedDevices::reset_test_counters();
        let desired = (0..64)
            .map(|index| {
                (
                    format!("peer-{index:03}"),
                    Some(crate::semantic::Role::Member),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert!(apply_projected_roles_in(&mut roster, &desired));
        assert_eq!(roster.authorized_devices.len(), desired.len());
        assert_eq!(AuthorizedDevices::test_counters(), (0, 1));

        AuthorizedDevices::reset_test_counters();
        let role_updates = desired
            .keys()
            .cloned()
            .map(|key| (key, Some(crate::semantic::Role::Controller)))
            .collect::<BTreeMap<_, _>>();
        assert!(apply_projected_roles_in(&mut roster, &role_updates));
        assert_eq!(AuthorizedDevices::test_counters(), (0, 0));
        assert!(roster
            .authorized_devices
            .iter()
            .all(|peer| peer.role == crate::semantic::Role::Controller));

        AuthorizedDevices::reset_test_counters();
        let structural = BTreeMap::from([
            ("peer-000".to_string(), None),
            ("peer-new".to_string(), Some(crate::semantic::Role::Owner)),
        ]);
        assert!(apply_projected_roles_in(&mut roster, &structural));
        assert_eq!(AuthorizedDevices::test_counters(), (0, 1));
        assert!(!is_authorized(&roster, "peer-000"));
        assert!(is_authorized(&roster, "peer-new"));
        assert_eq!(
            roster
                .authorized_devices
                .get_by_key("peer-new")
                .map(|peer| peer.role),
            Some(crate::semantic::Role::Owner)
        );
    }

    #[test]
    fn old_hard_alpha_roster_without_role_is_refused() {
        let old_json = r#"{
            "version": 1,
            "network_id": "net-a",
            "authorized_devices": [
                { "device_id": "peer1", "label": "Old laptop", "approved_at": 1700000000 }
            ]
        }"#;
        assert!(serde_json::from_str::<Roster>(old_json).is_err());
    }

    #[test]
    fn set_role_changes_existing_entry() {
        let mut r = empty_for("net-a");
        add_peer_in(&mut r, "peer1", "Laptop");
        assert!(set_role_in(
            &mut r,
            "peer1",
            crate::semantic::Role::Controller
        ));
        assert_eq!(
            r.authorized_devices[0].role,
            crate::semantic::Role::Controller
        );
        // Idempotent — same role is a no-op.
        assert!(!set_role_in(
            &mut r,
            "peer1",
            crate::semantic::Role::Controller
        ));
    }

    #[test]
    fn set_role_is_noop_on_missing_peer() {
        let mut r = empty_for("net-a");
        assert!(!set_role_in(&mut r, "ghost", crate::semantic::Role::Owner));
        assert!(r.authorized_devices.is_empty());
    }

    #[test]
    fn persisted_metadata_comparison_ignores_role_but_detects_row_changes() {
        let mut before = empty_for("net-a");
        add_peer_in(&mut before, "peer1", "Laptop");
        let keys = ["peer1".to_string()].into_iter().collect();

        let mut role_only = before.clone();
        assert!(set_role_in(
            &mut role_only,
            "peer1",
            crate::semantic::Role::Controller
        ));
        assert!(persisted_metadata_equal(&before, &role_only, &keys));

        let mut metadata = role_only.clone();
        add_peer_in(&mut metadata, "peer1", "Laptop-renamed");
        assert!(!persisted_metadata_equal(&before, &metadata, &keys));

        let mut membership = role_only;
        remove_peer_in(&mut membership, "peer1");
        assert!(!persisted_metadata_equal(&before, &membership, &keys));
    }

    #[test]
    fn add_peer_preserves_existing_role() {
        let mut r = empty_for("net-a");
        add_peer_in(&mut r, "peer1", "Laptop");
        set_role_in(&mut r, "peer1", crate::semantic::Role::Owner);
        // Re-add with a new label — role stays.
        add_peer_in(&mut r, "peer1", "Laptop-renamed");
        assert_eq!(r.authorized_devices[0].label, "Laptop-renamed");
        assert_eq!(r.authorized_devices[0].role, crate::semantic::Role::Owner);
    }

    #[test]
    fn keyed_save_omits_role_and_preserves_unrelated_rows() {
        let root = tempfile::tempdir().expect("roster metadata root");
        let mut roster = empty_for_at(Some(root.path()), "net-keyed");
        add_peer_in(&mut roster, "peer1", "Laptop");
        add_peer_in(&mut roster, "peer2", "Phone");
        set_role_in(&mut roster, "peer1", crate::semantic::Role::Owner);
        let keys = ["peer1".to_string(), "peer2".to_string()]
            .into_iter()
            .collect();
        save_affected(&roster, &keys).expect("initial keyed save");

        let peer2_path = root
            .path()
            .join("rosters")
            .join("net-keyed")
            .join("peer2.json");
        let peer2_before = std::fs::read(&peer2_path).expect("unrelated row");
        assert!(!std::fs::read_to_string(
            root.path()
                .join("rosters")
                .join("net-keyed")
                .join("peer1.json")
        )
        .expect("peer1 row")
        .contains("role"));

        add_peer_in(&mut roster, "peer1", "Laptop-renamed");
        let changed = ["peer1".to_string()].into_iter().collect();
        save_affected(&roster, &changed).expect("single keyed update");
        assert_eq!(
            std::fs::read(&peer2_path).expect("unrelated row remains"),
            peer2_before
        );

        remove_peer_in(&mut roster, "peer1");
        save_affected(&roster, &changed).expect("single keyed delete");
        assert!(!root
            .path()
            .join("rosters")
            .join("net-keyed")
            .join("peer1.json")
            .exists());
        assert_eq!(
            load_advisory_at(Some(root.path()), "net-keyed")
                .authorized_devices
                .len(),
            1
        );
    }

    #[test]
    fn load_orders_reordered_directory_entries_by_device_id() {
        let root = tempfile::tempdir().expect("roster metadata root");
        let directory = root.path().join("rosters").join("net-order");
        std::fs::create_dir_all(&directory).expect("keyed roster directory");
        for (device_id, label) in [("peer-z", "Z"), ("peer-a", "A")] {
            let record = RosterEntryRecord {
                version: ROSTER_VERSION,
                network_id: "net-order".to_string(),
                device_id: device_id.to_string(),
                label: label.to_string(),
                approved_at: 7,
            };
            std::fs::write(
                directory.join(format!("{device_id}.json")),
                serde_json::to_vec(&record).expect("entry serializes"),
            )
            .expect("entry writes");
        }
        let loaded = load_advisory_at(Some(root.path()), "net-order");
        let ids = loaded
            .authorized_devices
            .iter()
            .map(|peer| peer.device_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["peer-a", "peer-z"]);
    }

    #[test]
    fn affected_batch_failure_rolls_back_every_published_key() {
        let root = tempfile::tempdir().expect("roster metadata root");
        let mut base = empty_for_at(Some(root.path()), "net-batch");
        add_peer_in(&mut base, "peer-a", "A");
        add_peer_in(&mut base, "peer-b", "B");
        add_peer_in(&mut base, "peer-c", "C");
        let all = ["peer-a", "peer-b", "peer-c"]
            .into_iter()
            .map(str::to_string)
            .collect();
        save_affected(&base, &all).expect("initial batch");
        let directory = root.path().join("rosters").join("net-batch");
        let before_a = std::fs::read(directory.join("peer-a.json")).expect("a before");
        let before_b = std::fs::read(directory.join("peer-b.json")).expect("b before");
        let before_c = std::fs::read(directory.join("peer-c.json")).expect("c before");

        let mut candidate = base.clone();
        add_peer_in(&mut candidate, "peer-a", "A2");
        add_peer_in(&mut candidate, "peer-b", "B2");
        let affected = ["peer-a", "peer-b"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let mut publishes = 0;
        let error = save_affected_with_publisher(&candidate, &affected, |path, desired| {
            let _ = (path, desired);
            publishes += 1;
            if publishes == 2 {
                return Err(Error::Roster("injected mid-batch refusal".into()));
            }
            Ok(())
        })
        .expect_err("mid-batch failure must refuse");
        assert!(matches!(error, Error::Roster(_)));
        assert_eq!(
            std::fs::read(directory.join("peer-a.json")).unwrap(),
            before_a
        );
        assert_eq!(
            std::fs::read(directory.join("peer-b.json")).unwrap(),
            before_b
        );
        assert_eq!(
            std::fs::read(directory.join("peer-c.json")).unwrap(),
            before_c
        );
        assert!(!directory.join(".txn").exists());
    }

    #[test]
    fn committed_publication_reopens_when_directory_sync_is_unsupported() {
        let root = tempfile::tempdir().expect("roster metadata root");
        let mut roster = empty_for_at(Some(root.path()), "net-windows-sync");
        add_peer_in(&mut roster, "peer-a", "A");
        let affected = ["peer-a".to_string()].into_iter().collect();

        save_affected_with_publisher_and_sync(
            &roster,
            &affected,
            |_path, _desired| Ok(()),
            |_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "Windows directory durability sync is unsupported",
                ))
            },
            |_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "Windows directory durability sync is unsupported",
                ))
            },
        )
        .expect("post-commit durability-unproved outcome must not roll back");

        let loaded = load_advisory_at(Some(root.path()), "net-windows-sync");
        assert_eq!(loaded.authorized_devices.len(), 1);
        assert_eq!(loaded.authorized_devices[0].device_id, "peer-a");
        assert_eq!(loaded.authorized_devices[0].label, "A");
        assert!(!root
            .path()
            .join("rosters")
            .join("net-windows-sync")
            .join(".txn")
            .exists());
    }

    #[test]
    fn prepared_batch_recovers_to_the_previous_complete_projection() {
        let root = tempfile::tempdir().expect("roster metadata root");
        let mut roster = empty_for_at(Some(root.path()), "net-recovery");
        add_peer_in(&mut roster, "peer-a", "old");
        let key = ["peer-a".to_string()].into_iter().collect();
        save_affected(&roster, &key).expect("initial row");
        let directory = root.path().join("rosters").join("net-recovery");
        let target = directory.join("peer-a.json");
        let old = std::fs::read(&target).expect("old row");
        let mut changed = roster.clone();
        add_peer_in(&mut changed, "peer-a", "new");
        let desired = serde_json::to_vec(&RosterEntryRecord {
            version: ROSTER_VERSION,
            network_id: "net-recovery".to_string(),
            device_id: "peer-a".to_string(),
            label: "new".to_string(),
            approved_at: changed.authorized_devices[0].approved_at,
        })
        .expect("new row");
        let directory_cap = DirectoryCapability::open_selected_root(root.path(), false)
            .expect("selected root")
            .open_dir("rosters", false)
            .expect("rosters")
            .open_dir("net-recovery", false)
            .expect("directory");
        let transaction_cap = directory_cap
            .open_dir(".txn", true)
            .expect("transaction directory");
        write_roster_new(&transaction_cap, "backup-0.bin", &old).expect("backup");
        replace_roster_file(&directory_cap, "peer-a.json", &desired, &directory_cap)
            .expect("partial publish");
        write_roster_transaction_manifest(
            &transaction_cap,
            &RosterTransaction {
                version: ROSTER_TRANSACTION_VERSION,
                network_id: "net-recovery".to_string(),
                state: RosterTransactionState::Prepared,
                operations: vec![RosterTransactionOperation {
                    device_id: "peer-a".to_string(),
                    existed: true,
                }],
            },
            false,
        )
        .expect("manifest");
        drop(transaction_cap);
        drop(directory_cap);

        let loaded = load_advisory_at(Some(root.path()), "net-recovery");
        assert_eq!(loaded.authorized_devices[0].label, "old");
        assert_eq!(std::fs::read(&target).expect("recovered row"), old);
        assert!(!directory.join(".txn").exists());
    }

    #[cfg(unix)]
    #[test]
    fn selected_root_alias_preserves_keyed_roster_and_default_layout() {
        use std::os::unix::fs::symlink;

        let sandbox = tempfile::tempdir().expect("roster selection sandbox");
        let parent = sandbox.path().join("physical");
        let alias = sandbox.path().join("alias");
        std::fs::create_dir(&parent).unwrap();
        symlink(&parent, &alias).unwrap();
        let selected = alias.join("instance");
        let mut roster = empty_for_at(Some(&selected), "net-selected");
        add_peer_in(&mut roster, "peer-a", "A");
        let keys = ["peer-a".to_string()].into_iter().collect();
        save_affected(&roster, &keys).expect("selected-root keyed save");
        let loaded = load_at(Some(&selected), "net-selected").expect("keyed reopen");
        assert_eq!(loaded.authorized_devices.len(), 1);
        assert!(parent
            .join("instance/rosters/net-selected/peer-a.json")
            .is_file());

        // Exercise the exact default-layout helper without changing the
        // process-global MYOWNMESH_HOME used by concurrent tests.
        let selected_default = alias.join("default-home");
        assert_eq!(
            open_roster_store(&selected_default, true, false)
                .err()
                .unwrap()
                .kind(),
            std::io::ErrorKind::NotFound
        );
        assert!(!parent.join("default-home").exists());
        let default_store = open_roster_store(&selected_default, true, true).unwrap();
        default_store
            .write_new("marker", b"default-layout", 0o600)
            .unwrap();
        assert_eq!(
            std::fs::read(parent.join("default-home/mesh/rosters/marker")).unwrap(),
            b"default-layout"
        );
        assert!(!parent.join("default-home/rosters").exists());
    }

    #[cfg(unix)]
    #[test]
    fn selected_root_never_resolves_managed_mesh_or_rosters_links() {
        use std::os::unix::fs::symlink;

        let sandbox = tempfile::tempdir().expect("roster selection sandbox");
        let selected = sandbox.path().join("state");
        let outside = sandbox.path().join("outside");
        std::fs::create_dir(&selected).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"unchanged").unwrap();

        let mesh = selected.join("mesh");
        symlink(&outside, &mesh).unwrap();
        for create in [false, true] {
            assert!(open_roster_store(&selected, true, create).is_err());
        }
        assert!(!outside.join("rosters").exists());
        std::fs::remove_file(&mesh).unwrap();
        std::fs::create_dir(&mesh).unwrap();
        symlink(&outside, mesh.join("rosters")).unwrap();
        for create in [false, true] {
            assert!(open_roster_store(&selected, true, create).is_err());
        }

        symlink(&outside, selected.join("rosters")).unwrap();
        let mut roster = empty_for_at(Some(&selected), "net-outside");
        add_peer_in(&mut roster, "peer-a", "A");
        let keys = ["peer-a".to_string()].into_iter().collect();
        assert!(save_affected(&roster, &keys).is_err());
        assert!(!outside.join("net-outside").exists());
        assert_eq!(
            std::fs::read(outside.join("sentinel")).unwrap(),
            b"unchanged"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_roster_components_refuse_without_external_mutation() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("roster metadata root");
        let outside = tempfile::tempdir().expect("outside target");
        let outside_file = outside.path().join("sentinel.json");
        std::fs::write(&outside_file, b"outside-before").expect("sentinel");
        let rosters = root.path().join("rosters");
        std::fs::create_dir_all(&rosters).expect("roster parent");

        let network_link = rosters.join("net-links");
        symlink(outside.path(), &network_link).expect("network symlink");
        let mut roster = empty_for_at(Some(root.path()), "net-links");
        add_peer_in(&mut roster, "peer-a", "A");
        let key = ["peer-a".to_string()].into_iter().collect();
        assert!(save_affected(&roster, &key).is_err());
        assert_eq!(std::fs::read(&outside_file).unwrap(), b"outside-before");
        std::fs::remove_file(&network_link).expect("remove network symlink");

        let network = rosters.join("net-links");
        std::fs::create_dir(&network).expect("network directory");
        let transaction_link = network.join(".txn");
        symlink(outside.path(), &transaction_link).expect("transaction symlink");
        assert!(save_affected(&roster, &key).is_err());
        assert_eq!(std::fs::read(&outside_file).unwrap(), b"outside-before");
        std::fs::remove_file(&transaction_link).expect("remove transaction symlink");

        let entry_link = network.join("peer-a.json");
        symlink(&outside_file, &entry_link).expect("entry symlink");
        assert!(save_affected(&roster, &key).is_err());
        assert_eq!(std::fs::read(&outside_file).unwrap(), b"outside-before");
    }

    #[cfg(unix)]
    #[test]
    fn retained_directory_capability_survives_parent_swap() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("roster capability root");
        let outside = tempfile::tempdir().expect("outside target");
        let sentinel = outside.path().join("sentinel.json");
        std::fs::write(&sentinel, b"outside-before").expect("sentinel");
        let network = root.path().join("rosters").join("net-swap");
        std::fs::create_dir_all(&network).expect("network directory");

        // The capability is the synchronization boundary. The path is
        // deliberately swapped only after both descriptors are acquired.
        let store =
            DirectoryCapability::open_selected_root(root.path(), false).expect("root handle");
        let store = store.open_dir("rosters", false).expect("rosters handle");
        let network_cap = store.open_dir("net-swap", false).expect("network handle");
        let moved = root.path().join("rosters").join("net-swap-old");
        std::fs::rename(&network, &moved).expect("swap original parent");
        symlink(outside.path(), &network).expect("install swapped parent link");

        write_roster_new(&network_cap, "peer-a.json", b"original-directory")
            .expect("descriptor-relative write");
        assert_eq!(
            std::fs::read(moved.join("peer-a.json")).expect("original directory write"),
            b"original-directory"
        );
        assert!(!outside.path().join("peer-a.json").exists());
        assert_eq!(
            std::fs::read(&sentinel).expect("outside sentinel"),
            b"outside-before"
        );

        network_cap
            .remove_file("peer-a.json")
            .expect("descriptor delete");
        assert!(!moved.join("peer-a.json").exists());
        assert_eq!(
            std::fs::read(&sentinel).expect("outside sentinel"),
            b"outside-before"
        );
    }

    #[cfg(windows)]
    #[test]
    fn retained_directory_capability_survives_windows_reparse_swap() {
        use std::os::windows::fs::symlink_dir;

        let root = tempfile::tempdir().expect("roster capability root");
        let outside = tempfile::tempdir().expect("outside target");
        let sentinel = outside.path().join("sentinel.json");
        std::fs::write(&sentinel, b"outside-before").expect("sentinel");
        let network = root.path().join("rosters").join("net-swap");
        std::fs::create_dir_all(&network).expect("network directory");

        let store =
            DirectoryCapability::open_selected_root(root.path(), false).expect("root handle");
        let store = store.open_dir("rosters", false).expect("rosters handle");
        let network_cap = store.open_dir("net-swap", false).expect("network handle");
        let moved = root.path().join("rosters").join("net-swap-old");
        std::fs::rename(&network, &moved).expect("swap original parent");

        // Developer mode or the test runner may deny symlink creation. In
        // that case retain the parent-swap half of the control with a fresh
        // directory; the capability must still remain bound to the moved
        // directory and never follow the replacement path.
        let replacement_is_reparse = symlink_dir(outside.path(), &network).is_ok();
        if !replacement_is_reparse {
            std::fs::create_dir(&network).expect("replacement directory");
        }

        write_roster_new(&network_cap, "peer-a.json", b"original-directory")
            .expect("descriptor-relative write");
        assert_eq!(
            std::fs::read(moved.join("peer-a.json")).expect("original directory write"),
            b"original-directory"
        );
        assert!(!outside.path().join("peer-a.json").exists());
        assert_eq!(
            std::fs::read(&sentinel).expect("outside sentinel"),
            b"outside-before"
        );

        network_cap
            .remove_file("peer-a.json")
            .expect("descriptor delete");
        assert!(!moved.join("peer-a.json").exists());
        assert_eq!(
            std::fs::read(&sentinel).expect("outside sentinel"),
            b"outside-before"
        );
    }

    #[test]
    fn metadata_limits_refuse_n_plus_one_before_filesystem_effects() {
        let root = tempfile::tempdir().expect("roster metadata root");
        let mut roster = empty_for_at(Some(root.path()), "net-limits");
        let too_many = (0..=ROSTER_MAX_ENTRIES)
            .map(|index| format!("peer-{index}"))
            .collect::<std::collections::BTreeSet<_>>();
        assert!(save_affected(&roster, &too_many).is_err());
        assert!(!root.path().join("rosters").exists());

        add_peer_in(
            &mut roster,
            "peer-a",
            &"x".repeat(ROSTER_MAX_LABEL_BYTES + 1),
        );
        let one = ["peer-a".to_string()].into_iter().collect();
        assert!(save_affected(&roster, &one).is_err());
        assert!(!root.path().join("rosters").exists());
    }

    #[test]
    fn network_id_and_authority_like_entry_fields_fail_before_path_use() {
        let root = tempfile::tempdir().expect("roster metadata root");
        assert!(load_at(Some(root.path()), "../escape").is_err());
        assert!(delete("../escape").is_err());
        let roster = empty_for_at(Some(root.path()), "../escape");
        let keys = ["peer-a".to_string()].into_iter().collect();
        assert!(save_affected(&roster, &keys).is_err());
        assert!(!root.path().join("escape").exists());

        let directory = root.path().join("rosters").join("net-fields");
        std::fs::create_dir_all(&directory).expect("keyed roster directory");
        std::fs::write(
            directory.join("peer-a.json"),
            br#"{"version":2,"network_id":"net-fields","device_id":"peer-a","label":"A","approved_at":7,"role":"Owner"}"#,
        )
        .expect("authority-like field");
        let loaded = load_advisory_at(Some(root.path()), "net-fields");
        assert!(loaded.authorized_devices.is_empty());
        assert!(directory.join("peer-a.json.corrupt").exists());
    }

    #[test]
    fn retired_whole_roster_document_is_quarantined_without_parsing() {
        let root = tempfile::tempdir().expect("roster metadata root");
        let legacy_dir = root.path().join("rosters");
        std::fs::create_dir_all(&legacy_dir).expect("legacy roster directory");
        let legacy = legacy_dir.join("net-legacy.json");
        std::fs::write(
            &legacy,
            r#"{"version":1,"network_id":"net-legacy","authorized_devices":[]}"#,
        )
        .expect("legacy roster document");

        let loaded = load_advisory_at(Some(root.path()), "net-legacy");
        assert!(loaded.authorized_devices.is_empty());
        assert!(!legacy.exists());
        assert!(legacy_dir.join("net-legacy.json.corrupt").exists());
    }
}
