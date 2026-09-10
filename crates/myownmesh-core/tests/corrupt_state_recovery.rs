//! Integration test: corrupt state files heal instead of bricking.
//!
//! A device that loses power mid-write must not be blocked by advisory roster
//! metadata. These tests pin the recovery
//! contract:
//!
//!  * corrupt or retired roster metadata → quarantined aside as
//!    `{name}.corrupt` (bytes preserved) and advisory load returns a fresh
//!    default, so canonical startup can proceed;
//!  * keyed saves go through atomic temp+rename per DeviceId, omit projected
//!    role authority, and leave no `.tmp` litter.
//!
//! Everything shares one process-wide `MYOWNMESH_HOME` (set once,
//! first thing) because the env var is process-global; the sub-cases
//! run sequentially inside one `#[test]` for the same reason.

use myownmesh_core::{config::MeshConfig, roster};

#[test]
fn corrupt_state_files_quarantine_and_heal() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("MYOWNMESH_HOME", tmp.path());

    corrupt_roster_heals();
    corrupt_config_heals();
    prepared_multi_key_roster_recovery();
    atomic_saves_round_trip();
}

/// The KVM incident, in miniature: a 0-byte roster file for a network
/// must not fail the load — it quarantines and yields a fresh roster.
fn corrupt_roster_heals() {
    let net = "fleet-brick-repro";
    let dir = myownmesh_core::dirs::rosters_dir().expect("rosters dir");
    std::fs::create_dir_all(&dir).expect("create rosters dir");
    let path = dir.join(format!("{net}.json"));
    std::fs::write(&path, b"").expect("plant truncated roster");

    let loaded = roster::load(net).expect("corrupt roster must not error");
    assert_eq!(loaded.network_id, net);
    assert!(loaded.authorized_devices.is_empty(), "fresh roster");
    assert!(!path.exists(), "corrupt file must be moved aside");
    let quarantined = dir.join(format!("{net}.json.corrupt"));
    assert!(quarantined.exists(), "corrupt bytes must be preserved");

    // And the *next* save/load cycle behaves like a healthy network.
    let mut fresh = roster::empty_for(net);
    roster::add_peer_in(&mut fresh, "peerpubkey", "Repro");
    roster::save(&fresh).expect("save after heal");
    let back = roster::load(net).expect("load after heal");
    assert_eq!(back.authorized_devices.len(), 1);
}

/// Same contract for config.json — a corrupt config used to stop the
/// daemon from starting at all. Defaults are fail-safe (no networks,
/// no services) and embedders rebuild the file over the control
/// socket once the daemon is up.
fn corrupt_config_heals() {
    let path = myownmesh_core::dirs::config_path().expect("config path");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create data dir");
    }
    std::fs::write(&path, b"").expect("plant truncated config");

    let cfg = MeshConfig::load().expect("corrupt config must not error");
    assert!(cfg.networks.is_empty(), "defaults are fail-safe");
    assert!(!path.exists(), "corrupt file must be moved aside");
    let quarantined = path.with_file_name("config.json.corrupt");
    assert!(quarantined.exists(), "corrupt bytes must be preserved");
}

/// A crash after a Prepared manifest but during publication must restore every
/// affected key, not only the first row that happened to be published.
fn prepared_multi_key_roster_recovery() {
    let net = "prepared-multi-key-recovery";
    let dir = myownmesh_core::dirs::rosters_dir()
        .expect("rosters dir")
        .join(net);
    let txn = dir.join(".txn");
    std::fs::create_dir_all(&txn).expect("transaction directory");

    let old_a = br#"{"version":2,"network_id":"prepared-multi-key-recovery","device_id":"peer-a","label":"old-a","approved_at":7}"#;
    let desired_a = br#"{"version":2,"network_id":"prepared-multi-key-recovery","device_id":"peer-a","label":"new-a","approved_at":7}"#;
    let desired_b = br#"{"version":2,"network_id":"prepared-multi-key-recovery","device_id":"peer-b","label":"new-b","approved_at":8}"#;
    std::fs::write(dir.join("peer-a.json"), desired_a).expect("partial a publish");
    std::fs::write(dir.join("peer-b.json"), desired_b).expect("partial b publish");
    std::fs::write(dir.join("peer-c.json"), br#"{"version":2,"network_id":"prepared-multi-key-recovery","device_id":"peer-c","label":"unrelated","approved_at":9}"#)
        .expect("unrelated row");
    std::fs::write(txn.join("backup-0.bin"), old_a).expect("a backup");
    let manifest = br#"{"version":1,"network_id":"prepared-multi-key-recovery","state":"Prepared","operations":[{"device_id":"peer-a","existed":true},{"device_id":"peer-b","existed":false}]}"#;
    std::fs::write(txn.join("manifest.json"), manifest).expect("prepared manifest");

    let loaded = roster::load(net).expect("prepared roster recovers");
    let ids = loaded
        .authorized_devices
        .iter()
        .map(|peer| peer.device_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids, ["peer-a", "peer-c"]);
    assert_eq!(loaded.authorized_devices[0].label, "old-a");
    assert_eq!(
        std::fs::read(dir.join("peer-a.json")).expect("restored a"),
        old_a
    );
    assert!(!dir.join("peer-b.json").exists(), "new b is rolled back");
    assert!(dir.join("peer-c.json").exists(), "unrelated row remains");
    assert!(!txn.exists(), "prepared transaction is cleaned");
}

/// The prevention half: saves are atomic (temp + rename), so a
/// completed save reads back exactly and leaves no `.tmp` behind.
fn atomic_saves_round_trip() {
    let net = "atomic-save";
    let mut r = roster::empty_for(net);
    roster::add_peer_in(&mut r, "peerpubkey", "Laptop");
    roster::save(&r).expect("first save");
    roster::add_peer_in(&mut r, "otherpeer", "Phone");
    roster::save(&r).expect("overwrite save");

    let back = roster::load(net).expect("load");
    assert_eq!(back.authorized_devices.len(), 2);

    let dir = myownmesh_core::dirs::rosters_dir().expect("rosters dir");
    let first_entry = dir.join(net).join("peerpubkey.json");
    let first_raw = std::fs::read_to_string(&first_entry).expect("first keyed entry");
    assert!(first_raw.contains("\"label\":\"Laptop\""));
    assert!(
        !first_raw.contains("role"),
        "role is never persisted as authority"
    );
    assert!(
        !dir.join(format!("{net}.json.tmp")).exists(),
        "no temp litter after a successful save"
    );

    let cfg = MeshConfig::default();
    cfg.save().expect("config save");
    let path = myownmesh_core::dirs::config_path().expect("config path");
    assert!(path.exists());
    assert!(!path.with_file_name("config.json.tmp").exists());
}
