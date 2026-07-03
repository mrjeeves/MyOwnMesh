//! Integration test: corrupt state files heal instead of bricking.
//!
//! A device that loses power mid-write (or has its daemon killed at
//! the wrong moment) used to be left with a truncated state file —
//! and a file that *exists but doesn't parse* failed every subsequent
//! load, hard. For the roster that meant every join of that network
//! failed forever: a real KVM was found stranded off its own fleet by
//! an empty `rosters/{fleet}.json`. These tests pin the recovery
//! contract:
//!
//!  * corrupt roster / network_state / config → quarantined aside as
//!    `{name}.corrupt` (bytes preserved) and the load returns a fresh
//!    default, so the daemon comes up and the state re-converges;
//!  * saves go through the atomic temp+rename path — a completed save
//!    is readable back and leaves no `.tmp` litter.
//!
//! Everything shares one process-wide `MYOWNMESH_HOME` (set once,
//! first thing) because the env var is process-global; the sub-cases
//! run sequentially inside one `#[test]` for the same reason.

use myownmesh_core::{config::MeshConfig, network_state, roster};

#[test]
fn corrupt_state_files_quarantine_and_heal() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("MYOWNMESH_HOME", tmp.path());

    corrupt_roster_heals();
    corrupt_network_state_heals();
    corrupt_config_heals();
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

/// Same contract for the signed-governance state file.
fn corrupt_network_state_heals() {
    let net = "gov-brick-repro";
    let dir = myownmesh_core::dirs::states_dir().expect("states dir");
    std::fs::create_dir_all(&dir).expect("create states dir");
    let path = dir.join(format!("{net}.json"));
    std::fs::write(&path, b"{\"version\": 2, \"netwo").expect("plant half-written state");

    let loaded = network_state::load(net).expect("corrupt state must not error");
    assert_eq!(loaded.network_id, net);
    assert!(!path.exists(), "corrupt file must be moved aside");
    assert!(dir.join(format!("{net}.json.corrupt")).exists());
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
