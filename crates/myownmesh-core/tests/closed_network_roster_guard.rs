//! Regression test for **MOM-01**: closed-network roster membership may
//! only be expanded by an authority (Controller/Owner).
//!
//! Before the fix, `governance::on_roster_entries` added any device id a
//! peer gossiped to the local roster regardless of the network kind or the
//! sender's authority. Because a rostered peer is auto-approved on every
//! future connection (`auto = cfg.auto_approve || rostered`), an attacker
//! who cleared a single approval — or any plain Member — could conscript
//! arbitrary identities into a *closed* network and have them auto-approved
//! network-wide.
//!
//! The fix gates membership *introductions* on a closed network behind
//! `Role::can_grant(Role::Member)` (true only for Controller/Owner). Open
//! networks stay permissionless by design (a member is anyone any current
//! member has vouched for).
//!
//! The test drives `on_roster_entries` directly against a closed-network
//! state set up in-process — no transport/handshake timing — so the
//! authority gate is exercised deterministically.
//!
//! Companion to `roster_gossip.rs` (open-network convergence) and
//! `closed_network_governance.rs` (signed transitions).

use std::sync::Arc;

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::state::NetworkState;
use myownmesh_core::engine::{governance, spawn_network};
use myownmesh_core::identity::Identity;
use myownmesh_core::protocol::governance::{RosterEntriesMessage, RosterEntry};
use myownmesh_core::transport::Transport;
use myownmesh_core::{NetworkKind, Role};

fn fresh_network(id: &str, network_id: &str) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: network_id.to_string(),
        label: id.to_string(),
        kind: Default::default(),
        topology: TopologyMode::FullMesh,
        signaling: SignalingConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        roster_path: None,
        auto_approve: false,
    }
}

fn rostered(state: &Arc<NetworkState>, id: &str) -> bool {
    myownmesh_core::roster::is_authorized(&state.roster.read(), id)
}

/// One gossiped roster entry introducing `id` as a plain member.
fn vouch(id: &str, label: &str) -> RosterEntriesMessage {
    RosterEntriesMessage {
        entries: vec![RosterEntry {
            device_id: id.to_string(),
            label: label.to_string(),
            approved_at: 0,
            role: Role::Member,
            // Unsigned, attacker-controllable in the wild — the guard keys
            // off the cryptographically-authenticated *sender's* role, not
            // this field, so its value is irrelevant to the decision.
            granted_by: String::new(),
        }],
        // No governance log on this gossip — exercises the membership-only path
        // (and the `#[serde(default)]` skew an older peer's reply would take).
        transitions: Vec::new(),
    }
}

// Both scenarios share one process (and so one `MYOWNMESH_HOME`); distinct
// network ids keep their roster files apart. Running them in one test avoids
// the env-var race two parallel `#[tokio::test]`s in a file would hit.
#[tokio::test]
async fn roster_membership_authority_gate() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("MYOWNMESH_HOME", tmp.path());
    let transport = Transport::new().expect("transport");

    // Identities used across both scenarios.
    let bob = Arc::new(Identity::ephemeral()); // a plain Member
    let carol = Arc::new(Identity::ephemeral()); // a Controller
    let mallory = Arc::new(Identity::ephemeral()); // attacker-introduced id
    let dave = Arc::new(Identity::ephemeral()); // legitimately vouched by Carol
    let eve = Arc::new(Identity::ephemeral()); // vouched on the open network

    // ---- Scenario 1: CLOSED network — only authorities may admit --------
    let alice_id = Arc::new(Identity::ephemeral());
    let (alice, _alice_driver) = spawn_network(
        fresh_network("alice", "closed-roster-guard"),
        alice_id.clone(),
        transport.clone(),
    )
    .await
    .expect("spawn alice (closed)");

    // Stand the network up as `closed` with Bob=Member, Carol=Controller.
    // (In production this state is reached via the signed open→closed
    // transition + role grants; here we set it directly to isolate the
    // gate under test.)
    {
        let mut gov = alice.governance_state.write();
        gov.kind = NetworkKind::Closed;
        gov.roles.insert(bob.public_id().to_string(), Role::Member);
        gov.roles
            .insert(carol.public_id().to_string(), Role::Controller);
    }
    alice
        .approve_roster(bob.public_id(), "bob")
        .await
        .expect("seed bob");
    alice
        .approve_roster(carol.public_id(), "carol")
        .await
        .expect("seed carol");

    // (a) A MEMBER (Bob) gossips a brand-new id → MUST be refused.
    governance::on_roster_entries(
        &alice,
        bob.public_id(),
        vouch(mallory.public_id(), "mallory"),
    )
    .await;
    assert!(
        !rostered(&alice, mallory.public_id()),
        "MOM-01: a Member's gossip conscripted a new member into a closed network"
    );

    // (b) An UNKNOWN sender (role defaults to Member) gossips → MUST be refused.
    governance::on_roster_entries(
        &alice,
        mallory.public_id(),
        vouch(mallory.public_id(), "mallory"),
    )
    .await;
    assert!(
        !rostered(&alice, mallory.public_id()),
        "MOM-01: an unrostered stranger's gossip added a member to a closed network"
    );

    // (c) A CONTROLLER (Carol) gossips a new member → MUST be accepted, so
    //     legitimate authority-driven convergence is preserved (no regression).
    governance::on_roster_entries(&alice, carol.public_id(), vouch(dave.public_id(), "dave")).await;
    assert!(
        rostered(&alice, dave.public_id()),
        "a Controller's gossip should still admit members on a closed network"
    );

    // ---- Scenario 2: OPEN network stays permissionless ------------------
    let alice2_id = Arc::new(Identity::ephemeral());
    let (alice2, _alice2_driver) = spawn_network(
        fresh_network("alice-open", "open-roster-guard"),
        alice2_id.clone(),
        transport.clone(),
    )
    .await
    .expect("spawn alice (open)");

    // Default kind is `open`. A plain Member (Bob) vouching for Eve is
    // accepted — the documented open-network membership model, unchanged.
    governance::on_roster_entries(&alice2, bob.public_id(), vouch(eve.public_id(), "eve")).await;
    assert!(
        rostered(&alice2, eve.public_id()),
        "open-network roster gossip must remain permissionless (member-vouching)"
    );
}
