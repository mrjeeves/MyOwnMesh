//! Integration test: the per-device custody MFA gate on governance authoring.
//!
//! Proves that once a device enrolls a custody lock for a network,
//! `governance::propose` refuses to author a transition without a valid
//! second factor — and proceeds once one is supplied. (The same
//! `custody::require` chokepoint guards `sign_proposal`; see the unit tests
//! in `custody.rs` for the verify/enroll/disable mechanics.)

use std::sync::Arc;

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::{governance, spawn_network};
use myownmesh_core::identity::Identity;
use myownmesh_core::transport::Transport;
use myownmesh_core::{NetworkKind, TransitionVariant};

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

#[tokio::test]
async fn custody_gate_blocks_unauthenticated_governance_authoring() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("MYOWNMESH_HOME", tmp.path());
    let transport = Transport::new().expect("transport");

    let net_id = "custody-gate";
    let alice = Arc::new(Identity::ephemeral());
    let (state, _driver) = spawn_network(fresh_network("alice", net_id), alice, transport)
        .await
        .expect("spawn alice");

    // Enroll a custody lock for this network on this device.
    let enrolled = myownmesh_core::custody::enroll(net_id, "alice-laptop").expect("enroll");
    assert!(myownmesh_core::custody::is_enrolled(net_id));

    // Authoring with no second factor is refused *at the gate* — before any
    // signing happens.
    let err = governance::propose(
        &state,
        TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        },
        None,
    )
    .await
    .expect_err("propose without a code must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("custody") || msg.contains("authenticator"),
        "expected a custody-gate error, got: {msg}"
    );

    // With a valid one-time recovery code, the gate opens and authoring
    // proceeds (sole-owner founder election ratifies the close).
    governance::propose(
        &state,
        TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        },
        Some(&enrolled.recovery_codes[0]),
    )
    .await
    .expect("propose with a valid recovery code");

    // Disable the lock (with another recovery code), and the gate is a no-op
    // again — governance authoring no longer demands a factor.
    myownmesh_core::custody::disable(net_id, &enrolled.recovery_codes[1]).expect("disable");
    assert!(!myownmesh_core::custody::is_enrolled(net_id));
    assert!(
        myownmesh_core::custody::require(net_id, None).is_ok(),
        "with no enrollment the gate must be a no-op"
    );
}
