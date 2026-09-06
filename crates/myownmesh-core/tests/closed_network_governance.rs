#![cfg(feature = "transport-lab")]

//! End-to-end engine integration test: closed-network governance.
//!
//! Two peers handshake through an in-process LocalBroker, import one verified
//! Closed bootstrap, and onboard Bob through Alice's root-signed member grant.
//!
//! Companion to `two_peer_handshake.rs` which covers the open-
//! network roster-approve flow; this one drives the
//! current signed-governance engine path from
//! [`docs/NETWORK-TYPES.md`](../../../docs/NETWORK-TYPES.md) end
//! to end.

use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{
    ClosedRelayPolicyConfig, NetworkConfig, NetworkKind, RoutingPolicyConfig, SignalingConfig,
    TopologyMode,
};
use myownmesh_core::engine::transport_lab::{
    attach_local, create_network_in_instance_root, import_network_in_instance_root, NetworkState,
};
use myownmesh_core::identity::Identity;
use myownmesh_core::semantic::{ClosedProfileId, Role, VerifiedProjectPolicy};
use myownmesh_core::{MeshEvent, PeerEvent};
use myownmesh_signaling::local::LocalBroker;
use tempfile::TempDir;
use tokio::time::Instant;

fn fresh_network(id: &str, network_id: &str) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: network_id.to_string(),
        event_capacity: NetworkConfig::from_network_id("", "").event_capacity,
        connection_trace_capacity: NetworkConfig::from_network_id("", "").connection_trace_capacity,
        label: id.to_string(),
        kind: Default::default(),
        semantic_policy: Default::default(),
        scheduler: Default::default(),
        topology: TopologyMode::FullMesh,
        routing_policy: RoutingPolicyConfig::default(),
        hub: None,
        local_observations: None,
        tree: None,
        signaling: SignalingConfig::default(),
        closed_relay: ClosedRelayPolicyConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        pinned_peers: Vec::new(),
        // `auto_approve = true` makes the wire-level approve frame
        // fire automatically so both peers reach ACTIVE without a
        // user-clicked approve. Reaching ACTIVE now also persists each
        // peer into the other's roster. Closed authorization still comes
        // only from the root-signed RoleGrant exercised by these controls.
        auto_approve: true,
    }
}

fn node_root() -> TempDir {
    tempfile::tempdir().expect("per-node persistence root")
}

async fn spawn_shared_closed_pair(
    network_id: &str,
    alice_id: Arc<Identity>,
    bob_id: Arc<Identity>,
    transport: myownmesh_core::transport::Transport,
    alice_root: &TempDir,
    bob_root: &TempDir,
) -> myownmesh_core::Result<(
    (Arc<NetworkState>, tokio::task::JoinHandle<()>),
    (Arc<NetworkState>, tokio::task::JoinHandle<()>),
)> {
    let creation_id = [0x42; 32];
    let mut alice_config = fresh_network("alice", network_id);
    alice_config.kind = NetworkKind::Closed;
    let mut bob_config = fresh_network("bob", network_id);
    bob_config.kind = NetworkKind::Closed;
    let (alice_state, alice_driver) = create_network_in_instance_root(
        alice_config,
        alice_id,
        transport.clone(),
        alice_root.path().to_path_buf(),
        creation_id,
    )
    .await?;
    let record = alice_state.verified_bootstrap_record().clone();
    let context_id = alice_state.mesh_context_id();
    let (bob_state, bob_driver) = import_network_in_instance_root(
        bob_config,
        bob_id,
        transport,
        bob_root.path().to_path_buf(),
        context_id,
        record,
    )
    .await?;
    Ok(((alice_state, alice_driver), (bob_state, bob_driver)))
}

async fn spawn_closed_creator(
    network_id: &str,
    identity: Arc<Identity>,
    transport: myownmesh_core::transport::Transport,
    root: &TempDir,
    creation_id: [u8; 32],
) -> myownmesh_core::Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let mut config = fresh_network("creator", network_id);
    config.kind = NetworkKind::Closed;
    let (state, driver) = create_network_in_instance_root(
        config,
        identity.clone(),
        transport,
        root.path().to_path_buf(),
        creation_id,
    )
    .await?;
    assert_eq!(state.verified_bootstrap().context().scope, network_id);
    assert_eq!(
        state.mesh_context_id(),
        state.verified_bootstrap().context_id()
    );
    assert!(matches!(
        state.verified_policy(),
        VerifiedProjectPolicy::Closed(policy)
            if policy.profile() == ClosedProfileId::SingleRootSignedMemberLogV1
    ));
    assert_eq!(
        state.verified_authority_root(),
        Some(identity.public_id()),
        "the explicit Closed creator must be the verified bootstrap root"
    );
    Ok((state, driver))
}

async fn shutdown_drivers(
    drivers: impl IntoIterator<Item = (Arc<NetworkState>, tokio::task::JoinHandle<()>)>,
) {
    let drivers: Vec<_> = drivers.into_iter().collect();
    for (state, _) in &drivers {
        state.request_shutdown();
    }
    for (_, driver) in drivers {
        let _ = driver.await;
    }
}

/// Stamp the peer into each side's on-disk roster and establish Bob's signed
/// membership before the network closes.
/// In production, this happens via the user's "approve" click in
/// the GUI; in the integration test we drive it directly so the
/// test doesn't depend on the wire-level approve flow's side
/// effects on roster state.
async fn onboard_member(
    alice: &Arc<NetworkState>,
    bob: &Arc<NetworkState>,
    alice_id: &Identity,
    bob_id: &Identity,
    alice_events: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
    bob_events: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
) {
    assert_eq!(
        alice.mesh_context_id(),
        bob.mesh_context_id(),
        "Alice and Bob must use the exact shared MeshContextId"
    );
    assert_eq!(
        alice.verified_bootstrap_record(),
        bob.verified_bootstrap_record(),
        "Alice and Bob must use the exact shared BootstrapRecord"
    );
    assert_eq!(
        alice.verified_policy(),
        bob.verified_policy(),
        "Alice and Bob must use the exact shared verified policy"
    );
    assert!(matches!(
        alice.verified_policy(),
        VerifiedProjectPolicy::Closed(policy)
            if policy.profile() == ClosedProfileId::SingleRootSignedMemberLogV1
    ));
    assert_eq!(
        alice.verified_bootstrap().profile(),
        Some(ClosedProfileId::SingleRootSignedMemberLogV1)
    );
    wait_for_authenticated(alice_events, bob_id.public_id()).await;
    wait_for_authenticated(bob_events, alice_id.public_id()).await;

    // Closed admission begins from the verified shared bootstrap. Alice's
    // root-signed RoleGrant is the only onboarding authority; no roster write
    // or Open-network bypass is allowed to stand in for the semantic grant.
    myownmesh_core::engine::governance::propose_role_grant(
        alice,
        bob_id.public_id(),
        Role::Member,
        None,
    )
    .await
    .expect("alice signs bob's root-authorized Closed membership");
    // This proves production delivery of the canonical grant: Bob has an exact
    // Member role entry, both sides of the Closed policy have explicit role
    // entries, and the production roster mirror authorizes Bob as Member.
    wait_for(
        "bob's canonical Closed projection admits bob",
        Duration::from_secs(10),
        || {
            let bob_pk = bob_id.public_id();
            let alice_pk = alice_id.public_id();
            let policy_has_explicit_roles = bob.is_rostered(bob_pk)
                && bob.is_rostered(alice_pk)
                && roster_role(bob, bob_pk) == Some(Role::Member);
            policy_has_explicit_roles
                && bob.is_rostered(bob_pk)
                && roster_role(bob, bob_pk) == Some(Role::Member)
        },
    )
    .await;

    let alice_approved = wait_for_approval(alice_events, bob_id.public_id()).await;
    let bob_approved = wait_for_approval(bob_events, alice_id.public_id()).await;
    assert!(
        alice_approved && bob_approved,
        "both peers must reach the Approved/Active outcome"
    );
}

#[tokio::test]
async fn shared_closed_bootstrap_onboards_root_signed_member() {
    let alice_root = node_root();
    let bob_root = node_root();

    let broker = LocalBroker::new();
    let transport = support::test_transport();

    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());

    // Unique per-test network id so a parallel test that happens to
    // collide on file paths doesn't reuse stale semantic state.
    let network_id = "closed-net-test";
    let ((alice_state, alice_driver), (bob_state, bob_driver)) = spawn_shared_closed_pair(
        network_id,
        alice_id.clone(),
        bob_id.clone(),
        transport,
        &alice_root,
        &bob_root,
    )
    .await
    .expect("shared Closed bootstrap engines");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();

    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);
    onboard_member(
        &alice_state,
        &bob_state,
        &alice_id,
        &bob_id,
        &mut alice_events,
        &mut bob_events,
    )
    .await;

    // The onboarding helper has completed the root-signed grant and the
    // production approval barriers. Both nodes began from the same verified
    // Closed bootstrap.
    assert!(matches!(
        alice_state.verified_policy(),
        VerifiedProjectPolicy::Closed(_)
    ));
    assert!(matches!(
        bob_state.verified_policy(),
        VerifiedProjectPolicy::Closed(_)
    ));

    // The verified bootstrap seats Alice as root Owner; the canonical RoleGrant
    // admits Bob as Member without a separate kind-change command.
    {
        assert_eq!(
            alice_state.verified_authority_root(),
            Some(alice_id.public_id()),
        );
        assert_eq!(
            bob_state.verified_authority_root(),
            Some(alice_id.public_id()),
        );
        assert_eq!(
            roster_role(&alice_state, alice_id.public_id()),
            Some(Role::Owner),
            "alice should be the verified bootstrap root Owner"
        );
        assert_eq!(
            roster_role(&bob_state, alice_id.public_id()),
            Some(Role::Owner),
            "alice should remain the verified bootstrap root Owner on Bob's view"
        );
        assert_eq!(
            roster_role(&alice_state, bob_id.public_id()),
            Some(Role::Member),
            "bob should be the root-signed plain Member, not an Owner"
        );
        assert_eq!(
            roster_role(&bob_state, bob_id.public_id()),
            Some(Role::Member),
            "bob's own view agrees with the signed Member grant"
        );

        assert_eq!(
            roster_role(&bob_state, bob_id.public_id()),
            Some(Role::Member),
            "bob's canonical role projection must retain the exact Member entry"
        );
    }
    assert!(
        bob_state.is_rostered(bob_id.public_id()),
        "Bob must be authorized by the production roster mirror"
    );
    assert_eq!(
        roster_role(&bob_state, bob_id.public_id()),
        Some(Role::Member),
        "Bob's production roster tag must remain Member"
    );
    shutdown_drivers([
        (alice_state.clone(), alice_driver),
        (bob_state.clone(), bob_driver),
    ])
    .await;
}

#[tokio::test]
async fn owner_signed_member_grant_converges_via_canonical_signed_facts() {
    // Closed-network membership is owner-**signed**: an owner admits a member
    // by authoring a ratified `RoleGrant`, and that membership converges to
    // every other member through the verified signed fact set — NOT through
    // unsigned roster metadata, and WITHOUT the new member needing to be
    // present. This is the regression guard for the fleet bug where a member
    // could not see its co-members until the owner retransmitted facts: the
    // canonical fact set is complete and self-sufficient, so any member that
    // adopts it holds the full roster.
    let broker = LocalBroker::new();
    let transport = support::test_transport();
    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());
    // Carol is a third device — admitted by the owner's signature, never
    // connected in this test. She must still surface on Bob's roster.
    let carol_id = Arc::new(Identity::ephemeral());

    let network_id = "signed-membership-net";
    let alice_root = node_root();
    let bob_root = node_root();
    let ((alice_state, alice_driver), (bob_state, bob_driver)) = spawn_shared_closed_pair(
        network_id,
        alice_id.clone(),
        bob_id.clone(),
        transport,
        &alice_root,
        &bob_root,
    )
    .await
    .expect("shared Closed bootstrap engines");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();
    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);

    onboard_member(
        &alice_state,
        &bob_state,
        &alice_id,
        &bob_id,
        &mut alice_events,
        &mut bob_events,
    )
    .await;

    // Alice (Owner) admits Carol with a single signed `RoleGrant` — the quorum
    // for a Member grant is ≥1 owner/controller, so it ratifies on Alice at
    // once (no co-signer, and Carol need not be present).
    myownmesh_core::engine::governance::propose_role_grant(
        &alice_state,
        carol_id.public_id(),
        Role::Member,
        None,
    )
    .await
    .expect("propose member grant");

    // Carol lands in the OWNER's roster immediately (ratified + mirrored locally).
    wait_for(
        "alice's roster carries carol",
        Duration::from_secs(10),
        || rostered(&alice_state, carol_id.public_id()),
    )
    .await;

    // The whole point: Carol converges into BOB's roster too — derived from
    // Alice's verified signed facts — even though Carol is offline and only the
    // owner ever signed her in. Before signed membership, Bob could learn a
    // co-member only from live owner metadata; now the canonical facts carry
    // the complete membership.
    wait_for(
        "bob's roster carries carol",
        Duration::from_secs(10),
        || rostered(&bob_state, carol_id.public_id()),
    )
    .await;
    assert_eq!(
        canonical_role(&bob_state, carol_id.public_id()),
        Some(Role::Member),
        "Carol must converge as a Member on Bob via the canonical fact graph"
    );
    shutdown_drivers([
        (alice_state.clone(), alice_driver),
        (bob_state.clone(), bob_driver),
    ])
    .await;
}

#[tokio::test]
async fn evict_converges_and_drops_the_member_on_a_fact_exchange_peer() {
    // The lost/stolen-device kick must propagate. When the owner evicts a
    // member, every peer that learned that member through canonical fact
    // exchange (not by ratifying the evict locally) has to drop it from its
    // roster too, so the
    // device loses authorisation network-wide — not just on the owner. This is
    // the regression guard for the bug where the fact-adoption path re-projected
    // roles but never removed the evicted row, so evicted devices lingered
    // (still authorised) on every co-member.
    let broker = LocalBroker::new();
    let transport = support::test_transport();
    let alice_id = Arc::new(Identity::ephemeral()); // owner
    let bob_id = Arc::new(Identity::ephemeral()); // co-member, online
    let carol_id = Arc::new(Identity::ephemeral()); // admitted then evicted, offline

    let network_id = "evict-fact-exchange-net";
    let alice_root = node_root();
    let bob_root = node_root();
    let ((alice_state, alice_driver), (bob_state, bob_driver)) = spawn_shared_closed_pair(
        network_id,
        alice_id.clone(),
        bob_id.clone(),
        transport,
        &alice_root,
        &bob_root,
    )
    .await
    .expect("shared Closed bootstrap engines");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();
    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);

    onboard_member(
        &alice_state,
        &bob_state,
        &alice_id,
        &bob_id,
        &mut alice_events,
        &mut bob_events,
    )
    .await;

    // The shared bootstrap is already Closed; admit Carol into its signed
    // canonical member facts (she never connects).
    myownmesh_core::engine::governance::propose_role_grant(
        &alice_state,
        carol_id.public_id(),
        Role::Member,
        None,
    )
    .await
    .expect("admit carol");

    // Carol converges into Bob's roster via the signed facts — Bob only ever
    // learns her through fact exchange, never a direct connection.
    wait_for(
        "bob's roster carries carol",
        Duration::from_secs(10),
        || rostered(&bob_state, carol_id.public_id()),
    )
    .await;

    // Alice evicts Carol (the propagating lost-device kick).
    myownmesh_core::engine::governance::propose_evict(&alice_state, carol_id.public_id(), None)
        .await
        .expect("evict carol");

    // Gone on the owner (local ratify path already removed her)...
    wait_for(
        "carol leaves alice's roster",
        Duration::from_secs(10),
        || !rostered(&alice_state, carol_id.public_id()),
    )
    .await;
    // ...and — the fix — gone on Bob too, who learned the evict only through
    // canonical fact exchange.
    wait_for("carol leaves bob's roster", Duration::from_secs(10), || {
        !rostered(&bob_state, carol_id.public_id())
    })
    .await;
    assert!(
        !rostered(&bob_state, carol_id.public_id()),
        "an evicted member must be dropped from a fact-exchange peer's roster"
    );
    // The owner is still authorised on Bob (the prune keeps genuine members).
    assert!(
        rostered(&bob_state, alice_id.public_id()),
        "the owner must remain in the roster after an unrelated evict"
    );
    shutdown_drivers([
        (alice_state.clone(), alice_driver),
        (bob_state.clone(), bob_driver),
    ])
    .await;
}

#[tokio::test]
async fn controller_admits_a_member_which_converges_via_canonical_facts() {
    // The two-key model end to end: an owner promotes a peer to Controller,
    // and that controller — not just the owner — admits a member.
    // The admission rides a controller-authored canonical RoleGrant and converges
    // to the owner even though the owner never signed it. This is the cert
    // chain in motion: the owner issues the controller, then the controller issues
    // the member through the canonical fact graph.
    let broker = LocalBroker::new();
    let transport = support::test_transport();
    let alice_id = Arc::new(Identity::ephemeral()); // owner
    let bob_id = Arc::new(Identity::ephemeral()); // promoted to Controller
    let dave_id = Arc::new(Identity::ephemeral()); // admitted by the controller, offline

    let network_id = "controller-admit-net";
    let alice_root = node_root();
    let bob_root = node_root();
    let ((alice_state, alice_driver), (bob_state, bob_driver)) = spawn_shared_closed_pair(
        network_id,
        alice_id.clone(),
        bob_id.clone(),
        transport,
        &alice_root,
        &bob_root,
    )
    .await
    .expect("shared Closed bootstrap engines");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();
    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);

    onboard_member(
        &alice_state,
        &bob_state,
        &alice_id,
        &bob_id,
        &mut alice_events,
        &mut bob_events,
    )
    .await;

    // Alice promotes Bob to Controller — owner-only authority. This
    // rides the canonical fact graph and converges to Bob.
    myownmesh_core::engine::governance::propose_role_grant(
        &alice_state,
        bob_id.public_id(),
        Role::Controller,
        None,
    )
    .await
    .expect("grant controller");
    wait_for(
        "bob's governance view makes bob a controller",
        Duration::from_secs(10),
        || canonical_role(&bob_state, bob_id.public_id()) == Some(Role::Controller),
    )
    .await;

    // Bob — now a controller — admits Dave. Authority for a member grant is ≥1
    // controller/owner; Bob qualifies, so it ratifies on Bob alone and lands in
    // the canonical graph (Dave need not be present).
    myownmesh_core::engine::governance::propose_role_grant(
        &bob_state,
        dave_id.public_id(),
        Role::Member,
        None,
    )
    .await
    .expect("controller admits dave");
    wait_for("bob's roster carries dave", Duration::from_secs(10), || {
        rostered(&bob_state, dave_id.public_id())
    })
    .await;

    // The controller-authored admission is a canonical RoleGrant fact; no
    // compatibility representation is authoritative.
    assert_eq!(
        canonical_role(&bob_state, dave_id.public_id()),
        Some(Role::Member),
        "Dave's canonical member grant must project on the controller"
    );

    // And it converges to the OWNER by union-merge: Alice never signed Dave, yet
    // recognises Bob's controller-authored admission and surfaces Dave as a member.
    wait_for(
        "alice's roster carries dave",
        Duration::from_secs(10),
        || rostered(&alice_state, dave_id.public_id()),
    )
    .await;
    assert_eq!(
        canonical_role(&alice_state, dave_id.public_id()),
        Some(Role::Member),
        "Dave converges as a Member on the owner via canonical fact exchange"
    );
    shutdown_drivers([
        (alice_state.clone(), alice_driver),
        (bob_state.clone(), bob_driver),
    ])
    .await;
}

#[tokio::test]
async fn plain_member_role_grant_is_rejected_without_canonical_mutation() {
    let broker = LocalBroker::new();
    let transport = support::test_transport();
    let alice_id = Arc::new(Identity::ephemeral()); // owner
    let bob_id = Arc::new(Identity::ephemeral()); // plain member
    let carol_id = Arc::new(Identity::ephemeral()); // whom Bob proposes to admit

    let network_id = "deny-test-net";
    let alice_root = node_root();
    let bob_root = node_root();
    let ((alice_state, alice_driver), (bob_state, bob_driver)) = spawn_shared_closed_pair(
        network_id,
        alice_id.clone(),
        bob_id.clone(),
        transport,
        &alice_root,
        &bob_root,
    )
    .await
    .expect("shared Closed bootstrap engines");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();

    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);

    onboard_member(
        &alice_state,
        &bob_state,
        &alice_id,
        &bob_id,
        &mut alice_events,
        &mut bob_events,
    )
    .await;

    // Alice is the bootstrap owner and Bob is a plain signed member; Bob's
    // authority-bearing RoleGrant must be rejected by the canonical graph.

    // Bob is a member and therefore cannot author this authority-bearing fact;
    // the canonical graph must refuse it before any pending state is created.
    let refusal = myownmesh_core::engine::governance::propose_role_grant(
        &bob_state,
        carol_id.public_id(),
        Role::Member,
        None,
    )
    .await;
    assert!(
        refusal.is_err(),
        "a plain Member must not author an authority-bearing RoleGrant"
    );
    assert_eq!(
        canonical_role(&bob_state, bob_id.public_id()),
        Some(Role::Member),
        "Bob's valid canonical membership must remain after the refusal"
    );
    assert!(rostered(&bob_state, bob_id.public_id()));
    assert_eq!(
        roster_role(&bob_state, bob_id.public_id()),
        Some(Role::Member),
        "Bob's roster projection must remain a non-vacuous Member"
    );
    assert!(!rostered(&alice_state, carol_id.public_id()));
    assert!(!rostered(&bob_state, carol_id.public_id()));
    assert!(!canonical_has_role(&alice_state, carol_id.public_id()));
    assert!(!canonical_has_role(&bob_state, carol_id.public_id()));
    shutdown_drivers([
        (alice_state.clone(), alice_driver),
        (bob_state.clone(), bob_driver),
    ])
    .await;
}

#[tokio::test]
async fn causally_re_admitting_an_evicted_member_restores_membership() {
    // The explicit Closed creator supplies the verified root. Each governance
    // mutation cites the current exclusive-cell head, so this is a causal
    // replacement sequence rather than an arrival-order test.
    // The assertions below read the canonical role and roster projections.
    let transport = support::test_transport();
    let alice_id = Arc::new(Identity::ephemeral());
    let carol_id = Arc::new(Identity::ephemeral());
    let carol_pk = carol_id.public_id().to_string();

    let network_id = "re-admit-net";
    let alice_root = node_root();
    let (alice_state, alice_driver) = spawn_closed_creator(
        network_id,
        alice_id.clone(),
        transport.clone(),
        &alice_root,
        [0x51; 32],
    )
    .await
    .expect("alice engine");

    use myownmesh_core::engine::governance::{propose_evict, propose_role_grant};
    propose_role_grant(&alice_state, &carol_pk, Role::Member, None)
        .await
        .expect("admit");
    assert_eq!(
        canonical_role(&alice_state, &carol_pk),
        Some(Role::Member),
        "the root-authored member grant must be visible before eviction"
    );
    propose_evict(&alice_state, &carol_pk, None)
        .await
        .expect("evict");
    assert!(
        !canonical_has_role(&alice_state, carol_pk.as_str()),
        "an evicted member must be absent from the projected membership"
    );
    myownmesh_core::engine::governance::propose_membership_admit(&alice_state, &carol_pk, None)
        .await
        .expect("re-admit membership");
    assert_eq!(
        roster_role(&alice_state, &carol_pk),
        None,
        "membership admission alone must not grant a role"
    );
    propose_role_grant(&alice_state, &carol_pk, Role::Member, None)
        .await
        .expect("re-admit");

    assert_eq!(
        canonical_role(&alice_state, &carol_pk),
        Some(Role::Member),
        "a causal re-admit must supersede the evict head deterministically"
    );
    assert!(
        rostered(&alice_state, &carol_pk),
        "the causally restored member must return to the roster projection"
    );
    shutdown_drivers([(alice_state.clone(), alice_driver)]).await;
}

#[tokio::test]
async fn evicting_a_promoted_member_tombstones_its_member_admit() {
    // Regression for "I removed an owner/controller, but it stays controllable and
    // the other owners still see it in the fleet."
    //
    // A device promoted past plain member (admitted as Member, then granted
    // Controller/Owner) still carries its original member-tier admit in the
    // member facts. Evicting it extends the signed governance facts — but any
    // peer that re-derives membership straight from those facts, which is
    // exactly what a co-owner does when it adopts the fact set through peer
    // exchange (e.g. it was offline
    // during the kick), folds that stale admit back in and resurrects the evicted
    // device as a plain member: it lingers in the roster, still authorised to
    // control the fleet, and every such owner keeps seeing it. The evict must
    // tombstone the admit so the projected membership drops the device and the
    // roster mirror prunes it — the same convergence a plain-member evict gets.
    //
    // This drives the projection functions the fact-adoption path is built on
    // (`project_roles` / the roster mirror), so it fails deterministically
    // without the fix — unlike an online peer,
    // which ratifies the evict incrementally and never hits the resurrecting
    // re-projection.
    let transport = support::test_transport();
    let alice_id = Arc::new(Identity::ephemeral());
    let carol_id = Arc::new(Identity::ephemeral());
    let carol_pk = carol_id.public_id().to_string();

    let network_id = "evict-promoted-projection-net";
    let alice_root = node_root();
    let (alice_state, alice_driver) = spawn_closed_creator(
        network_id,
        alice_id.clone(),
        transport.clone(),
        &alice_root,
        [0x52; 32],
    )
    .await
    .expect("alice engine");

    use myownmesh_core::engine::governance::{propose_evict, propose_role_grant};
    // Admit Carol as a plain member (member facts), then promote her to
    // Controller (governance facts) — so her stale member-tier admit outlives the
    // promotion.
    propose_role_grant(&alice_state, &carol_pk, Role::Member, None)
        .await
        .expect("admit carol");
    propose_role_grant(&alice_state, &carol_pk, Role::Controller, None)
        .await
        .expect("promote carol");
    assert_eq!(
        canonical_role(&alice_state, &carol_pk),
        Some(Role::Controller),
        "carol should be a Controller after promotion"
    );

    // Evict the Controller.
    propose_evict(&alice_state, &carol_pk, None)
        .await
        .expect("evict carol");

    // Canonical role and roster projection are authoritative here. Compatibility
    // records may remain evidence but cannot decide whether Carol remains admitted.
    assert!(!canonical_has_role(&alice_state, &carol_pk));
    assert_eq!(
        canonical_role(&alice_state, alice_id.public_id()),
        Some(Role::Owner),
        "evicting Carol must not remove the verified bootstrap root"
    );
    assert!(!rostered(&alice_state, &carol_pk));
    assert_ne!(roster_role(&alice_state, &carol_pk), Some(Role::Controller));
    shutdown_drivers([(alice_state.clone(), alice_driver)]).await;
}

#[tokio::test]
async fn withdrawing_a_role_updates_the_local_roster_tag() {
    // Regression: withdrawing a peer's role (owner/controller → plain member) must
    // update the *authoring* device's cached roster tag, not just the projected
    // `roles` map. The fact-adoption path reprojects the whole role map onto
    // the roster, but the local ratify path open-coded per-variant mirrors and
    // skipped RoleRevoke entirely — so on the device that authored the
    // withdrawal, the peer's row kept rendering the old authority and the
    // downgrade "didn't take". Single engine: the owner authors the whole chain
    // and we read the on-disk roster tag it mirrors for its own peer rows.
    let transport = support::test_transport();
    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());
    let bob_pk = bob_id.public_id().to_string();

    let network_id = "withdraw-role-net";
    let alice_root = node_root();
    let (alice_state, alice_driver) = spawn_closed_creator(
        network_id,
        alice_id.clone(),
        transport.clone(),
        &alice_root,
        [0x53; 32],
    )
    .await
    .expect("alice engine");

    use myownmesh_core::engine::governance::propose_role_grant;
    propose_role_grant(&alice_state, &bob_pk, Role::Member, None)
        .await
        .expect("admit bob");
    propose_role_grant(&alice_state, &bob_pk, Role::Controller, None)
        .await
        .expect("promote bob");
    assert_eq!(
        canonical_role(&alice_state, &bob_pk),
        Some(Role::Controller),
        "Bob must be a Controller before the withdrawal"
    );
    // The mirrored roster tag should read controller on the authoring device.
    wait_for(
        "alice's roster tags bob a controller",
        Duration::from_secs(5),
        || roster_role(&alice_state, &bob_pk) == Some(Role::Controller),
    )
    .await;

    // Demote Bob explicitly back to a plain member. RoleRevoke means no role;
    // a durable demotion is a canonical RoleGrant(Member).
    propose_role_grant(&alice_state, &bob_pk, Role::Member, None)
        .await
        .expect("withdraw bob");

    // The cached roster tag must drop to member on the authoring device — the
    // withdrawal has to "take" right where the owner performed it.
    assert_eq!(
        roster_role(&alice_state, &bob_pk),
        Some(Role::Member),
        "withdrawing a role must reset the authoring device's roster tag to member"
    );
    assert_eq!(
        canonical_role(&alice_state, &bob_pk),
        Some(Role::Member),
        "the canonical projection must retain Bob as an explicit Member"
    );
    assert!(
        canonical_has_role(&alice_state, &bob_pk),
        "the demotion grant must remain an explicit canonical role"
    );
    // ...and Bob stays in the roster — a withdraw demotes, it doesn't remove.
    assert!(
        rostered(&alice_state, &bob_pk),
        "a withdrawn member stays in the fleet — only its authority drops"
    );
    shutdown_drivers([(alice_state.clone(), alice_driver)]).await;
}

/// An offline evicted device receives the exact signed governance proof before
/// the denying session is retired. The Deny frame is only a transport outcome:
/// stand-down follows canonical fact verification and causal dependency
/// admission. No roster hint, presence signal, or elapsed time participates.
#[tokio::test]
async fn evicted_offline_device_learns_on_reconnect_and_stands_down() {
    // The "offline and lost devices just keep showing back up" loop, killed
    // end to end. Carol is admitted to the closed network and then evicted
    // while OFFLINE — she never receives the eviction fact. When she comes back she
    // redials with a stale credential; before this fix, the handshake
    // treated her as a fresh face and (on an auto-approve network — every
    // fleet mesh) re-approved her, put her back in rosters on mutual
    // ACTIVE, and exchanged the resurrection. Now: the members' handshake
    // gate denies her WITH the signed facts attached, she verifies her own
    // eviction through the standard strict-extension adoption (the owner's
    // signatures are the authority, not the denier), flips to stood-down,
    // and nobody's roster ever re-admits her.
    let broker = LocalBroker::new();
    let transport = support::test_transport();
    let alice_id = Arc::new(Identity::ephemeral()); // owner
    let bob_id = Arc::new(Identity::ephemeral()); // co-member, online
    let carol_id = Arc::new(Identity::ephemeral()); // evicted while offline

    let network_id = "evict-deny-proof-net";
    let alice_root = node_root();
    let bob_root = node_root();
    let carol_root = node_root();
    let ((alice_state, alice_driver), (bob_state, bob_driver)) = spawn_shared_closed_pair(
        network_id,
        alice_id.clone(),
        bob_id.clone(),
        transport.clone(),
        &alice_root,
        &bob_root,
    )
    .await
    .expect("shared Closed bootstrap engines");
    // Carol imports the same verified Closed bootstrap but remains unattached
    // until after eviction, so her return exercises the real stale-proof path.
    let mut carol_config = fresh_network("carol", network_id);
    carol_config.kind = NetworkKind::Closed;
    let (carol_state, carol_driver) = import_network_in_instance_root(
        carol_config,
        carol_id.clone(),
        transport,
        carol_root.path().to_path_buf(),
        alice_state.mesh_context_id(),
        alice_state.verified_bootstrap_record().clone(),
    )
    .await
    .expect("carol shared Closed bootstrap import");
    let carol_initial_fact_count = carol_state.semantic_fact_count();

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();
    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);

    onboard_member(
        &alice_state,
        &bob_state,
        &alice_id,
        &bob_id,
        &mut alice_events,
        &mut bob_events,
    )
    .await;

    use myownmesh_core::engine::governance::{propose_evict, propose_role_grant};
    propose_role_grant(&alice_state, carol_id.public_id(), Role::Member, None)
        .await
        .expect("admit carol");
    wait_for(
        "bob's roster carries carol",
        Duration::from_secs(10),
        || rostered(&bob_state, carol_id.public_id()),
    )
    .await;
    propose_evict(&alice_state, carol_id.public_id(), None)
        .await
        .expect("evict carol while she is offline");
    wait_for(
        "carol leaves both members' rosters",
        Duration::from_secs(10),
        || {
            !rostered(&alice_state, carol_id.public_id())
                && !rostered(&bob_state, carol_id.public_id())
        },
    )
    .await;

    // Carol comes back online, clueless, and redials the mesh.
    attach_local(&carol_state, &broker);

    // She learns: some member's handshake denies her with the signed facts,
    // she adopts them (strict extension over her empty fact set), and the
    // verified verdict stands her down.
    wait_for(
        "carol adopts the proof and stands down",
        Duration::from_secs(20),
        || {
            carol_state
                .self_evicted
                .load(std::sync::atomic::Ordering::SeqCst)
        },
    )
    .await;
    assert!(
        carol_state
            .self_evicted
            .load(std::sync::atomic::Ordering::SeqCst),
        "the denied device must adopt the eviction proof and stand down"
    );

    // And the resurrection is dead: give the mesh a few more announce/
    // fact-exchange beats — nobody re-admits her, on either member.
    assert!(
        !rostered(&alice_state, carol_id.public_id()),
        "an evicted device redialing must not re-enter the owner's roster"
    );
    assert!(
        !rostered(&bob_state, carol_id.public_id()),
        "an evicted device redialing must not re-enter a member's roster"
    );
    // Her own roster view keeps whatever she had; the flag is what stands
    // her down — and the signed facts she adopted agree she is out.
    let verdict = !canonical_has_role(&carol_state, carol_id.public_id());
    assert!(
        verdict,
        "carol's own adopted (verified) state must carry her eviction"
    );

    // The proof was admitted through the production durable semantic owner,
    // not just held in the live graph. Restart Carol from the same instance
    // root and prove the exact context, restored fact set, and stand-down
    // survive before she is allowed another handshake attempt.
    let restored_fact_count = carol_state.semantic_fact_count();
    let restored_context = carol_state.mesh_context_id();
    assert!(
        restored_fact_count > 0,
        "the proof must be durably admitted"
    );
    assert!(
        restored_fact_count > carol_initial_fact_count,
        "the restored graph must contain facts learned from the eviction proof"
    );
    assert_eq!(
        carol_state.semantic_unresolved_count(),
        0,
        "the eviction proof must restore without unresolved dependencies"
    );
    shutdown_drivers([(carol_state, carol_driver)]).await;
    let mut carol_config = fresh_network("carol", network_id);
    carol_config.kind = NetworkKind::Closed;
    let (carol_state, carol_driver) = import_network_in_instance_root(
        carol_config,
        carol_id.clone(),
        support::test_transport(),
        carol_root.path().to_path_buf(),
        restored_context,
        alice_state.verified_bootstrap_record().clone(),
    )
    .await
    .expect("carol restores the durable semantic snapshot");
    assert_eq!(
        carol_state.mesh_context_id(),
        restored_context,
        "restart must preserve the exact mesh context"
    );
    assert_eq!(
        carol_state.semantic_fact_count(),
        restored_fact_count,
        "restart must restore the exact admitted proof fact set"
    );
    assert_eq!(
        carol_state.semantic_unresolved_count(),
        0,
        "restart must not resurrect unresolved proof dependencies"
    );
    assert!(
        carol_state
            .self_evicted
            .load(std::sync::atomic::Ordering::SeqCst),
        "restart must preserve the verified stand-down verdict"
    );
    attach_local(&carol_state, &broker);
    wait_for(
        "restarted carol remains stood down",
        Duration::from_secs(10),
        || {
            carol_state
                .self_evicted
                .load(std::sync::atomic::Ordering::SeqCst)
        },
    )
    .await;

    shutdown_drivers([
        (alice_state.clone(), alice_driver),
        (bob_state.clone(), bob_driver),
        (carol_state.clone(), carol_driver),
    ])
    .await;
}

#[tokio::test]
async fn two_owners_converge_their_rosters() {
    // The reported symptom, inverted into a guarantee: a fleet with two owners
    // where the rosters never converge and only one behaves like the "real"
    // owner. With flat peer authority (any owner is a full owner), an
    // order-independent governance fact set (both recognise the same shared prefix
    // regardless of ack order), and the union-merged member tier, the two owners
    // must each recognise the other, and a member admitted by *either* must
    // appear on *both*.
    let broker = LocalBroker::new();
    let transport = support::test_transport();
    let alice_id = Arc::new(Identity::ephemeral()); // bootstrap root Owner
    let bob_id = Arc::new(Identity::ephemeral()); // promoted to a second owner
    let carol_id = Arc::new(Identity::ephemeral()); // admitted by Alice, offline
    let dave_id = Arc::new(Identity::ephemeral()); // admitted by Bob, offline

    let network_id = "two-owner-net";
    let alice_root = node_root();
    let bob_root = node_root();
    let ((alice_state, alice_driver), (bob_state, bob_driver)) = spawn_shared_closed_pair(
        network_id,
        alice_id.clone(),
        bob_id.clone(),
        transport,
        &alice_root,
        &bob_root,
    )
    .await
    .expect("shared Closed bootstrap engines");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();
    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);
    onboard_member(
        &alice_state,
        &bob_state,
        &alice_id,
        &bob_id,
        &mut alice_events,
        &mut bob_events,
    )
    .await;

    use myownmesh_core::engine::governance::propose_role_grant;
    // Alice promotes Bob to a second Owner under the shared Closed policy.
    propose_role_grant(&alice_state, bob_id.public_id(), Role::Owner, None)
        .await
        .expect("grant bob owner");

    // Both sides must agree Bob is a *full* owner — not just on Alice's view.
    // (This is the "only one acts like the real owner" half of the symptom.)
    wait_for(
        "both governance views make bob an owner",
        Duration::from_secs(10),
        || {
            canonical_role(&alice_state, bob_id.public_id()) == Some(Role::Owner)
                && canonical_role(&bob_state, bob_id.public_id()) == Some(Role::Owner)
        },
    )
    .await;

    // Each owner independently admits a different member (both offline).
    let alice_carol_fact =
        propose_role_grant(&alice_state, carol_id.public_id(), Role::Member, None)
            .await
            .expect("alice admits carol");
    let bob_dave_fact = propose_role_grant(&bob_state, dave_id.public_id(), Role::Member, None)
        .await
        .expect("bob admits dave");
    assert_ne!(
        alice_carol_fact, bob_dave_fact,
        "the two owners must author distinct content-derived canonical facts"
    );

    // Canonical fact exchange must converge: BOTH owners end up holding BOTH
    // members. This is the "rosters never converge between the two owners"
    // symptom turned into a passing assertion.
    wait_for_two_owner_rosters(
        &alice_state,
        &bob_state,
        carol_id.public_id(),
        dave_id.public_id(),
        Duration::from_secs(15),
    )
    .await;
    assert!(
        rostered(&alice_state, dave_id.public_id()),
        "Alice must see the member Bob admitted"
    );
    assert!(
        rostered(&bob_state, carol_id.public_id()),
        "Bob must see the member Alice admitted"
    );
    assert_eq!(
        canonical_role(&alice_state, carol_id.public_id()),
        Some(Role::Member),
        "Alice's local canonical fact must project Carol locally"
    );
    assert!(
        canonical_has_role(&alice_state, carol_id.public_id()),
        "Alice's canonical role map must contain Carol"
    );
    assert_eq!(
        canonical_role(&bob_state, dave_id.public_id()),
        Some(Role::Member),
        "Bob's local canonical fact must project Dave locally"
    );
    assert!(
        canonical_has_role(&bob_state, dave_id.public_id()),
        "Bob's canonical role map must contain Dave"
    );
    assert_eq!(
        canonical_role(&alice_state, dave_id.public_id()),
        Some(Role::Member),
        "Bob's remote canonical fact must reach Alice's role projection"
    );
    assert!(
        canonical_has_role(&alice_state, dave_id.public_id()),
        "Alice's canonical role map must contain Bob's remote Dave grant"
    );
    assert_eq!(
        canonical_role(&bob_state, carol_id.public_id()),
        Some(Role::Member),
        "Alice's remote canonical fact must reach Bob's role projection"
    );
    assert!(
        canonical_has_role(&bob_state, carol_id.public_id()),
        "Bob's canonical role map must contain Alice's remote Carol grant"
    );
    assert_eq!(
        roster_role(&alice_state, dave_id.public_id()),
        Some(Role::Member),
        "Bob's remote canonical fact must drive Alice's roster projection"
    );
    assert_eq!(
        roster_role(&bob_state, carol_id.public_id()),
        Some(Role::Member),
        "Alice's remote canonical fact must drive Bob's roster projection"
    );
    shutdown_drivers([
        (alice_state.clone(), alice_driver),
        (bob_state.clone(), bob_driver),
    ])
    .await;
}

// ---- helpers --------------------------------------------------------

#[tokio::test]
async fn local_topology_control_does_not_enter_canonical_governance() {
    let broker = LocalBroker::new();
    let transport = support::test_transport();

    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());

    let network_id = "governed-topology-net";
    let alice_root = node_root();
    let bob_root = node_root();
    let ((alice_state, alice_driver), (bob_state, bob_driver)) = spawn_shared_closed_pair(
        network_id,
        alice_id.clone(),
        bob_id.clone(),
        transport,
        &alice_root,
        &bob_root,
    )
    .await
    .expect("shared Closed bootstrap engines");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();
    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);
    onboard_member(
        &alice_state,
        &bob_state,
        &alice_id,
        &bob_id,
        &mut alice_events,
        &mut bob_events,
    )
    .await;

    // The bootstrap root designates herself the network's infra hub. One signed
    // local topology command carries the whole shape (mode + hub set + redundancy).
    let governed = TopologyMode::Hubs {
        hubs: vec![alice_id.public_id().to_string()],
        spoke_redundancy: Some(1),
    };
    assert!(
        myownmesh_core::engine::transport_lab::set_topology(&alice_state, governed.clone()),
        "send local topology set"
    );

    // Both governance views AND both runtime selectors converge — Bob
    // never signs anything; a local topology selector cannot reshape him.
    wait_for(
        "alice's local selector takes the topology",
        Duration::from_secs(10),
        || *alice_state.topology.read() == governed,
    )
    .await;

    // Canonical governance remains unchanged; a third node joining later must
    // not infer this local selector change as a governance fact.
    // Backstop: a manual local SetTopology on a governed network is
    // ignored — one device can't fork itself off the owner's shape.
    assert!(
        *bob_state.topology.read() != governed,
        "a local topology policy must not reshape a different node"
    );
    shutdown_drivers([
        (alice_state.clone(), alice_driver),
        (bob_state.clone(), bob_driver),
    ])
    .await;
}

async fn wait_for_approval(
    rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
    peer_id: &str,
) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if Instant::now() > deadline {
            panic!("never saw PeerApproved for {peer_id}");
        }
        let next = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
        match next {
            Ok(Ok(MeshEvent::Peer(PeerEvent::Approved { device_id, .. })))
                if device_id == peer_id =>
            {
                return true;
            }
            _ => continue,
        }
    }
}

async fn wait_for_authenticated(
    rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
    peer_id: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if Instant::now() > deadline {
            panic!("never saw PeerAuthenticated for {peer_id}");
        }
        let next = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
        match next {
            Ok(Ok(MeshEvent::Peer(PeerEvent::Authenticated { device_id, .. })))
                if device_id == peer_id =>
            {
                return
            }
            _ => continue,
        }
    }
}

/// Poll `check` until it holds, or fail naming the step that never converged.
///
/// `what` is the whole reason this takes a label. The panic is raised here, so
/// its location names this helper rather than the caller, and this file has
/// twenty-eight waits — several of them the same predicate in different tests.
/// A timeout was therefore unattributable to any one convergence step, which is
/// exactly the position a Windows failure at this line left the diagnosis in.
///
/// Diagnostic only: the caller's timeout, the polling interval and every
/// predicate are unchanged. This adds a name to a failure, not a behaviour.
async fn wait_for(what: &str, timeout: Duration, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("wait_for predicate never satisfied within {timeout:?}: {what}");
}

/// The two-owner control's existing roster wait, with diagnostics only on its
/// timeout path. The predicate, deadline, and polling cadence intentionally
/// match the original inline wait so a timeout report cannot change the
/// control's scheduling or acceptance condition.
async fn wait_for_two_owner_rosters(
    alice: &Arc<NetworkState>,
    bob: &Arc<NetworkState>,
    carol: &str,
    dave: &str,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if rostered(alice, carol)
            && rostered(alice, dave)
            && rostered(bob, carol)
            && rostered(bob, dave)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let alice_carol = (
        canonical_has_role(alice, carol),
        canonical_role(alice, carol),
        rostered(alice, carol),
    );
    let alice_dave = (
        canonical_has_role(alice, dave),
        canonical_role(alice, dave),
        rostered(alice, dave),
    );
    let bob_carol = (
        canonical_has_role(bob, carol),
        canonical_role(bob, carol),
        rostered(bob, carol),
    );
    let bob_dave = (
        canonical_has_role(bob, dave),
        canonical_role(bob, dave),
        rostered(bob, dave),
    );
    panic!(
        concat!(
            "two-owner roster wait timed out within {:?}; ",
            "Alice Carol role/roster={:?}, Dave={:?}; ",
            "Bob Carol role/roster={:?}, Dave={:?}"
        ),
        timeout, alice_carol, alice_dave, bob_carol, bob_dave,
    );
}

fn canonical_role(state: &Arc<NetworkState>, id: &str) -> Option<Role> {
    roster_role(state, id)
}

fn canonical_has_role(state: &Arc<NetworkState>, id: &str) -> bool {
    roster_role(state, id).is_some()
}

fn rostered(state: &Arc<NetworkState>, id: &str) -> bool {
    myownmesh_core::roster::is_authorized(&state.roster.read(), id)
}

/// The cached authority tag for `id` in `state`'s on-disk roster, if the peer
/// is present. This is the projection the fleet UI renders each member's
/// grant/withdraw controls from, so a role change that doesn't reach here
/// "doesn't take" on the device that authored it.
fn roster_role(state: &Arc<NetworkState>, id: &str) -> Option<Role> {
    let pk = myownmesh_core::signing::pubkey_part(id);
    state
        .roster
        .read()
        .authorized_devices
        .iter()
        .find(|p| p.device_id == pk)
        .map(|p| p.role)
}

/// Each engine owns a stable TempDir-backed persistence root for its lifetime.
mod support;
