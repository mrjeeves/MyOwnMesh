//! End-to-end engine integration test: closed-network governance.
//!
//! Two peers handshake through an in-process LocalBroker; the founder
//! (Alice) self-elects the network `Closed` with a single signature
//! even though Bob is already present, and both sides end with matching
//! single-signer genesis logs + Alice installed as founder owner.
//!
//! Companion to `two_peer_handshake.rs` which covers the open-
//! network roster-approve flow; this one drives the
//! `network_state_v1` engine half from
//! [`docs/NETWORK-TYPES.md`](../../../docs/NETWORK-TYPES.md) end
//! to end.

use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::{attach_local, spawn_network};
use myownmesh_core::identity::Identity;
use myownmesh_core::transport::Transport;
use myownmesh_core::{MeshEvent, NetworkKind, PeerEvent, Role, TransitionVariant};
use myownmesh_signaling::local::LocalBroker;
use tokio::time::Instant;

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
        pinned_peers: Vec::new(),
        // `auto_approve = true` makes the wire-level approve frame
        // fire automatically so both peers reach ACTIVE without a
        // user-clicked approve. Reaching ACTIVE now also persists each
        // peer into the other's roster (the mutual-confirmation =
        // membership rule), which is exactly what the closed-network
        // quorum needs. The explicit `cross_approve` below is kept as a
        // belt-and-braces seed so the test doesn't depend on that
        // handshake side effect's timing.
        auto_approve: true,
    }
}

/// Stamp the peer into each side's on-disk roster so the closed-
/// network quorum check has a real member set to evaluate against.
/// In production, this happens via the user's "approve" click in
/// the GUI; in the integration test we drive it directly so the
/// test doesn't depend on the wire-level approve flow's side
/// effects on roster state.
async fn cross_approve(
    alice: &Arc<myownmesh_core::engine::state::NetworkState>,
    bob: &Arc<myownmesh_core::engine::state::NetworkState>,
    alice_id: &Identity,
    bob_id: &Identity,
) {
    alice
        .approve_roster(bob_id.public_id(), "bob")
        .await
        .expect("alice roster-approve bob");
    bob.approve_roster(alice_id.public_id(), "alice")
        .await
        .expect("bob roster-approve alice");
}

#[tokio::test]
async fn founder_self_elects_open_to_closed_even_when_populated() {
    shared_home();

    let broker = LocalBroker::new();
    let transport = Transport::new().expect("transport");

    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());

    // Unique per-test network id so a parallel test that happens to
    // collide on file paths doesn't reuse a stale state log.
    let network_id = "closed-net-test";
    let alice_cfg = fresh_network("alice", network_id);
    let bob_cfg = fresh_network("bob", network_id);

    let (alice_state, _alice_driver) =
        spawn_network(alice_cfg, alice_id.clone(), transport.clone())
            .await
            .expect("alice engine");
    let (bob_state, _bob_driver) = spawn_network(bob_cfg, bob_id.clone(), transport.clone())
        .await
        .expect("bob engine");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();

    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);

    // Wait until each peer sees the other approved + the connection
    // is ACTIVE. Until then, broadcasts from `governance::propose`
    // would land in the void.
    wait_for_approval(&mut alice_events, bob_id.public_id()).await;
    wait_for_approval(&mut bob_events, alice_id.public_id()).await;

    // Stamp Bob into Alice's roster (and vice-versa) *before* the close, so the
    // open network is already populated when Alice founds. This is the exact
    // condition that used to strand a fleet: the old quorum demanded unanimous
    // consent from every rostered peer, so a lone founder could never close a
    // populated open network. Founding now stands on the founder's own signature
    // (the founder is `signers.first()`) regardless of who else is present — a
    // co-signed genesis is fine too, but no co-signer is *required*.
    cross_approve(&alice_state, &bob_state, &alice_id, &bob_id).await;

    // Sanity: both sides start in `Open` with no transitions logged.
    assert_eq!(alice_state.governance_state.read().kind, NetworkKind::Open);
    assert_eq!(bob_state.governance_state.read().kind, NetworkKind::Open);
    assert!(alice_state.governance_state.read().transitions.is_empty());

    // Alice proposes `KindChange { to: Closed }`. She self-signs at issue time,
    // which alone satisfies the genesis quorum — so this ratifies on Alice
    // immediately (no co-signer needed) and propagates to Bob, who adopts the
    // single-signer genesis and converges without ever signing it.
    let _proposal_id = myownmesh_core::engine::governance::propose(
        &alice_state,
        TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        },
        None,
    )
    .await
    .expect("propose");

    // Wait until both sides see the ratified transition.
    wait_for(Duration::from_secs(10), || {
        alice_state.governance_state.read().kind == NetworkKind::Closed
            && bob_state.governance_state.read().kind == NetworkKind::Closed
    })
    .await;

    // Founder election: Alice (the sole signer) is Owner; Bob, already present
    // in the open network, lands as a plain Member of the closed one.
    let alice_view = alice_state.governance_state.read();
    let bob_view = bob_state.governance_state.read();

    assert_eq!(alice_view.kind, NetworkKind::Closed);
    assert_eq!(bob_view.kind, NetworkKind::Closed);

    assert_eq!(
        alice_view.role_of(alice_id.public_id()),
        Role::Owner,
        "alice should be founder-owner on alice's view"
    );
    assert_eq!(
        bob_view.role_of(alice_id.public_id()),
        Role::Owner,
        "alice should be owner on bob's view too — both ratify the same transition"
    );
    assert_eq!(
        alice_view.role_of(bob_id.public_id()),
        Role::Member,
        "bob was present at founding but is a plain member, not an owner"
    );
    assert_eq!(
        bob_view.role_of(bob_id.public_id()),
        Role::Member,
        "bob's own view agrees: still member"
    );

    // Both transition logs should have one entry (the close).
    assert_eq!(alice_view.transitions.len(), 1);
    assert_eq!(bob_view.transitions.len(), 1);
    // And the proposal should have left the pending list on both sides.
    assert!(
        alice_view.pending.is_empty(),
        "alice still has pending: {:?}",
        alice_view.pending
    );
    assert!(
        bob_view.pending.is_empty(),
        "bob still has pending: {:?}",
        bob_view.pending
    );

    // Byte-identical genesis on both peers. A lone founder signs this one (a
    // co-signed genesis is also valid — `verify_log` elects `signers.first()`
    // either way); here we assert the single-signer shape the engine authors.
    assert_eq!(
        alice_view.transitions[0].variant,
        bob_view.transitions[0].variant
    );
    assert_eq!(
        alice_view.transitions[0].signers, bob_view.transitions[0].signers,
        "both peers record the identical single-signer genesis\n\
         alice = {:?}\n\
         bob   = {:?}",
        alice_view.transitions[0], bob_view.transitions[0],
    );
    assert_eq!(
        alice_view.transitions[0].signers,
        vec![alice_id.public_id().to_string()],
        "genesis is the founder's lone self-election"
    );

    // The genesis log must re-verify standalone — the guarantee a third peer
    // relies on when it converges the fleet purely from gossip.
    myownmesh_core::network_state::verify_log(network_id, &alice_view.transitions)
        .expect("single-signer genesis must verify from scratch");
}

#[tokio::test]
async fn owner_signed_member_grant_converges_to_a_member_via_the_log() {
    // Closed-network membership is owner-**signed**: an owner admits a member
    // by authoring a ratified `RoleGrant`, and that membership converges to
    // every other member through the verified signed log — NOT through unsigned
    // roster gossip, and WITHOUT the new member needing to be present. This is
    // the regression guard for the fleet bug where a member couldn't see its
    // co-members until the owner re-gossiped: the signed log is complete and
    // self-sufficient, so any member that has adopted it holds the full roster.
    shared_home();

    let broker = LocalBroker::new();
    let transport = Transport::new().expect("transport");
    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());
    // Carol is a third device — admitted by the owner's signature, never
    // connected in this test. She must still surface on Bob's roster.
    let carol_id = Arc::new(Identity::ephemeral());

    let network_id = "signed-membership-net";
    let (alice_state, _ad) = spawn_network(
        fresh_network("alice", network_id),
        alice_id.clone(),
        transport.clone(),
    )
    .await
    .expect("alice engine");
    let (bob_state, _bd) = spawn_network(
        fresh_network("bob", network_id),
        bob_id.clone(),
        transport.clone(),
    )
    .await
    .expect("bob engine");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();
    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);

    wait_for_approval(&mut alice_events, bob_id.public_id()).await;
    wait_for_approval(&mut bob_events, alice_id.public_id()).await;
    cross_approve(&alice_state, &bob_state, &alice_id, &bob_id).await;

    // Close the network: Alice becomes founder-owner, Bob a member.
    // Alice founds the closed network with her lone signature; it ratifies on
    // her at once and converges to Bob (single-signer genesis needs no co-sign).
    myownmesh_core::engine::governance::propose(
        &alice_state,
        TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        },
        None,
    )
    .await
    .expect("propose close");
    wait_for(Duration::from_secs(10), || {
        alice_state.governance_state.read().kind == NetworkKind::Closed
            && bob_state.governance_state.read().kind == NetworkKind::Closed
    })
    .await;

    // Alice (Owner) admits Carol with a single signed `RoleGrant` — the quorum
    // for a Member grant is ≥1 owner/controller, so it ratifies on Alice at
    // once (no co-signer, and Carol need not be present).
    myownmesh_core::engine::governance::propose(
        &alice_state,
        TransitionVariant::RoleGrant {
            target: carol_id.public_id().to_string(),
            role: Role::Member,
        },
        None,
    )
    .await
    .expect("propose member grant");

    // Carol lands in the OWNER's roster immediately (ratified + mirrored locally).
    wait_for(Duration::from_secs(10), || {
        rostered(&alice_state, carol_id.public_id())
    })
    .await;

    // The whole point: Carol converges into BOB's roster too — derived from
    // Alice's verified signed log — even though Carol is offline and only the
    // owner ever signed her in. Before signed membership, Bob could learn a
    // co-member only from live owner gossip; now the log carries it, complete.
    wait_for(Duration::from_secs(10), || {
        rostered(&bob_state, carol_id.public_id())
    })
    .await;
    assert_eq!(
        bob_state
            .governance_state
            .read()
            .role_of(carol_id.public_id()),
        Role::Member,
        "Carol must converge as a Member on Bob via the signed log alone"
    );
}

#[tokio::test]
async fn evict_converges_and_drops_the_member_on_a_gossip_peer() {
    // The lost/stolen-device kick must propagate. When the owner evicts a
    // member, every peer that learned that member *through gossip* (not by
    // ratifying the evict locally) has to drop it from its roster too, so the
    // device loses authorisation network-wide — not just on the owner. This is
    // the regression guard for the bug where the gossip-adopt path re-projected
    // roles but never removed the evicted row, so evicted devices lingered
    // (still authorised) on every co-member.
    shared_home();

    let broker = LocalBroker::new();
    let transport = Transport::new().expect("transport");
    let alice_id = Arc::new(Identity::ephemeral()); // owner
    let bob_id = Arc::new(Identity::ephemeral()); // co-member, online
    let carol_id = Arc::new(Identity::ephemeral()); // admitted then evicted, offline

    let network_id = "evict-gossip-net";
    let (alice_state, _ad) = spawn_network(
        fresh_network("alice", network_id),
        alice_id.clone(),
        transport.clone(),
    )
    .await
    .expect("alice engine");
    let (bob_state, _bd) = spawn_network(
        fresh_network("bob", network_id),
        bob_id.clone(),
        transport.clone(),
    )
    .await
    .expect("bob engine");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();
    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);

    wait_for_approval(&mut alice_events, bob_id.public_id()).await;
    wait_for_approval(&mut bob_events, alice_id.public_id()).await;
    cross_approve(&alice_state, &bob_state, &alice_id, &bob_id).await;

    // Found, then admit Carol into the signed member log (she never connects).
    myownmesh_core::engine::governance::propose(
        &alice_state,
        TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        },
        None,
    )
    .await
    .expect("propose close");
    wait_for(Duration::from_secs(10), || {
        alice_state.governance_state.read().kind == NetworkKind::Closed
            && bob_state.governance_state.read().kind == NetworkKind::Closed
    })
    .await;
    myownmesh_core::engine::governance::propose(
        &alice_state,
        TransitionVariant::RoleGrant {
            target: carol_id.public_id().to_string(),
            role: Role::Member,
        },
        None,
    )
    .await
    .expect("admit carol");

    // Carol converges into Bob's roster via the signed log — Bob only ever
    // learns her through gossip, never a direct connection.
    wait_for(Duration::from_secs(10), || {
        rostered(&bob_state, carol_id.public_id())
    })
    .await;

    // Alice evicts Carol (the propagating lost-device kick).
    myownmesh_core::engine::governance::propose(
        &alice_state,
        TransitionVariant::Evict {
            target: carol_id.public_id().to_string(),
        },
        None,
    )
    .await
    .expect("evict carol");

    // Gone on the owner (local ratify path already removed her)...
    wait_for(Duration::from_secs(10), || {
        !rostered(&alice_state, carol_id.public_id())
    })
    .await;
    // ...and — the fix — gone on Bob too, who learned the evict only via gossip.
    wait_for(Duration::from_secs(10), || {
        !rostered(&bob_state, carol_id.public_id())
    })
    .await;
    assert!(
        !rostered(&bob_state, carol_id.public_id()),
        "an evicted member must be dropped from a gossip peer's roster"
    );
    // The owner is still authorised on Bob (the prune keeps genuine members).
    assert!(
        rostered(&bob_state, alice_id.public_id()),
        "the owner must remain in the roster after an unrelated evict"
    );
}

#[tokio::test]
async fn manager_admits_a_member_which_converges_via_the_member_log() {
    // The two-key model end to end: an owner promotes a peer to **manager**
    // (Controller), and that manager — not just the owner — admits a member.
    // The admission rides the multi-writer **member log** (not the governance
    // log), and converges to the owner by union-merge even though the owner
    // never signed it. This is the cert chain in motion: the owner issues the
    // manager (governance log), the manager issues the member (member log).
    shared_home();

    let broker = LocalBroker::new();
    let transport = Transport::new().expect("transport");
    let alice_id = Arc::new(Identity::ephemeral()); // owner
    let bob_id = Arc::new(Identity::ephemeral()); // promoted to manager
    let dave_id = Arc::new(Identity::ephemeral()); // admitted by the manager, offline

    let network_id = "manager-admit-net";
    let (alice_state, _ad) = spawn_network(
        fresh_network("alice", network_id),
        alice_id.clone(),
        transport.clone(),
    )
    .await
    .expect("alice engine");
    let (bob_state, _bd) = spawn_network(
        fresh_network("bob", network_id),
        bob_id.clone(),
        transport.clone(),
    )
    .await
    .expect("bob engine");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();
    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);

    wait_for_approval(&mut alice_events, bob_id.public_id()).await;
    wait_for_approval(&mut bob_events, alice_id.public_id()).await;
    cross_approve(&alice_state, &bob_state, &alice_id, &bob_id).await;

    // Close: Alice founder-owner, Bob a member.
    // Alice founds the closed network with her lone signature; it ratifies on
    // her at once and converges to Bob (single-signer genesis needs no co-sign).
    myownmesh_core::engine::governance::propose(
        &alice_state,
        TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        },
        None,
    )
    .await
    .expect("propose close");
    wait_for(Duration::from_secs(10), || {
        alice_state.governance_state.read().kind == NetworkKind::Closed
            && bob_state.governance_state.read().kind == NetworkKind::Closed
    })
    .await;

    // Alice promotes Bob to manager (Controller) — owner-only authority. This
    // rides the governance log and converges to Bob.
    myownmesh_core::engine::governance::propose(
        &alice_state,
        TransitionVariant::RoleGrant {
            target: bob_id.public_id().to_string(),
            role: Role::Controller,
        },
        None,
    )
    .await
    .expect("grant controller");
    wait_for(Duration::from_secs(10), || {
        bob_state
            .governance_state
            .read()
            .role_of(bob_id.public_id())
            == Role::Controller
    })
    .await;

    // Bob — now a manager — admits Dave. Authority for a member grant is ≥1
    // controller/owner; Bob qualifies, so it ratifies on Bob alone and lands in
    // his MEMBER log (Dave need not be present).
    myownmesh_core::engine::governance::propose(
        &bob_state,
        TransitionVariant::RoleGrant {
            target: dave_id.public_id().to_string(),
            role: Role::Member,
        },
        None,
    )
    .await
    .expect("manager admits dave");
    wait_for(Duration::from_secs(10), || {
        rostered(&bob_state, dave_id.public_id())
    })
    .await;

    // The admission rode the member log, NOT the governance log.
    {
        let bob_view = bob_state.governance_state.read();
        assert!(
            bob_view.member_log.iter().any(|t| matches!(
                &t.variant,
                TransitionVariant::RoleGrant { target, role: Role::Member } if target == dave_id.public_id()
            )),
            "Dave's admit must be in the manager's member log"
        );
        assert!(
            !bob_view.transitions.iter().any(|t| matches!(
                &t.variant,
                TransitionVariant::RoleGrant { target, .. } if target == dave_id.public_id()
            )),
            "a manager's member admit must NOT extend the governance (owner) log"
        );
    }

    // And it converges to the OWNER by union-merge: Alice never signed Dave, yet
    // recognises Bob's manager-authored admission and surfaces Dave as a member.
    wait_for(Duration::from_secs(10), || {
        rostered(&alice_state, dave_id.public_id())
    })
    .await;
    assert_eq!(
        alice_state
            .governance_state
            .read()
            .role_of(dave_id.public_id()),
        Role::Member,
        "Dave converges as a Member on the owner via the union-merged member log"
    );
}

#[tokio::test]
async fn deny_invalidates_proposal_on_both_sides() {
    shared_home();

    let broker = LocalBroker::new();
    let transport = Transport::new().expect("transport");
    let alice_id = Arc::new(Identity::ephemeral()); // owner
    let bob_id = Arc::new(Identity::ephemeral()); // plain member
    let carol_id = Arc::new(Identity::ephemeral()); // whom Bob proposes to admit

    let network_id = "deny-test-net";
    let (alice_state, _ad) = spawn_network(
        fresh_network("alice", network_id),
        alice_id.clone(),
        transport.clone(),
    )
    .await
    .expect("alice engine");
    let (bob_state, _bd) = spawn_network(
        fresh_network("bob", network_id),
        bob_id.clone(),
        transport.clone(),
    )
    .await
    .expect("bob engine");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();

    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);

    wait_for_approval(&mut alice_events, bob_id.public_id()).await;
    wait_for_approval(&mut bob_events, alice_id.public_id()).await;

    cross_approve(&alice_state, &bob_state, &alice_id, &bob_id).await;

    // Found the fleet: Alice is owner, Bob a plain member.
    myownmesh_core::engine::governance::propose(
        &alice_state,
        TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        },
        None,
    )
    .await
    .expect("propose close");
    wait_for(Duration::from_secs(10), || {
        alice_state.governance_state.read().kind == NetworkKind::Closed
            && bob_state.governance_state.read().kind == NetworkKind::Closed
    })
    .await;

    // Bob is a member, so he has no authority to admit anyone — but a member
    // *may propose* an admission for an owner/manager to co-sign. Bob's lone
    // signature can't satisfy the "≥ 1 controller or owner" quorum, so his
    // proposal to admit Carol sits pending, up for Alice's decision.
    let proposal_id = myownmesh_core::engine::governance::propose(
        &bob_state,
        TransitionVariant::RoleGrant {
            target: carol_id.public_id().to_string(),
            role: Role::Member,
        },
        None,
    )
    .await
    .expect("bob proposes admitting carol");
    // It did NOT ratify on Bob — he lacks the authority to self-sign it.
    assert!(
        bob_state
            .governance_state
            .read()
            .pending
            .iter()
            .any(|p| p.id == proposal_id),
        "a member's admit proposal must stay pending, not self-ratify"
    );

    // It reaches Alice as a pending decision.
    wait_for(Duration::from_secs(10), || {
        alice_state
            .governance_state
            .read()
            .pending
            .iter()
            .any(|p| p.id == proposal_id)
    })
    .await;

    // Alice denies. The proposal should disappear from both sides on the next
    // ratification pass, and Carol must never be admitted.
    myownmesh_core::engine::governance::deny_proposal(&alice_state, &proposal_id)
        .await
        .expect("alice deny");

    wait_for(Duration::from_secs(10), || {
        let a = alice_state.governance_state.read();
        let b = bob_state.governance_state.read();
        a.pending.is_empty() && b.pending.is_empty()
    })
    .await;

    assert!(
        !rostered(&alice_state, carol_id.public_id()),
        "a denied admit must not add the target to the roster"
    );
    // The denied admit was recorded in neither tier of the log (a member admit
    // would ride the member log; only the genesis close should be present).
    {
        let a = alice_state.governance_state.read();
        assert_eq!(a.transitions.len(), 1, "only the genesis close is logged");
        assert!(
            a.member_log.is_empty(),
            "the denied admit must not ride the member log"
        );
    }
    assert!(bob_state.governance_state.read().member_log.is_empty());
}

#[tokio::test]
async fn re_admitting_an_evicted_member_supersedes_the_tombstone() {
    // Member-tier convergence is last-writer-wins on `at`. A re-admit that
    // follows an evict of the same device must supersede the tombstone even when
    // both are authored within the same wall-clock second — otherwise the evict
    // sticks and the re-invite silently no-ops. The engine stamps member-tier
    // authoring monotonically to guarantee this. Single engine: the owner
    // authors admit → evict → re-admit back to back, and we read the projected
    // membership (`roles`), which is where the tombstone would otherwise win.
    shared_home();

    let transport = Transport::new().expect("transport");
    let alice_id = Arc::new(Identity::ephemeral());
    let carol_id = Arc::new(Identity::ephemeral());
    let carol_pk = carol_id.public_id().to_string();

    let network_id = "re-admit-net";
    let (alice_state, _ad) = spawn_network(
        fresh_network("alice", network_id),
        alice_id.clone(),
        transport.clone(),
    )
    .await
    .expect("alice engine");

    use myownmesh_core::engine::governance::propose;
    propose(
        &alice_state,
        TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        },
        None,
    )
    .await
    .expect("found");
    propose(
        &alice_state,
        TransitionVariant::RoleGrant {
            target: carol_pk.clone(),
            role: Role::Member,
        },
        None,
    )
    .await
    .expect("admit");
    propose(
        &alice_state,
        TransitionVariant::Evict {
            target: carol_pk.clone(),
        },
        None,
    )
    .await
    .expect("evict");
    assert!(
        !alice_state
            .governance_state
            .read()
            .roles
            .contains_key(carol_pk.as_str()),
        "an evicted member must be absent from the projected membership"
    );
    propose(
        &alice_state,
        TransitionVariant::RoleGrant {
            target: carol_pk.clone(),
            role: Role::Member,
        },
        None,
    )
    .await
    .expect("re-admit");

    // Even authored back-to-back in the same wall-clock second, the re-admit
    // must win the member-tier LWW and put Carol back in the membership.
    assert!(
        alice_state
            .governance_state
            .read()
            .roles
            .contains_key(carol_pk.as_str()),
        "re-admitting an evicted member must supersede the tombstone"
    );
}

#[tokio::test]
async fn evicted_offline_device_learns_on_reconnect_and_stands_down() {
    // The "offline and lost devices just keep showing back up" loop, killed
    // end to end. Carol is admitted to the closed network and then evicted
    // while OFFLINE — she never hears the evict. When she comes back she
    // redials with a stale credential; before this fix, the handshake
    // treated her as a fresh face and (on an auto-approve network — every
    // fleet mesh) re-approved her, put her back in rosters on mutual
    // ACTIVE, and gossiped the resurrection. Now: the members' handshake
    // gate denies her WITH the signed log attached, she verifies her own
    // eviction through the standard strict-extension adoption (the owner's
    // signatures are the authority, not the denier), flips to stood-down,
    // and nobody's roster ever re-admits her.
    shared_home();

    let broker = LocalBroker::new();
    let transport = Transport::new().expect("transport");
    let alice_id = Arc::new(Identity::ephemeral()); // owner
    let bob_id = Arc::new(Identity::ephemeral()); // co-member, online
    let carol_id = Arc::new(Identity::ephemeral()); // evicted while offline

    let network_id = "evict-deny-proof-net";
    let (alice_state, _ad) = spawn_network(
        fresh_network("alice", network_id),
        alice_id.clone(),
        transport.clone(),
    )
    .await
    .expect("alice engine");
    let (bob_state, _bd) = spawn_network(
        fresh_network("bob", network_id),
        bob_id.clone(),
        transport.clone(),
    )
    .await
    .expect("bob engine");
    // Carol's engine is SPAWNED now (so she holds a clean, empty in-memory
    // governance state — the test home's shared on-disk state must not
    // leak her own eviction to her) but only ATTACHED to signaling after
    // the eviction: spawned-but-unattached is this harness's "offline".
    let (carol_state, _cd) = spawn_network(
        fresh_network("carol", network_id),
        carol_id.clone(),
        transport.clone(),
    )
    .await
    .expect("carol engine");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();
    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);

    wait_for_approval(&mut alice_events, bob_id.public_id()).await;
    wait_for_approval(&mut bob_events, alice_id.public_id()).await;
    cross_approve(&alice_state, &bob_state, &alice_id, &bob_id).await;

    use myownmesh_core::engine::governance::propose;
    propose(
        &alice_state,
        TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        },
        None,
    )
    .await
    .expect("found");
    wait_for(Duration::from_secs(10), || {
        alice_state.governance_state.read().kind == NetworkKind::Closed
            && bob_state.governance_state.read().kind == NetworkKind::Closed
    })
    .await;
    propose(
        &alice_state,
        TransitionVariant::RoleGrant {
            target: carol_id.public_id().to_string(),
            role: Role::Member,
        },
        None,
    )
    .await
    .expect("admit carol");
    wait_for(Duration::from_secs(10), || {
        rostered(&bob_state, carol_id.public_id())
    })
    .await;
    propose(
        &alice_state,
        TransitionVariant::Evict {
            target: carol_id.public_id().to_string(),
        },
        None,
    )
    .await
    .expect("evict carol while she is offline");
    wait_for(Duration::from_secs(10), || {
        !rostered(&alice_state, carol_id.public_id()) && !rostered(&bob_state, carol_id.public_id())
    })
    .await;

    // Carol comes back online, clueless, and redials the mesh.
    attach_local(&carol_state, &broker);

    // She learns: some member's handshake denies her with the signed log,
    // she adopts it (strict extension over her empty log), and the
    // verified verdict stands her down.
    wait_for(Duration::from_secs(20), || {
        carol_state
            .self_evicted
            .load(std::sync::atomic::Ordering::SeqCst)
    })
    .await;
    assert!(
        carol_state
            .self_evicted
            .load(std::sync::atomic::Ordering::SeqCst),
        "the denied device must adopt the eviction proof and stand down"
    );

    // And the resurrection is dead: give the mesh a few more announce/
    // gossip beats — nobody re-admits her, on either member.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        !rostered(&alice_state, carol_id.public_id()),
        "an evicted device redialing must not re-enter the owner's roster"
    );
    assert!(
        !rostered(&bob_state, carol_id.public_id()),
        "an evicted device redialing must not re-enter a member's roster"
    );
    // Her own roster view keeps whatever she had; the flag is what stands
    // her down — and the signed logs she adopted agree she is out.
    let verdict = {
        let gov = carol_state.governance_state.read();
        myownmesh_core::network_state::member_log_removed(&gov, &gov.member_log, network_id)
            .contains(carol_id.public_id())
    };
    assert!(
        verdict,
        "carol's own adopted (verified) state must carry her eviction"
    );
}

#[tokio::test]
async fn two_owners_converge_their_rosters() {
    // The reported symptom, inverted into a guarantee: a fleet with two owners
    // where the rosters never converge and only one behaves like the "real"
    // owner. With flat peer authority (any owner is a full owner), an
    // order-independent governance log (both recognise the same shared prefix
    // regardless of ack order), and the union-merged member tier, the two owners
    // must each recognise the other, and a member admitted by *either* must
    // appear on *both*.
    shared_home();

    let broker = LocalBroker::new();
    let transport = Transport::new().expect("transport");
    let alice_id = Arc::new(Identity::ephemeral()); // founder-owner
    let bob_id = Arc::new(Identity::ephemeral()); // promoted to a second owner
    let carol_id = Arc::new(Identity::ephemeral()); // admitted by Alice, offline
    let dave_id = Arc::new(Identity::ephemeral()); // admitted by Bob, offline

    let network_id = "two-owner-net";
    let (alice_state, _ad) = spawn_network(
        fresh_network("alice", network_id),
        alice_id.clone(),
        transport.clone(),
    )
    .await
    .expect("alice engine");
    let (bob_state, _bd) = spawn_network(
        fresh_network("bob", network_id),
        bob_id.clone(),
        transport.clone(),
    )
    .await
    .expect("bob engine");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();
    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);
    wait_for_approval(&mut alice_events, bob_id.public_id()).await;
    wait_for_approval(&mut bob_events, alice_id.public_id()).await;
    cross_approve(&alice_state, &bob_state, &alice_id, &bob_id).await;

    use myownmesh_core::engine::governance::propose;
    // Alice founds; then promotes Bob to a *second owner* — peer authority, so a
    // single owner's signature suffices (no unanimous round to stall on).
    propose(
        &alice_state,
        TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        },
        None,
    )
    .await
    .expect("found");
    wait_for(Duration::from_secs(10), || {
        alice_state.governance_state.read().kind == NetworkKind::Closed
            && bob_state.governance_state.read().kind == NetworkKind::Closed
    })
    .await;
    propose(
        &alice_state,
        TransitionVariant::RoleGrant {
            target: bob_id.public_id().to_string(),
            role: Role::Owner,
        },
        None,
    )
    .await
    .expect("grant bob owner");

    // Both sides must agree Bob is a *full* owner — not just on Alice's view.
    // (This is the "only one acts like the real owner" half of the symptom.)
    wait_for(Duration::from_secs(10), || {
        alice_state
            .governance_state
            .read()
            .role_of(bob_id.public_id())
            == Role::Owner
            && bob_state
                .governance_state
                .read()
                .role_of(bob_id.public_id())
                == Role::Owner
    })
    .await;

    // Each owner independently admits a different member (both offline).
    propose(
        &alice_state,
        TransitionVariant::RoleGrant {
            target: carol_id.public_id().to_string(),
            role: Role::Member,
        },
        None,
    )
    .await
    .expect("alice admits carol");
    propose(
        &bob_state,
        TransitionVariant::RoleGrant {
            target: dave_id.public_id().to_string(),
            role: Role::Member,
        },
        None,
    )
    .await
    .expect("bob admits dave");

    // The union-merged member log must converge: BOTH owners end up holding BOTH
    // members. This is the "rosters never converge between the two owners"
    // symptom turned into a passing assertion.
    wait_for(Duration::from_secs(15), || {
        rostered(&alice_state, carol_id.public_id())
            && rostered(&alice_state, dave_id.public_id())
            && rostered(&bob_state, carol_id.public_id())
            && rostered(&bob_state, dave_id.public_id())
    })
    .await;
    assert!(
        rostered(&alice_state, dave_id.public_id()),
        "Alice must see the member Bob admitted"
    );
    assert!(
        rostered(&bob_state, carol_id.public_id()),
        "Bob must see the member Alice admitted"
    );
}

// ---- helpers --------------------------------------------------------

#[tokio::test]
async fn owner_signed_topology_converges_and_reshapes_both_nodes() {
    shared_home();

    let broker = LocalBroker::new();
    let transport = Transport::new().expect("transport");

    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());

    let network_id = "governed-topology-net";
    let (alice_state, _alice_driver) = spawn_network(
        fresh_network("alice", network_id),
        alice_id.clone(),
        transport.clone(),
    )
    .await
    .expect("alice engine");
    let (bob_state, _bob_driver) = spawn_network(
        fresh_network("bob", network_id),
        bob_id.clone(),
        transport.clone(),
    )
    .await
    .expect("bob engine");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();
    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);
    wait_for_approval(&mut alice_events, bob_id.public_id()).await;
    wait_for_approval(&mut bob_events, alice_id.public_id()).await;
    cross_approve(&alice_state, &bob_state, &alice_id, &bob_id).await;

    // Close the network — Alice self-elects founder-owner.
    myownmesh_core::engine::governance::propose(
        &alice_state,
        TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        },
        None,
    )
    .await
    .expect("close proposal");
    wait_for(Duration::from_secs(10), || {
        alice_state.governance_state.read().kind == NetworkKind::Closed
            && bob_state.governance_state.read().kind == NetworkKind::Closed
    })
    .await;

    // The owner designates herself the network's infra hub. One signed
    // transition carries the whole shape (mode + hub set + redundancy).
    let governed = TopologyMode::Hubs {
        hubs: vec![alice_id.public_id().to_string()],
        spoke_redundancy: Some(1),
    };
    myownmesh_core::engine::governance::propose(
        &alice_state,
        TransitionVariant::TopologyChange {
            to: governed.clone(),
        },
        None,
    )
    .await
    .expect("topology proposal");

    // Both governance views AND both runtime selectors converge — Bob
    // never signs anything; adopting the extended log reshapes him.
    wait_for(Duration::from_secs(10), || {
        alice_state.governance_state.read().topology.as_ref() == Some(&governed)
            && bob_state.governance_state.read().topology.as_ref() == Some(&governed)
            && *alice_state.topology.read() == governed
            && *bob_state.topology.read() == governed
    })
    .await;

    // The governed log re-verifies from scratch — what a third node
    // joining later replays to learn the shape with zero prior trust.
    myownmesh_core::network_state::verify_log(
        network_id,
        &alice_state.governance_state.read().transitions,
    )
    .expect("governed log re-verifies standalone");

    // Backstop: a manual local SetTopology on a governed network is
    // ignored — one device can't fork itself off the owner's shape.
    bob_state
        .cmd_tx
        .send(myownmesh_core::engine::state::NetworkCmd::SetTopology(
            TopologyMode::FullMesh,
        ))
        .expect("send local set");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        *bob_state.topology.read(),
        governed,
        "local topology set must not override the governed shape"
    );
}

async fn wait_for_approval(rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>, peer_id: &str) {
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
                return;
            }
            _ => continue,
        }
    }
}

async fn wait_for(timeout: Duration, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("wait_for predicate never satisfied within {timeout:?}");
}

/// Whether `id` is in `state`'s on-disk roster — i.e. authorised membership.
fn rostered(state: &Arc<myownmesh_core::engine::state::NetworkState>, id: &str) -> bool {
    myownmesh_core::roster::is_authorized(&state.roster.read(), id)
}

/// All tests in this file share ONE `MYOWNMESH_HOME` for the process lifetime.
/// Each `#[tokio::test]` runs on its own thread, but `MYOWNMESH_HOME` is a
/// process-global env var — per-test tempdirs would clobber each other, and
/// when one test's tempdir drops, another test's `network_state::save` writes
/// under a path that no longer exists (a flaky `NotFound`). A single
/// process-lifetime tempdir, set idempotently by every test, plus distinct
/// per-test `network_id`s, keeps state files apart without the env-var race.
fn shared_home() {
    use std::sync::OnceLock;
    static HOME: OnceLock<tempfile::TempDir> = OnceLock::new();
    let dir = HOME.get_or_init(|| tempfile::tempdir().expect("tempdir"));
    std::env::set_var("MYOWNMESH_HOME", dir.path());
}
