//! End-to-end engine integration test: closed-network governance.
//!
//! Two peers handshake through an in-process LocalBroker, exchange
//! a `KindChange { to: Closed }` proposal across the wire, ratify
//! it once both sides sign, and end with matching signed
//! transition logs + the proposer (Alice) installed as founder
//! owner on both sides.
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
async fn two_peers_ratify_open_to_closed_transition() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("MYOWNMESH_HOME", tmp.path());

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

    // Stamp each peer into the other's roster so the open→closed
    // quorum has a real member set to evaluate against.
    cross_approve(&alice_state, &bob_state, &alice_id, &bob_id).await;

    // Sanity: both sides start in `Open` with no transitions logged.
    assert_eq!(alice_state.governance_state.read().kind, NetworkKind::Open);
    assert_eq!(bob_state.governance_state.read().kind, NetworkKind::Open);
    assert!(alice_state.governance_state.read().transitions.is_empty());

    // Alice proposes `KindChange { to: Closed }`. The proposer also
    // signs at issue time, so this is one signature so far.
    let proposal_id = myownmesh_core::engine::governance::propose(
        &alice_state,
        TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        },
        None,
    )
    .await
    .expect("propose");

    // The proposal should land in Bob's pending list via the
    // `NetworkStatePropose` broadcast.
    wait_for(Duration::from_secs(10), || {
        bob_state
            .governance_state
            .read()
            .pending
            .iter()
            .any(|p| p.id == proposal_id)
    })
    .await;

    // Bob signs → unanimous-of-members quorum is satisfied →
    // the engine ratifies + applies + broadcasts the new state.
    myownmesh_core::engine::governance::sign_proposal(&bob_state, &proposal_id, None)
        .await
        .expect("bob sign");

    // Wait until both sides see the ratified transition.
    wait_for(Duration::from_secs(10), || {
        alice_state.governance_state.read().kind == NetworkKind::Closed
            && bob_state.governance_state.read().kind == NetworkKind::Closed
    })
    .await;

    // Founder election: Alice (the proposer) is now Owner; Bob is
    // a co-signer, so he's still Member.
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
        "bob is a co-signer, not an owner"
    );
    assert_eq!(
        bob_view.role_of(bob_id.public_id()),
        Role::Member,
        "bob's own view agrees: still member"
    );

    // Both transition logs should have one entry (the close).
    assert_eq!(alice_view.transitions.len(), 1);
    assert_eq!(bob_view.transitions.len(), 1);
    // And the proposal should have left the pending list on both
    // sides.
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

    // Both transitions should carry the same signer set + matching
    // variant — the signed log is byte-identical across peers when
    // the close ratifies cleanly.
    assert_eq!(
        alice_view.transitions[0].variant,
        bob_view.transitions[0].variant
    );
    let mut alice_signers = alice_view.transitions[0].signers.clone();
    let mut bob_signers = bob_view.transitions[0].signers.clone();
    alice_signers.sort();
    bob_signers.sort();
    assert_eq!(
        alice_signers, bob_signers,
        "both peers' transition log entries should record the same signer set\n\
         alice = {:?}\n\
         bob   = {:?}",
        alice_view.transitions[0], bob_view.transitions[0],
    );
    assert_eq!(alice_signers.len(), 2, "alice + bob both signed");
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
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("MYOWNMESH_HOME", tmp.path());

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
    let close = myownmesh_core::engine::governance::propose(
        &alice_state,
        TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        },
        None,
    )
    .await
    .expect("propose close");
    wait_for(Duration::from_secs(10), || {
        bob_state
            .governance_state
            .read()
            .pending
            .iter()
            .any(|p| p.id == close)
    })
    .await;
    myownmesh_core::engine::governance::sign_proposal(&bob_state, &close, None)
        .await
        .expect("bob sign close");
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
async fn manager_admits_a_member_which_converges_via_the_member_log() {
    // The two-key model end to end: an owner promotes a peer to **manager**
    // (Controller), and that manager — not just the owner — admits a member.
    // The admission rides the multi-writer **member log** (not the governance
    // log), and converges to the owner by union-merge even though the owner
    // never signed it. This is the cert chain in motion: the owner issues the
    // manager (governance log), the manager issues the member (member log).
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("MYOWNMESH_HOME", tmp.path());

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
    let close = myownmesh_core::engine::governance::propose(
        &alice_state,
        TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        },
        None,
    )
    .await
    .expect("propose close");
    wait_for(Duration::from_secs(10), || {
        bob_state
            .governance_state
            .read()
            .pending
            .iter()
            .any(|p| p.id == close)
    })
    .await;
    myownmesh_core::engine::governance::sign_proposal(&bob_state, &close, None)
        .await
        .expect("bob sign close");
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
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("MYOWNMESH_HOME", tmp.path());

    let broker = LocalBroker::new();
    let transport = Transport::new().expect("transport");
    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());

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

    let proposal_id = myownmesh_core::engine::governance::propose(
        &alice_state,
        TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        },
        None,
    )
    .await
    .expect("propose");

    wait_for(Duration::from_secs(10), || {
        bob_state
            .governance_state
            .read()
            .pending
            .iter()
            .any(|p| p.id == proposal_id)
    })
    .await;

    // Bob denies. The proposal should disappear from both sides on
    // the next ratification pass.
    myownmesh_core::engine::governance::deny_proposal(&bob_state, &proposal_id)
        .await
        .expect("bob deny");

    wait_for(Duration::from_secs(10), || {
        let a = alice_state.governance_state.read();
        let b = bob_state.governance_state.read();
        a.pending.is_empty() && b.pending.is_empty()
    })
    .await;

    // The network kind must NOT have transitioned to Closed —
    // deny is a hard kill switch.
    assert_eq!(alice_state.governance_state.read().kind, NetworkKind::Open);
    assert_eq!(bob_state.governance_state.read().kind, NetworkKind::Open);
    // And the transition log stays empty.
    assert!(alice_state.governance_state.read().transitions.is_empty());
    assert!(bob_state.governance_state.read().transitions.is_empty());
}

// ---- helpers --------------------------------------------------------

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
