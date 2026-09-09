#![cfg(feature = "transport-lab")]

//! Native LocalBroker pair controls: permissionless Open and Closed signed
//! onboarding. Exact owners shut down before behavioral assertions.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{
    ClosedRelayPolicyConfig, NetworkConfig, NetworkKind, RoutingPolicyConfig, SignalingConfig,
    TopologyMode,
};
use myownmesh_core::engine::transport_lab::{
    attach_local, capture_transport_channel, channel, create_network_in_instance_root,
    import_network_in_instance_root, proof_owner_for_device, spawn_network_in_instance_root,
    NetworkState,
};
use myownmesh_core::identity::Identity;
use myownmesh_core::semantic::{Role, VerifiedProjectPolicy};
use myownmesh_core::{Channel, MeshEvent, PeerEvent};
use myownmesh_signaling::local::LocalBroker;
use tokio::time::Instant;

fn fresh_network(id: &str) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: format!("two-peer-test-{id}"),
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
        application_transport: None,
        tree: None,
        signaling: SignalingConfig::default(),
        closed_relay: ClosedRelayPolicyConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        pinned_peers: Vec::new(),
        auto_approve: false,
    }
}

type Driver = (Arc<NetworkState>, tokio::task::JoinHandle<()>);

/// Instance-owned network stores do not select custody's process-wide home.
/// Run each exact native case in its own process so the real custody gate
/// reads only fresh test-owned state, without changing the parent's environment.
async fn isolated_native_case(selector: &str, work: impl Future<Output = ()>) {
    const CHILD_SELECTOR: &str = "MYOWNMESH_TWO_PEER_CHILD_SELECTOR";
    const CHILD_HOME: &str = "MYOWNMESH_TWO_PEER_CHILD_HOME";
    const COMPLETED: &str = "native-case-completed";
    if let Some(selected) = std::env::var_os(CHILD_SELECTOR) {
        assert_eq!(
            selected,
            std::ffi::OsStr::new(selector),
            "wrong child selector"
        );
        let home =
            std::path::PathBuf::from(std::env::var_os(CHILD_HOME).expect("child-owned home"));
        assert!(
            home.is_absolute() && home.is_dir(),
            "child home must exist and be absolute"
        );
        assert_eq!(
            std::env::var_os("MYOWNMESH_HOME"),
            Some(home.clone().into_os_string())
        );
        // Do not load, repair, or relax custody data. A fresh unenrolled home
        // exercises the ordinary custody::require path as shipped.
        work.await;
        std::fs::write(home.join(COMPLETED), selector.as_bytes()).expect("child completion marker");
        return;
    }

    let home = tempfile::tempdir().expect("isolated process home");
    let home_path = home
        .path()
        .canonicalize()
        .expect("absolute isolated process home");
    let mut command =
        tokio::process::Command::new(std::env::current_exe().expect("test executable"));
    command
        .args(["--exact", selector, "--nocapture", "--test-threads=1"])
        .env("MYOWNMESH_HOME", &home_path)
        .env(CHILD_SELECTOR, selector)
        .env(CHILD_HOME, &home_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.as_std_mut().creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let mut child = command.spawn().expect("spawn exact isolated native case");
    // This is an outer process backstop, not an extension/reset of any native
    // stage's original absolute deadline or its ten-second owner join fence.
    let deadline = Instant::now() + Duration::from_secs(120);
    let status = match tokio::time::timeout_at(deadline, child.wait()).await {
        Ok(status) => status.expect("reap native case"),
        Err(_) => {
            let killed = child.start_kill();
            let reaped = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
            panic!("native child deadline expired; kill={killed:?}, reap={reaped:?}");
        }
    };
    assert!(
        Instant::now() <= deadline,
        "native child completed after deadline"
    );
    assert!(status.success(), "isolated native case failed: {status}");
    assert_eq!(
        std::fs::read(home_path.join(COMPLETED))
            .expect("native body completed, not zero selected tests"),
        selector.as_bytes(),
    );
}

fn require(condition: bool, reason: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(reason.to_string())
    }
}

/// A ready result polled after the absolute deadline is not a timely result.
async fn within<T>(deadline: Instant, work: impl Future<Output = T>) -> Result<T, String> {
    let value = tokio::time::timeout_at(deadline, work)
        .await
        .map_err(|_| "absolute stage deadline expired".to_string())?;
    require(
        Instant::now() <= deadline,
        "stage completed after its absolute deadline",
    )?;
    Ok(value)
}

/// Request both retirements first. Timeout/abort is failure, not proof of native cleanup.
async fn shutdown_drivers(drivers: Vec<Driver>) -> Result<(), String> {
    for (state, _) in &drivers {
        state.request_shutdown();
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut failures = Vec::new();
    for (_, mut driver) in drivers {
        match tokio::time::timeout_at(deadline, &mut driver).await {
            Ok(Ok(())) if Instant::now() <= deadline => {}
            Ok(result) => failures.push(format!("late or failed driver shutdown: {result:?}")),
            Err(_) => {
                driver.abort();
                let terminal = tokio::time::timeout(Duration::from_secs(1), &mut driver).await;
                failures.push(format!(
                    "native shutdown deadline expired; driver abort: {terminal:?}"
                ));
            }
        }
    }
    require(failures.is_empty(), &failures.join("; "))
}

async fn wait_for_peer(
    rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
    peer_id: &str,
    need_authentication: bool,
    need_activation: bool,
    deadline: Instant,
) -> Result<(), String> {
    let mut authenticated = !need_authentication;
    let mut approved = !need_activation;
    while !authenticated || !approved {
        match within(deadline, rx.recv())
            .await?
            .map_err(|e| e.to_string())?
        {
            MeshEvent::Peer(PeerEvent::Authenticated { device_id, .. }) if device_id == peer_id => {
                authenticated = true;
            }
            MeshEvent::Peer(PeerEvent::Approved { device_id, .. }) if device_id == peer_id => {
                approved = true;
            }
            _ => {}
        }
    }
    Ok(())
}

fn open_ledger_empty(state: &NetworkState) -> Result<(), String> {
    require(
        matches!(state.verified_policy(), VerifiedProjectPolicy::Open),
        "expected Open bootstrap",
    )?;
    require(
        state.semantic_fact_count() == 0,
        "Open participation retained a semantic fact",
    )?;
    require(
        state.semantic_unresolved_count() == 0,
        "Open participation retained quarantine",
    )?;
    require(
        state.semantic_provisional_custody_count() == 0,
        "Open participation retained provisional custody",
    )
}

/// Failure-only, fixed two-endpoint observations. Never print PeerInfo (it
/// contains identities/codes/metadata), signed bodies, keys, or native data.
/// Separate locks mean this is a local observation, not an atomic snapshot.
fn closed_failure_snapshot(state: &Arc<NetworkState>, local: &str, remote: &str) -> String {
    let roles = {
        let roster = state.roster.read();
        [local, remote].map(|id| {
            roster
                .authorized_devices
                .iter()
                .find(|peer| peer.device_id == myownmesh_core::signing::pubkey_part(id))
                .map(|peer| peer.role)
        })
    };
    let peer_phase = state
        .peer_snapshot()
        .into_iter()
        .find(|peer| peer.device_id == remote)
        .map(|peer| {
            (
                peer.status,
                peer.authenticated,
                peer.local_approve_sent,
                peer.remote_approve_seen,
            )
        });
    let owner = proof_owner_for_device(state, remote);
    let current_worker = owner
        .as_ref()
        .and_then(|owner| capture_transport_channel(state, owner))
        .is_some();
    format!(
        "facts={} unresolved={} provisional={} role_cache_local_remote={roles:?} canonical_pair_admitted={} peer_phase_auth_local_approve_remote_approve={peer_phase:?} owner_present={} owner_current_with_worker={current_worker}",
        state.semantic_fact_count(), state.semantic_unresolved_count(),
        state.semantic_provisional_custody_count(), state.is_rostered(remote), owner.is_some(),
    )
}

/// Native pre-fix discriminator: both configurations disable auto_approve;
/// no manual Approve is issued. The real signed handshake must suffice.
#[tokio::test]
async fn two_peers_handshake_and_exchange_channel_message() {
    isolated_native_case(
        "two_peers_handshake_and_exchange_channel_message",
        open_pair_case(),
    )
    .await;
}

async fn open_pair_case() {
    let alice_root = tempfile::tempdir().expect("alice root");
    let bob_root = tempfile::tempdir().expect("bob root");
    let broker = LocalBroker::new();
    let transport = support::test_transport();
    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());
    let mut alice_cfg = fresh_network("alice");
    let mut bob_cfg = fresh_network("bob");
    alice_cfg.network_id = "two-peer-handshake".into();
    bob_cfg.network_id = alice_cfg.network_id.clone();
    assert!(!alice_cfg.auto_approve && !bob_cfg.auto_approve);
    let alice = spawn_network_in_instance_root(
        alice_cfg.clone(),
        alice_id.clone(),
        transport.clone(),
        alice_root.path().to_path_buf(),
    )
    .await
    .expect("alice engine");
    let bob_result = spawn_network_in_instance_root(
        bob_cfg.clone(),
        bob_id.clone(),
        transport.clone(),
        bob_root.path().to_path_buf(),
    )
    .await;
    let bob = match bob_result {
        Ok(bob) => bob,
        Err(error) => {
            let cleanup = shutdown_drivers(vec![alice]).await;
            panic!("bob startup failed: {error}; cleanup: {cleanup:?}");
        }
    };
    let result: Result<(), String> = async {
        open_ledger_empty(&alice.0)?;
        open_ledger_empty(&bob.0)?;
        require(
            alice.0.mesh_context_id() == bob.0.mesh_context_id(),
            "exact Open contexts differ",
        )?;
        let mut alice_events = alice.0.events_tx.subscribe();
        let mut bob_events = bob.0.events_tx.subscribe();
        let deadline = Instant::now() + Duration::from_secs(20);
        attach_local(&alice.0, &broker);
        attach_local(&bob.0, &broker);
        // Observe both completed facts; neither event is manual permission.
        wait_for_peer(&mut alice_events, bob_id.public_id(), true, true, deadline).await?;
        wait_for_peer(&mut bob_events, alice_id.public_id(), true, true, deadline).await?;
        let alice_chan: Channel<String> = channel("greetings".into(), alice.0.clone());
        let bob_chan: Channel<String> = channel("greetings".into(), bob.0.clone());
        let mut bob_sub = bob_chan.subscribe().map_err(|e| e.to_string())?;
        let mut alice_sub = alice_chan.subscribe().map_err(|e| e.to_string())?;
        let deadline = Instant::now() + Duration::from_secs(10);
        within(
            deadline,
            alice_chan.send_to(bob_id.public_id(), &"hello from alice".to_string()),
        )
        .await?
        .map_err(|e| e.to_string())?;
        let msg = within(deadline, bob_sub.recv())
            .await?
            .ok_or("bob subscription closed")?
            .map_err(|e| e.to_string())?;
        require(
            msg.from() == alice_id.public_id() && msg.body().as_str() == "hello from alice",
            "wrong Alice payload",
        )?;
        let deadline = Instant::now() + Duration::from_secs(10);
        within(
            deadline,
            bob_chan.send_to(alice_id.public_id(), &"hi back".to_string()),
        )
        .await?
        .map_err(|e| e.to_string())?;
        let msg = within(deadline, alice_sub.recv())
            .await?
            .ok_or("alice subscription closed")?
            .map_err(|e| e.to_string())?;
        require(
            msg.from() == bob_id.public_id() && msg.body().as_str() == "hi back",
            "wrong Bob payload",
        )?;
        open_ledger_empty(&alice.0)?;
        open_ledger_empty(&bob.0)?;
        Ok(())
    }
    .await;
    let cleanup = shutdown_drivers(vec![alice, bob]).await;
    assert!(cleanup.is_ok(), "{cleanup:?}; result: {result:?}");
    assert!(result.is_ok(), "{result:?}");

    // Same-home canonical restore, without signaling or additional facts.
    for (cfg, identity, root) in [
        (alice_cfg, alice_id, alice_root.path()),
        (bob_cfg, bob_id, bob_root.path()),
    ] {
        let reopened =
            spawn_network_in_instance_root(cfg, identity, transport.clone(), root.to_path_buf())
                .await
                .expect("same-home Open restore");
        let restored = open_ledger_empty(&reopened.0);
        let cleanup = shutdown_drivers(vec![reopened]).await;
        assert!(cleanup.is_ok(), "{cleanup:?}; restored: {restored:?}");
        assert!(restored.is_ok(), "{restored:?}");
    }
}

/// Closed signed governance supplies the negative, not obsolete Open pair
/// permission. The SAME native pair delivers after Bob's root-signed grant.
#[tokio::test]
async fn application_payload_is_refused_before_approval_then_delivered_after_approval() {
    isolated_native_case(
        "application_payload_is_refused_before_approval_then_delivered_after_approval",
        closed_pair_case(),
    )
    .await;
}

async fn closed_pair_case() {
    let alice_root = tempfile::tempdir().expect("alice root");
    let bob_root = tempfile::tempdir().expect("bob root");
    let broker = LocalBroker::new();
    let transport = support::test_transport();
    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());
    let mut alice_cfg = fresh_network("closed-alice");
    let mut bob_cfg = fresh_network("closed-bob");
    alice_cfg.network_id = "two-peer-closed-admission".into();
    bob_cfg.network_id = alice_cfg.network_id.clone();
    alice_cfg.kind = NetworkKind::Closed;
    bob_cfg.kind = NetworkKind::Closed;
    // Unchanged Closed auto-approval cannot supply an absent governance role.
    alice_cfg.auto_approve = true;
    bob_cfg.auto_approve = true;
    let alice = create_network_in_instance_root(
        alice_cfg,
        alice_id.clone(),
        transport.clone(),
        alice_root.path().to_path_buf(),
        [0x76; 32],
    )
    .await
    .expect("Closed creator");
    let bob_result = import_network_in_instance_root(
        bob_cfg,
        bob_id.clone(),
        transport,
        bob_root.path().to_path_buf(),
        alice.0.mesh_context_id(),
        alice.0.verified_bootstrap_record().clone(),
    )
    .await;
    let bob = match bob_result {
        Ok(bob) => bob,
        Err(error) => {
            let cleanup = shutdown_drivers(vec![alice]).await;
            panic!("Closed import failed: {error}; cleanup: {cleanup:?}");
        }
    };
    let mut stage = "closed.preconditions";
    let result: Result<(), String> = async {
        require(
            matches!(alice.0.verified_policy(), VerifiedProjectPolicy::Closed(_)),
            "expected Closed bootstrap",
        )?;
        require(
            alice.0.verified_bootstrap_record() == bob.0.verified_bootstrap_record(),
            "Closed bootstrap differs",
        )?;
        let mut alice_events = alice.0.events_tx.subscribe();
        let mut bob_events = bob.0.events_tx.subscribe();
        let deadline = Instant::now() + Duration::from_secs(20);
        attach_local(&alice.0, &broker);
        attach_local(&bob.0, &broker);
        stage = "closed.authenticate.alice_observes_bob";
        wait_for_peer(&mut alice_events, bob_id.public_id(), true, false, deadline).await?;
        stage = "closed.authenticate.bob_observes_alice";
        wait_for_peer(&mut bob_events, alice_id.public_id(), true, false, deadline).await?;
        stage = "closed.pregrant.preconditions";
        require(
            alice.0.semantic_fact_count() == 0 && bob.0.semantic_fact_count() == 0,
            "unexpected pre-grant facts",
        )?;
        require(
            !alice.0.is_rostered(bob_id.public_id())
                && !bob.0.is_rostered(alice_id.public_id()),
            "the authenticated pair must lack canonical Closed admission before the grant",
        )?;
        let alice_chan: Channel<String> = channel("closed-admission".into(), alice.0.clone());
        let bob_chan: Channel<String> = channel("closed-admission".into(), bob.0.clone());
        let mut bob_sub = bob_chan.subscribe().map_err(|e| e.to_string())?;
        stage = "closed.pregrant.send_refused";
        let refusal = within(
            Instant::now() + Duration::from_secs(10),
            alice_chan.send_to(bob_id.public_id(), &"must not cross".to_string()),
        )
        .await?;
        // The current send path filters unadmitted direct owners before
        // lending, then routes over only usable canonical sessions. This
        // two-node FullMesh has none before the grant: the precise refusal is
        // NoRoute, not the direct lender's later no-live-session error. Do not
        // accept pressure, an unknown write outcome, or arbitrary failure.
        require(
            matches!(&refusal, Err(myownmesh_core::ChannelError::Transport(message))
                if message == "network: routed frame refused: topology returned no usable next hop"),
            &format!("pre-grant send lacked exact Closed no-route refusal: {refusal:?}"),
        )?;
        stage = "closed.pregrant.no_subscriber_delivery";
        require(
            tokio::time::timeout_at(Instant::now() + Duration::from_millis(200), bob_sub.recv())
                .await
                .is_err(),
            "refused payload reached subscriber",
        )?;
        let deadline = Instant::now() + Duration::from_secs(20);
        stage = "closed.grant.propose_and_publish";
        within(
            deadline,
            myownmesh_core::engine::governance::propose_role_grant(
                &alice.0,
                bob_id.public_id(),
                Role::Member,
                None,
            ),
        )
        .await?
        .map_err(|e| e.to_string())?;
        stage = "closed.approval.alice_observes_bob";
        wait_for_peer(&mut alice_events, bob_id.public_id(), false, true, deadline).await?;
        stage = "closed.approval.bob_observes_alice";
        wait_for_peer(&mut bob_events, alice_id.public_id(), false, true, deadline).await?;
        stage = "closed.postgrant.canonical_projection";
        require(
            alice.0.semantic_fact_count() == 1 && bob.0.semantic_fact_count() == 1,
            "same signed grant not retained at both endpoints",
        )?;
        require(
            bob.0.is_rostered(bob_id.public_id()),
            "Bob lacks canonical member projection",
        )?;
        for state in [&alice.0, &bob.0] {
            let role = state
                .roster
                .read()
                .authorized_devices
                .iter()
                .find(|peer| {
                    peer.device_id == myownmesh_core::signing::pubkey_part(bob_id.public_id())
                })
                .map(|peer| peer.role);
            require(
                role == Some(Role::Member),
                "Bob's canonical role is not Member",
            )?;
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        stage = "closed.body.send";
        within(
            deadline,
            alice_chan.send_to(bob_id.public_id(), &"approved payload".to_string()),
        )
        .await?
        .map_err(|e| e.to_string())?;
        stage = "closed.body.receive_and_validate";
        let delivered = within(deadline, bob_sub.recv())
            .await?
            .ok_or("Closed subscriber ended")?
            .map_err(|e| e.to_string())?;
        require(
            delivered.from() == alice_id.public_id()
                && delivered.body().as_str() == "approved payload",
            "wrong granted payload",
        )?;
        Ok(())
    }
    .await;
    let result = result.map_err(|error| {
        let alice_snapshot =
            closed_failure_snapshot(&alice.0, alice_id.public_id(), bob_id.public_id());
        let bob_snapshot =
            closed_failure_snapshot(&bob.0, bob_id.public_id(), alice_id.public_id());
        format!("stage={stage}: {error}; alice=[{alice_snapshot}]; bob=[{bob_snapshot}]")
    });
    let cleanup = shutdown_drivers(vec![alice, bob]).await;
    assert!(cleanup.is_ok(), "{cleanup:?}; result: {result:?}");
    assert!(result.is_ok(), "{result:?}");
}

mod support;
