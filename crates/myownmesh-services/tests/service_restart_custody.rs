use myownmesh_core::config::{StunServiceConfig, TurnCredential, TurnServiceConfig};
use myownmesh_core::{
    FiniteResourceProvider, LocalApplicationResourceScope, ResourceClaim, ResourceClass,
    ResourceProviderPort,
};
use myownmesh_services::{StunServer, TurnServer};

fn service_scope() -> LocalApplicationResourceScope {
    let grant = ResourceClaim::try_from_entries(
        ResourceClass::ALL
            .into_iter()
            .map(|class| (class, 1_000_000)),
    )
    .expect("service fixture grant is representable");
    let port = ResourceProviderPort::new(FiniteResourceProvider::new(grant))
        .expect("service fixture provider is valid");
    LocalApplicationResourceScope::transport_lab_child_of(&port)
        .expect("service fixture scope is valid")
}

fn stun_config(port: u16) -> StunServiceConfig {
    StunServiceConfig {
        enabled: true,
        bind: "127.0.0.1".into(),
        port,
    }
}

fn turn_config(port: u16) -> TurnServiceConfig {
    TurnServiceConfig {
        enabled: true,
        bind: "127.0.0.1".into(),
        port,
        public_ip: "127.0.0.1".into(),
        realm: "restart-custody".into(),
        credentials: vec![TurnCredential {
            username: "restart-user".into(),
            password: "restart-password".into(),
        }],
        max_bps_per_connection: 0,
        relay_port_min: 0,
        relay_port_max: 0,
        ..Default::default()
    }
}

#[test]
fn awaited_stun_stop_releases_exact_listener_for_immediate_restart() {
    with_service_cleanup(None, |cleanup| async move {
        let first = StunServer::start_with_resource_scope(
            &stun_config(0),
            service_scope(),
            cleanup.clone(),
        )
        .await
        .expect("initial STUN listener starts");
        let exact_addr = first.local_addr();

        first
            .stop_and_wait()
            .await
            .expect("STUN listener task reaches terminal state");

        let replacement = StunServer::start_with_resource_scope(
            &stun_config(exact_addr.port()),
            service_scope(),
            cleanup.clone(),
        )
        .await
        .expect("same STUN address is immediately reusable");
        assert_eq!(replacement.local_addr(), exact_addr);
        replacement
            .stop_and_wait()
            .await
            .expect("replacement STUN listener task reaches terminal state");
    });
}

#[test]
fn awaited_turn_stop_releases_exact_listener_for_immediate_restart() {
    with_service_cleanup(None, |cleanup| async move {
        let first = TurnServer::start_with_resource_scope(
            &turn_config(0),
            service_scope(),
            cleanup.clone(),
        )
        .await
        .expect("initial TURN listener starts");
        let exact_addr = first.local_addr();

        first
            .stop()
            .await
            .expect("TURN close task reaches terminal state");

        let replacement = TurnServer::start_with_resource_scope(
            &turn_config(exact_addr.port()),
            service_scope(),
            cleanup.clone(),
        )
        .await
        .expect("same TURN address is immediately reusable");
        assert_eq!(replacement.local_addr(), exact_addr);
        replacement
            .stop()
            .await
            .expect("replacement TURN close task reaches terminal state");
    });
}

fn with_service_cleanup<F, Fut>(workers: Option<usize>, body: F)
where
    F: FnOnce(myownmesh_services::ServiceCleanupPort) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    use myownmesh_services::ServiceCleanupOwner;
    let grant = ServiceCleanupOwner::planning_charge()
        .expect("actual outside root plan")
        .checked_add(
            FiniteResourceProvider::scope_planning_charge()
                .checked_scale(2)
                .unwrap(),
        )
        .unwrap();
    let provider = FiniteResourceProvider::new(grant);
    let port = ResourceProviderPort::new(provider.clone()).unwrap();
    let scope = LocalApplicationResourceScope::transport_lab_child_of(&port).unwrap();
    let owner = ServiceCleanupOwner::new(scope.clone()).unwrap();
    let cleanup = owner.port();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut builder = if let Some(workers) = workers {
            let mut builder = tokio::runtime::Builder::new_multi_thread();
            builder.worker_threads(workers);
            builder
        } else {
            tokio::runtime::Builder::new_current_thread()
        };
        let runtime = builder.enable_all().build().unwrap();
        runtime.block_on(body(cleanup));
        drop(runtime);
    }));
    let report = owner.close_and_join().expect("outside service root joined");
    drop((scope, port));
    assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    assert_eq!(
        provider.retained_after_failed_cleanup(),
        ResourceClaim::ZERO
    );
    if let Err(error) = outcome {
        std::panic::resume_unwind(error);
    }
    assert_eq!(report.task_failures, 0);
    assert_eq!(report.worker_failures, 0);
}
