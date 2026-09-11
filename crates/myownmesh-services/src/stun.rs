//! Standalone STUN server.
//!
//! Answers RFC 5389 Binding requests with the source transport address
//! XOR-mapped per spec. Pure reflexion: no authentication, no
//! allocations, no `CHANGE-REQUEST` handling — just the one job a STUN
//! server does in an ICE flow, which is to tell a client what address
//! the world sees it coming from.
//!
//! For relaying (symmetric NAT), run the [`crate::turn`] server instead
//! — a TURN server answers Binding requests too, so you rarely need
//! both on one host.

use std::net::SocketAddr;
use std::sync::Arc;

use stun::message::{Message, BINDING_REQUEST, BINDING_SUCCESS};
use stun::xoraddr::XorMappedAddress;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

use myownmesh_core::config::StunServiceConfig;
use myownmesh_core::{FundedArc, LocalApplicationResourceScope, ResourceClaim, ResourceClass};

use crate::cleanup::{planned, ServiceCompletion, ServiceCustody, StunTerminalGuard};
use crate::{Error, Result, ServiceCleanupError, ServiceCleanupPort};

/// A running STUN server. Constructed via
/// [`StunServer::start_with_resource_scope`].
pub struct StunServer;

/// A running STUN listener with an already registered outside cleanup entry.
/// Drop aborts and transfers the exact listener; it never joins locally.
pub struct StunServerHandle {
    task: Option<JoinHandle<()>>,
    terminal: FundedArc<ServiceCompletion>,
    custody: ServiceCustody,
    local_addr: SocketAddr,
}

impl StunServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn request_stop(&self) {
        if let Some(task) = &self.task {
            self.terminal.request_stun_stop();
            task.abort();
        }
    }

    /// Observe the original listener, then the same outside-owned disposition.
    /// Cancelling either await leaves the task in this handle or the root.
    pub async fn stop_and_wait(mut self) -> Result<()> {
        self.request_stop();
        let task_result = if let Some(task) = self.task.as_mut() {
            (&mut *task).await
        } else {
            Ok(())
        };
        self.task.take();
        let failed = self.terminal.stun_task_failed(&task_result);
        self.custody.finish_stun(None, failed);
        self.terminal.wait_joined().await;
        self.custody.observe_disposition();
        if !failed && self.terminal.task_failed() {
            return Err(Error::Cleanup(ServiceCleanupError::WorkerJoin));
        }
        match task_result {
            Ok(()) => Ok(()),
            Err(error) if error.is_cancelled() && !failed => Ok(()),
            Err(error) => Err(Error::TaskJoin(error.to_string())),
        }
    }
}

impl Drop for StunServerHandle {
    fn drop(&mut self) {
        self.request_stop();
        if let Some(task) = self.task.take() {
            self.custody.finish_stun(Some(task), false);
        }
    }
}

impl StunServer {
    /// Exact retained no-client service reservations; excludes root and scopes.
    pub fn startup_planning_charge() -> std::result::Result<ResourceClaim, ServiceCleanupError> {
        Ok(planned(stun_startup_claim())?
            .checked_add(ServiceCleanupPort::entry_planning_charge()?)?)
    }
    /// The unscoped constructor is intentionally non-binding. Service
    /// ownership must come from the process owner's resource scope.
    pub async fn start(config: &StunServiceConfig) -> Result<StunServerHandle> {
        let _ = config;
        Err(Error::Resource(
            "owner-selected resource scope required; use start_with_resource_scope".into(),
        ))
    }

    /// Bind a UDP socket and start serving Binding requests under exact
    /// owner-funded custody. The scope is consumed by the service boundary;
    /// the noncloneable lease remains with the handle until terminal join.
    pub async fn start_with_resource_scope(
        config: &StunServiceConfig,
        scope: LocalApplicationResourceScope,
        cleanup: ServiceCleanupPort,
    ) -> Result<StunServerHandle> {
        let service_lease = scope
            .acquire(stun_startup_claim())
            .map_err(|error| Error::Resource(error.to_string()))?;
        let mut custody = cleanup.reserve(&scope, service_lease)?;
        let terminal = custody.completion();
        if let Err(error) = custody.spawn_stun_observer() {
            custody.submit();
            terminal.wait_joined().await;
            custody.observe_disposition();
            return Err(error.into());
        }
        let addr = format!("{}:{}", config.bind, config.port);
        let socket = match UdpSocket::bind(&addr).await {
            Ok(socket) => socket,
            Err(error) => {
                custody.submit();
                terminal.wait_joined().await;
                custody.observe_disposition();
                return Err(Error::Bind(addr, error));
            }
        };
        let local_addr = match socket.local_addr() {
            Ok(addr) => addr,
            Err(error) => {
                drop(socket);
                custody.submit();
                terminal.wait_joined().await;
                custody.observe_disposition();
                return Err(Error::Bind(addr, error));
            }
        };
        info!(%local_addr, "STUN server listening");
        let socket = Arc::new(socket);
        let terminal_guard = StunTerminalGuard(terminal.clone());
        let task = tokio::spawn(async move {
            terminal_guard.entered();
            let _terminal = terminal_guard;
            serve(socket).await;
        });
        Ok(StunServerHandle {
            task: Some(task),
            terminal,
            custody,
            local_addr,
        })
    }
}

fn stun_startup_claim() -> ResourceClaim {
    ResourceClaim::try_from_entries([
        (ResourceClass::SocketOrHandle, 1),
        (ResourceClass::WorkerOrTask, 2),
    ])
    .expect("fixed STUN startup claim is representable")
}

async fn serve(socket: Arc<UdpSocket>) {
    // STUN messages are tiny; an MTU-sized buffer is plenty and a stray
    // oversized datagram just gets truncated and fails to decode (which
    // we handle as a bad packet).
    let mut buf = vec![0u8; 1500];
    loop {
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!("STUN recv error: {e}");
                continue;
            }
        };
        match binding_response(&buf[..n], src) {
            Ok(Some(resp)) => {
                if let Err(e) = socket.send_to(&resp, src).await {
                    trace!(%src, "STUN send error: {e}");
                } else {
                    trace!(%src, "STUN binding response sent");
                }
            }
            // Decoded fine but wasn't a Binding request — ignore
            // silently (could be a TURN client probing the wrong port).
            Ok(None) => {}
            Err(e) => trace!(%src, "STUN: dropping bad packet: {e}"),
        }
    }
}

/// Build a Binding success response for an incoming packet. Returns
/// `Ok(None)` when the packet decodes but isn't a Binding request, and
/// `Err` when it doesn't decode as STUN at all.
fn binding_response(packet: &[u8], src: SocketAddr) -> Result<Option<Vec<u8>>> {
    let mut req = Message::new();
    req.unmarshal_binary(packet)
        .map_err(|e| Error::Decode(e.to_string()))?;
    if req.typ != BINDING_REQUEST {
        return Ok(None);
    }
    debug!(%src, "STUN binding request");

    let mut resp = Message::new();
    let xor = XorMappedAddress {
        ip: src.ip(),
        port: src.port(),
    };
    // Order matters: the request setter copies its transaction id onto
    // the response, and XorMappedAddress XORs the address against that
    // transaction id, so it must run after the request setter.
    resp.build(&[
        Box::new(BINDING_SUCCESS),
        Box::new(req.clone()),
        Box::new(xor),
    ])
    .map_err(|e| Error::Encode(e.to_string()))?;
    Ok(Some(resp.raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cleanup::test_support::{with_runtime, TestRoot};

    #[test]
    fn two_queued_stun_services_keep_both_leases_until_original_tasks_and_workers_join() {
        use myownmesh_core::{FiniteResourceProvider, ResourceProviderPort};
        let root = TestRoot::new();
        let plan = StunServer::startup_planning_charge().unwrap();
        let grant = plan
            .checked_scale(2)
            .unwrap()
            .checked_add(
                FiniteResourceProvider::scope_planning_charge()
                    .checked_scale(2)
                    .unwrap(),
            )
            .unwrap();
        let provider = FiniteResourceProvider::new(grant);
        let provider_port = ResourceProviderPort::new(provider.clone()).unwrap();
        let scope = LocalApplicationResourceScope::transport_lab_child_of(&provider_port).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let observations = runtime.block_on(async {
            let config = StunServiceConfig {
                enabled: true,
                bind: "127.0.0.1".into(),
                port: 0,
            };
            let first =
                StunServer::start_with_resource_scope(&config, scope.clone(), root.port()).await?;
            let second =
                StunServer::start_with_resource_scope(&config, scope.clone(), root.port()).await?;
            tokio::task::yield_now().await;
            let terminals = (first.terminal.clone(), second.terminal.clone());
            // No await after abort: neither listener can be destroyed by this
            // current-thread runtime until its execution/destruction resumes.
            drop((first, second));
            let held = provider.in_use().amount(ResourceClass::SocketOrHandle) == 2
                && provider.in_use().amount(ResourceClass::WorkerOrTask) == 4;
            let both_pending = !terminals.0.is_joined() && !terminals.1.is_joined();
            Ok::<_, Error>((terminals, held, both_pending))
        });
        drop(runtime);
        let report = root.close();
        let observed = observations.map(|(terminals, held, pending)| {
            let joined = terminals.0.is_joined() && terminals.1.is_joined();
            drop(terminals);
            (held, pending, joined)
        });
        drop((scope, provider_port));
        let (held, pending, joined) = observed.expect("two exact real listeners");
        assert!(held && pending && joined);
        assert_eq!(report.completed, 2);
        assert_eq!(report.task_failures, 0);
        assert_eq!(report.worker_failures, 0);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
        assert_eq!(
            provider.retained_after_failed_cleanup(),
            ResourceClaim::ZERO
        );
    }

    #[test]
    fn cancelled_stun_stop_preserves_original_task_custody() {
        use std::future::Future;
        use std::task::Poll;
        with_runtime(|cleanup| async move {
            let config = StunServiceConfig {
                enabled: true,
                bind: "127.0.0.1".into(),
                port: 0,
            };
            let server = start_with_scope(&cleanup, &config).await.unwrap();
            tokio::task::yield_now().await;
            let terminal = server.terminal.clone();
            let first_pending = {
                let stopping = server.stop_and_wait();
                tokio::pin!(stopping);
                std::future::poll_fn(|cx| Poll::Ready(stopping.as_mut().poll(cx).is_pending()))
                    .await
                // pinned future is destroyed here, before waiting on terminal
            };
            terminal.wait_joined().await;
            let report = cleanup.report_for_test();
            assert!(first_pending && terminal.is_joined());
            assert!(!terminal.task_failed());
            assert_eq!(report.completed, 1);
            assert_eq!(report.task_failures, 0);
            assert_eq!(report.worker_failures, 0);
        });
    }
    use stun::message::Getter;
    use stun::xoraddr::XorMappedAddress;

    fn test_scope() -> LocalApplicationResourceScope {
        let grant = ResourceClaim::try_from_entries(
            ResourceClass::ALL
                .into_iter()
                .map(|class| (class, 1_000_000)),
        )
        .expect("test provider grant is representable");
        let port = myownmesh_core::ResourceProviderPort::new(
            myownmesh_core::FiniteResourceProvider::new(grant),
        )
        .expect("test provider is valid");
        LocalApplicationResourceScope::transport_lab_child_of(&port)
            .expect("test application scope is valid")
    }

    async fn start_with_scope(
        cleanup: &ServiceCleanupPort,
        config: &StunServiceConfig,
    ) -> Result<StunServerHandle> {
        StunServer::start_with_resource_scope(config, test_scope(), cleanup.clone()).await
    }

    /// Evidence discriminator only: run alone under an external process
    /// deadline. A stuck synchronous Drop cannot be preempted by Tokio.
    #[test]
    #[ignore = "real current-thread STUN Drop; requires an external process watchdog"]
    fn live_stun_drop_current_thread_without_external_custodian() {
        use myownmesh_core::{FiniteResourceProvider, ResourceProviderPort};
        let root = TestRoot::new();
        let startup = StunServer::startup_planning_charge().expect("actual service plan");
        let grant = startup
            .checked_add(
                FiniteResourceProvider::scope_planning_charge()
                    .checked_scale(2)
                    .unwrap(),
            )
            .unwrap();
        let provider = FiniteResourceProvider::new(grant);
        let provider_port = ResourceProviderPort::new(provider.clone()).unwrap();
        let scope = LocalApplicationResourceScope::transport_lab_child_of(&provider_port).unwrap();
        let baseline = provider.in_use();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let observed = runtime.block_on(async {
            let config = StunServiceConfig {
                enabled: true,
                bind: "127.0.0.1".into(),
                port: 0,
            };
            let server =
                StunServer::start_with_resource_scope(&config, scope.clone(), root.port()).await?;
            tokio::task::yield_now().await;
            let live_listener = server.local_addr().port() != 0
                && server.task.as_ref().is_some_and(|task| !task.is_finished());
            let live_delta = provider.in_use().checked_sub(baseline);
            let terminal = server.terminal.clone();
            eprintln!("stun-drop-discriminator/v2 before-handle-drop");
            drop(server);
            eprintln!("stun-drop-discriminator/v2 after-handle-drop");
            Ok::<_, Error>((live_listener, live_delta, terminal))
        });
        eprintln!("stun-drop-discriminator/v2 before-runtime-drop");
        drop(runtime);
        eprintln!("stun-drop-discriminator/v2 after-runtime-drop");
        let report = root.close();
        let (live_listener, live_delta, terminal) = observed.expect("real constructor");
        let service_terminal = terminal.is_joined();
        let custodian_terminal = report.completed == 1 && report.worker_failures == 0;
        drop(terminal);
        let after_cleanup = provider.in_use();
        drop((scope, provider_port));
        assert!(live_listener);
        assert_eq!(live_delta.unwrap(), startup);
        assert!(service_terminal, "the exact listener join was observed");
        assert!(
            custodian_terminal,
            "the outside root joined the final worker"
        );
        assert_eq!(report.task_failures, 0);
        assert_eq!(after_cleanup, baseline);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
        assert_eq!(
            provider.retained_after_failed_cleanup(),
            ResourceClaim::ZERO
        );
    }

    #[test]
    fn binding_request_gets_reflexive_address_back() {
        with_runtime(|cleanup| async move {
            let cfg = StunServiceConfig {
                enabled: true,
                bind: "127.0.0.1".into(),
                port: 0, // ephemeral
            };
            let server = start_with_scope(&cleanup, &cfg).await.unwrap();
            let server_addr = server.local_addr();

            // A real client socket sends a real Binding request.
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let client_addr = client.local_addr().unwrap();

            let mut req = Message::new();
            req.build(&[Box::new(BINDING_REQUEST)]).unwrap();
            client.send_to(&req.raw, server_addr).await.unwrap();

            let mut buf = vec![0u8; 1500];
            let (n, from) = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                client.recv_from(&mut buf),
            )
            .await
            .expect("STUN response timed out")
            .unwrap();
            assert_eq!(from, server_addr);

            let mut resp = Message::new();
            resp.unmarshal_binary(&buf[..n]).unwrap();
            assert_eq!(resp.typ, BINDING_SUCCESS);
            assert_eq!(resp.transaction_id, req.transaction_id);

            // The server should report back the client's own address.
            let mut mapped = XorMappedAddress::default();
            mapped.get_from(&resp).unwrap();
            assert_eq!(mapped.ip, client_addr.ip());
            assert_eq!(mapped.port, client_addr.port());

            server.stop_and_wait().await.unwrap();
        });
    }

    #[test]
    fn non_binding_packet_is_ignored() {
        with_runtime(|_cleanup| async move {
            // Garbage that isn't STUN at all decodes-errors and is dropped;
            // a well-formed non-Binding message returns None. Either way
            // the helper must not panic.
            let src: SocketAddr = "127.0.0.1:9".parse().unwrap();
            assert!(binding_response(b"not a stun packet", src).is_err());
        });
    }

    #[test]
    fn active_stop_observes_listener_terminal() {
        with_runtime(|cleanup| async move {
            let cfg = StunServiceConfig {
                enabled: true,
                bind: "127.0.0.1".into(),
                port: 0,
            };
            let server = start_with_scope(&cleanup, &cfg).await.unwrap();
            let terminal = server.terminal.clone();

            server.stop_and_wait().await.unwrap();

            assert!(terminal.is_joined());
        });
    }

    #[test]
    fn runtime_ended_before_drop_is_reaped_without_runtime_reentry() {
        let root = TestRoot::new();
        let (server, terminal) = {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let config = StunServiceConfig {
                    enabled: true,
                    bind: "127.0.0.1".into(),
                    port: 0,
                };
                let server = start_with_scope(&root.port(), &config).await.unwrap();
                let terminal = server.terminal.clone();
                (server, terminal)
            })
        };
        drop(server);
        let report = root.close();
        assert!(terminal.is_joined());
        assert!(terminal.task_failed());
        assert_eq!(report.completed, 1);
        assert_eq!(report.task_failures, 1);
        assert_eq!(report.worker_failures, 0);
    }

    fn cancellation_provenance_control(request_before_runtime_drop: bool, poll_listener: bool) {
        use myownmesh_core::{FiniteResourceProvider, ResourceProviderPort};
        let root = TestRoot::new();
        let startup = StunServer::startup_planning_charge().unwrap();
        let grant = startup
            .checked_add(
                FiniteResourceProvider::scope_planning_charge()
                    .checked_scale(2)
                    .unwrap(),
            )
            .unwrap();
        let provider = FiniteResourceProvider::new(grant);
        let provider_port = ResourceProviderPort::new(provider.clone()).unwrap();
        let scope = LocalApplicationResourceScope::transport_lab_child_of(&provider_port).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let started = runtime.block_on(async {
            let config = StunServiceConfig {
                enabled: true,
                bind: "127.0.0.1".into(),
                port: 0,
            };
            let server =
                StunServer::start_with_resource_scope(&config, scope.clone(), root.port()).await?;
            if poll_listener {
                while !server.terminal.listener_was_polled() {
                    tokio::task::yield_now().await;
                }
            }
            Ok::<_, Error>(server)
        });
        // Both handle and root stay outside the destroyed origin runtime. The
        // only difference between paired cases is the private request's order.
        let observed = started.as_ref().ok().map(|server| {
            let polled = server.terminal.listener_was_polled();
            let retained = provider.in_use();
            if request_before_runtime_drop {
                server.request_stop();
            }
            (server.terminal.clone(), polled, retained)
        });
        drop(runtime);
        let setup_error = started.err(); // drops the still-owned handle on Ok
        let report = root.close();
        let observed = observed.map(|(terminal, polled, retained)| {
            let joined = terminal.is_joined();
            let failed = terminal.task_failed();
            drop(terminal);
            (polled, retained, joined, failed)
        });
        drop((scope, provider_port));
        assert!(
            setup_error.is_none(),
            "real listener setup: {setup_error:?}"
        );
        let (polled, retained, joined, failed) = observed.expect("saved exact listener");
        assert_eq!(polled, poll_listener);
        assert_eq!(retained, grant);
        assert!(joined);
        assert_eq!(failed, !request_before_runtime_drop);
        assert_eq!(report.completed, 1);
        assert_eq!(
            report.task_failures,
            u64::from(!request_before_runtime_drop)
        );
        assert_eq!(report.worker_failures, 0);
        // Unexpected cancellation is a task failure, not an unobserved cleanup:
        // both exact handles were joined, so no native obligation is retained.
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
        assert_eq!(
            provider.retained_after_failed_cleanup(),
            ResourceClaim::ZERO
        );
    }

    #[test]
    fn runtime_first_unpolled_stun_cancellation_cannot_be_relabelled_by_late_drop() {
        cancellation_provenance_control(false, false);
    }

    #[test]
    fn requested_unpolled_stun_cancellation_is_clean_after_exact_joins() {
        cancellation_provenance_control(true, false);
    }

    #[test]
    fn runtime_first_polled_stun_cancellation_cannot_be_relabelled_by_late_drop() {
        cancellation_provenance_control(false, true);
    }

    #[test]
    fn requested_polled_stun_cancellation_is_clean_after_exact_joins() {
        cancellation_provenance_control(true, true);
    }

    #[test]
    fn current_thread_drop_observes_worker_before_runtime_destruction() {
        // The repaired contract observes the worker AFTER runtime destruction
        // and outside-root join; Drop itself must return without joining.
        let root = TestRoot::new();
        let (terminal, port) = {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let config = StunServiceConfig {
                    enabled: true,
                    bind: "127.0.0.1".into(),
                    port: 0,
                };
                let server = start_with_scope(&root.port(), &config).await.unwrap();
                let terminal = server.terminal.clone();
                let port = server.local_addr().port();
                drop(server);
                (terminal, port)
            })
        };
        let report = root.close();
        assert!(terminal.is_joined());
        assert_eq!(report.completed, 1);
        assert_eq!(report.worker_failures, 0);
        with_runtime(|cleanup| async move {
            let config = StunServiceConfig {
                enabled: true,
                bind: "127.0.0.1".into(),
                port,
            };
            start_with_scope(&cleanup, &config)
                .await
                .expect("exact port reusable")
                .stop_and_wait()
                .await
                .unwrap();
        });
    }

    #[test]
    fn stopped_stun_releases_the_exact_control_port_for_reuse() {
        with_runtime(|cleanup| async move {
            let mut config = StunServiceConfig {
                enabled: true,
                bind: "127.0.0.1".into(),
                port: 0,
            };
            let first = start_with_scope(&cleanup, &config).await.unwrap();
            let port = first.local_addr().port();
            first.stop_and_wait().await.unwrap();

            config.port = port;
            let second = start_with_scope(&cleanup, &config).await.unwrap();
            assert_eq!(second.local_addr().port(), port);
            second.stop_and_wait().await.unwrap();
        });
    }

    #[test]
    fn exact_startup_grant_rejects_n_plus_one_and_reuses_after_stop() {
        with_runtime(|cleanup| async move {
            let insufficient_port = myownmesh_core::ResourceProviderPort::new(
                myownmesh_core::FiniteResourceProvider::new(
                    StunServer::startup_planning_charge()
                        .unwrap()
                        .checked_sub(ResourceClaim::single(ResourceClass::WorkerOrTask, 1))
                        .unwrap()
                        .checked_add(
                            myownmesh_core::FiniteResourceProvider::scope_planning_charge()
                                .checked_scale(2)
                                .unwrap(),
                        )
                        .unwrap(),
                ),
            )
            .unwrap();
            let insufficient_scope =
                LocalApplicationResourceScope::transport_lab_child_of(&insufficient_port).unwrap();
            let insufficient_config = StunServiceConfig {
                enabled: true,
                bind: "127.0.0.1".into(),
                port: 0,
            };
            assert!(matches!(
                StunServer::start_with_resource_scope(
                    &insufficient_config,
                    insufficient_scope,
                    cleanup.clone()
                )
                .await,
                Err(Error::Resource(_))
            ));

            let port = myownmesh_core::ResourceProviderPort::new(
                myownmesh_core::FiniteResourceProvider::new(
                    StunServer::startup_planning_charge()
                        .unwrap()
                        .checked_add(
                            myownmesh_core::FiniteResourceProvider::scope_planning_charge()
                                .checked_scale(2)
                                .unwrap(),
                        )
                        .unwrap(),
                ),
            )
            .unwrap();
            let scope = LocalApplicationResourceScope::transport_lab_child_of(&port).unwrap();
            let config = StunServiceConfig {
                enabled: true,
                bind: "127.0.0.1".into(),
                port: 0,
            };
            let first =
                StunServer::start_with_resource_scope(&config, scope.clone(), cleanup.clone())
                    .await
                    .unwrap();
            let refused =
                StunServer::start_with_resource_scope(&config, scope.clone(), cleanup.clone())
                    .await;
            assert!(matches!(refused, Err(Error::Resource(_))));
            first.stop_and_wait().await.unwrap();
            StunServer::start_with_resource_scope(&config, scope, cleanup.clone())
                .await
                .unwrap()
                .stop_and_wait()
                .await
                .unwrap();
        });
    }

    #[test]
    fn drop_outside_runtime_is_reaped_by_runtime_owner() {
        with_runtime(|cleanup| async move {
            let cfg = StunServiceConfig {
                enabled: true,
                bind: "127.0.0.1".into(),
                port: 0,
            };
            let server = start_with_scope(&cleanup, &cfg).await.unwrap();
            let terminal = server.terminal.clone();
            let notified = terminal.wait_joined();

            std::thread::spawn(move || drop(server))
                .join()
                .expect("drop thread panicked");
            notified.await;

            assert!(terminal.is_joined());
        });
    }

    #[test]
    fn double_bind_same_port_errors() {
        with_runtime(|cleanup| async move {
            let cfg = StunServiceConfig {
                enabled: true,
                bind: "127.0.0.1".into(),
                port: 0,
            };
            let server = start_with_scope(&cleanup, &cfg).await.unwrap();
            let taken = server.local_addr();
            // Re-binding the now-occupied port must surface as Error::Bind.
            let cfg2 = StunServiceConfig {
                enabled: true,
                bind: "127.0.0.1".into(),
                port: taken.port(),
            };
            let err = start_with_scope(&cleanup, &cfg2).await;
            assert!(matches!(err, Err(Error::Bind(_, _))));
            server.stop_and_wait().await.unwrap();
        });
    }
}
