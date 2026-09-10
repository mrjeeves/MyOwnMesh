#[cfg(test)]
mod server_test;

#[cfg(test)]
mod cleanup_controls {
    use super::*;
    use crate::resource::BoundedTestAdmission;

    struct NoAuthentication;
    impl AuthHandler for NoAuthentication {
        fn auth_handle(&self, _: &str, _: &str, _: std::net::SocketAddr) -> Result<Vec<u8>> {
            Err(Error::ErrClosed)
        }
    }

    #[tokio::test]
    async fn server_joins_all_taken_siblings_and_preserves_first_read_failure() {
        let charge = CleanupStatus::charge().unwrap();
        let limit = charge.units + charge.retained_bytes.div_ceil(1024) + 2;
        let admission = Arc::new(BoundedTestAdmission::new(limit));
        let cleanup = CleanupStatus::new(admission.as_ref()).unwrap();
        let first_lease = admission
            .acquire(ResourceKind::ReadLoop, ResourceCharge::units(1))
            .unwrap();
        let second_lease = admission
            .acquire(ResourceKind::ReadLoop, ResourceCharge::units(1))
            .unwrap();
        let (release, held) = oneshot::channel();
        let first = tokio::spawn(async move {
            let _lease = first_lease;
            panic!("injected first server read panic");
        });
        let second = tokio::spawn(async move {
            let _lease = second_lease;
            let _ = held.await;
            Ok(())
        });
        let server = Arc::new(Server {
            auth_handler: Arc::new(NoAuthentication),
            realm: String::new(),
            channel_bind_timeout: Duration::ZERO,
            nonces: Arc::new(Mutex::new(HashMap::new())),
            resource_admission: admission.clone(),
            command_tx: Mutex::new(None),
            tasks: Mutex::new(Some(vec![first, second])),
            cleanup: cleanup.clone(),
            #[cfg(feature = "custody-lab")]
            cleanup_probe: None,
        });
        let closing = server.clone();
        let close = tokio::spawn(async move { closing.close().await });
        cleanup.wait_for_failure().await;
        let pending = !close.is_finished();
        let sibling_funded = admission.remaining_for_test()
            < limit - charge.units - charge.retained_bytes.div_ceil(1024);
        let _ = release.send(());
        let result = close.await;
        let repeat = server.close().await;
        let no_handles = server.tasks.lock().await.is_none();
        drop((server, cleanup));
        assert!(pending && sibling_funded && no_handles);
        assert!(matches!(
            result,
            Ok(Err(Error::Cleanup(CleanupFailure::TaskPanicked(
                CleanupTaskLayer::ServerRead
            ))))
        ));
        assert!(matches!(
            repeat,
            Err(Error::Cleanup(CleanupFailure::TaskPanicked(
                CleanupTaskLayer::ServerRead
            )))
        ));
        assert_eq!(admission.remaining_for_test(), limit);
    }
}

pub mod config;
pub mod request;

use std::collections::HashMap;
use std::sync::Arc;

use config::*;
use request::*;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::broadcast::{self};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::{Duration, Instant};
use util::Conn;

use crate::allocation::allocation_manager::*;
use crate::allocation::five_tuple::FiveTuple;
use crate::allocation::AllocationInfo;
use crate::auth::AuthHandler;
use crate::error::*;
use crate::proto::lifetime::DEFAULT_LIFETIME;
use crate::resource::{
    CleanupFailure, CleanupStatus, CleanupTaskLayer, ResourceAdmission, ResourceCharge,
    ResourceKind, ResourceLease,
};

const INBOUND_MTU: usize = 1500;

/// Server is an instance of the TURN Server
pub struct Server {
    auth_handler: Arc<dyn AuthHandler + Send + Sync>,
    realm: String,
    channel_bind_timeout: Duration,
    pub(crate) nonces: Arc<Mutex<HashMap<String, (Instant, Box<dyn ResourceLease>)>>>,
    resource_admission: Arc<dyn ResourceAdmission>,
    command_tx: Mutex<Option<broadcast::Sender<Command>>>,
    tasks: Mutex<Option<Vec<tokio::task::JoinHandle<Result<()>>>>>,
    cleanup: CleanupStatus,
    #[cfg(feature = "custody-lab")]
    cleanup_probe: Option<crate::resource::CleanupProbe>,
}

impl Server {
    /// Creates a TURN server with the owner-selected admission authority.
    /// Admission is a constructor input rather than a `ServerConfig` field so
    /// existing downstream config literals remain source-compatible while
    /// production cannot accidentally omit the authority.
    pub async fn new_with_resource_admission(
        config: ServerConfig,
        admission: Arc<dyn ResourceAdmission>,
    ) -> Result<Self> {
        Self::new_inner(
            config,
            admission,
            #[cfg(feature = "custody-lab")]
            None,
        )
        .await
    }

    #[cfg(feature = "custody-lab")]
    pub async fn new_with_resource_admission_and_cleanup_probe(
        config: ServerConfig,
        admission: Arc<dyn ResourceAdmission>,
        probe: crate::resource::CleanupProbe,
    ) -> Result<Self> {
        Self::new_inner(config, admission, Some(probe)).await
    }

    async fn new_inner(
        config: ServerConfig,
        admission: Arc<dyn ResourceAdmission>,
        #[cfg(feature = "custody-lab")] cleanup_probe: Option<crate::resource::CleanupProbe>,
    ) -> Result<Self> {
        config.validate()?;

        let cleanup =
            CleanupStatus::new(admission.as_ref()).map_err(|_| Error::ErrResourceAdmission)?;

        let (command_tx, _) = broadcast::channel(16);
        let mut s = Server {
            auth_handler: config.auth_handler,
            realm: config.realm,
            channel_bind_timeout: config.channel_bind_timeout,
            nonces: Arc::new(Mutex::new(HashMap::new())),
            resource_admission: Arc::clone(&admission),
            command_tx: Mutex::new(Some(command_tx.clone())),
            tasks: Mutex::new(Some(Vec::new())),
            cleanup,
            #[cfg(feature = "custody-lab")]
            cleanup_probe,
        };

        if s.channel_bind_timeout == Duration::from_secs(0) {
            s.channel_bind_timeout = DEFAULT_LIFETIME;
        }

        for p in config.conn_configs.into_iter() {
            let nonces = Arc::clone(&s.nonces);
            let auth_handler = Arc::clone(&s.auth_handler);
            let realm = s.realm.clone();
            let channel_bind_timeout = s.channel_bind_timeout;
            let handle_rx = command_tx.subscribe();
            let conn = p.conn;
            let read_lease =
                match admission.acquire(ResourceKind::ReadLoop, ResourceCharge::units(1)) {
                    Ok(lease) => lease,
                    Err(_) => {
                        let _ = s.close().await;
                        return Err(Error::ErrResourceAdmission);
                    }
                };
            let command_lease =
                match admission.acquire(ResourceKind::CommandLoop, ResourceCharge::units(1)) {
                    Ok(lease) => lease,
                    Err(_) => {
                        let _ = s.close().await;
                        return Err(Error::ErrResourceAdmission);
                    }
                };
            let allocation_manager = Arc::new(Manager::new(ManagerConfig {
                relay_addr_generator: p.relay_addr_generator,
                alloc_close_notify: config.alloc_close_notify.clone(),
                resource_admission: Arc::clone(&admission),
                cleanup: s.cleanup.clone(),
            }));

            let task = tokio::spawn(Server::read_loop(
                conn,
                allocation_manager,
                nonces,
                Arc::clone(&admission),
                auth_handler,
                realm,
                channel_bind_timeout,
                handle_rx,
                read_lease,
                command_lease,
                s.cleanup.clone(),
                #[cfg(feature = "custody-lab")]
                s.cleanup_probe.clone(),
            ));
            s.tasks.lock().await.as_mut().unwrap().push(task);
        }

        Ok(s)
    }

    /// Deletes all existing [`Allocation`][`Allocation`]s by the provided `username`.
    ///
    /// [`Allocation`]: crate::allocation::Allocation
    pub async fn delete_allocations_by_username(&self, username: String) -> Result<()> {
        let tx = {
            let command_tx = self.command_tx.lock().await;
            command_tx.clone()
        };
        if let Some(tx) = tx {
            let (closed_tx, closed_rx) = mpsc::channel(1);
            tx.send(Command::DeleteAllocations(username, Arc::new(closed_rx)))
                .map_err(|_| Error::ErrClosed)?;

            closed_tx.closed().await;

            Ok(())
        } else {
            Err(Error::ErrClosed)
        }
    }

    /// Get information of [`Allocation`][`Allocation`]s by specified [`FiveTuple`]s.
    ///
    /// If `five_tuples` is:
    /// - [`None`]: It returns information about the all
    ///   [`Allocation`][`Allocation`]s.
    /// - [`Some`] and not empty: It returns information about
    ///   the [`Allocation`][`Allocation`]s associated with
    ///   the specified [`FiveTuples`].
    /// - [`Some`], but empty: It returns an empty [`HashMap`].
    ///
    /// [`Allocation`]: crate::allocation::Allocation
    pub async fn get_allocations_info(
        &self,
        five_tuples: Option<Vec<FiveTuple>>,
    ) -> Result<HashMap<FiveTuple, AllocationInfo>> {
        if let Some(five_tuples) = &five_tuples {
            if five_tuples.is_empty() {
                return Ok(HashMap::new());
            }
        }

        let tx = {
            let command_tx = self.command_tx.lock().await;
            command_tx.clone()
        };
        if let Some(tx) = tx {
            let (infos_tx, mut infos_rx) = mpsc::channel(1);
            tx.send(Command::GetAllocationsInfo(five_tuples, infos_tx))
                .map_err(|_| Error::ErrClosed)?;

            let mut info: HashMap<FiveTuple, AllocationInfo> = HashMap::new();

            for _ in 0..tx.receiver_count() {
                info.extend(infos_rx.recv().await.ok_or(Error::ErrClosed)?);
            }

            Ok(info)
        } else {
            Err(Error::ErrClosed)
        }
    }

    async fn read_loop(
        conn: Arc<dyn Conn + Send + Sync>,
        allocation_manager: Arc<Manager>,
        nonces: Arc<Mutex<HashMap<String, (Instant, Box<dyn ResourceLease>)>>>,
        resource_admission: Arc<dyn ResourceAdmission>,
        auth_handler: Arc<dyn AuthHandler + Send + Sync>,
        realm: String,
        channel_bind_timeout: Duration,
        mut handle_rx: broadcast::Receiver<Command>,
        read_lease: Box<dyn ResourceLease>,
        command_lease: Box<dyn ResourceLease>,
        cleanup: CleanupStatus,
        #[cfg(feature = "custody-lab")] cleanup_probe: Option<crate::resource::CleanupProbe>,
    ) -> Result<()> {
        let mut buf = vec![0u8; INBOUND_MTU];

        let (mut close_tx, mut close_rx) = oneshot::channel::<()>();

        let command_task = tokio::spawn({
            let allocation_manager = Arc::clone(&allocation_manager);
            #[cfg(feature = "custody-lab")]
            let cleanup_probe = cleanup_probe.clone();

            async move {
                let _command_lease = command_lease;
                loop {
                    match handle_rx.recv().await {
                        Ok(Command::DeleteAllocations(name, _)) => {
                            allocation_manager
                                .delete_allocations_by_username(name.as_str())
                                .await;
                            continue;
                        }
                        Ok(Command::GetAllocationsInfo(five_tuples, tx)) => {
                            let infos = allocation_manager.get_allocations_info(five_tuples).await;
                            let _ = tx.send(infos).await;

                            continue;
                        }
                        Ok(Command::Close(ack)) => {
                            close_rx.close();
                            drop(ack);
                            #[cfg(feature = "custody-lab")]
                            if let Some(probe) = &cleanup_probe {
                                probe.command_after_ack().await;
                            }
                            break;
                        }
                        Err(RecvError::Closed) => {
                            close_rx.close();
                            break;
                        }
                        Err(RecvError::Lagged(n)) => {
                            log::warn!("Turn server has lagged by {} messages", n);
                            continue;
                        }
                    }
                }
            }
        });

        loop {
            let (n, addr) = tokio::select! {
                v = conn.recv_from(&mut buf) => {
                    match v {
                        Ok(v) => v,
                        Err(err) => {
                            log::debug!("exit read loop on error: {}", err);
                            break;
                        }
                    }
                },
                _ = close_tx.closed() => break
            };

            let mut r = Request {
                conn: Arc::clone(&conn),
                src_addr: addr,
                buff: buf[..n].to_vec(),
                allocation_manager: Arc::clone(&allocation_manager),
                nonces: Arc::clone(&nonces),
                resource_admission: Some(Arc::clone(&resource_admission)),
                auth_handler: Arc::clone(&auth_handler),
                realm: realm.clone(),
                channel_bind_timeout,
            };

            if let Err(err) = r.handle_request().await {
                log::error!("error when handling datagram: {}", err);
            }
        }

        let mut first_error = cleanup.result().err();
        if let Err(error) = allocation_manager.close().await {
            if !matches!(error, Error::ErrClosed) {
                cleanup.error(&error, CleanupFailure::AllocationClose);
                first_error.get_or_insert(error);
            }
        }
        if let Err(error) = conn.close().await {
            cleanup.record(CleanupFailure::ControlSocketClose);
            first_error.get_or_insert(error.into());
        }
        #[cfg(feature = "custody-lab")]
        if let Some(probe) = &cleanup_probe {
            probe.before_command_abort().await;
        }
        command_task.abort();
        cleanup.observe_join(command_task.await, CleanupTaskLayer::ServerCommand, true);
        #[cfg(feature = "custody-lab")]
        if let Some(probe) = &cleanup_probe {
            probe.mark_command_joined();
        }
        let _read_lease = read_lease;
        first_error.map_or_else(|| cleanup.result(), Err)
    }

    /// Close stops the TURN Server. It cleans up any associated state and closes all connections it is managing.
    pub async fn close(&self) -> Result<()> {
        let mut first_error = self.cleanup.result().err();
        let tx = {
            let mut command_tx = self.command_tx.lock().await;
            command_tx.take()
        };

        if let Some(tx) = tx {
            if tx.receiver_count() > 0 {
                let (closed_tx, closed_rx) = mpsc::channel(1);
                let _ = tx.send(Command::Close(Arc::new(closed_rx)));
                closed_tx.closed().await;
            }
        }

        let tasks = self.tasks.lock().await.take().unwrap_or_default();
        #[cfg(feature = "custody-lab")]
        if !tasks.is_empty() {
            if let Some(probe) = &self.cleanup_probe {
                probe.after_vec_take().await;
            }
        }
        for task in tasks {
            #[cfg(feature = "custody-lab")]
            if let Some(probe) = &self.cleanup_probe {
                probe.mark_read_waiting();
            }
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    self.cleanup.error(&error, CleanupFailure::AllocationClose);
                    first_error.get_or_insert(error);
                }
                Err(error) => {
                    self.cleanup
                        .observe_join(Err(error), CleanupTaskLayer::ServerRead, false)
                }
            }
            if first_error.is_none() {
                first_error = self.cleanup.result().err();
            }
        }
        #[cfg(feature = "custody-lab")]
        if let Some(probe) = &self.cleanup_probe {
            probe.mark_read_joined();
        }

        first_error.map_or_else(|| self.cleanup.result(), Err)
    }
}

/// The protocol to communicate between the [`Server`]'s public methods
/// and the tasks spawned in the [`Server::read_loop`] method.
#[derive(Clone)]
enum Command {
    /// Command to delete [`Allocation`][`Allocation`] by provided `username`.
    ///
    /// [`Allocation`]: `crate::allocation::Allocation`
    DeleteAllocations(String, Arc<mpsc::Receiver<()>>),

    /// Command to get information of [`Allocation`][`Allocation`]s by provided [`FiveTuple`]s.
    ///
    /// [`Allocation`]: `crate::allocation::Allocation`
    GetAllocationsInfo(
        Option<Vec<FiveTuple>>,
        mpsc::Sender<HashMap<FiveTuple, AllocationInfo>>,
    ),

    /// Command to close the [`Server`].
    Close(Arc<mpsc::Receiver<()>>),
}
