#[cfg(test)]
mod allocation_manager_test;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use futures::future;
use stun::textattrs::Username;
use tokio::sync::mpsc;
use util::Conn;

use super::*;
use crate::error::*;
use crate::relay::*;
use crate::resource::{
    CleanupFailure, CleanupStatus, CleanupTaskLayer, ResourceAdmission, ResourceCharge,
    ResourceKind, ResourceLease,
};

#[cfg(test)]
mod cleanup_controls {
    use super::*;
    use crate::relay::relay_none::RelayAddressGeneratorNone;
    use crate::resource::BoundedTestAdmission;
    use std::sync::atomic::{AtomicBool, Ordering};
    use util::vnet::net::Net;

    struct Terminal(Arc<AtomicBool>);
    impl Drop for Terminal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn manager_joins_remaining_children_after_first_task_panic() {
        let charge = CleanupStatus::charge().unwrap();
        let limit = charge.units + charge.retained_bytes.div_ceil(1024) + 2;
        let admission = Arc::new(BoundedTestAdmission::new(limit));
        let cleanup = CleanupStatus::new(admission.as_ref()).unwrap();
        let manager = Manager::new(ManagerConfig {
            relay_addr_generator: Box::new(RelayAddressGeneratorNone {
                address: "127.0.0.1".into(),
                net: Arc::new(Net::new(None)),
            }),
            alloc_close_notify: None,
            resource_admission: admission.clone(),
            cleanup: cleanup.clone(),
        });
        let first_lease = admission
            .acquire(ResourceKind::AllocationTimer, ResourceCharge::units(1))
            .unwrap();
        let second_lease = admission
            .acquire(ResourceKind::AllocationTimer, ResourceCharge::units(1))
            .unwrap();
        let (first_ready, first_rx) = tokio::sync::oneshot::channel();
        let (second_ready, second_rx) = tokio::sync::oneshot::channel();
        let second_terminal = Arc::new(AtomicBool::new(false));
        let second_observer = second_terminal.clone();
        let first = tokio::spawn(async move {
            let _lease = first_lease;
            let _ = first_ready.send(());
            panic!("injected manager child panic");
        });
        let second = tokio::spawn(async move {
            let _lease = second_lease;
            let _terminal = Terminal(second_observer);
            let _ = second_ready.send(());
            std::future::pending::<()>().await;
        });
        manager.tasks.lock().await.extend([first, second]);
        let started = first_rx.await.is_ok() && second_rx.await.is_ok();
        let result = manager.close().await;
        let first_failure = cleanup.first();
        let repeat = manager.close().await;
        let terminal = second_terminal.load(Ordering::Acquire);
        drop((manager, cleanup));
        assert!(started && terminal);
        assert_eq!(
            first_failure,
            Some(CleanupFailure::TaskPanicked(CleanupTaskLayer::ManagerChild))
        );
        assert!(matches!(
            result,
            Err(Error::Cleanup(CleanupFailure::TaskPanicked(
                CleanupTaskLayer::ManagerChild
            )))
        ));
        assert!(matches!(
            repeat,
            Err(Error::Cleanup(CleanupFailure::TaskPanicked(
                CleanupTaskLayer::ManagerChild
            )))
        ));
        assert_eq!(admission.remaining_for_test(), limit);
    }
}

struct ReservationEntry {
    port: u16,
    generation: u64,
    _lease: Box<dyn ResourceLease>,
}

/// `ManagerConfig` a bag of config params for `Manager`.
pub struct ManagerConfig {
    pub relay_addr_generator: Box<dyn RelayAddressGenerator + Send + Sync>,
    pub alloc_close_notify: Option<mpsc::Sender<AllocationInfo>>,
    pub resource_admission: Arc<dyn ResourceAdmission>,
    pub cleanup: CleanupStatus,
}

/// `Manager` is used to hold active allocations.
pub struct Manager {
    allocations: Arc<Mutex<AllocationMap>>,
    reservations: Arc<Mutex<HashMap<String, ReservationEntry>>>,
    relay_addr_generator: Box<dyn RelayAddressGenerator + Send + Sync>,
    alloc_close_notify: Option<mpsc::Sender<AllocationInfo>>,
    resource_admission: Arc<dyn ResourceAdmission>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    next_reservation_generation: AtomicU64,
    cleanup: CleanupStatus,
}

impl Manager {
    /// Creates a new [`Manager`].
    pub fn new(config: ManagerConfig) -> Self {
        Manager {
            allocations: Arc::new(Mutex::new(HashMap::new())),
            reservations: Arc::new(Mutex::new(HashMap::new())),
            relay_addr_generator: config.relay_addr_generator,
            alloc_close_notify: config.alloc_close_notify,
            resource_admission: config.resource_admission,
            tasks: Mutex::new(Vec::new()),
            next_reservation_generation: AtomicU64::new(1),
            cleanup: config.cleanup,
        }
    }

    /// Closes this [`manager`] and closes all [`Allocation`]s it manages.
    pub async fn close(&self) -> Result<()> {
        let mut first_error = self.cleanup.result().err();
        let allocations = self.allocations.lock().await;
        for a in allocations.values() {
            if let Err(err) = a.close().await {
                if !matches!(err, Error::ErrClosed) {
                    self.cleanup.error(&err, CleanupFailure::AllocationClose);
                    first_error.get_or_insert(err);
                }
            }
        }
        drop(allocations);
        let tasks = self.tasks.lock().await.drain(..).collect::<Vec<_>>();
        for task in tasks {
            task.abort();
            self.cleanup
                .observe_join(task.await, CleanupTaskLayer::ManagerChild, true);
        }
        self.allocations.lock().await.clear();
        self.reservations.lock().await.clear();
        first_error.map_or_else(|| self.cleanup.result(), Err)
    }

    /// Returns the information about the all [`Allocation`]s associated with
    /// the specified [`FiveTuple`]s.
    pub async fn get_allocations_info(
        &self,
        five_tuples: Option<Vec<FiveTuple>>,
    ) -> HashMap<FiveTuple, AllocationInfo> {
        let mut infos = HashMap::new();

        let guarded = self.allocations.lock().await;

        guarded.iter().for_each(|(five_tuple, alloc)| {
            if five_tuples.is_none() || five_tuples.as_ref().unwrap().contains(five_tuple) {
                infos.insert(
                    *five_tuple,
                    AllocationInfo::new_with_admission(
                        *five_tuple,
                        alloc.username.text.clone(),
                        alloc.relay_addr,
                        #[cfg(feature = "metrics")]
                        alloc.relayed_bytes.load(Ordering::Acquire),
                    ),
                );
            }
        });

        infos
    }

    /// Fetches the [`Allocation`] matching the passed [`FiveTuple`].
    pub async fn get_allocation(&self, five_tuple: &FiveTuple) -> Option<Arc<Allocation>> {
        let allocations = self.allocations.lock().await;
        allocations.get(five_tuple).cloned()
    }

    /// Creates a new [`Allocation`] and starts relaying.
    pub async fn create_allocation(
        &self,
        five_tuple: FiveTuple,
        turn_socket: Arc<dyn Conn + Send + Sync>,
        requested_port: u16,
        lifetime: Duration,
        username: Username,
        use_ipv4: bool,
    ) -> Result<Arc<Allocation>> {
        if lifetime == Duration::from_secs(0) {
            return Err(Error::ErrLifetimeZero);
        }

        if self.get_allocation(&five_tuple).await.is_some() {
            return Err(Error::ErrDupeFiveTuple);
        }

        // Every retained allocation and both of its production tasks are
        // admitted before the relay generator can bind a native socket.
        let allocation_lease = self
            .resource_admission
            .acquire(ResourceKind::Allocation, ResourceCharge::units(1))
            .map_err(|_| Error::ErrResourceAdmission)?;
        let timer_lease = self
            .resource_admission
            .acquire(ResourceKind::AllocationTimer, ResourceCharge::units(1))
            .map_err(|_| Error::ErrResourceAdmission)?;
        let packet_lease = self
            .resource_admission
            .acquire(ResourceKind::PacketPump, ResourceCharge::units(1))
            .map_err(|_| Error::ErrResourceAdmission)?;

        let (relay_socket, relay_addr) = self
            .relay_addr_generator
            .allocate_conn(use_ipv4, requested_port)
            .await?;
        let mut a = Allocation::new_with_admission(
            turn_socket,
            relay_socket,
            relay_addr,
            five_tuple,
            username,
            Arc::downgrade(&self.allocations),
            self.alloc_close_notify.clone(),
            Arc::clone(&self.resource_admission),
            allocation_lease,
            self.cleanup.clone(),
        );

        log::debug!("listening on relay addr: {:?}", a.relay_addr);
        let timer_task = a.start(lifetime, timer_lease).await;
        let packet_task = a.packet_handler(packet_lease).await;

        let a = Arc::new(a);
        {
            let mut allocations = self.allocations.lock().await;
            allocations.insert(five_tuple, Arc::clone(&a));
        }
        let mut tasks = self.tasks.lock().await;
        tasks.push(timer_task);
        tasks.push(packet_task);

        Ok(a)
    }

    /// Removes an [`Allocation`].
    pub async fn delete_allocation(&self, five_tuple: &FiveTuple) {
        let allocation = self.allocations.lock().await.remove(five_tuple);

        if let Some(a) = allocation {
            if let Err(err) = a.close().await {
                if !matches!(err, Error::ErrClosed) {
                    self.cleanup.error(&err, CleanupFailure::AllocationClose);
                }
                log::error!("Failed to close allocation: {}", err);
            }
        }
    }

    /// Deletes the [`Allocation`]s according to the specified username `name`.
    pub async fn delete_allocations_by_username(&self, name: &str) {
        let to_delete = {
            let mut allocations = self.allocations.lock().await;

            let mut to_delete = Vec::new();

            // TODO(logist322): Use `.drain_filter()` once stabilized.
            allocations.retain(|_, allocation| {
                let match_name = allocation.username.text == name;

                if match_name {
                    to_delete.push(Arc::clone(allocation));
                }

                !match_name
            });

            to_delete
        };

        future::join_all(to_delete.iter().map(|a| async move {
            if let Err(err) = a.close().await {
                if !matches!(err, Error::ErrClosed) {
                    self.cleanup.error(&err, CleanupFailure::AllocationClose);
                }
                log::error!("Failed to close allocation: {}", err);
            }
        }))
        .await;
    }

    /// Stores the reservation for the token+port.
    pub async fn create_reservation(&self, reservation_token: String, port: u16) -> Result<()> {
        let token_bytes =
            u64::try_from(reservation_token.capacity()).map_err(|_| Error::ErrResourceAdmission)?;
        let record_lease = self
            .resource_admission
            .acquire(
                ResourceKind::Reservation,
                ResourceCharge::with_bytes(1, token_bytes),
            )
            .map_err(|_| Error::ErrResourceAdmission)?;
        let timer_lease = self
            .resource_admission
            .acquire(ResourceKind::AllocationTimer, ResourceCharge::units(1))
            .map_err(|_| Error::ErrResourceAdmission)?;
        let reservations = Arc::clone(&self.reservations);
        let reservation_token2 = reservation_token.clone();
        let generation = self
            .next_reservation_generation
            .fetch_add(1, Ordering::Relaxed);

        let task = tokio::spawn(async move {
            let _lease = timer_lease;
            let sleep = tokio::time::sleep(Duration::from_secs(30));
            tokio::pin!(sleep);
            tokio::select! {
                _ = &mut sleep => {
                    let mut reservations = reservations.lock().await;
                    if reservations
                        .get(&reservation_token2)
                        .is_some_and(|entry| entry.generation == generation)
                    {
                        reservations.remove(&reservation_token2);
                    }
                },
            }
        });

        let mut reservations = self.reservations.lock().await;
        reservations.insert(
            reservation_token,
            ReservationEntry {
                port,
                generation,
                _lease: record_lease,
            },
        );
        drop(reservations);
        self.tasks.lock().await.push(task);
        Ok(())
    }

    /// Returns the port for a given reservation if it exists.
    pub async fn get_reservation(&self, reservation_token: &str) -> Option<u16> {
        let reservations = self.reservations.lock().await;
        reservations.get(reservation_token).map(|entry| entry.port)
    }

    /// Consumes a reservation and releases its record lease. The caller must
    /// admit the replacement allocation before binding the consumed port.
    pub async fn take_reservation(&self, reservation_token: &str) -> Option<u16> {
        self.reservations
            .lock()
            .await
            .remove(reservation_token)
            .map(|entry| entry.port)
    }

    /// Returns a random un-allocated udp4 port.
    pub async fn get_random_even_port(&self) -> Result<u16> {
        let probe_lease = self
            .resource_admission
            .acquire(ResourceKind::RelayProbe, ResourceCharge::units(1))
            .map_err(|_| Error::ErrResourceAdmission)?;
        let (_, addr) = self.relay_addr_generator.allocate_conn(true, 0).await?;
        drop(probe_lease);
        Ok(addr.port())
    }
}
