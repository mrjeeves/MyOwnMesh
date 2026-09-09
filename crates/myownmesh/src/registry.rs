//! Per-daemon registry of joined networks, keyed by both the user-chosen
//! config id and the wire-level network id. The control socket uses
//! this to address per-network operations (peers list, roster mutations,
//! topology changes, add/remove) without `serve.rs` having to thread a
//! handle through every dispatch arm.
//!
//! Each entry pairs a `JoinedNetwork` with its `SignalingDrivers` — the
//! signaling driver set (Nostr and/or mDNS, per the network's
//! strategy) is per-network, and dropping the handle stops it.
//!
//! # One lifecycle owner
//!
//! This registry is the only owner of a joined runtime's lifecycle, and
//! [`RuntimeState`] is the only place the answer lives.
//!
//! An `Arc` refcount cannot stand in for it. A refcount answers "is this value
//! shared", which is a different question — a runtime with one in-flight
//! control request and a runtime that has finished tearing down are both "not
//! solely owned" — and dropping the command sender does not exit the engine,
//! because `NetworkState` holds that sender itself. An engine left running with
//! live sessions while no key in this map could reach it would be joined beside
//! by the next `network_update` under the same configuration, leaving a hidden
//! runtime next to the visible one.
//!
//! Four properties carry it instead, and each is structural rather than
//! observed:
//!
//! * a runtime is claimed for teardown, unlinked, and moved to the closing set
//!   in **one** acquisition of the registry's state lock, so there is no
//!   instant in which it is unreachable, unowned, or invisible to the check a
//!   concurrent insert makes;
//! * a `Closing` entry stays owned here until teardown completes, so no live
//!   runtime is ever ownerless;
//! * a replacement under either id is refused while **any** runtime holding
//!   either id is not yet `Stopped` — `Running` as well as `Closing`. A
//!   `Running` collision falling through to the map would let `insert`
//!   overwrite one alias while `or_insert` left the other pointing at the
//!   predecessor: two live runtimes, one half-reachable, neither being torn
//!   down;
//! * every caller that loses the race to claim a teardown **waits for the
//!   winner** and observes `Stopped` before returning. Answering "already
//!   closing" and returning immediately would let `shutdown_all` finish while a
//!   concurrent removal was still awaiting an engine driver, exiting the daemon
//!   with that engine live.
//!
//! Teardown itself needs no unwrapping: [`JoinedNetwork::shutdown`] takes
//! `&self` and is idempotent, so the supervisor drives it through the shared
//! handle rather than requiring unique ownership of every outstanding facade.
//! A loser calls it too — that is what makes "wait for the winner" go through
//! the runtime's own seam rather than through a second mechanism — and then
//! waits on [`Lifecycle::await_stopped`], because `shutdown` returning proves
//! the driver is retired and not yet that this registry has finished
//! bookkeeping the fact.
//!
//! Concurrency: one [`parking_lot::Mutex`] guards the aliases and the closing
//! set together, because every decision here is about both. Callers pull an
//! `Arc<JoinedNetwork>` out and drop the guard before awaiting any per-network
//! method — holding a `parking_lot` guard across `.await` is forbidden, and no
//! path here does.

use std::collections::HashMap;
use std::sync::Arc;

use myownmesh_core::engine::SignalingDrivers;
use myownmesh_core::handle::ClosedRelayChannel;
use myownmesh_core::JoinedNetwork;
use parking_lot::Mutex;
use parking_lot::MutexGuard;

/// Where one joined runtime is in its life. The single owner of that answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeState {
    /// Registered and authoritative. Operations are admitted.
    Running,
    /// Teardown has begun. The aliases are gone and no new operation is
    /// admitted, but the runtime is still owned here. An outstanding facade
    /// observes this instead of keeping an unregistered runtime authoritative.
    Closing,
    /// Teardown finished: signaling drivers dropped, engine driver retired. A
    /// replacement may install under the same ids.
    Stopped,
}

/// Atomic answer for a prospective join's two identity aliases.
///
/// `Existing` is deliberately returned for an unbound local config id that
/// names the same currently-running wire network.  A caller can therefore
/// replay a config with a different local id without creating a second
/// runtime.  `Collision` covers both a different wire owner and a runtime
/// that is still closing; neither may be bypassed by a later insert.
pub(crate) enum JoinAdmission {
    Empty,
    Existing(Arc<JoinedNetwork>),
    Collision(RuntimeState),
}

/// Snapshot view of one joined network for ctl / GUI consumers.
/// Cheap to compute — every field is already cached on the
/// `JoinedNetwork`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NetworkSummary {
    /// User-chosen config record id (unique per device). Auto-generated
    /// (`net_<rand>_<stamp>`) at create time and used as a stable
    /// key for control-protocol ops — not the friendly display name.
    pub config_id: String,
    /// Wire-level network rendezvous handle. Human-typed at create
    /// time (e.g. `cpjeeves-home`); the GUI falls back to this when
    /// no cosmetic `label` is set.
    pub network_id: String,
    /// Cosmetic display name picked at create time. Empty falls
    /// back to `network_id`.
    pub label: String,
    /// Coarse-grained phase: joining / alone / discovering / active / degraded / stopped.
    pub phase: myownmesh_core::MeshPhase,
    /// Current topology mode. Serialised with serde-internal tagging so
    /// `Star { hub }` keeps its hub field on the wire.
    pub topology: myownmesh_core::TopologyMode,
    /// Per-network traffic accounting since join — frames/bytes by
    /// class, signaling publish/receive split into presence vs
    /// negotiation, forwarding duty, acked-delivery backlog. The
    /// numbers a topology experiment compares.
    pub traffic: myownmesh_core::engine::traffic::TrafficSnapshot,
}

/// Where one runtime is in its life, and the signal that it has finished.
///
/// Separated from [`Entry`] because it is the whole of the lifecycle rule and
/// none of it needs a runtime to be true. Claiming, waiting and finishing are
/// the three things that have to be right, and keeping them in one small type
/// is what lets them be exercised directly rather than only through a joined
/// network.
pub(crate) struct Lifecycle {
    state: Mutex<RuntimeState>,
    /// Fired once, when [`Self::finish`] lands. Waiters re-read the state
    /// rather than trusting the wake, so a notify that arrives before a waiter
    /// registers cannot be lost.
    stopped: tokio::sync::Notify,
}

impl Lifecycle {
    /// A runtime begins `Running`. Deliberately not `Default`: which state a
    /// lifecycle starts in is a decision, and a derived one would read as the
    /// state a runtime is in when nobody said.
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(RuntimeState::Running),
            stopped: tokio::sync::Notify::new(),
        }
    }

    pub(crate) fn state(&self) -> RuntimeState {
        *self.state.lock()
    }

    /// Claim this runtime for teardown, exactly once.
    ///
    /// `true` to the caller that moved it `Running` -> `Closing`, and `false`
    /// to every other — which is what makes "exactly one teardown" a property
    /// of the transition rather than of caller discipline.
    pub(crate) fn begin_closing(&self) -> bool {
        let mut state = self.state.lock();
        if *state != RuntimeState::Running {
            return false;
        }
        *state = RuntimeState::Closing;
        true
    }

    /// Record that teardown is complete and release every waiter.
    ///
    /// The state moves first and the wake follows, which is the order
    /// [`Self::await_stopped`]'s double check depends on: a waiter that reads
    /// the state after registering its `Notified` cannot miss a `finish` that
    /// happened in between.
    pub(crate) fn finish(&self) {
        *self.state.lock() = RuntimeState::Stopped;
        self.stopped.notify_waiters();
    }

    /// Wait until this runtime has actually stopped.
    ///
    /// Returns `Stopped` and nothing else — the return exists so a caller can
    /// state what it observed rather than assert it. The double check around
    /// registration is the standard race-free `Notify` shape: read, register,
    /// read again, then await. Without the second read a `finish` landing
    /// between the first read and the registration would be lost and the
    /// waiter would park forever.
    pub(crate) async fn await_stopped(&self) -> RuntimeState {
        loop {
            if self.state() == RuntimeState::Stopped {
                return RuntimeState::Stopped;
            }
            let notified = self.stopped.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state() == RuntimeState::Stopped {
                return RuntimeState::Stopped;
            }
            notified.await;
        }
    }
}

/// One row of the registry: the `JoinedNetwork` handle, the
/// `SignalingDrivers` that keep signaling alive, and where that runtime is in
/// its life. `drivers` is `Mutex<Option<...>>` so teardown can `take()` it
/// through the shared `Arc` without `&mut self`.
struct Entry {
    joined: Arc<JoinedNetwork>,
    drivers: Mutex<Option<SignalingDrivers>>,
    lifecycle: Lifecycle,
}

impl Entry {
    /// Whether this runtime answers to `id` under either of its two names.
    fn holds(&self, id: &str) -> bool {
        self.joined.config_id() == id || self.joined.network_id() == id
    }
}

/// Registry shared between `serve.rs` (which owns initial population
/// + final shutdown) and the control socket dispatcher (which clones
///   `Arc<JoinedNetwork>`s out to perform per-network work, and may
///   add/remove networks via the NetworkAdd / NetworkRemove ops).
#[derive(Default)]
pub struct NetworkRegistry {
    state: Mutex<RegistryState>,
    #[cfg(test)]
    claim_pause: Mutex<Option<Arc<ClaimPause>>>,
}

/// The daemon-owned capability table for Closed relay endpoint sessions.
///
/// A control handle is deliberately not an engine handle: only this table can
/// reach the move-only channel, and every entry is removed before its
/// consuming close is awaited. Reservations are counted before the engine
/// allocates an endpoint, so the daemon never starts a relay it cannot retain.
pub(crate) struct ClosedRelayRegistry {
    state: Mutex<ClosedRelayState>,
}

struct ClosedRelayState {
    entries: HashMap<String, Arc<ClosedRelayEntry>>,
    reservations: HashMap<String, usize>,
    next_generation: u64,
    closing: bool,
}

struct ClosedRelayEntry {
    snapshot: ClosedRelaySnapshot,
    channel: tokio::sync::Mutex<Option<ClosedRelayChannel>>,
    _lease: myownmesh_core::ResourceLease,
}

#[derive(Clone, Debug)]
pub(crate) struct ClosedRelaySnapshot {
    pub(crate) network: String,
    pub(crate) peer: String,
    pub(crate) relay: String,
    pub(crate) session_id: [u8; 16],
    pub(crate) allocation_epoch: u64,
    pub(crate) generation: u64,
    pub(crate) max_allocations: u64,
    pub(crate) max_frame_bytes: u64,
}

pub(crate) struct ClosedRelayCapability {
    pub(crate) handle: String,
    pub(crate) snapshot: ClosedRelaySnapshot,
}

pub(crate) struct ClosedRelayReservation {
    registry: Arc<ClosedRelayRegistry>,
    network: String,
    max_allocations: u64,
    max_frame_bytes: u64,
    lease: Option<myownmesh_core::ResourceLease>,
    active: bool,
}

pub(crate) struct ClosedRelayCommitError {
    pub(crate) channel: ClosedRelayChannel,
    pub(crate) message: &'static str,
}

impl ClosedRelayRegistry {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ClosedRelayState {
                entries: HashMap::new(),
                reservations: HashMap::new(),
                next_generation: 0,
                closing: false,
            }),
        })
    }

    pub(crate) fn reserve(
        self: &Arc<Self>,
        resources: &myownmesh_core::LocalApplicationResourceScope,
        network: &JoinedNetwork,
    ) -> std::result::Result<ClosedRelayReservation, &'static str> {
        let config = network.config_snapshot();
        let network_id = network.config_id().to_owned();
        let mut state = self.state.lock();
        if state.closing {
            return Err("closed relay registry is closing");
        }
        let active = state
            .entries
            .values()
            .filter(|entry| entry.snapshot.network == network_id)
            .count();
        let reserved = state.reservations.get(&network_id).copied().unwrap_or(0);
        let limit = usize::try_from(config.closed_relay.max_allocations)
            .map_err(|_| "closed relay allocation limit is not representable")?;
        let would_exceed = active
            .checked_add(reserved)
            .and_then(|count| count.checked_add(1))
            .is_none_or(|count| count > limit);
        if would_exceed {
            return Err("closed relay allocation limit is full");
        }
        let lease = resources
            .acquire(myownmesh_core::ResourceClaim::single(
                myownmesh_core::ResourceClass::OpaqueDependencyResidual,
                1,
            ))
            .map_err(|_| "closed relay registry custody was refused")?;
        *state.reservations.entry(network_id.clone()).or_default() += 1;
        Ok(ClosedRelayReservation {
            registry: Arc::clone(self),
            network: network_id,
            max_allocations: config.closed_relay.max_allocations,
            max_frame_bytes: config.closed_relay.max_frame_ciphertext_bytes,
            lease: Some(lease),
            active: true,
        })
    }

    pub(crate) async fn send(
        &self,
        handle: &str,
        payload: &[u8],
    ) -> std::result::Result<(ClosedRelaySnapshot, usize), String> {
        let entry = self.entry(handle)?;
        let snapshot = entry.snapshot.clone();
        if u64::try_from(payload.len()).map_or(true, |bytes| bytes > snapshot.max_frame_bytes) {
            return Err(format!(
                "closed relay payload exceeds configured {} byte ceiling",
                snapshot.max_frame_bytes
            ));
        }
        let channel = entry.channel.lock().await;
        let channel = channel
            .as_ref()
            .ok_or_else(|| "closed relay handle is already closed".to_string())?;
        channel
            .send(payload)
            .await
            .map_err(|error| error.to_string())?;
        Ok((snapshot, payload.len()))
    }

    pub(crate) async fn recv(
        &self,
        handle: &str,
        wait_ms: u64,
    ) -> std::result::Result<(ClosedRelaySnapshot, Vec<u8>), String> {
        let entry = self.entry(handle)?;
        let snapshot = entry.snapshot.clone();
        let channel = entry.channel.lock().await;
        let channel = channel
            .as_ref()
            .ok_or_else(|| "closed relay handle is already closed".to_string())?;
        let payload =
            tokio::time::timeout(std::time::Duration::from_millis(wait_ms), channel.recv())
                .await
                .map_err(|_| "closed relay receive wait expired".to_string())?
                .map_err(|error| error.to_string())?;
        Ok((snapshot, payload))
    }

    pub(crate) async fn close(
        &self,
        handle: &str,
    ) -> std::result::Result<ClosedRelaySnapshot, String> {
        let entry = {
            let mut state = self.state.lock();
            state
                .entries
                .remove(handle)
                .ok_or_else(|| "unknown or already closed relay handle".to_string())?
        };
        let snapshot = entry.snapshot.clone();
        let channel = entry.channel.lock().await.take();
        if let Some(channel) = channel {
            channel.close().await.map_err(|error| error.to_string())?;
        }
        Ok(snapshot)
    }

    pub(crate) async fn state(
        &self,
        handle: &str,
    ) -> std::result::Result<(ClosedRelaySnapshot, usize), String> {
        let entry = self.entry(handle)?;
        let network = entry.snapshot.network.clone();
        let active = {
            let state = self.state.lock();
            state
                .entries
                .values()
                .filter(|entry| entry.snapshot.network == network)
                .count()
        };
        Ok((entry.snapshot.clone(), active))
    }

    pub(crate) async fn shutdown_all(&self) -> std::result::Result<(), String> {
        let entries = {
            let mut state = self.state.lock();
            state.closing = true;
            state
                .entries
                .drain()
                .map(|(_, entry)| entry)
                .collect::<Vec<_>>()
        };
        let mut failures = Vec::new();
        for entry in entries {
            if let Some(channel) = entry.channel.lock().await.take() {
                if let Err(error) = channel.close().await {
                    failures.push(error.to_string());
                }
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }

    fn entry(&self, handle: &str) -> std::result::Result<Arc<ClosedRelayEntry>, String> {
        self.state
            .lock()
            .entries
            .get(handle)
            .cloned()
            .ok_or_else(|| "unknown or already closed relay handle".to_string())
    }
}

impl ClosedRelayReservation {
    pub(crate) fn commit(
        mut self,
        channel: ClosedRelayChannel,
    ) -> std::result::Result<ClosedRelayCapability, ClosedRelayCommitError> {
        self.active = false;
        let lease = self
            .lease
            .take()
            .expect("a live reservation owns its registry lease");
        let mut state = self.registry.state.lock();
        let reservations = state
            .reservations
            .get_mut(&self.network)
            .expect("a live reservation owns its registry count");
        *reservations -= 1;
        if *reservations == 0 {
            state.reservations.remove(&self.network);
        }
        if state.closing {
            return Err(ClosedRelayCommitError {
                channel,
                message: "closed relay registry is closing",
            });
        }
        let mut bytes = [0u8; 32];
        if getrandom::getrandom(&mut bytes).is_err() {
            return Err(ClosedRelayCommitError {
                channel,
                message: "could not mint closed relay capability",
            });
        }
        let handle = data_encoding::BASE64URL_NOPAD.encode(&bytes);
        if state.entries.contains_key(&handle) {
            return Err(ClosedRelayCommitError {
                channel,
                message: "closed relay capability collision",
            });
        }
        state.next_generation = match state.next_generation.checked_add(1) {
            Some(generation) => generation,
            None => {
                return Err(ClosedRelayCommitError {
                    channel,
                    message: "closed relay generation exhausted",
                })
            }
        };
        let snapshot = ClosedRelaySnapshot {
            network: self.network.clone(),
            peer: channel.peer_device_id().to_owned(),
            relay: channel.relay_device_id().to_owned(),
            session_id: channel.session_id(),
            allocation_epoch: channel.allocation_epoch(),
            generation: state.next_generation,
            max_allocations: self.max_allocations,
            max_frame_bytes: self.max_frame_bytes,
        };
        state.entries.insert(
            handle.clone(),
            Arc::new(ClosedRelayEntry {
                snapshot: snapshot.clone(),
                channel: tokio::sync::Mutex::new(Some(channel)),
                _lease: lease,
            }),
        );
        Ok(ClosedRelayCapability { handle, snapshot })
    }
}

impl Drop for ClosedRelayReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.registry.state.lock();
        if let Some(reservations) = state.reservations.get_mut(&self.network) {
            *reservations = reservations.saturating_sub(1);
            if *reservations == 0 {
                state.reservations.remove(&self.network);
            }
        }
    }
}

pub(crate) struct StatusSource<'a> {
    state: MutexGuard<'a, RegistryState>,
    identity: &'a myownmesh_core::Identity,
    realtime: &'a crate::control::RealtimeAdvert,
}

/// A capacity-only description of the next NetworksList snapshot.
///
/// No entry, id, state value, or authority crosses the provider acquisition:
/// pass zero contributes numbers only. [`Self::measure_line_ceiling`] measures
/// after work admission, and the resulting [`MeasuredNetworksList`] reacquires
/// the daemon registry for its authoritative snapshot.
#[must_use = "a NetworksList plan has not yet funded or built its snapshot"]
pub(crate) struct PreparedNetworksList<'a> {
    registry: &'a NetworkRegistry,
    typed_claim: myownmesh_core::ResourceClaim,
    work_claim: myownmesh_core::ResourceClaim,
}

/// A NetworksList plan whose exact current line length was measured while its
/// transient traversal work was already funded.
#[must_use = "a measured NetworksList plan has not yet committed its funded rows"]
pub(crate) struct MeasuredNetworksList<'a> {
    registry: &'a NetworkRegistry,
    typed_claim: myownmesh_core::ResourceClaim,
    work_claim: myownmesh_core::ResourceClaim,
    line_ceiling: usize,
}

/// One prepared NetworksList value and the retention that outlives its rows.
#[must_use = "dropping a funded NetworksList releases the snapshot it owns"]
pub(crate) struct FundedNetworksList {
    rows: Box<[PreparedSlot<PreparedNetworkSummary>]>,
    _retention: myownmesh_core::ResourceLease,
    _work: myownmesh_core::ResourceLease,
}

impl serde::Serialize for FundedNetworksList {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(
            &PreparedNetworksData {
                networks: &self.rows,
            },
            serializer,
        )
    }
}

/// The exact internal wire shape of one prepared topology.
///
/// Dynamic hub storage uses fixed boxes so its requested bytes and allocation
/// count are derivable from the borrowed core view before it is copied.
#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
enum PreparedTopology {
    Ring {
        n_preferred: Option<u32>,
    },
    Star {
        hub: Box<str>,
    },
    HubTree {
        root: Box<str>,
        hubs: Box<[PreparedSlot<Box<str>>]>,
        backup_candidates: u32,
    },
    Hubs {
        hubs: Box<[PreparedSlot<Box<str>>]>,
        spoke_redundancy: Option<u32>,
    },
    FullMesh,
}

/// The exact owned row serialized by [`FundedNetworksList`].
#[derive(serde::Serialize)]
struct PreparedNetworkSummary {
    config_id: Box<str>,
    network_id: Box<str>,
    label: Box<str>,
    phase: myownmesh_core::MeshPhase,
    topology: PreparedTopology,
    traffic: myownmesh_core::engine::traffic::TrafficSnapshot,
}

/// One exact slot in the final fixed row box.
///
/// Slots start empty and are filled in canonical order. A funded owner is
/// published only after every slot is present, so serialization never emits an
/// option wrapper or a `null` in place of a row.
struct PreparedSlot<T>(Option<T>);

impl<T: serde::Serialize> serde::Serialize for PreparedSlot<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        serde::Serialize::serialize(
            self.0
                .as_ref()
                .ok_or_else(|| S::Error::custom("an admitted NetworksList row was not built"))?,
            serializer,
        )
    }
}

/// Allocate the staging slots used while one registry reply is prepared.
fn empty_prepared_slots<T>(count: usize) -> Box<[PreparedSlot<T>]> {
    std::iter::repeat_with(|| PreparedSlot(None))
        .take(count)
        .collect()
}

#[derive(serde::Serialize)]
struct BorrowedNetworkSummary<'a> {
    config_id: &'a str,
    network_id: &'a str,
    label: &'a str,
    phase: myownmesh_core::MeshPhase,
    topology: &'a myownmesh_core::TopologyMode,
    traffic: myownmesh_core::engine::traffic::TrafficSnapshot,
}

struct NetworksView<'a>(&'a RegistryState);

impl serde::Serialize for NetworksView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let count = self
            .0
            .aliases
            .iter()
            .filter(|(key, entry)| key.as_str() == entry.joined.config_id())
            .count();
        let mut sequence = serializer.serialize_seq(Some(count))?;
        let mut error = None;
        self.0.for_each_canonical_in_config_order(|entry| {
            if error.is_some() {
                return;
            }
            entry.joined.with_network_summary_view(
                |config_id, network_id, label, phase, topology, traffic| {
                    error = sequence
                        .serialize_element(&BorrowedNetworkSummary {
                            config_id,
                            network_id,
                            label,
                            phase,
                            topology,
                            traffic,
                        })
                        .err();
                },
            );
        });
        if let Some(error) = error {
            return Err(error);
        }
        sequence.end()
    }
}

#[derive(serde::Serialize)]
struct BorrowedNetworksData<'a> {
    networks: NetworksView<'a>,
}

#[derive(serde::Serialize)]
struct PreparedNetworksData<'a> {
    networks: &'a [PreparedSlot<PreparedNetworkSummary>],
}

/// The exact owned projection serialized by the prepared Status reply.
///
/// Kept separate from [`FundedStatus`] so the central serialized measurement
/// and exact owned type layout price the value it actually retains. The lease
/// is the funding for this value; including that handle in the priced type
/// would make its own claim circular.
#[derive(serde::Serialize)]
struct OwnedStatusData {
    version: &'static str,
    device_id: String,
    joined_networks: Vec<String>,
    realtime: crate::control::RealtimeAdvert,
}

/// One Status projection and the retention that outlives every owned field.
pub(crate) struct FundedStatus {
    data: OwnedStatusData,
    _retention: myownmesh_core::ResourceLease,
}

impl FundedStatus {
    pub(crate) fn version(&self) -> &'static str {
        self.data.version
    }

    pub(crate) fn device_id(&self) -> &str {
        &self.data.device_id
    }

    pub(crate) fn joined_networks(&self) -> &[String] {
        &self.data.joined_networks
    }

    pub(crate) fn realtime(&self) -> &crate::control::RealtimeAdvert {
        &self.data.realtime
    }
}

struct DisplayIdWidth(usize);

impl std::fmt::Display for DisplayIdWidth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for _ in 0..self.0 {
            formatter.write_str("a")?;
        }
        Ok(())
    }
}

impl serde::Serialize for DisplayIdWidth {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

struct VisibleNetworkIds<'a>(&'a RegistryState);

impl RegistryState {
    /// Visit canonical entries in the current NetworksList/`summaries()` order without a
    /// staging allocation. Each step scans for the least config id greater
    /// than the previous one, so this is O(N²) comparisons and O(1) auxiliary
    /// space. Config ids are bounded control coordinates and the registry lock
    /// keeps the observation coherent; the final owned output is still built
    /// only after its retention has been admitted.
    fn for_each_canonical_in_config_order(&self, mut visit: impl FnMut(&Arc<Entry>)) {
        let mut after: Option<&str> = None;
        loop {
            let next = self
                .aliases
                .iter()
                .filter(|(key, entry)| key.as_str() == entry.joined.config_id())
                .filter(|(key, _)| after.is_none_or(|after| key.as_str() > after))
                .min_by(|(left, _), (right, _)| left.cmp(right));
            let Some((key, entry)) = next else { break };
            visit(entry);
            after = Some(key.as_str());
        }
    }

    fn canonical_count(&self) -> usize {
        self.aliases
            .iter()
            .filter(|(key, entry)| key.as_str() == entry.joined.config_id())
            .count()
    }
}

fn checked_network_bytes_add(
    total: &mut usize,
    more: usize,
) -> Result<(), myownmesh_core::ResourceMailboxItemError> {
    *total =
        total
            .checked_add(more)
            .ok_or(myownmesh_core::ResourceMailboxItemError::Measurement(
                "NetworksList retention length overflowed",
            ))?;
    Ok(())
}

fn serialized_typed_claim<T>(
    value: &impl serde::Serialize,
) -> Result<myownmesh_core::ResourceClaim, myownmesh_core::ResourceMailboxItemError> {
    let (retained, queued, allocations) = myownmesh_core::mailbox_measure_serialized(value)?;
    let fixed = std::mem::size_of::<T>().checked_add(retained).ok_or(
        myownmesh_core::ResourceClaimArithmeticError::Overflow {
            dimension: myownmesh_core::ResourceClass::AccountedMemoryBytes,
        },
    )?;
    let fixed = u64::try_from(fixed).map_err(|_| {
        myownmesh_core::ResourceClaimArithmeticError::Overflow {
            dimension: myownmesh_core::ResourceClass::AccountedMemoryBytes,
        }
    })?;
    let queued = u64::try_from(queued).map_err(|_| {
        myownmesh_core::ResourceClaimArithmeticError::Overflow {
            dimension: myownmesh_core::ResourceClass::QueuedBytes,
        }
    })?;
    let allocations = u64::try_from(allocations)
        .map_err(|_| myownmesh_core::ResourceClaimArithmeticError::Overflow {
            dimension: myownmesh_core::ResourceClass::OpaqueDependencyResidual,
        })?
        .checked_add(1)
        .ok_or(myownmesh_core::ResourceClaimArithmeticError::Overflow {
            dimension: myownmesh_core::ResourceClass::OpaqueDependencyResidual,
        })?;
    Ok(myownmesh_core::ResourceClaim::try_from_entries([
        (myownmesh_core::ResourceClass::AccountedMemoryBytes, fixed),
        (myownmesh_core::ResourceClass::QueuedBytes, queued),
        (myownmesh_core::ResourceClass::ParsingOrCpuWork, queued),
        (
            myownmesh_core::ResourceClass::OpaqueDependencyResidual,
            allocations,
        ),
    ])?)
}

fn checked_network_allocations_add(
    total: &mut usize,
    more: usize,
) -> Result<(), myownmesh_core::ResourceMailboxItemError> {
    *total =
        total
            .checked_add(more)
            .ok_or(myownmesh_core::ResourceMailboxItemError::Measurement(
                "NetworksList allocation count overflowed",
            ))?;
    Ok(())
}

fn measure_network_text(
    value: &str,
    bytes: &mut usize,
    allocations: &mut usize,
) -> Result<(), myownmesh_core::ResourceMailboxItemError> {
    checked_network_bytes_add(bytes, value.len())?;
    if !value.is_empty() {
        checked_network_allocations_add(allocations, 1)?;
    }
    Ok(())
}

fn measure_network_row(
    config_id: &str,
    network_id: &str,
    label: &str,
    topology: &myownmesh_core::TopologyMode,
) -> Result<(usize, usize), myownmesh_core::ResourceMailboxItemError> {
    let mut bytes = 0usize;
    let mut allocations = 0usize;
    measure_network_text(config_id, &mut bytes, &mut allocations)?;
    measure_network_text(network_id, &mut bytes, &mut allocations)?;
    measure_network_text(label, &mut bytes, &mut allocations)?;
    match topology {
        myownmesh_core::TopologyMode::Ring { .. } | myownmesh_core::TopologyMode::FullMesh => {}
        myownmesh_core::TopologyMode::Star { hub } => {
            measure_network_text(hub, &mut bytes, &mut allocations)?;
        }
        myownmesh_core::TopologyMode::HubTree { root, hubs, .. } => {
            measure_network_text(root, &mut bytes, &mut allocations)?;
            checked_network_bytes_add(
                &mut bytes,
                hubs.len()
                    .checked_mul(std::mem::size_of::<PreparedSlot<Box<str>>>())
                    .ok_or(myownmesh_core::ResourceMailboxItemError::Measurement(
                        "NetworksList HubTree hubs storage overflowed",
                    ))?,
            )?;
            if !hubs.is_empty() {
                checked_network_allocations_add(&mut allocations, 1)?;
            }
            for hub in hubs {
                measure_network_text(hub, &mut bytes, &mut allocations)?;
            }
        }
        myownmesh_core::TopologyMode::Hubs { hubs, .. } => {
            checked_network_bytes_add(
                &mut bytes,
                hubs.len()
                    .checked_mul(std::mem::size_of::<PreparedSlot<Box<str>>>())
                    .ok_or(myownmesh_core::ResourceMailboxItemError::Measurement(
                        "NetworksList hubs storage overflowed",
                    ))?,
            )?;
            if !hubs.is_empty() {
                checked_network_allocations_add(&mut allocations, 1)?;
            }
            for hub in hubs {
                measure_network_text(hub, &mut bytes, &mut allocations)?;
            }
        }
    }
    Ok((bytes, allocations))
}

fn add_network_dynamic_fitting(
    actual: &mut myownmesh_core::ResourceClaim,
    admitted: myownmesh_core::ResourceClaim,
    bytes: usize,
    allocations: usize,
) -> Result<bool, myownmesh_core::ResourceMailboxItemError> {
    let next = actual.checked_add(networks_dynamic_claim(bytes, allocations)?)?;
    if !claim_fits(next, admitted) {
        return Ok(false);
    }
    *actual = next;
    Ok(true)
}

/// Add one current row's dynamic retention, stopping before the first term
/// whose traversal or construction would exceed the admitted typed capacity.
///
/// In particular the fixed hub-slot box is checked from `hubs.len()` before any
/// hub string is visited. A topology that grew far beyond pass zero therefore
/// refuses in O(1), rather than spending unadmitted work walking the new list.
fn add_network_row_fitting(
    actual: &mut myownmesh_core::ResourceClaim,
    admitted: myownmesh_core::ResourceClaim,
    config_id: &str,
    network_id: &str,
    label: &str,
    topology: &myownmesh_core::TopologyMode,
) -> Result<bool, myownmesh_core::ResourceMailboxItemError> {
    for value in [config_id, network_id, label] {
        if !add_network_dynamic_fitting(
            actual,
            admitted,
            value.len(),
            usize::from(!value.is_empty()),
        )? {
            return Ok(false);
        }
    }
    match topology {
        myownmesh_core::TopologyMode::Ring { .. } | myownmesh_core::TopologyMode::FullMesh => {}
        myownmesh_core::TopologyMode::Star { hub } => {
            if !add_network_dynamic_fitting(
                actual,
                admitted,
                hub.len(),
                usize::from(!hub.is_empty()),
            )? {
                return Ok(false);
            }
        }
        myownmesh_core::TopologyMode::HubTree { root, hubs, .. } => {
            if !add_network_dynamic_fitting(
                actual,
                admitted,
                root.len(),
                usize::from(!root.is_empty()),
            )? {
                return Ok(false);
            }
            let slots = hubs
                .len()
                .checked_mul(std::mem::size_of::<PreparedSlot<Box<str>>>())
                .ok_or(myownmesh_core::ResourceMailboxItemError::Measurement(
                    "NetworksList HubTree hubs storage overflowed",
                ))?;
            if !add_network_dynamic_fitting(actual, admitted, slots, usize::from(!hubs.is_empty()))?
            {
                return Ok(false);
            }
            for hub in hubs {
                if !add_network_dynamic_fitting(
                    actual,
                    admitted,
                    hub.len(),
                    usize::from(!hub.is_empty()),
                )? {
                    return Ok(false);
                }
            }
        }
        myownmesh_core::TopologyMode::Hubs { hubs, .. } => {
            let slots = hubs
                .len()
                .checked_mul(std::mem::size_of::<PreparedSlot<Box<str>>>())
                .ok_or(myownmesh_core::ResourceMailboxItemError::Measurement(
                    "NetworksList hubs storage overflowed",
                ))?;
            if !add_network_dynamic_fitting(actual, admitted, slots, usize::from(!hubs.is_empty()))?
            {
                return Ok(false);
            }
            for hub in hubs {
                if !add_network_dynamic_fitting(
                    actual,
                    admitted,
                    hub.len(),
                    usize::from(!hub.is_empty()),
                )? {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

/// Re-measure the current authoritative registry without allocating. Returns
/// `None` on any drift that does not fit the pass-zero typed lease.
fn current_networks_claim_fitting(
    state: &RegistryState,
    admitted: myownmesh_core::ResourceClaim,
) -> Result<Option<myownmesh_core::ResourceClaim>, myownmesh_core::ResourceMailboxItemError> {
    let typed_bytes = admitted.amount(myownmesh_core::ResourceClass::AccountedMemoryBytes);
    let aliases = u64::try_from(state.aliases.len()).map_err(|_| {
        myownmesh_core::ResourceMailboxItemError::Measurement(
            "NetworksList alias count does not fit the resource model",
        )
    })?;
    // Bound even the first canonical-count traversal. Every admitted row owns a
    // nonzero fixed slot, so an alias table larger than the admitted byte count
    // cannot possibly fit and is refused without scanning it.
    if aliases > typed_bytes {
        return Ok(None);
    }
    let count = state.canonical_count();
    let mut actual = match networks_claim(count, 0, 0) {
        Ok(claim) if claim_fits(claim, admitted) => claim,
        _ => return Ok(None),
    };
    let mut fits = true;
    let mut measurement_error = None;
    state.for_each_canonical_in_config_order(|entry| {
        if !fits || measurement_error.is_some() {
            return;
        }
        entry.joined.with_network_summary_view(
            |config_id, network_id, label, _phase, topology, _traffic| {
                match add_network_row_fitting(
                    &mut actual,
                    admitted,
                    config_id,
                    network_id,
                    label,
                    topology,
                ) {
                    Ok(current_fits) => fits = current_fits,
                    Err(error) => measurement_error = Some(error),
                }
            },
        );
    });
    if let Some(error) = measurement_error {
        return Err(error);
    }
    Ok(fits.then_some(actual))
}

fn networks_claim(
    count: usize,
    row_bytes: usize,
    row_allocations: usize,
) -> Result<myownmesh_core::ResourceClaim, myownmesh_core::ResourceMailboxItemError> {
    let rows = count
        .checked_mul(std::mem::size_of::<PreparedSlot<PreparedNetworkSummary>>())
        .ok_or(myownmesh_core::ResourceMailboxItemError::Measurement(
            "NetworksList row storage overflowed",
        ))?;
    let bytes = std::mem::size_of::<Box<[PreparedSlot<PreparedNetworkSummary>]>>()
        .checked_add(rows)
        .and_then(|bytes| bytes.checked_add(row_bytes))
        .ok_or(myownmesh_core::ResourceMailboxItemError::Measurement(
            "NetworksList typed retention overflowed",
        ))?;
    let allocations = row_allocations.checked_add(usize::from(count != 0)).ok_or(
        myownmesh_core::ResourceMailboxItemError::Measurement(
            "NetworksList typed allocation count overflowed",
        ),
    )?;
    Ok(myownmesh_core::ResourceClaim::try_from_entries([
        (
            myownmesh_core::ResourceClass::AccountedMemoryBytes,
            u64::try_from(bytes).map_err(|_| {
                myownmesh_core::ResourceMailboxItemError::Measurement(
                    "NetworksList typed bytes do not fit the resource model",
                )
            })?,
        ),
        (
            myownmesh_core::ResourceClass::OpaqueDependencyResidual,
            u64::try_from(allocations).map_err(|_| {
                myownmesh_core::ResourceMailboxItemError::Measurement(
                    "NetworksList allocation count does not fit the resource model",
                )
            })?,
        ),
    ])?)
}

fn networks_dynamic_claim(
    bytes: usize,
    allocations: usize,
) -> Result<myownmesh_core::ResourceClaim, myownmesh_core::ResourceMailboxItemError> {
    Ok(myownmesh_core::ResourceClaim::try_from_entries([
        (
            myownmesh_core::ResourceClass::AccountedMemoryBytes,
            u64::try_from(bytes).map_err(|_| {
                myownmesh_core::ResourceMailboxItemError::Measurement(
                    "NetworksList dynamic bytes do not fit the resource model",
                )
            })?,
        ),
        (
            myownmesh_core::ResourceClass::OpaqueDependencyResidual,
            u64::try_from(allocations).map_err(|_| {
                myownmesh_core::ResourceMailboxItemError::Measurement(
                    "NetworksList dynamic allocation count does not fit the resource model",
                )
            })?,
        ),
    ])?)
}

/// Maximum decimal widths of the integer fields in a network row.
const U32_DECIMAL_DIGITS: u64 = 10;
const U64_DECIMAL_DIGITS: u64 = 20;

/// One JSON source byte can become at most `\u00XX`.
const JSON_STRING_ESCAPE_BYTES_PER_SOURCE_BYTE: u64 = 6;

/// Post-admission serialization walks: borrowed line measurement, built-row
/// equality measurement, and the final output encoding.
const NETWORKS_SERIALIZATION_PASSES: u64 = 3;

/// Typed-source walks after admission: the fit check before line measurement,
/// the authoritative fit check during commit, and construction's exact copy.
const NETWORKS_TYPED_SOURCE_PASSES: u64 = 3;

/// Canonical-order scans after admission: the fit check before line
/// measurement, borrowed line measurement itself, and the authoritative
/// build. `for_each_canonical_in_config_order` is deliberately allocation-free
/// and therefore quadratic; the work ceiling prices that choice instead of
/// pretending it is a linear traversal.
const NETWORKS_ORDERING_PASSES: u64 = 3;

const NETWORK_LANE_NAMES: [&str; 10] = [
    "keepalive_tx",
    "keepalive_rx",
    "control_tx",
    "control_rx",
    "gossip_tx",
    "gossip_rx",
    "app_tx",
    "app_rx",
    "other_tx",
    "other_rx",
];

const NETWORK_TRAFFIC_SCALAR_NAMES: [&str; 5] = [
    "announces_rx",
    "announces_tx",
    "negotiation_rx",
    "negotiation_tx",
    "reliable_pending",
];

const fn json_key_prefix_len(key: &str) -> u64 {
    // Opening quote, key bytes, closing quote, colon.
    key.len() as u64 + 3
}

/// Exact encoded width of the widest fixed-value `TrafficSnapshot`.
const fn widest_traffic_json_len() -> u64 {
    let mut bytes = 2; // braces
    let mut fields = 0usize;
    let mut lane = 0usize;
    while lane < NETWORK_LANE_NAMES.len() {
        if fields != 0 {
            bytes += 1; // comma
        }
        bytes += json_key_prefix_len(NETWORK_LANE_NAMES[lane]);
        bytes += 2; // lane braces
        bytes += json_key_prefix_len("frames") + U64_DECIMAL_DIGITS;
        bytes += 1; // comma
        bytes += json_key_prefix_len("bytes") + U64_DECIMAL_DIGITS;
        fields += 1;
        lane += 1;
    }
    let mut scalar = 0usize;
    while scalar < NETWORK_TRAFFIC_SCALAR_NAMES.len() {
        bytes += 1; // comma; every scalar follows the lanes
        bytes += json_key_prefix_len(NETWORK_TRAFFIC_SCALAR_NAMES[scalar]);
        bytes += U64_DECIMAL_DIGITS;
        scalar += 1;
    }
    bytes
}

/// Fixed JSON bytes in the widest row after every variable string is replaced
/// by its empty form. `HubTree` is the widest topology tag once the root and
/// hub elements themselves are excluded; each actual element is added
/// separately below.
const WIDEST_FIXED_TOPOLOGY_JSON_BYTES: u64 =
    "{\"kind\":\"hub_tree\",\"root\":\"\",\"hubs\":[],\"backup_candidates\":".len() as u64
        + U32_DECIMAL_DIGITS
        + 1; // closing brace
const WIDEST_FIXED_NETWORK_ROW_JSON_BYTES: u64 =
    "{\"config_id\":\"\",\"network_id\":\"\",\"label\":\"\",\"phase\":\"discovering\",\"topology\":"
        .len() as u64
        + WIDEST_FIXED_TOPOLOGY_JSON_BYTES
        + ",\"traffic\":".len() as u64
        + widest_traffic_json_len()
        + 1; // closing row brace

const NETWORKS_LINE_WRAPPER_BYTES: u64 =
    "{\"ok\":true,\"data\":{\"networks\":[".len() as u64 + "]}}\n".len() as u64;

/// Derive a mechanical ceiling for every post-admission traversal from the
/// exact typed capacity already quoted by pass zero.
///
/// Variable string bytes get their six-byte JSON escape maximum. Row and hub
/// counts are bounded by the fixed slots that the same typed claim must fund,
/// so all field names, punctuation and maximum-width integers are added from
/// constants tied to the actual serialized shape. Three full JSON walks and
/// the two fit scans plus retained-byte copy are then charged explicitly; no
/// unexplained multiplier remains.
fn networks_work_claim(
    typed: myownmesh_core::ResourceClaim,
) -> Result<myownmesh_core::ResourceClaim, myownmesh_core::ResourceMailboxItemError> {
    let typed_bytes = typed.amount(myownmesh_core::ResourceClass::AccountedMemoryBytes);
    let row_slot = u64::try_from(std::mem::size_of::<PreparedSlot<PreparedNetworkSummary>>())
        .map_err(|_| {
            myownmesh_core::ResourceMailboxItemError::Measurement(
                "NetworksList row slot does not fit the work model",
            )
        })?;
    let hub_slot = u64::try_from(std::mem::size_of::<PreparedSlot<Box<str>>>()).map_err(|_| {
        myownmesh_core::ResourceMailboxItemError::Measurement(
            "NetworksList hub slot does not fit the work model",
        )
    })?;
    let max_rows = typed_bytes / row_slot.max(1);
    let max_hubs = typed_bytes / hub_slot.max(1);
    let dynamic_json = typed_bytes
        .checked_mul(JSON_STRING_ESCAPE_BYTES_PER_SOURCE_BYTE)
        .ok_or(myownmesh_core::ResourceMailboxItemError::Measurement(
            "NetworksList escaped work ceiling overflowed",
        ))?;
    let fixed_rows = max_rows
        .checked_mul(WIDEST_FIXED_NETWORK_ROW_JSON_BYTES + 1) // one separator per row
        .ok_or(myownmesh_core::ResourceMailboxItemError::Measurement(
            "NetworksList fixed-row work ceiling overflowed",
        ))?;
    let hub_elements = max_hubs
        .checked_mul(3) // quotes plus a conservative comma for every element
        .ok_or(myownmesh_core::ResourceMailboxItemError::Measurement(
            "NetworksList hub work ceiling overflowed",
        ))?;
    let encoded_ceiling = NETWORKS_LINE_WRAPPER_BYTES
        .checked_add(dynamic_json)
        .and_then(|bytes| bytes.checked_add(fixed_rows))
        .and_then(|bytes| bytes.checked_add(hub_elements))
        .ok_or(myownmesh_core::ResourceMailboxItemError::Measurement(
            "NetworksList encoded work ceiling overflowed",
        ))?;
    let work = encoded_ceiling
        .checked_mul(NETWORKS_SERIALIZATION_PASSES)
        .and_then(|work| {
            typed_bytes
                .checked_mul(NETWORKS_TYPED_SOURCE_PASSES)
                .and_then(|source| work.checked_add(source))
        })
        .and_then(|work| {
            max_rows
                .checked_mul(max_rows)
                // Each comparison may inspect a retained coordinate all the
                // way to its end; `typed_bytes` is a ceiling for those bytes.
                .and_then(|comparisons| comparisons.checked_mul(typed_bytes))
                .and_then(|comparisons| comparisons.checked_mul(NETWORKS_ORDERING_PASSES))
                .and_then(|ordering| work.checked_add(ordering))
        })
        .ok_or(myownmesh_core::ResourceMailboxItemError::Measurement(
            "NetworksList snapshot work overflowed",
        ))?;
    Ok(myownmesh_core::ResourceClaim::single(
        myownmesh_core::ResourceClass::ParsingOrCpuWork,
        work,
    ))
}

fn claim_fits(
    actual: myownmesh_core::ResourceClaim,
    admitted: myownmesh_core::ResourceClaim,
) -> bool {
    admitted.checked_sub(actual).is_ok()
}

fn networks_line_ceiling(
    data: &impl serde::Serialize,
) -> Result<usize, myownmesh_core::ResourceMailboxItemError> {
    let (_, encoded, _) = myownmesh_core::mailbox_measure_serialized(data)?;
    encoded
        .checked_add("{\"ok\":true,\"data\":".len())
        .and_then(|bytes| bytes.checked_add("}\n".len()))
        .ok_or(myownmesh_core::ResourceMailboxItemError::Measurement(
            "NetworksList line length overflowed",
        ))
}

impl PreparedNetworkSummary {
    fn from_view(
        config_id: &str,
        network_id: &str,
        label: &str,
        phase: myownmesh_core::MeshPhase,
        topology: &myownmesh_core::TopologyMode,
        traffic: myownmesh_core::engine::traffic::TrafficSnapshot,
    ) -> Self {
        let topology = match topology {
            myownmesh_core::TopologyMode::Ring { n_preferred } => PreparedTopology::Ring {
                n_preferred: *n_preferred,
            },
            myownmesh_core::TopologyMode::Star { hub } => PreparedTopology::Star {
                hub: hub.as_str().into(),
            },
            myownmesh_core::TopologyMode::HubTree {
                root,
                hubs,
                backup_candidates,
            } => {
                let mut prepared = empty_prepared_slots(hubs.len());
                for (slot, hub) in prepared.iter_mut().zip(hubs) {
                    slot.0 = Some(Box::<str>::from(hub.as_str()));
                }
                PreparedTopology::HubTree {
                    root: root.as_str().into(),
                    hubs: prepared,
                    backup_candidates: *backup_candidates,
                }
            }
            myownmesh_core::TopologyMode::Hubs {
                hubs,
                spoke_redundancy,
            } => {
                let mut prepared = empty_prepared_slots(hubs.len());
                for (slot, hub) in prepared.iter_mut().zip(hubs) {
                    slot.0 = Some(Box::<str>::from(hub.as_str()));
                }
                PreparedTopology::Hubs {
                    hubs: prepared,
                    spoke_redundancy: *spoke_redundancy,
                }
            }
            myownmesh_core::TopologyMode::FullMesh => PreparedTopology::FullMesh,
        };
        Self {
            config_id: config_id.into(),
            network_id: network_id.into(),
            label: label.into(),
            phase,
            topology,
            traffic,
        }
    }
}

impl serde::Serialize for VisibleNetworkIds<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let count = self
            .0
            .aliases
            .iter()
            .filter(|(key, entry)| key.as_str() == entry.joined.config_id())
            .count();
        let mut sequence = serializer.serialize_seq(Some(count))?;
        let mut error = None;
        self.0.for_each_canonical_in_config_order(|entry| {
            if error.is_none() {
                error = sequence.serialize_element(entry.joined.network_id()).err();
            }
        });
        if let Some(error) = error {
            return Err(error);
        }
        sequence.end()
    }
}

#[derive(serde::Serialize)]
struct StatusView<'a> {
    version: &'static str,
    device_id: DisplayIdWidth,
    joined_networks: VisibleNetworkIds<'a>,
    realtime: &'a crate::control::RealtimeAdvert,
}

/// The one retained test barrier in this file, and the only race it exists for.
///
/// `remove` takes the removal claim under the state lock, releases it, and only
/// then tears the runtime down. An `insert` of the same id arriving inside that
/// window must wait for the predecessor to finish stopping rather than
/// installing beside a runtime that is still live. That window is real and it is
/// short, so a test that tries to hit it by timing hits it almost never — and a
/// control that only usually reproduces its race is worse than none, because it
/// passes while the ordering is broken.
///
/// The barrier holds `remove` at exactly the post-claim point so the racing
/// `insert` is guaranteed to arrive inside the window. It parks nothing else and
/// observes nothing; the assertions are on the registry's own visible state.
#[cfg(test)]
struct ClaimPause {
    reached: tokio::sync::Barrier,
    release: tokio::sync::Barrier,
}

#[cfg(test)]
impl ClaimPause {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            reached: tokio::sync::Barrier::new(2),
            release: tokio::sync::Barrier::new(2),
        })
    }
}

/// The aliases and the closing set, behind **one** lock.
///
/// They are one lock because every decision this registry makes reads both. An
/// insert has to know whether either id is held by a visible runtime *or* by
/// one draining; a removal has to move an entry from the first to the second
/// without a moment in between. Two locks made those two-step operations, and
/// each step was a window: an insert that checked the closing set, released it,
/// and then took the map could be interleaved by the removal it was checking
/// for.
#[derive(Default)]
struct RegistryState {
    /// Both ids of every visible runtime, two keys to one `Arc<Entry>`.
    aliases: HashMap<String, Arc<Entry>>,
    /// Runtimes past their aliases and not yet `Stopped`.
    ///
    /// This is what makes "no unreachable live runtime" structural rather than
    /// hoped for. Removal unlinks the aliases before teardown can finish, and
    /// in that window the entry must be owned by something or it is running
    /// with nobody able to name it. It is owned here, and a replacement under
    /// either of its ids is refused until it drains.
    closing: Vec<Arc<Entry>>,
}

impl RegistryState {
    /// The runtime answering to `key`, visible or draining.
    ///
    /// The closing set is searched too: a lookup starting at the alias map
    /// alone would miss a network whose aliases a first removal has already
    /// unlinked, and report `NotFound` about one that is still there.
    fn find(&self, key: &str) -> Option<Arc<Entry>> {
        if let Some(entry) = self.aliases.get(key) {
            return Some(entry.clone());
        }
        self.closing.iter().find(|entry| entry.holds(key)).cloned()
    }

    /// Any runtime holding either id that has not reached `Stopped`.
    ///
    /// Both sets and both states. `Running` is included deliberately: a live
    /// runtime under one of these ids is a collision, not a free slot, and
    /// admitting past it is what left two runtimes for one network with only
    /// one of them reachable.
    fn holder(&self, config_id: &str, network_id: &str) -> Option<Arc<Entry>> {
        self.aliases
            .values()
            .chain(self.closing.iter())
            .find(|entry| {
                (entry.holds(config_id) || entry.holds(network_id))
                    && entry.lifecycle.state() != RuntimeState::Stopped
            })
            .cloned()
    }

    /// Unlink every alias pointing at this exact entry.
    ///
    /// By pointer identity rather than by id string: the two aliases are two
    /// keys for one `Arc`, and a network whose config id happens to equal
    /// another's network id must not have its neighbour's key removed.
    fn unlink(&mut self, entry: &Arc<Entry>) {
        let target = Arc::as_ptr(entry);
        self.aliases.retain(|_, held| Arc::as_ptr(held) != target);
    }

    /// Claim `entry` for teardown and move it out of the aliases in one step.
    ///
    /// `true` to the one caller that won the claim. Everything the winner has
    /// to do before it can release the lock happens here, so no other caller
    /// can observe the entry half-moved.
    fn claim(&mut self, entry: &Arc<Entry>) -> bool {
        if !entry.lifecycle.begin_closing() {
            return false;
        }
        self.unlink(entry);
        if !self.closing.iter().any(|held| Arc::ptr_eq(held, entry)) {
            self.closing.push(entry.clone());
        }
        true
    }
}

impl NetworkRegistry {
    pub(crate) fn status_source<'a>(
        &'a self,
        identity: &'a myownmesh_core::Identity,
        realtime: &'a crate::control::RealtimeAdvert,
    ) -> StatusSource<'a> {
        StatusSource {
            state: self.state.lock(),
            identity,
            realtime,
        }
    }

    pub(crate) fn prepare_networks_list(
        &self,
    ) -> Result<PreparedNetworksList<'_>, myownmesh_core::ResourceMailboxItemError> {
        let state = self.state.lock();
        let count = state.canonical_count();
        let mut row_bytes = 0usize;
        let mut row_allocations = 0usize;
        let mut measurement_error = None;
        state.for_each_canonical_in_config_order(|entry| {
            if measurement_error.is_some() {
                return;
            }
            entry.joined.with_network_summary_view(
                |config_id, network_id, label, _phase, topology, _traffic| {
                    match measure_network_row(config_id, network_id, label, topology) {
                        Ok((bytes, allocations)) => {
                            if let Err(error) = checked_network_bytes_add(&mut row_bytes, bytes)
                                .and_then(|()| {
                                    checked_network_allocations_add(
                                        &mut row_allocations,
                                        allocations,
                                    )
                                })
                            {
                                measurement_error = Some(error);
                            }
                        }
                        Err(error) => measurement_error = Some(error),
                    }
                },
            );
        });
        if let Some(error) = measurement_error {
            return Err(error);
        }
        let typed_claim = networks_claim(count, row_bytes, row_allocations)?;
        let work_claim = networks_work_claim(typed_claim)?;
        drop(state);
        Ok(PreparedNetworksList {
            registry: self,
            typed_claim,
            work_claim,
        })
    }

    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Classify both aliases under the same registry fence used by `insert`.
    ///
    /// This is the only pre-join identity decision used by service
    /// reconciliation.  In particular, a `B/N` request is satisfied by a
    /// `Running A/N` owner when `B` is unbound, while `A/M` remains a
    /// collision.  A `Closing` owner is never treated as absent or reusable.
    pub(crate) fn classify_join(&self, config_id: &str, network_id: &str) -> JoinAdmission {
        let state = self.state.lock();
        let by_config = state.aliases.get(config_id).cloned();
        let by_network = state.aliases.get(network_id).cloned();

        if let Some(holder) = state.holder(config_id, network_id) {
            let lifecycle = holder.lifecycle.state();
            if lifecycle != RuntimeState::Running {
                return JoinAdmission::Collision(lifecycle);
            }
        }

        match (by_config, by_network) {
            (None, None) => JoinAdmission::Empty,
            (Some(config_owner), Some(network_owner))
                if Arc::ptr_eq(&config_owner, &network_owner)
                    && network_owner.joined.network_id() == network_id =>
            {
                JoinAdmission::Existing(config_owner.joined.clone())
            }
            (None, Some(network_owner)) if network_owner.joined.network_id() == network_id => {
                JoinAdmission::Existing(network_owner.joined.clone())
            }
            _ => JoinAdmission::Collision(RuntimeState::Running),
        }
    }

    /// Insert a freshly-joined network together with its signaling
    /// driver handles. Indexed by both the config record id and the
    /// wire-level network id so callers can use either as the lookup
    /// key (the CLI / GUI both have a habit of passing whichever
    /// happens to be in scope).
    ///
    /// Refused while **any** runtime holding either id has not reached
    /// `Stopped` — whether it is `Running` or still tearing down.
    ///
    /// Both refusals matter and they are different defects. `Closing` is the
    /// ordering rule of finding 13: `network_update` removes and re-joins under
    /// the same configuration, and admitting the replacement before the
    /// predecessor stopped is what produced two runtimes for one network.
    /// `Running` is the same outcome by a shorter route — without this check
    /// the two writes below would overwrite one alias and leave the other
    /// pointing at the live predecessor, which is then unreachable under half
    /// its names and owned by nothing that will ever tear it down.
    ///
    /// The check and the two writes are one acquisition of the state lock, so a
    /// removal cannot interleave between them.
    ///
    /// The caller is handed its `JoinedNetwork` back rather than having it
    /// dropped, so refusing costs it nothing it cannot retry.
    pub fn insert(
        &self,
        joined: JoinedNetwork,
        drivers: Option<SignalingDrivers>,
    ) -> InsertOutcome {
        let config_id = joined.config_id().to_string();
        let network_id = joined.network_id().to_string();
        let mut state = self.state.lock();
        let held = state.holder(&config_id, &network_id);
        if let Some(holder) = held {
            return InsertOutcome::refused(InsertRefused {
                joined,
                drivers,
                state: holder.lifecycle.state(),
            });
        }
        let entry = Arc::new(Entry {
            joined: Arc::new(joined),
            drivers: Mutex::new(drivers),
            lifecycle: Lifecycle::new(),
        });
        state.aliases.insert(config_id, entry.clone());
        state.aliases.entry(network_id).or_insert(entry);
        InsertOutcome::inserted()
    }

    /// Resolve a network's `JoinedNetwork` by either its config id or
    /// wire-level network id. Returns a cloned `Arc` so callers can
    /// release the internal lock before awaiting.
    ///
    /// Answers only for a `Running` runtime. A handle taken before removal may
    /// still be held by an in-flight request — that is unavoidable and
    /// harmless, because the runtime it names is being torn down by its owner
    /// and the operations that matter refuse on their own fences. What must not
    /// happen is this registry *issuing* a fresh authoritative handle to a
    /// runtime it has already begun closing.
    pub fn get(&self, key: &str) -> Option<Arc<JoinedNetwork>> {
        let entry = self.state.lock().aliases.get(key).cloned()?;
        (entry.lifecycle.state() == RuntimeState::Running).then(|| entry.joined.clone())
    }

    /// Run one bounded synchronous operation against the exact currently
    /// registered runtime.  The identity check and the closure share the
    /// registry state lock, so removal, replacement, or a second alias update
    /// cannot interleave after the caller captured its handle.  The closure
    /// must not await or re-enter this registry; it is the small mutation
    /// window used by network-update paths that need to commit against the
    /// same [`Arc<JoinedNetwork>`] they resolved.
    pub(crate) fn with_current<R>(
        &self,
        key: &str,
        expected: &Arc<JoinedNetwork>,
        effect: impl FnOnce(&Arc<JoinedNetwork>) -> R,
    ) -> Option<R> {
        let state = self.state.lock();
        let entry = state.aliases.get(key)?;
        if entry.lifecycle.state() != RuntimeState::Running || !Arc::ptr_eq(&entry.joined, expected)
        {
            return None;
        }
        Some(effect(&entry.joined))
    }

    /// Tear down only the exact currently registered runtime.
    ///
    /// This is the compare-and-claim counterpart to [`Self::with_current`].
    /// A caller holding a handle from before a removal or replacement must not
    /// be able to retire whatever newer runtime happens to answer to the same
    /// key. The identity check, `Running` check, and claim all happen while
    /// the registry state lock is held; a stale caller therefore returns
    /// `NotFound` without changing the successor. If the exact expected owner
    /// is already in the closing set, the caller waits for that owner and gets
    /// `AlreadyClosing` rather than racing a same-slot rejoin. A successful
    /// claim goes through the same owned closing set and teardown path as
    /// [`Self::remove`], including the test pause and stopped waiter semantics.
    pub(crate) async fn remove_if_current(
        &self,
        key: &str,
        expected: &Arc<JoinedNetwork>,
    ) -> RemoveResult {
        let claim = {
            let mut state = self.state.lock();
            if let Some(entry) = state.aliases.get(key).cloned() {
                if entry.lifecycle.state() != RuntimeState::Running
                    || !Arc::ptr_eq(&entry.joined, expected)
                {
                    return RemoveResult::NotFound;
                }
                let won = state.claim(&entry);
                (entry, won)
            } else if let Some(entry) = state
                .closing
                .iter()
                .find(|entry| entry.holds(key) && Arc::ptr_eq(&entry.joined, expected))
                .cloned()
            {
                // The exact owner may have been claimed by another caller
                // between its lookup and this call. Wait for that owner; do
                // not search by key once a successor has become visible.
                (entry, false)
            } else {
                return RemoveResult::NotFound;
            }
        };
        match claim {
            (entry, true) => {
                #[cfg(test)]
                self.pause_after_claim_for_test().await;
                RemoveResult::Removed(self.teardown(entry).await)
            }
            (entry, false) => RemoveResult::AlreadyClosing(Self::await_winner(&entry).await),
        }
    }

    /// The lifecycle state of the runtime under `key`, for a caller that needs
    /// to distinguish "never existed" from "on its way out".
    pub fn state(&self, key: &str) -> Option<RuntimeState> {
        self.state
            .lock()
            .find(key)
            .map(|entry| entry.lifecycle.state())
    }

    /// True when a runtime holding that id exists and has not stopped.
    ///
    /// A draining runtime counts. It still holds both ids as far as a
    /// replacement is concerned, so reporting it absent would invite a caller
    /// to attempt an insert this registry is about to refuse.
    pub fn contains(&self, key: &str) -> bool {
        self.state
            .lock()
            .find(key)
            .is_some_and(|entry| entry.lifecycle.state() != RuntimeState::Stopped)
    }

    /// Snapshot every distinct network in canonical config-id order. Each
    /// network appears once even though the map stores aliases.
    pub fn summaries(&self) -> Vec<NetworkSummary> {
        let state = self.state.lock();
        let mut out = Vec::new();
        state.for_each_canonical_in_config_order(|entry| {
            let j = &entry.joined;
            out.push(NetworkSummary {
                config_id: j.config_id().to_string(),
                network_id: j.network_id().to_string(),
                label: j.label().to_string(),
                phase: j.current_phase(),
                topology: j.current_topology(),
                traffic: j.traffic(),
            });
        });
        out
    }

    /// Number of visible joined runtimes, without constructing summaries.
    ///
    /// Every entry is stored under its config id and may also be stored under a
    /// distinct wire id. Counting only the canonical config-id alias therefore
    /// visits each entry exactly once without a deduplication buffer or cloned
    /// coordinate. Closing runtimes have already lost every alias and are not
    /// visible joined networks.
    pub fn joined_count(&self) -> usize {
        self.state
            .lock()
            .aliases
            .iter()
            .filter(|(key, entry)| key.as_str() == entry.joined.config_id())
            .count()
    }

    /// Tear one network down: mark it `Closing`, unlink every alias, drop the
    /// signaling drivers, await the engine driver, and mark it `Stopped`.
    ///
    /// The order is the correction. Marking precedes unlinking, so the runtime
    /// is never both unreachable and admitting work; ownership stays here
    /// across the await, so it is never live and ownerless; and the entry is
    /// only released once `shutdown` has returned, so the next `insert` under
    /// either id sees a finished teardown rather than a racing one.
    ///
    /// A caller that loses the claim does **not** return early. It waits for
    /// the winner through the runtime's own idempotent `shutdown` and then for
    /// this registry to record `Stopped`, and answers
    /// [`RemoveResult::AlreadyClosing`] carrying what it observed. Returning
    /// immediately is what let a concurrent `shutdown_all` finish while an
    /// engine driver was still being awaited.
    ///
    /// A runtime already past its aliases is still found: the closing set is
    /// searched too, so a second removal answers about the teardown in progress
    /// rather than reporting `NotFound` about a network that is still there.
    ///
    /// There is deliberately no "removed but still borrowed" answer: an
    /// outstanding facade is not a lifecycle state, and reporting it as one is
    /// what let a live runtime escape.
    pub async fn remove(&self, key: &str) -> RemoveResult {
        let claim = {
            let mut state = self.state.lock();
            let Some(entry) = state.find(key) else {
                return RemoveResult::NotFound;
            };
            let won = state.claim(&entry);
            (entry, won)
        };
        match claim {
            (entry, true) => {
                #[cfg(test)]
                self.pause_after_claim_for_test().await;
                RemoveResult::Removed(self.teardown(entry).await)
            }
            (entry, false) => RemoveResult::AlreadyClosing(Self::await_winner(&entry).await),
        }
    }

    #[cfg(test)]
    async fn pause_after_claim_for_test(&self) {
        let pause = self.claim_pause.lock().take();
        if let Some(pause) = pause {
            pause.reached.wait().await;
            pause.release.wait().await;
        }
    }

    #[cfg(test)]
    fn install_claim_pause_for_test(&self) -> Arc<ClaimPause> {
        let pause = ClaimPause::new();
        *self.claim_pause.lock() = Some(Arc::clone(&pause));
        pause
    }

    /// Wait for whoever won the claim on `entry` to finish.
    ///
    /// Two waits, and both are needed. `shutdown` is the runtime's own seam and
    /// is idempotent — its internal driver mutex is what makes a second caller
    /// observe the same retirement rather than an empty slot — so going through
    /// it means the loser waits on the same thing the winner waited on, not on
    /// a parallel mechanism that could drift from it. `await_stopped` then
    /// covers the remainder: `shutdown` returning proves the driver is retired,
    /// and not yet that this registry has recorded the fact and released the
    /// entry. A caller told `Stopped` can rely on both.
    async fn await_winner(entry: &Arc<Entry>) -> TeardownObservation {
        let outcome = Self::await_winner_result(entry).await;
        TeardownObservation {
            state: entry.lifecycle.state(),
            outcome,
        }
    }

    /// Await a teardown claimed by another caller while preserving its
    /// terminal error for shutdown-all callers. The lifecycle wait remains
    /// mandatory even when the driver reports a failure: ownership is not
    /// released until the registry has recorded `Stopped`.
    async fn await_winner_result(entry: &Arc<Entry>) -> Result<(), String> {
        let outcome = entry
            .joined
            .shutdown()
            .await
            .map_err(|error| error.to_string());
        let state = entry.lifecycle.await_stopped().await;
        if state != RuntimeState::Stopped {
            return Err(format!("network teardown ended in {state:?} state"));
        }
        outcome
    }

    /// Drivers down, engine driver awaited, state advanced to `Stopped`, entry
    /// released. The one teardown path; `remove` and `shutdown_all` share it so
    /// there is a single ordering to get right.
    async fn teardown(&self, entry: Arc<Entry>) -> Result<(), String> {
        // Signaling first: their `Drop` signals every spawned task to exit, and
        // doing it before the engine wait means those tasks are not still
        // publishing on behalf of a network that is going away.
        let drivers = entry.drivers.lock().take();
        if let Some(drivers) = drivers {
            drivers.shutdown().await;
        }
        let outcome = entry
            .joined
            .shutdown()
            .await
            .map_err(|error| error.to_string());
        // Ownership is released before the state moves, so a waiter released by
        // `finish` cannot find the entry still held here and conclude the
        // teardown is unfinished.
        let target = Arc::as_ptr(&entry);
        {
            let mut state = self.state.lock();
            state.closing.retain(|held| Arc::as_ptr(held) != target);
            // Publish `Stopped` before releasing the same guard insert/remove
            // acquire. No caller can observe an absent-but-still-Closing gap.
            entry.lifecycle.finish();
        }
        outcome
    }

    /// Depart every joined network before the caller drains the registry on
    /// daemon shutdown — the same courtesy `network_remove` extends to a single
    /// network, extended to all of them.
    ///
    /// **Each network's departure now travels on its authenticated sessions**
    /// rather than on a room-wide signaling `leave` this side hoped would land.
    /// A peer retires our session because the session itself said so, not
    /// because an unauthenticated carrier claimed it. The carrier `leave` still
    /// goes out behind it as reachability evidence with no teardown authority.
    ///
    /// The lock is taken only to snapshot the distinct entries and is dropped
    /// before the first `.await`, so this never holds a `parking_lot` guard
    /// across one. Networks are departed in sequence rather than raced: each is
    /// a bounded number of sends over channels that are already open, and a
    /// concurrent fan-out would buy nothing but interleaving on the way out.
    pub async fn announce_all_departures(&self) {
        let departing: Vec<Arc<Entry>> = {
            let state = self.state.lock();
            // Dedup by entry pointer — both id aliases point at the same Arc.
            let mut seen: Vec<*const Entry> = Vec::new();
            let mut distinct = Vec::new();
            for entry in state.aliases.values() {
                let ptr = Arc::as_ptr(entry);
                if seen.contains(&ptr) {
                    continue;
                }
                seen.push(ptr);
                distinct.push(Arc::clone(entry));
            }
            distinct
        };
        for entry in departing {
            entry.joined.announce_leave().await;
        }
    }

    /// Supervise authenticated departures alongside registry teardown.
    ///
    /// A departure waits for an authenticated observation, so awaiting all
    /// departures before requesting shutdown can deadlock on a silent peer.
    /// Starting both futures preserves the carrier hint path while letting the
    /// existing shutdown lifecycle cancel the departure waiter. No timeout,
    /// grace period, retry, or alternate acknowledgement mechanism is added.
    pub async fn shutdown_all_with_departures(&self) -> Vec<Result<(), String>> {
        let departures = self.announce_all_departures();
        let shutdown = self.shutdown_all();
        let (_, outcomes) = tokio::join!(departures, shutdown);
        outcomes
    }

    /// Tear down every distinct network, in the same order and through the same
    /// path as a single removal.
    ///
    /// Nothing is skipped and nothing is left running. The previous drain
    /// silently dropped any entry it could not `try_unwrap`, so a network held
    /// by one in-flight request at shutdown was neither left nor reported, and
    /// the daemon exited leaving peers to time it out.
    ///
    /// A network a concurrent control request is already tearing down is **not**
    /// skipped either: this waits for that teardown before returning. Skipping
    /// it let the daemon exit with an engine driver still being awaited, which
    /// is the same live-runtime-after-removal shape one layer up. Its outcome
    /// belongs to the caller that claimed it, so it is not repeated in the
    /// returned vector — what comes back is one result per teardown this call
    /// performed or observed. A concurrent loser observes the winner's exact
    /// shutdown result rather than turning a failed teardown into success.
    pub async fn shutdown_all(&self) -> Vec<Result<(), String>> {
        let (winners, losers) = {
            let mut state = self.state.lock();
            // Every distinct runtime, visible or already draining. Dedup by
            // pointer: both aliases of one network are the same `Arc`.
            let mut distinct: Vec<Arc<Entry>> = Vec::new();
            for entry in state.aliases.values().chain(state.closing.iter()) {
                if !distinct.iter().any(|held| Arc::ptr_eq(held, entry)) {
                    distinct.push(entry.clone());
                }
            }
            let mut winners = Vec::new();
            let mut losers = Vec::new();
            for entry in distinct {
                if state.claim(&entry) {
                    winners.push(entry);
                } else {
                    losers.push(entry);
                }
            }
            (winners, losers)
        };
        let mut outcomes = Vec::new();
        for entry in winners {
            outcomes.push(self.teardown(entry).await);
        }
        for entry in losers {
            outcomes.push(Self::await_winner_result(&entry).await);
        }
        outcomes
    }
}

impl StatusSource<'_> {
    fn view(&self) -> StatusView<'_> {
        StatusView {
            version: env!("CARGO_PKG_VERSION"),
            device_id: DisplayIdWidth(self.identity.display_id_len()),
            joined_networks: VisibleNetworkIds(&self.state),
            realtime: self.realtime,
        }
    }

    pub(crate) fn typed_claim(
        &self,
    ) -> Result<myownmesh_core::ResourceClaim, myownmesh_core::ResourceMailboxItemError> {
        serialized_typed_claim::<OwnedStatusData>(&self.view())
    }

    pub(crate) fn line_ceiling(&self) -> Result<usize, myownmesh_core::ResourceMailboxItemError> {
        let (_, encoded, _) = myownmesh_core::mailbox_measure_serialized(&self.view())?;
        encoded
            .checked_add("{\"ok\":true,\"data\":".len())
            .and_then(|bytes| bytes.checked_add("}\n".len()))
            .ok_or(myownmesh_core::ResourceMailboxItemError::Measurement(
                "status line length overflowed",
            ))
    }

    #[expect(
        clippy::result_large_err,
        reason = "the exact admitted lease must be returned by value; boxing would allocate on refusal"
    )]
    pub(crate) fn commit(
        self,
        retention: myownmesh_core::ResourceLease,
    ) -> Result<FundedStatus, myownmesh_core::ResourceLease> {
        if retention.claim()
            != self
                .typed_claim()
                .expect("a locked status source remains representable")
        {
            return Err(retention);
        }
        let count = self
            .state
            .aliases
            .iter()
            .filter(|(key, entry)| key.as_str() == entry.joined.config_id())
            .count();
        let mut joined_networks = Vec::with_capacity(count);
        self.state.for_each_canonical_in_config_order(|entry| {
            joined_networks.push(entry.joined.network_id().to_string());
        });
        Ok(FundedStatus {
            data: OwnedStatusData {
                version: env!("CARGO_PKG_VERSION"),
                device_id: self.identity.display_id(),
                joined_networks,
                realtime: self.realtime.clone(),
            },
            _retention: retention,
        })
    }
}

impl<'a> PreparedNetworksList<'a> {
    pub(crate) fn typed_claim(&self) -> myownmesh_core::ResourceClaim {
        self.typed_claim
    }

    pub(crate) fn work_claim(&self) -> myownmesh_core::ResourceClaim {
        self.work_claim
    }

    pub(crate) fn measure_line_ceiling(
        self,
        work: &myownmesh_core::ResourceLease,
    ) -> Result<MeasuredNetworksList<'a>, myownmesh_core::ResourceMailboxItemError> {
        if work.claim() != self.work_claim {
            return Err(myownmesh_core::ResourceMailboxItemError::Measurement(
                "NetworksList line measurement work was not admitted",
            ));
        }
        let state = self.registry.state.lock();
        let current = current_networks_claim_fitting(&state, self.typed_claim)?;
        if current != Some(self.typed_claim) {
            return Err(myownmesh_core::ResourceMailboxItemError::Measurement(
                "NetworksList changed typed shape before line measurement",
            ));
        }
        let line_ceiling = networks_line_ceiling(&BorrowedNetworksData {
            networks: NetworksView(&state),
        })?;
        drop(state);
        Ok(MeasuredNetworksList {
            registry: self.registry,
            typed_claim: self.typed_claim,
            work_claim: self.work_claim,
            line_ceiling,
        })
    }
}

impl MeasuredNetworksList<'_> {
    pub(crate) fn line_ceiling(&self) -> usize {
        self.line_ceiling
    }

    #[expect(
        clippy::result_large_err,
        reason = "both exact admitted leases must be returned by value; boxing would allocate on refusal"
    )]
    pub(crate) fn commit(
        self,
        retention: myownmesh_core::ResourceLease,
        work: myownmesh_core::ResourceLease,
    ) -> Result<FundedNetworksList, (myownmesh_core::ResourceLease, myownmesh_core::ResourceLease)>
    {
        let admitted = retention.claim();
        if admitted != self.typed_claim || work.claim() != self.work_claim {
            return Err((retention, work));
        }
        let state = self.registry.state.lock();
        let count = state.canonical_count();
        let base_claim = match networks_claim(count, 0, 0) {
            Ok(claim) if claim_fits(claim, admitted) => claim,
            _ => return Err((retention, work)),
        };
        // The staging box is covered by the response's broad planning owner.
        let mut rows = empty_prepared_slots(count);
        let mut built = 0usize;
        let mut actual = base_claim;
        let mut refused = false;
        state.for_each_canonical_in_config_order(|entry| {
            if refused {
                return;
            }
            entry.joined.with_network_summary_view(
                |config_id, network_id, label, phase, topology, traffic| {
                    // Refuse before the first allocation whose requested shape
                    // would cross the capacity acquired from pass zero.
                    let fits = add_network_row_fitting(
                        &mut actual,
                        admitted,
                        config_id,
                        network_id,
                        label,
                        topology,
                    );
                    if !matches!(fits, Ok(true)) {
                        refused = true;
                        return;
                    }
                    let Some(slot) = rows.get_mut(built) else {
                        refused = true;
                        return;
                    };
                    slot.0 = Some(PreparedNetworkSummary::from_view(
                        config_id, network_id, label, phase, topology, traffic,
                    ));
                    built += 1;
                },
            );
        });
        drop(state);

        if refused || built != count || actual != admitted {
            drop(rows);
            return Err((retention, work));
        }
        let actual_line = match networks_line_ceiling(&PreparedNetworksData { networks: &rows }) {
            Ok(line) => line,
            Err(_) => {
                drop(rows);
                return Err((retention, work));
            }
        };
        if actual_line != self.line_ceiling {
            drop(rows);
            return Err((retention, work));
        }
        Ok(FundedNetworksList {
            rows,
            _retention: retention,
            _work: work,
        })
    }
}

/// Outcome of a [`NetworkRegistry::remove`] call.
pub enum RemoveResult {
    /// The runtime was torn down: signaling drivers joined, engine driver retired,
    /// state `Stopped`. Carries the shutdown outcome so a failed teardown is
    /// reported rather than assumed clean.
    Removed(Result<(), String>),
    /// No entry under that key.
    NotFound,
    /// A teardown for this runtime was already in progress, so this call
    /// started nothing — and **waited for it**. Carries the state observed
    /// once that teardown finished, which is `Stopped`, together with the
    /// exact success or failure observed from the winning owner. The variant
    /// reports who did the work, not that the caller gave up early.
    AlreadyClosing(TeardownObservation),
}

/// The terminal observation returned to a removal caller that lost the
/// ownership claim to another concurrent remover.
#[derive(Debug)]
pub struct TeardownObservation {
    pub state: RuntimeState,
    pub outcome: Result<(), String>,
}

/// A rejected [`NetworkRegistry::insert`], handing the caller back exactly what
/// it passed in.
///
/// The values come back rather than being dropped: a refusal is an ordering
/// answer ("the previous runtime under this id has not stopped"), not a
/// decision to destroy a network the caller just joined.
pub struct InsertRefused {
    pub joined: JoinedNetwork,
    pub drivers: Option<SignalingDrivers>,
    /// The state of the runtime still holding one of these ids.
    pub state: RuntimeState,
}

/// Allocation-free answer from [`NetworkRegistry::insert`].
///
/// A refused insert must return the caller's joined runtime and signaling
/// drivers intact so the caller can shut them down. That payload is large
/// enough to trip `clippy::result_large_err`; boxing it would add an allocation
/// that no resource owner reserved. This wrapper retains the same inline
/// ownership and drop behavior without treating the refusal as a boxed error.
#[must_use = "a refused insert returns a live runtime that its caller must shut down"]
pub struct InsertOutcome {
    refusal: Option<InsertRefused>,
}

impl InsertOutcome {
    fn inserted() -> Self {
        Self { refusal: None }
    }

    fn refused(refusal: InsertRefused) -> Self {
        Self {
            refusal: Some(refusal),
        }
    }

    /// Return the refused runtime and drivers, or `None` when insertion won.
    pub fn into_refusal(self) -> Option<InsertRefused> {
        self.refusal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The two controls that stand up a real `Mesh` serialize on
    // `crate::exclusive_connector_fixture`, shared with every other
    // connector-consuming family in this binary. A mutex private to this module
    // would stop these two racing each other and not stop either of them racing
    // `ipc::bridge`, which is what actually exhausted the process-global
    // connector budget. The four `Lifecycle` controls take nothing: they drive
    // the state machine directly and open no runtime.

    fn connector_policy() -> myownmesh_core::WebRtcConnectorCapablePolicy {
        let profile = myownmesh_core::WebRtcConnectorProfile::new(
            myownmesh_core::ConnectorCallbackPolicy::elastic_data_only(),
        );
        myownmesh_core::WebRtcConnectorCapablePolicy::new(crate::test_resource_provider(), profile)
    }

    async fn mesh() -> myownmesh_core::MeshHandle {
        myownmesh_core::Mesh::open_connector_capable_with_identity(
            myownmesh_core::MeshConfig::default(),
            Arc::new(myownmesh_core::Identity::ephemeral()),
            connector_policy(),
        )
        .await
        .expect("registry fixture opens a connector-capable Mesh")
    }

    fn network(config_id: &str, network_id: &str) -> myownmesh_core::NetworkConfig {
        network_with_topology(
            config_id,
            network_id,
            myownmesh_core::TopologyMode::FullMesh,
        )
    }

    fn network_with_topology(
        config_id: &str,
        network_id: &str,
        topology: myownmesh_core::TopologyMode,
    ) -> myownmesh_core::NetworkConfig {
        myownmesh_core::NetworkConfig {
            id: config_id.to_string(),
            network_id: network_id.to_string(),
            event_capacity: myownmesh_core::NetworkConfig::from_network_id("", "").event_capacity,
            connection_trace_capacity: myownmesh_core::NetworkConfig::from_network_id("", "")
                .connection_trace_capacity,
            label: config_id.to_string(),
            kind: Default::default(),
            scheduler: myownmesh_core::config::SchedulerPolicyConfig::default(),
            routing_policy: myownmesh_core::config::RoutingPolicyConfig::default(),
            tree: None,
            hub: None,
            local_observations: None,
            application_transport: None,
            semantic_policy: myownmesh_core::config::SemanticPolicyConfig::default(),
            topology,
            signaling: myownmesh_core::config::SignalingConfig::default(),
            closed_relay: Default::default(),
            stun_servers: Vec::new(),
            turn_servers: Vec::new(),
            pinned_peers: Vec::new(),
            auto_approve: true,
        }
    }

    #[tokio::test]
    async fn join_admission_preserves_unbound_local_alias_for_running_wire_owner() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let mesh = mesh().await;
        let registry = NetworkRegistry::new();
        let incumbent = mesh
            .join(network("admission-owner", "admission-wire"))
            .await
            .expect("the admission fixture joins");
        assert!(registry.insert(incumbent, None).into_refusal().is_none());

        match registry.classify_join("admission-alias", "admission-wire") {
            JoinAdmission::Existing(owner) => {
                assert_eq!(owner.config_id(), "admission-owner");
                assert_eq!(owner.network_id(), "admission-wire");
            }
            JoinAdmission::Empty => panic!("a running wire owner must satisfy its alias"),
            JoinAdmission::Collision(state) => {
                panic!("unexpected {state:?} collision for a running wire owner")
            }
        }
        assert!(matches!(
            registry.classify_join("admission-owner", "other-wire"),
            JoinAdmission::Collision(RuntimeState::Running)
        ));
        let _ = registry.shutdown_all().await;
    }

    fn widest_traffic() -> myownmesh_core::engine::traffic::TrafficSnapshot {
        let lane = myownmesh_core::engine::traffic::LaneSnapshot {
            frames: u64::MAX,
            bytes: u64::MAX,
        };
        myownmesh_core::engine::traffic::TrafficSnapshot {
            keepalive_tx: lane,
            keepalive_rx: lane,
            control_tx: lane,
            control_rx: lane,
            gossip_tx: lane,
            gossip_rx: lane,
            app_tx: lane,
            app_rx: lane,
            other_tx: lane,
            other_rx: lane,
            announces_rx: u64::MAX,
            announces_tx: u64::MAX,
            negotiation_rx: u64::MAX,
            negotiation_tx: u64::MAX,
            reliable_pending: u64::MAX,
        }
    }

    #[test]
    fn v4_r3_daemon_the_networks_work_ceiling_covers_every_fixed_field() {
        let topologies = [
            myownmesh_core::TopologyMode::Ring {
                n_preferred: Some(u32::MAX),
            },
            myownmesh_core::TopologyMode::Star { hub: String::new() },
            myownmesh_core::TopologyMode::HubTree {
                root: String::new(),
                hubs: Vec::new(),
                backup_candidates: u32::MAX,
            },
            myownmesh_core::TopologyMode::Hubs {
                hubs: Vec::new(),
                spoke_redundancy: Some(u32::MAX),
            },
            myownmesh_core::TopologyMode::FullMesh,
        ];
        let traffic = widest_traffic();
        for topology in &topologies {
            let row = PreparedNetworkSummary::from_view(
                "",
                "",
                "",
                myownmesh_core::MeshPhase::Discovering,
                topology,
                traffic,
            );
            let encoded = serde_json::to_vec(&row).expect("the closed row shape serializes");
            assert!(
                u64::try_from(encoded.len()).expect("the control row fits u64")
                    <= WIDEST_FIXED_NETWORK_ROW_JSON_BYTES,
                "the fixed-row constant covers {topology:?}: {} > {}",
                encoded.len(),
                WIDEST_FIXED_NETWORK_ROW_JSON_BYTES
            );
        }

        let hub_tree = myownmesh_core::TopologyMode::HubTree {
            root: "tree-root".to_string(),
            hubs: vec!["tree-hub".to_string()],
            backup_candidates: 7,
        };
        let (dynamic_bytes, dynamic_allocations) =
            measure_network_row("config", "network", "label", &hub_tree)
                .expect("HubTree dynamic shape is measurable");
        let (topology_only_bytes, topology_only_allocations) =
            measure_network_row("", "", "", &hub_tree)
                .expect("HubTree topology-only shape is measurable");
        assert_eq!(
            topology_only_bytes,
            "tree-root".len() + "tree-hub".len() + std::mem::size_of::<PreparedSlot<Box<str>>>(),
            "topology-only HubTree measurement charges root, backing, and hub text"
        );
        assert_eq!(
            topology_only_allocations, 3,
            "topology-only HubTree charges root, backing, and hub string"
        );
        assert_eq!(
            dynamic_bytes,
            "config".len()
                + "network".len()
                + "label".len()
                + "tree-root".len()
                + "tree-hub".len()
                + std::mem::size_of::<PreparedSlot<Box<str>>>(),
            "HubTree charges root, hub text, and one funded hub-slot backing"
        );
        assert_eq!(
            dynamic_allocations, 6,
            "HubTree row charges three fixed strings plus root, backing, and hub string"
        );
        let encoded_tree = serde_json::to_value(PreparedNetworkSummary::from_view(
            "config",
            "network",
            "label",
            myownmesh_core::MeshPhase::Discovering,
            &hub_tree,
            traffic,
        ))
        .expect("HubTree owned shape serializes");
        assert_eq!(encoded_tree["topology"]["kind"], "hub_tree");
        assert_eq!(encoded_tree["topology"]["root"], "tree-root");
        assert_eq!(encoded_tree["topology"]["hubs"][0], "tree-hub");
        assert_eq!(encoded_tree["topology"]["backup_candidates"], 7);

        let mut rows = empty_prepared_slots(1);
        rows[0].0 = Some(PreparedNetworkSummary::from_view(
            "",
            "",
            "",
            myownmesh_core::MeshPhase::Discovering,
            &myownmesh_core::TopologyMode::Hubs {
                hubs: Vec::new(),
                spoke_redundancy: Some(u32::MAX),
            },
            traffic,
        ));
        let line = networks_line_ceiling(&PreparedNetworksData { networks: &rows })
            .expect("the widest fixed line is representable");
        let typed = networks_claim(1, 0, 0).expect("one empty row has an exact claim");
        let work = networks_work_claim(typed).expect("the work ceiling is representable");
        let three_walks_and_sources = u64::try_from(line)
            .expect("the fixed line fits u64")
            .checked_mul(NETWORKS_SERIALIZATION_PASSES)
            .and_then(|walks| {
                typed
                    .amount(myownmesh_core::ResourceClass::AccountedMemoryBytes)
                    .checked_mul(NETWORKS_TYPED_SOURCE_PASSES)
                    .and_then(|sources| walks.checked_add(sources))
            })
            .expect("the control work is representable");
        assert!(
            work.amount(myownmesh_core::ResourceClass::ParsingOrCpuWork) >= three_walks_and_sources,
            "the mechanically derived lease covers serialization, fit scans, and construction"
        );
    }

    #[tokio::test]
    async fn v4_r3_daemon_networks_drift_refuses_before_overbudget_build_and_rolls_back() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let mesh = mesh().await;
        let grant = myownmesh_core::ResourceClaim::try_from_entries([
            (myownmesh_core::ResourceClass::AccountedMemoryBytes, 1 << 20),
            (myownmesh_core::ResourceClass::ParsingOrCpuWork, 1 << 20),
            (
                myownmesh_core::ResourceClass::OpaqueDependencyResidual,
                1 << 20,
            ),
        ])
        .expect("the drift-control grant is representable");

        // Growth after exact line measurement cannot allocate even its row box
        // under the empty pass-zero claim.
        let registry = NetworkRegistry::new();
        let newcomer = mesh
            .join(network("growth-config", "growth-wire"))
            .await
            .expect("the growth runtime is ready before the measured pass");
        let provider = myownmesh_core::FiniteResourceProvider::new(grant);
        let port = myownmesh_core::ResourceProviderPort::new(provider.clone())
            .expect("the drift grant funds its process scope");
        let scope = port.process_scope();
        let baseline = provider.in_use();
        let plan = registry
            .prepare_networks_list()
            .expect("the empty plan is representable");
        let typed = port
            .acquire(
                &scope,
                myownmesh_core::ResourceAuthorityClass::Admitted,
                plan.typed_claim(),
            )
            .expect("the empty typed claim is funded");
        let work = port
            .acquire(
                &scope,
                myownmesh_core::ResourceAuthorityClass::Admitted,
                plan.work_claim(),
            )
            .expect("the empty work ceiling is funded");
        let measured = plan
            .measure_line_ceiling(&work)
            .expect("the empty line is measured");
        assert!(
            registry.insert(newcomer, None).into_refusal().is_none(),
            "the roster really grows between the two passes"
        );
        let (typed, work) = match measured.commit(typed, work) {
            Ok(_funded) => panic!("growth beyond the admitted row box must refuse"),
            Err(leases) => leases,
        };
        drop((typed, work));
        assert_eq!(
            provider.in_use(),
            baseline,
            "growth rollback releases exactly"
        );
        let _ = registry.shutdown_all().await;

        // Equal typed retention is not equal wire width: replacing `aa` with a
        // newline plus one byte preserves the exact allocation/length terms but
        // expands JSON. The private row may be built under admitted retention;
        // it must still be rolled back before publication.
        let registry = NetworkRegistry::new();
        let mut before_config = network("line-config", "line-wire");
        before_config.label = "aa".to_string();
        let mut after_config = before_config.clone();
        after_config.label = "\n?".to_string();
        let before = mesh
            .join(before_config)
            .await
            .expect("the predecessor joins");
        assert!(registry.insert(before, None).into_refusal().is_none());

        let provider = myownmesh_core::FiniteResourceProvider::new(grant);
        let port = myownmesh_core::ResourceProviderPort::new(provider.clone())
            .expect("the line-drift grant funds its process scope");
        let scope = port.process_scope();
        let baseline = provider.in_use();
        let plan = registry
            .prepare_networks_list()
            .expect("the predecessor plan is representable");
        let typed_claim = plan.typed_claim();
        let typed = port
            .acquire(
                &scope,
                myownmesh_core::ResourceAuthorityClass::Admitted,
                typed_claim,
            )
            .expect("the predecessor typed claim is funded");
        let work = port
            .acquire(
                &scope,
                myownmesh_core::ResourceAuthorityClass::Admitted,
                plan.work_claim(),
            )
            .expect("the predecessor work ceiling is funded");
        let measured = plan
            .measure_line_ceiling(&work)
            .expect("the predecessor line is measured");
        assert!(matches!(
            registry.remove("line-config").await,
            RemoveResult::Removed(Ok(()))
        ));
        let after = mesh
            .join(after_config)
            .await
            .expect("the same-sized successor joins after its predecessor stopped");
        assert!(
            registry.insert(after, None).into_refusal().is_none(),
            "the same-sized successor installs after its predecessor stopped"
        );
        let successor_claim = registry
            .prepare_networks_list()
            .expect("the successor is representable")
            .typed_claim();
        assert_eq!(
            successor_claim, typed_claim,
            "non-vacuity: only encoded width changed, not typed retention"
        );
        let (typed, work) = match measured.commit(typed, work) {
            Ok(_funded) => panic!("a wider line must not publish under the predecessor ceiling"),
            Err(leases) => leases,
        };
        drop((typed, work));
        assert_eq!(
            provider.in_use(),
            baseline,
            "line-mismatch rollback releases typed and work funding exactly"
        );
        let _ = registry.shutdown_all().await;
    }

    #[tokio::test]
    async fn v4_r3_daemon_prepared_rows_follow_the_canonical_config_order() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let mesh = mesh().await;
        let registry = NetworkRegistry::new();
        let cases = [
            (
                "01-ring",
                "wire-ring",
                myownmesh_core::TopologyMode::Ring {
                    n_preferred: Some(9),
                },
            ),
            (
                "02-star-\n-label",
                "wire-star",
                myownmesh_core::TopologyMode::Star {
                    hub: "star-hub".to_string(),
                },
            ),
            (
                "03-hubs",
                "wire-hubs",
                myownmesh_core::TopologyMode::Hubs {
                    hubs: vec!["hub-a".to_string(), "hub-b".to_string()],
                    spoke_redundancy: Some(2),
                },
            ),
            (
                "04-full",
                "wire-full",
                myownmesh_core::TopologyMode::FullMesh,
            ),
        ];
        for (config_id, network_id, topology) in cases {
            let joined = mesh
                .join(network_with_topology(config_id, network_id, topology))
                .await
                .expect("the topology fixture joins");
            assert!(
                registry.insert(joined, None).into_refusal().is_none(),
                "each distinct runtime installs"
            );
        }

        let plan = registry
            .prepare_networks_list()
            .expect("all four topology variants are representable");
        let grant = myownmesh_core::ResourceClaim::try_from_entries([
            (myownmesh_core::ResourceClass::AccountedMemoryBytes, 1 << 20),
            (myownmesh_core::ResourceClass::ParsingOrCpuWork, 1 << 20),
            (
                myownmesh_core::ResourceClass::OpaqueDependencyResidual,
                1 << 20,
            ),
        ])
        .expect("the fixture grant is representable");
        let provider = myownmesh_core::FiniteResourceProvider::new(grant);
        let port = myownmesh_core::ResourceProviderPort::new(provider.clone())
            .expect("the fixture grant funds its process scope");
        let scope = port.process_scope();
        let baseline = provider.in_use();
        let typed = port
            .acquire(
                &scope,
                myownmesh_core::ResourceAuthorityClass::Admitted,
                plan.typed_claim(),
            )
            .expect("the typed row owner is admitted");
        let work = port
            .acquire(
                &scope,
                myownmesh_core::ResourceAuthorityClass::Admitted,
                plan.work_claim(),
            )
            .expect("the snapshot and serialization work is admitted");
        let plan = plan
            .measure_line_ceiling(&work)
            .expect("the funded traversal measures the exact line");
        let line_ceiling = plan.line_ceiling();
        let funded = match plan.commit(typed, work) {
            Ok(funded) => funded,
            Err((_typed, _work)) => panic!("the unchanged authoritative pass commits"),
        };

        let prepared_json =
            serde_json::to_vec(&funded).expect("the funded prepared rows serialize");
        let summary_ids: Vec<_> = registry
            .summaries()
            .into_iter()
            .map(|summary| summary.config_id)
            .collect();
        assert_eq!(
            summary_ids,
            vec![
                "01-ring".to_owned(),
                "02-star-\n-label".to_owned(),
                "03-hubs".to_owned(),
                "04-full".to_owned(),
            ],
            "the public snapshot uses the same canonical config-id order"
        );
        assert_eq!(
            line_ceiling,
            "{\"ok\":true,\"data\":".len() + prepared_json.len() + "}\n".len(),
            "the measured full response line includes the exact wrapper and newline"
        );
        assert!(
            provider.in_use() != baseline,
            "the funded rows genuinely hold their typed and work leases"
        );
        drop(funded);
        assert_eq!(
            provider.in_use(),
            baseline,
            "the funded owner releases exactly"
        );
        let _ = registry.shutdown_all().await;
    }

    /// Exactly one caller may claim a runtime for teardown.
    ///
    /// This is the property every other one rests on. If two callers could
    /// claim, two teardowns would run against one runtime and the second would
    /// await a driver the first had already retired — and, worse, the second
    /// would report a successful removal it did not perform.
    ///
    /// Non-vacuous in both directions: the losers must be told `false`, and the
    /// state must actually have moved, so a `begin_closing` that always
    /// answered `true` and a `begin_closing` that never transitioned would each
    /// fail here.
    #[test]
    fn exactly_one_caller_claims_a_teardown() {
        let lifecycle = Lifecycle::new();
        assert_eq!(
            lifecycle.state(),
            RuntimeState::Running,
            "non-vacuity: a fresh runtime is claimable"
        );

        let claims: Vec<bool> = (0..8).map(|_| lifecycle.begin_closing()).collect();
        assert_eq!(
            claims.iter().filter(|won| **won).count(),
            1,
            "one winner, and the other seven are told they lost"
        );
        assert!(claims[0], "and the winner is the first to ask");
        assert_eq!(
            lifecycle.state(),
            RuntimeState::Closing,
            "the claim moved the state rather than merely answering about it"
        );

        lifecycle.finish();
        assert!(
            !lifecycle.begin_closing(),
            "a stopped runtime is not claimable either — `Running` is the only \
             state a teardown may start from, so a late caller cannot restart \
             one that has already finished"
        );
    }

    /// A loser waits for the winner and observes `Stopped`.
    ///
    /// A loser returning the moment it saw it had lost would let `shutdown_all`
    /// finish while a concurrent removal was still awaiting an engine driver,
    /// exiting the daemon with that engine live.
    ///
    /// Deterministic and sleepless. The runtime is single-threaded, so a
    /// `yield_now` is enough to run the waiter up to its park, and
    /// `is_finished` after that yield is what makes the assertion
    /// discriminating: without it, a `await_stopped` that returned immediately
    /// would pass this test.
    #[tokio::test]
    async fn a_losing_caller_waits_for_the_winner_to_finish() {
        let lifecycle = Arc::new(Lifecycle::new());
        assert!(lifecycle.begin_closing(), "the winner claims it");

        let waiter = tokio::spawn({
            let lifecycle = Arc::clone(&lifecycle);
            async move { lifecycle.await_stopped().await }
        });
        tokio::task::yield_now().await;
        assert!(
            !waiter.is_finished(),
            "non-vacuity: the loser is genuinely parked while the runtime is \
             still `Closing`"
        );

        lifecycle.finish();
        assert_eq!(
            waiter.await.expect("the waiter task does not panic"),
            RuntimeState::Stopped,
            "and it wakes only once teardown finished, reporting what it saw"
        );
    }

    /// A wait that begins after the winner has already finished returns at
    /// once, rather than parking for a notification that will never come again.
    ///
    /// `Notify::notify_waiters` wakes only those already registered, so a
    /// caller that trusted the wake alone would hang here. The state is
    /// re-read, which is what makes the wake an optimisation rather than the
    /// mechanism.
    #[tokio::test]
    async fn a_wait_after_the_finish_returns_immediately() {
        let lifecycle = Lifecycle::new();
        assert!(lifecycle.begin_closing());
        lifecycle.finish();

        assert_eq!(
            lifecycle.await_stopped().await,
            RuntimeState::Stopped,
            "the already-finished case is answered by the state, not by a \
             notification that has already been delivered to nobody"
        );
    }

    /// Several losers all wake, not just one.
    ///
    /// `notify_waiters` is the right primitive precisely because it releases
    /// every registered waiter; `notify_one` would leave a second concurrent
    /// removal parked forever behind a teardown that had already completed.
    #[tokio::test]
    async fn every_waiting_caller_is_released() {
        let lifecycle = Arc::new(Lifecycle::new());
        assert!(lifecycle.begin_closing());

        let waiters: Vec<_> = (0..4)
            .map(|_| {
                let lifecycle = Arc::clone(&lifecycle);
                tokio::spawn(async move { lifecycle.await_stopped().await })
            })
            .collect();
        tokio::task::yield_now().await;
        assert!(
            waiters.iter().all(|waiter| !waiter.is_finished()),
            "non-vacuity: all four are parked before the finish"
        );

        lifecycle.finish();
        for waiter in waiters {
            assert_eq!(
                waiter.await.expect("no waiter panics"),
                RuntimeState::Stopped
            );
        }
    }

    #[tokio::test]
    async fn running_collision_refuses_newcomer_and_preserves_both_incumbent_aliases() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let mesh = mesh().await;
        let registry = NetworkRegistry::new();
        let incumbent = mesh
            .join(network("f13-running-config", "f13-running-wire"))
            .await
            .expect("incumbent joins");
        let same_config_error = match mesh
            .join(network("f13-running-config", "f13-other-wire"))
            .await
        {
            Ok(_) => panic!("a concurrent same-config join must refuse its busy writer"),
            Err(error) => error,
        };
        assert!(
            same_config_error
                .to_string()
                .to_ascii_lowercase()
                .contains("writer is busy"),
            "same-config join reports the typed WriterBusy refusal: {same_config_error}"
        );
        let same_network = mesh
            .join(network("f13-other-config", "f13-running-wire"))
            .await
            .expect("same-network newcomer joins independently");
        assert!(
            registry.insert(incumbent, None).into_refusal().is_none(),
            "the first runtime installs"
        );

        let refused_network = registry
            .insert(same_network, None)
            .into_refusal()
            .expect("a Running network-id collision must not overwrite either alias");
        assert_eq!(refused_network.state, RuntimeState::Running);
        let by_config = registry
            .get("f13-running-config")
            .expect("the incumbent config alias remains");
        let by_network = registry
            .get("f13-running-wire")
            .expect("the incumbent network alias remains");
        assert!(
            Arc::ptr_eq(&by_config, &by_network),
            "both incumbent aliases still name the same exact runtime"
        );
        assert_eq!(by_network.network_id(), "f13-running-wire");
        assert!(
            registry.get("f13-other-config").is_none(),
            "the same-network newcomer did not install its distinct config alias"
        );
        let by_config_after = registry
            .get("f13-running-config")
            .expect("the incumbent config alias remains after both refusals");
        let by_network_after = registry
            .get("f13-running-wire")
            .expect("the incumbent network alias remains after both refusals");
        assert!(Arc::ptr_eq(&by_config_after, &by_network_after));
        assert!(Arc::ptr_eq(&by_config, &by_config_after));

        refused_network
            .joined
            .shutdown()
            .await
            .expect("the refused same-network runtime is explicitly retired");
        let _ = registry.shutdown_all().await;
    }

    #[tokio::test]
    async fn exact_current_closure_excludes_remove_until_it_returns() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let mesh = mesh().await;
        let registry = NetworkRegistry::new();
        let joined = mesh
            .join(network("fence-closure-config", "fence-closure-wire"))
            .await
            .expect("the exact-current fixture joins");
        assert!(
            registry.insert(joined, None).into_refusal().is_none(),
            "the exact-current fixture installs"
        );
        let expected = registry
            .get("fence-closure-config")
            .expect("the exact current handle exists");
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let fenced_registry = Arc::clone(&registry);
        let fenced_expected = Arc::clone(&expected);
        let fenced = tokio::task::spawn_blocking(move || {
            fenced_registry.with_current("fence-closure-config", &fenced_expected, |_current| {
                entered_tx
                    .send(())
                    .expect("the control observes entry into the fence");
                release_rx
                    .recv()
                    .expect("the control releases the bounded synchronous closure");
                17u8
            })
        });
        entered_rx
            .recv()
            .expect("the exact-current closure entered before removal");
        let removing = {
            let registry = Arc::clone(&registry);
            let runtime = tokio::runtime::Handle::current();
            tokio::task::spawn_blocking(move || {
                runtime.block_on(async move { registry.remove("fence-closure-config").await })
            })
        };
        tokio::task::yield_now().await;
        assert!(
            !removing.is_finished(),
            "removal cannot interleave while the exact-current closure holds the registry fence"
        );
        release_tx
            .send(())
            .expect("the exact-current closure is released");
        assert_eq!(
            fenced.await.expect("the fenced closure does not panic"),
            Some(17),
            "the closure committed against the exact handle"
        );
        assert!(matches!(
            removing.await.expect("the removal task does not panic"),
            RemoveResult::Removed(Ok(()))
        ));
    }

    #[tokio::test]
    async fn stale_current_handle_is_refused_and_successor_is_not_substituted() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let mesh = mesh().await;
        let registry = NetworkRegistry::new();
        let joined = mesh
            .join(network("fence-stale-config", "fence-stale-wire"))
            .await
            .expect("the predecessor joins");
        assert!(
            registry.insert(joined, None).into_refusal().is_none(),
            "the predecessor installs"
        );
        let predecessor = registry
            .get("fence-stale-config")
            .expect("the predecessor handle exists");
        let pause = registry.install_claim_pause_for_test();
        let removing = {
            let registry = Arc::clone(&registry);
            tokio::spawn(async move { registry.remove("fence-stale-config").await })
        };
        pause.reached.wait().await;
        assert_eq!(
            registry.state("fence-stale-config"),
            Some(RuntimeState::Closing)
        );
        assert!(
            registry
                .with_current("fence-stale-config", &predecessor, |_| ())
                .is_none(),
            "a handle held before the claim is refused after removal starts"
        );
        pause.release.wait().await;
        assert!(matches!(
            removing.await.expect("the removal task does not panic"),
            RemoveResult::Removed(Ok(()))
        ));

        let successor = mesh
            .join(network("fence-stale-config", "fence-stale-wire"))
            .await
            .expect("the successor joins after the predecessor stopped");
        assert!(
            registry.insert(successor, None).into_refusal().is_none(),
            "the successor installs after the predecessor stopped"
        );
        let current = registry
            .get("fence-stale-config")
            .expect("the successor handle exists");
        assert!(!Arc::ptr_eq(&predecessor, &current));
        assert!(
            registry
                .with_current("fence-stale-config", &predecessor, |_| ())
                .is_none(),
            "the successor is never mistaken for the predecessor"
        );
        assert_eq!(
            registry.with_current("fence-stale-config", &current, |joined| {
                joined.network_id().to_string()
            }),
            Some("fence-stale-wire".to_string()),
            "the successor is accepted only with its own exact handle"
        );
        let _ = registry.shutdown_all().await;
    }

    #[tokio::test]
    async fn remove_if_current_retires_exact_owner_and_allows_replacement() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let mesh = mesh().await;
        let registry = NetworkRegistry::new();
        let predecessor = mesh
            .join(network("exact-remove-config", "exact-remove-wire"))
            .await
            .expect("the predecessor joins");
        assert!(
            registry.insert(predecessor, None).into_refusal().is_none(),
            "the predecessor installs"
        );
        let expected = registry
            .get("exact-remove-config")
            .expect("the exact owner exists before retirement");

        assert!(matches!(
            registry
                .remove_if_current("exact-remove-config", &expected)
                .await,
            RemoveResult::Removed(Ok(()))
        ));
        assert!(
            registry.get("exact-remove-config").is_none(),
            "exact retirement removes the predecessor alias"
        );

        let successor = mesh
            .join(network("exact-remove-config", "exact-remove-wire"))
            .await
            .expect("the successor joins after exact retirement");
        assert!(
            registry.insert(successor, None).into_refusal().is_none(),
            "the successor installs after the predecessor stops"
        );
        let current = registry
            .get("exact-remove-config")
            .expect("the successor is visible");
        assert!(
            !Arc::ptr_eq(&expected, &current),
            "replacement has a distinct lifecycle owner"
        );
        let _ = registry.shutdown_all().await;
    }

    #[tokio::test]
    async fn remove_if_current_waits_for_exact_claimed_owner() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let mesh = mesh().await;
        let registry = NetworkRegistry::new();
        let joined = mesh
            .join(network("exact-closing-config", "exact-closing-wire"))
            .await
            .expect("the exact-closing fixture joins");
        assert!(
            registry.insert(joined, None).into_refusal().is_none(),
            "the exact-closing fixture installs"
        );
        let expected = registry
            .get("exact-closing-config")
            .expect("the exact owner exists before removal");
        let pause = registry.install_claim_pause_for_test();
        let removing = {
            let registry = Arc::clone(&registry);
            tokio::spawn(async move { registry.remove("exact-closing-config").await })
        };
        pause.reached.wait().await;
        assert_eq!(
            registry.state("exact-closing-config"),
            Some(RuntimeState::Closing)
        );

        let waiting = {
            let registry = Arc::clone(&registry);
            let expected = Arc::clone(&expected);
            tokio::spawn(async move {
                registry
                    .remove_if_current("exact-closing-config", &expected)
                    .await
            })
        };
        tokio::task::yield_now().await;
        assert!(
            !waiting.is_finished(),
            "the exact Closing owner is awaited before teardown settles"
        );
        pause.release.wait().await;

        assert!(matches!(
            removing.await.expect("the removal task does not panic"),
            RemoveResult::Removed(Ok(()))
        ));
        assert!(matches!(
            waiting.await.expect("the exact waiter does not panic"),
            RemoveResult::AlreadyClosing(TeardownObservation {
                state: RuntimeState::Stopped,
                outcome: Ok(()),
            })
        ));
        assert!(
            registry.get("exact-closing-config").is_none(),
            "the exact owner is gone after the shared teardown"
        );
    }

    #[tokio::test]
    async fn remove_if_current_rejects_stale_owner_before_and_after_successor() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let mesh = mesh().await;
        let registry = NetworkRegistry::new();
        let predecessor = mesh
            .join(network("stale-remove-config", "stale-remove-wire"))
            .await
            .expect("the predecessor joins");
        assert!(
            registry.insert(predecessor, None).into_refusal().is_none(),
            "the predecessor installs"
        );
        let predecessor = registry
            .get("stale-remove-config")
            .expect("the predecessor owner exists");

        let unrelated = mesh
            .join(network(
                "stale-remove-unrelated",
                "stale-remove-unrelated-wire",
            ))
            .await
            .expect("the unrelated owner joins");
        assert!(
            registry.insert(unrelated, None).into_refusal().is_none(),
            "the unrelated owner installs"
        );
        let unrelated = registry
            .get("stale-remove-unrelated")
            .expect("the unrelated owner is visible");
        assert!(matches!(
            registry
                .remove_if_current("stale-remove-config", &unrelated)
                .await,
            RemoveResult::NotFound
        ));
        assert!(
            registry.get("stale-remove-config").is_some(),
            "a mismatched owner cannot retire the live predecessor"
        );
        assert!(matches!(
            registry.remove("stale-remove-unrelated").await,
            RemoveResult::Removed(Ok(()))
        ));

        assert!(matches!(
            registry.remove("stale-remove-config").await,
            RemoveResult::Removed(Ok(()))
        ));
        let successor = mesh
            .join(network("stale-remove-config", "stale-remove-wire"))
            .await
            .expect("the successor joins after predecessor retirement");
        assert!(
            registry.insert(successor, None).into_refusal().is_none(),
            "the successor installs"
        );
        let current = registry
            .get("stale-remove-config")
            .expect("the successor owner exists");
        assert!(matches!(
            registry
                .remove_if_current("stale-remove-config", &predecessor)
                .await,
            RemoveResult::NotFound
        ));
        assert!(
            Arc::ptr_eq(
                &current,
                &registry
                    .get("stale-remove-config")
                    .expect("successor remains")
            ),
            "a stale predecessor cannot retire its successor"
        );
        let _ = registry.shutdown_all().await;
    }

    #[tokio::test]
    async fn insert_racing_remove_waits_until_predecessor_is_stopped() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let mesh = mesh().await;
        let registry = NetworkRegistry::new();
        let incumbent = mesh
            .join(network("f13-race-config", "f13-race-wire"))
            .await
            .expect("incumbent joins");
        let replacement = mesh
            .join(network("f13-race-replacement", "f13-race-wire"))
            .await
            .expect("replacement joins independently");
        assert!(
            registry.insert(incumbent, None).into_refusal().is_none(),
            "the predecessor installs"
        );
        let predecessor = registry
            .state
            .lock()
            .find("f13-race-config")
            .expect("the predecessor is visible");
        let pause = registry.install_claim_pause_for_test();
        let remover = tokio::spawn({
            let registry = Arc::clone(&registry);
            async move { registry.remove("f13-race-config").await }
        });
        pause.reached.wait().await;

        assert_eq!(predecessor.lifecycle.state(), RuntimeState::Closing);
        assert!(registry.get("f13-race-config").is_none());
        assert!(registry.contains("f13-race-config"));
        let refused = registry
            .insert(replacement, None)
            .into_refusal()
            .expect("replacement installed before predecessor stopped");
        assert_eq!(refused.state, RuntimeState::Closing);

        pause.release.wait().await;
        assert!(matches!(
            remover.await.expect("remove task does not panic"),
            RemoveResult::Removed(Ok(()))
        ));
        assert_eq!(predecessor.lifecycle.state(), RuntimeState::Stopped);
        assert!(
            registry
                .insert(refused.joined, refused.drivers)
                .into_refusal()
                .is_none(),
            "the same replacement installs only after Stopped"
        );
        let installed = registry
            .get("f13-race-replacement")
            .expect("the replacement is now authoritative");
        assert_eq!(installed.network_id(), "f13-race-wire");
        let _ = registry.shutdown_all().await;
    }
}
