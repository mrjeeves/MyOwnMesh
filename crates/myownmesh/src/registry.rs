//! Per-daemon registry of joined networks, keyed by both the user-chosen
//! config id and the wire-level network id. The control socket uses
//! this to address per-network operations (peers list, roster mutations,
//! topology changes, add/remove) without `serve.rs` having to thread a
//! handle through every dispatch arm.
//!
//! Each entry pairs a `JoinedNetwork` with its `NostrDriverHandle` — the
//! signaling driver is per-network, and dropping the handle stops it.
//! Bundling them means removing a network from the registry tears down
//! both the engine driver (via `leave()`) and the signaling driver
//! (via `Drop`) without serve.rs having to keep parallel vectors.
//!
//! `JoinedNetwork` is not [`Clone`] — its `leave(self)` consumes the
//! value to make sure the engine driver task tears down cleanly. So we
//! wrap each entry in [`Arc`], hand out clones to the dispatcher, and
//! extract the inner value via [`Arc::try_unwrap`] at remove / shutdown
//! time. Failed unwraps are tolerated — the engine driver tears down
//! when its command-channel sender drops, so a leaked entry still
//! resolves cleanly.
//!
//! Concurrency: a [`parking_lot::RwLock`] guards the map. The control
//! dispatcher does `read().get(...).cloned()` to pull an
//! `Arc<JoinedNetwork>` out of the lock and then drops the guard before
//! awaiting any per-network method — holding a `parking_lot` guard
//! across `.await` is forbidden.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::JoinedNetwork;
use myownmesh_signaling::nostr::driver::NostrDriverHandle;
use parking_lot::Mutex;
use parking_lot::RwLock;

/// How long [`NetworkRegistry::announce_all_departures`] waits after queuing
/// the per-network `leave` broadcasts before returning, so they reach the
/// already-connected relay sockets before the registry is drained on
/// shutdown. Mirrors core's per-network `JoinedNetwork::announce_leave`
/// flush window.
const DEPARTURE_FLUSH: Duration = Duration::from_millis(250);

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
}

/// One row of the registry: the `JoinedNetwork` handle plus the
/// `NostrDriverHandle` that keeps signaling alive. `nostr` is
/// `Mutex<Option<...>>` so we can `take()` it during a remove without
/// requiring `&mut self` access through the `Arc` (which is shared).
struct Entry {
    joined: Arc<JoinedNetwork>,
    nostr: Mutex<Option<NostrDriverHandle>>,
}

/// Registry shared between `serve.rs` (which owns initial population
/// + final shutdown) and the control socket dispatcher (which clones
///   `Arc<JoinedNetwork>`s out to perform per-network work, and may
///   add/remove networks via the NetworkAdd / NetworkRemove ops).
#[derive(Default)]
pub struct NetworkRegistry {
    inner: RwLock<HashMap<String, Arc<Entry>>>,
}

impl NetworkRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Insert a freshly-joined network together with its signaling
    /// driver handle. Indexed by both the config record id and the
    /// wire-level network id so callers can use either as the lookup
    /// key (the CLI / GUI both have a habit of passing whichever
    /// happens to be in scope).
    pub fn insert(&self, joined: JoinedNetwork, nostr: Option<NostrDriverHandle>) {
        let config_id = joined.config_id().to_string();
        let network_id = joined.network_id().to_string();
        let entry = Arc::new(Entry {
            joined: Arc::new(joined),
            nostr: Mutex::new(nostr),
        });
        let mut map = self.inner.write();
        map.insert(config_id, entry.clone());
        map.entry(network_id).or_insert(entry);
    }

    /// Resolve a network's `JoinedNetwork` by either its config id or
    /// wire-level network id. Returns a cloned `Arc` so callers can
    /// release the internal lock before awaiting.
    pub fn get(&self, key: &str) -> Option<Arc<JoinedNetwork>> {
        self.inner.read().get(key).map(|e| e.joined.clone())
    }

    /// True when an entry exists for either alias of the given id.
    pub fn contains(&self, key: &str) -> bool {
        self.inner.read().contains_key(key)
    }

    /// Snapshot every distinct network. Each network appears once
    /// even though the map stores aliases.
    pub fn summaries(&self) -> Vec<NetworkSummary> {
        let map = self.inner.read();
        // Dedup by entry pointer — both the config-id and
        // network-id aliases point at the same `Arc<Entry>`, so
        // pointer identity is the cheapest dedup key.
        let mut seen: Vec<*const Entry> = Vec::new();
        let mut out = Vec::new();
        for entry in map.values() {
            let ptr = Arc::as_ptr(entry);
            if seen.contains(&ptr) {
                continue;
            }
            seen.push(ptr);
            let j = &entry.joined;
            out.push(NetworkSummary {
                config_id: j.config_id().to_string(),
                network_id: j.network_id().to_string(),
                label: j.label().to_string(),
                phase: j.current_phase(),
                topology: j.current_topology(),
            });
        }
        // Stable order across calls: alphabetical by config id.
        out.sort_by(|a, b| a.config_id.cmp(&b.config_id));
        out
    }

    /// Remove a network from the registry, returning the owned
    /// `JoinedNetwork` for the caller to `leave().await`. Both the
    /// config-id and network-id aliases are removed atomically.
    /// Returns `None` if no matching entry exists. Returns the
    /// `JoinedNetwork` in an `Err` variant if a clone is still
    /// outstanding (e.g. a control request is mid-flight); the
    /// caller can retry shortly or just drop the registry handle
    /// and let the engine tear down via its command channel.
    ///
    /// The accompanying `NostrDriverHandle`, if any, is dropped
    /// inside this call — its `Drop` impl signals every signaling
    /// task to exit, so callers don't need to do anything else for
    /// the signaling side.
    pub fn remove(&self, key: &str) -> RemoveResult {
        // Find both aliases that point at this entry.
        let (entry, all_keys) = {
            let map = self.inner.read();
            let entry = match map.get(key).cloned() {
                Some(e) => e,
                None => return RemoveResult::NotFound,
            };
            let target = Arc::as_ptr(&entry);
            let keys: Vec<String> = map
                .iter()
                .filter_map(|(k, v)| {
                    if Arc::as_ptr(v) == target {
                        Some(k.clone())
                    } else {
                        None
                    }
                })
                .collect();
            (entry, keys)
        };
        {
            let mut map = self.inner.write();
            for k in &all_keys {
                map.remove(k);
            }
        }
        // Drop the signaling driver — its Drop signals every spawned
        // task to exit.
        drop(entry.nostr.lock().take());
        // Extract the JoinedNetwork. Three-step dance because we
        // have to unwrap the outer `Arc<Entry>` AND the inner
        // `Arc<JoinedNetwork>`.
        match Arc::try_unwrap(entry) {
            Ok(Entry { joined, .. }) => match Arc::try_unwrap(joined) {
                Ok(joined) => RemoveResult::Removed(joined),
                Err(_) => RemoveResult::StillBorrowed,
            },
            Err(_) => RemoveResult::StillBorrowed,
        }
    }

    /// Broadcast a graceful `leave` on every joined network, then wait
    /// briefly for the publishes to reach the relays, before the caller
    /// drains the registry on daemon shutdown. Peers drop our sessions
    /// immediately on the `leave` instead of waiting out their ~90 s
    /// heartbeat timeout — the same courtesy `network_remove` extends for a
    /// single network. The read lock is held only for the synchronous emit
    /// (dropped before the flush wait), so this never holds a `parking_lot`
    /// guard across `.await`.
    pub async fn announce_all_departures(&self) {
        let mut emitted = false;
        {
            let map = self.inner.read();
            // Dedup by entry pointer — both id aliases point at the same Arc.
            let mut seen: Vec<*const Entry> = Vec::new();
            for entry in map.values() {
                let ptr = Arc::as_ptr(entry);
                if seen.contains(&ptr) {
                    continue;
                }
                seen.push(ptr);
                entry.joined.request_departure();
                emitted = true;
            }
        }
        if emitted {
            tokio::time::sleep(DEPARTURE_FLUSH).await;
        }
    }

    /// Drain the registry, returning the owned `JoinedNetwork`
    /// values so the caller can `leave().await` each one. Any
    /// entries still held by an in-flight control request are
    /// skipped — they'll be released when the request finishes
    /// and the daemon exits immediately after this returns, so the
    /// engine driver will be aborted via process termination rather
    /// than a clean leave.
    pub fn take_all(&self) -> Vec<JoinedNetwork> {
        let drained: Vec<Arc<Entry>> = self.inner.write().drain().map(|(_, v)| v).collect();
        // Dedup by entry pointer — both aliases of the same network
        // appear in the drain.
        let mut by_ptr: HashMap<*const Entry, Arc<Entry>> = HashMap::new();
        for arc in drained {
            by_ptr.entry(Arc::as_ptr(&arc)).or_insert(arc);
        }
        let mut out = Vec::new();
        for (_, arc) in by_ptr {
            // Drop the nostr handle first; we don't need it past this point.
            drop(arc.nostr.lock().take());
            if let Ok(Entry { joined, .. }) = Arc::try_unwrap(arc) {
                if let Ok(joined) = Arc::try_unwrap(joined) {
                    out.push(joined);
                }
            }
        }
        out
    }
}

/// Outcome of a [`NetworkRegistry::remove`] call.
pub enum RemoveResult {
    /// Entry was removed and we successfully extracted the owned
    /// `JoinedNetwork` for the caller to `leave().await`.
    Removed(JoinedNetwork),
    /// Entry didn't exist.
    NotFound,
    /// Entry was removed from the map but another part of the
    /// daemon still holds a strong reference to it (a control
    /// request mid-flight). The engine driver will exit on the next
    /// command-channel drop; no further action needed from the
    /// caller.
    StillBorrowed,
}
