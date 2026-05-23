//! Per-daemon registry of joined networks, keyed by both the user-chosen
//! config id and the wire-level network id. The control socket uses
//! this to address per-network operations (peers list, roster mutations,
//! topology changes) without `serve.rs` having to thread a handle
//! through every dispatch arm.
//!
//! `JoinedNetwork` itself is not [`Clone`] — its `leave(self)` consumes
//! the value to make sure the engine driver task tears down cleanly. So
//! we wrap each entry in [`Arc`], hand out clones to the dispatcher, and
//! drain the registry at shutdown via [`NetworkRegistry::take_all`],
//! which returns the inner `JoinedNetwork` values only when this is the
//! last strong reference (the typical case at process exit).
//!
//! Concurrency: a [`parking_lot::RwLock`] guards the map. The control
//! dispatcher does `read().get(...).cloned()` to pull an
//! `Arc<JoinedNetwork>` out of the lock and then drops the guard before
//! awaiting any per-network method — holding a `parking_lot` guard
//! across `.await` is forbidden.

use std::collections::HashMap;
use std::sync::Arc;

use myownmesh_core::JoinedNetwork;
use parking_lot::RwLock;

/// Snapshot view of one joined network for ctl / GUI consumers.
/// Cheap to compute — every field is already cached on the
/// `JoinedNetwork`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NetworkSummary {
    /// User-chosen config record id (unique per device).
    pub config_id: String,
    /// Wire-level network rendezvous handle.
    pub network_id: String,
    /// Coarse-grained phase: joining / alone / discovering / active / degraded / stopped.
    pub phase: myownmesh_core::MeshPhase,
    /// Current topology mode. Serialised with serde-internal tagging so
    /// `Star { hub }` keeps its hub field on the wire.
    pub topology: myownmesh_core::TopologyMode,
}

/// Registry shared between `serve.rs` (which owns insertion + final
/// shutdown) and the control socket dispatcher (which clones entries
/// out to perform per-network work).
#[derive(Default)]
pub struct NetworkRegistry {
    inner: RwLock<HashMap<String, Arc<JoinedNetwork>>>,
}

impl NetworkRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Insert a freshly-joined network. Indexed by both the config
    /// record id and the wire-level network id so callers can use
    /// either as the lookup key (the CLI / GUI both have a habit of
    /// passing whichever happens to be in scope).
    pub fn insert(&self, joined: JoinedNetwork) {
        let config_id = joined.config_id().to_string();
        let network_id = joined.network_id().to_string();
        let entry = Arc::new(joined);
        let mut map = self.inner.write();
        map.insert(config_id, entry.clone());
        map.entry(network_id).or_insert(entry);
    }

    /// Resolve a network by either its config id or wire-level
    /// network id. Returns a cloned `Arc` so callers can release the
    /// internal lock before awaiting.
    pub fn get(&self, key: &str) -> Option<Arc<JoinedNetwork>> {
        self.inner.read().get(key).cloned()
    }

    /// Snapshot every distinct network. Each network appears once
    /// even though the map stores aliases.
    pub fn summaries(&self) -> Vec<NetworkSummary> {
        let map = self.inner.read();
        // Dedup by config_id — both the config-id and network-id
        // aliases point at the same `Arc`, so pointer identity is
        // the cheapest dedup key.
        let mut seen: Vec<*const JoinedNetwork> = Vec::new();
        let mut out = Vec::new();
        for entry in map.values() {
            let ptr = Arc::as_ptr(entry);
            if seen.contains(&ptr) {
                continue;
            }
            seen.push(ptr);
            out.push(NetworkSummary {
                config_id: entry.config_id().to_string(),
                network_id: entry.network_id().to_string(),
                phase: entry.current_phase(),
                topology: entry.current_topology(),
            });
        }
        // Stable order across calls: alphabetical by config id.
        out.sort_by(|a, b| a.config_id.cmp(&b.config_id));
        out
    }

    /// Drain the registry, returning the owned `JoinedNetwork`
    /// values so the caller can `leave().await` each one. Any
    /// entries still held by an in-flight control request are
    /// skipped — they'll be released when the request finishes
    /// and the daemon exits immediately after this returns, so the
    /// engine driver will be aborted via process termination rather
    /// than a clean leave.
    pub fn take_all(&self) -> Vec<JoinedNetwork> {
        let drained: Vec<Arc<JoinedNetwork>> = self
            .inner
            .write()
            .drain()
            .map(|(_, v)| v)
            .collect();
        // Drop alias duplicates first so try_unwrap can succeed.
        let mut by_ptr: HashMap<*const JoinedNetwork, Arc<JoinedNetwork>> = HashMap::new();
        for arc in drained {
            by_ptr.entry(Arc::as_ptr(&arc)).or_insert(arc);
        }
        let mut out = Vec::new();
        for (_, arc) in by_ptr {
            match Arc::try_unwrap(arc) {
                Ok(joined) => out.push(joined),
                Err(_arc) => {
                    // Another strong ref is alive (a control request
                    // is mid-flight). Best-effort: drop it; engine
                    // driver tears down when its command sender goes
                    // away.
                }
            }
        }
        out
    }
}
