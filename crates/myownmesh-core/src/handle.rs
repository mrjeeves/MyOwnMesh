//! User-facing facade — what embedders actually call.
//!
//! - [`Mesh`] is the entry constructor. One per process.
//! - [`MeshHandle`] is the device-level handle: identity,
//!   network join/leave, event stream.
//! - [`JoinedNetwork`] is the per-network handle: channels,
//!   RPC, topology, roster.

use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::info;

use crate::channels::Channel;
use crate::config::{MeshConfig, NetworkConfig, TopologyMode};
use crate::engine::connection::PeerStatus;
use crate::engine::ladder::ConnectionTier;
use crate::engine::spawn_network;
use crate::engine::state::{NetworkCmd, NetworkState};
use crate::error::{Error, Result};
use crate::events::{DropReason, MeshEvent, MeshPhase};
use crate::identity::Identity;
use crate::protocol::CapabilityAdvert;
use crate::roster::AuthorizedPeer;
use crate::rpc::Rpc;
use crate::transport::{IceCandidateStats, Transport};

/// One mesh instance bound to a single device identity. Constructs
/// the local identity on first call and shares the WebRTC API
/// across all joined networks.
pub struct Mesh {
    inner: Arc<MeshInner>,
}

struct MeshInner {
    identity: Arc<Identity>,
    transport: Transport,
    events_tx: broadcast::Sender<MeshEvent>,
    networks: Mutex<Vec<NetworkEntry>>,
}

struct NetworkEntry {
    config_id: String,
    network_id: String,
    #[allow(dead_code)] // Reserved for ctl access; tracked but not read yet.
    state: Arc<NetworkState>,
    driver: Option<tokio::task::JoinHandle<()>>,
    fanout: Option<tokio::task::JoinHandle<()>>,
}

impl Mesh {
    /// Build a fresh `Mesh`. Loads (or generates) the identity
    /// anchor and constructs the shared WebRTC API.
    pub async fn open(_config: MeshConfig) -> Result<MeshHandle> {
        let identity = Arc::new(crate::identity::load_or_create()?);
        let transport = Transport::new()?;
        let (events_tx, _) = broadcast::channel(256);
        let inner = Arc::new(MeshInner {
            identity,
            transport,
            events_tx,
            networks: Mutex::new(Vec::new()),
        });
        info!(
            device_id = %inner.identity.display_id(),
            "mesh opened"
        );
        Ok(MeshHandle {
            mesh: Mesh { inner },
        })
    }
}

/// Clonable handle to the mesh. Created by [`Mesh::open`].
#[derive(Clone)]
pub struct MeshHandle {
    mesh: Mesh,
}

impl Clone for Mesh {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl MeshHandle {
    /// Device identity loaded on first construction.
    pub fn identity(&self) -> &Arc<Identity> {
        &self.mesh.inner.identity
    }

    /// Convenience: bare-pubkey device id.
    pub fn device_id(&self) -> String {
        self.mesh.inner.identity.public_id().to_string()
    }

    /// Subscribe to mesh-wide events (every joined network's
    /// PeerEvent / PhaseEvent / Diag stream is fanned into this
    /// single broadcaster).
    pub fn events(&self) -> broadcast::Receiver<MeshEvent> {
        self.mesh.inner.events_tx.subscribe()
    }

    /// Join a network. Returns a [`JoinedNetwork`] handle for
    /// channels / RPC / roster. The driver task keeps running
    /// until [`JoinedNetwork::leave`] is called (or the
    /// `JoinedNetwork` is dropped).
    pub async fn join(&self, mut config: NetworkConfig) -> Result<JoinedNetwork> {
        // Normalize the network id so signaling derivation is
        // case-insensitive on the user input.
        config.network_id = crate::identity::normalize_network_id(&config.network_id)?;

        let (state, driver) = spawn_network(
            config.clone(),
            self.mesh.inner.identity.clone(),
            self.mesh.inner.transport.clone(),
        )
        .await?;
        let rpc = Rpc::new(state.clone());
        *state.rpc.write() = Some(rpc.inner.clone());

        // Fan-out per-network events into the mesh-wide broadcaster.
        let mesh_events_tx = self.mesh.inner.events_tx.clone();
        let mut net_events_rx = state.events_tx.subscribe();
        let fanout = tokio::spawn(async move {
            loop {
                match net_events_rx.recv().await {
                    Ok(ev) => {
                        let _ = mesh_events_tx.send(ev);
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                }
            }
        });

        // Track the entry so leave() can find it.
        self.mesh.inner.networks.lock().push(NetworkEntry {
            config_id: config.id.clone(),
            network_id: config.network_id.clone(),
            state: state.clone(),
            driver: Some(driver),
            fanout: Some(fanout),
        });

        Ok(JoinedNetwork {
            mesh: self.mesh.clone(),
            state,
            rpc: Arc::new(rpc),
            config_id: config.id,
            label: config.label,
        })
    }

    /// Convenience: snapshot all currently-joined networks.
    pub fn joined_network_ids(&self) -> Vec<String> {
        self.mesh
            .inner
            .networks
            .lock()
            .iter()
            .map(|e| e.network_id.clone())
            .collect()
    }
}

/// One joined network's user-facing handle.
pub struct JoinedNetwork {
    mesh: Mesh,
    state: Arc<NetworkState>,
    rpc: Arc<Rpc>,
    config_id: String,
    label: String,
}

impl JoinedNetwork {
    pub fn network_id(&self) -> &str {
        &self.state.network_id
    }

    /// User-chosen config record id (distinguishes multiple
    /// saved entries for the same wire-level network).
    pub fn config_id(&self) -> &str {
        &self.config_id
    }

    /// Cosmetic display name. Empty when the user didn't pick one
    /// at create time — the GUI falls back to `network_id`.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Snapshot the per-network rollup.
    pub fn current_phase(&self) -> MeshPhase {
        *self.state.current_phase.read()
    }

    pub fn current_topology(&self) -> TopologyMode {
        self.state.topology.read().clone()
    }

    /// Reconfigure the topology selector at runtime. Triggers
    /// a synchronous re-evaluation of preferred peers and emits
    /// any necessary shelve / unshelve frames.
    pub async fn set_topology(&self, mode: TopologyMode) -> Result<()> {
        self.state
            .cmd_tx
            .send(NetworkCmd::SetTopology(mode))
            .map_err(|_| Error::Network("engine command queue closed".into()))?;
        Ok(())
    }

    /// Type-safe publish/subscribe channel. The same `name` on
    /// two peers binds their `Channel<T>` senders to receivers.
    pub fn channel<T>(&self, name: &str) -> Channel<T>
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Send + Sync + 'static,
    {
        Channel::new(name.to_string(), self.state.clone())
    }

    /// RPC dispatcher for this network. Cheap to clone; multiple
    /// holders can call / serve independently.
    pub fn rpc(&self) -> Arc<Rpc> {
        self.rpc.clone()
    }

    /// Snapshot every peer the engine is currently tracking.
    pub fn peers(&self) -> Vec<PeerInfo> {
        self.state.peer_snapshot()
    }

    /// Single-peer detail.
    pub fn peer(&self, device_id: &str) -> Option<PeerInfo> {
        self.state.peer_info(device_id)
    }

    /// List approved peers from the on-disk roster.
    pub async fn roster_list(&self) -> Result<Vec<AuthorizedPeer>> {
        Ok(self.state.roster.read().authorized_devices.clone())
    }

    /// Approve a peer into the roster (and send the on-the-wire
    /// `approve` if a session is currently open).
    pub async fn roster_approve(&self, device_id: &str, label: &str) -> Result<()> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        self.state
            .cmd_tx
            .send(NetworkCmd::ApproveRoster {
                device_id: device_id.to_string(),
                label: label.to_string(),
                reply,
            })
            .map_err(|_| Error::Network("engine command queue closed".into()))?;
        rx.await
            .map_err(|_| Error::Network("engine dropped approve reply".into()))??;
        // Emit local approve frame after roster persistence.
        crate::engine::handshake::send_local_approve(&self.state, device_id).await;
        Ok(())
    }

    /// Remove a peer from the roster. Drops the active session
    /// if any.
    pub async fn roster_remove(&self, device_id: &str) -> Result<()> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        self.state
            .cmd_tx
            .send(NetworkCmd::RemoveRoster {
                device_id: device_id.to_string(),
                reply,
            })
            .map_err(|_| Error::Network("engine command queue closed".into()))?;
        rx.await
            .map_err(|_| Error::Network("engine dropped reply".into()))??;
        let _ = self.state.cmd_tx.send(NetworkCmd::DropPeer {
            device_id: device_id.to_string(),
            reason: DropReason::Denied,
        });
        Ok(())
    }

    /// Set the capability advertisement we share with peers via
    /// hello + capabilities_update frames.
    pub fn advertise(&self, caps: CapabilityAdvert) {
        self.rpc.advertise(caps);
    }

    /// Stop the network. Tears down all peer sessions, signals
    /// the driver to exit, and drops the entry. After leave, the
    /// `JoinedNetwork` is no longer usable.
    pub async fn leave(self) -> Result<()> {
        let _ = self.state.cmd_tx.send(NetworkCmd::Shutdown);
        // Take the entry under the lock, drop the lock, then
        // await the driver outside. Holding parking_lot's
        // MutexGuard across an await is forbidden.
        let mut entry = {
            let mut nets = self.mesh.inner.networks.lock();
            let idx = nets.iter().position(|e| e.config_id == self.config_id);
            idx.map(|i| nets.remove(i))
        };
        if let Some(entry) = entry.as_mut() {
            if let Some(driver) = entry.driver.take() {
                let _ = driver.await;
            }
            if let Some(fanout) = entry.fanout.take() {
                fanout.abort();
            }
        }
        Ok(())
    }

    /// Direct access to the shared network state. Hidden from
    /// the API surface for embedders — the engine reaches across
    /// crate boundaries to manipulate it.
    #[doc(hidden)]
    pub fn state(&self) -> Arc<NetworkState> {
        self.state.clone()
    }
}

/// User-facing snapshot of a peer's current view in the engine.
/// All fields are immutable copies; re-fetch for fresh data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub device_id: String,
    pub status: PeerStatus,
    pub tier: ConnectionTier,
    pub rtt_ms: Option<u32>,
    pub label: String,
    pub capabilities: Option<CapabilityAdvert>,
    pub local_shelved: bool,
    pub remote_shelved: bool,
    pub authenticated: bool,
    /// 5-char UPPERCASE-HEX display tag derived from the peer's
    /// pubkey. Same scheme as `Identity::display_id` — peers compare
    /// suffixes to confirm "yes, this is the right device" without
    /// reading the full pubkey aloud. Surfaced separately so the GUI
    /// can render it in a distinct tile during pending-approval.
    pub device_suffix: String,
    /// Verification code the peer sent us in their `hello` — i.e.
    /// the peer's own code that we should be displaying as "theirs"
    /// in the approval UI. `None` until we receive a hello.
    pub verification_code_received: Option<String>,
    /// Verification code WE sent the peer in our `hello` — i.e. our
    /// own code that we should be displaying as "ours" in the
    /// approval UI. Both ends generate one (independent random
    /// strings), and the bilateral approval flow asks each user to
    /// confirm all four values match what the other side reads
    /// back: this device's suffix + code, the peer's suffix + code.
    /// `None` until our handshake has fired.
    pub verification_code_sent: Option<String>,
    /// True once we've sent an `Approve` to this peer — either via
    /// the user clicking Approve in the GUI, or via auto-approve
    /// because the peer is already in the roster. Surfaced so the
    /// approval UI can flip the row from "review and approve" to
    /// "waiting for peer to approve their side" — the connection
    /// doesn't transition to Active until both ends have approved.
    pub local_approve_sent: bool,
    /// True once we've received an `Approve` from this peer. Pairs
    /// with `local_approve_sent`: when both are true the engine
    /// transitions the peer to Active. Either alone means the
    /// handshake is half-complete and waiting on the other end.
    pub remote_approve_seen: bool,
    /// True when the engine has decided this peer is unreachable
    /// without a TURN relay (multiple ICE failures, zero relay
    /// candidates on either side). Mirrors the one-shot
    /// `no_turn_diag_emitted` flag the ICE watchdog sets — the GUI
    /// uses it to surface "we can see them on signaling but the data
    /// pipe never comes up" without making the user grep the
    /// Activity log. Reset when the peer recovers to Active.
    pub needs_turn: bool,
    /// Counts of locally-gathered ICE candidates by type. The GUI
    /// uses these to infer the link kind for the layout: `host`-only
    /// pairs are LAN neighbours and sit directly next to "you",
    /// while `server_reflexive` / `relay` pairs sit on the far side
    /// of the Internet node. Zeroed until ICE starts gathering.
    pub local_candidates: IceCandidateStats,
    /// Counts of ICE candidates the peer sent us. Same layout role
    /// as `local_candidates` — both sides have to surface a host
    /// candidate before we treat the link as LAN-direct.
    pub remote_candidates: IceCandidateStats,
}
