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
use crate::transport::{IceCandidateStats, SelectedCandidatePair, Transport};

/// How long [`JoinedNetwork::announce_leave`] waits after queuing the
/// departure broadcast before returning, so the publish reaches the
/// already-connected relay sockets before the caller drops the signaling
/// driver. Long enough for one WebSocket frame on a live socket, short
/// enough to be imperceptible on a user-initiated reconnect.
const LEAVE_FLUSH: std::time::Duration = std::time::Duration::from_millis(250);

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
    /// Build a fresh `Mesh`. Loads (or generates) the on-disk identity
    /// anchor (`~/.myownmesh/.secrets/identity.json`) and constructs the
    /// shared WebRTC API.
    pub async fn open(config: MeshConfig) -> Result<MeshHandle> {
        let identity = Arc::new(crate::identity::load_or_create()?);
        Self::open_with_identity(config, identity).await
    }

    /// Build a fresh `Mesh` with a **caller-supplied identity**, for embedders
    /// that manage their own key storage rather than the on-disk anchor — e.g.
    /// a mobile app holding its ed25519 seed in the iOS Keychain / Android
    /// Keystore, or any host that has already loaded a key. Pair with
    /// [`Identity::from_signing_key`](crate::identity::Identity::from_signing_key).
    /// Otherwise identical to [`Mesh::open`]: same shared WebRTC stack, same
    /// network join/leave surface.
    pub async fn open_with_identity(
        _config: MeshConfig,
        identity: Arc<Identity>,
    ) -> Result<MeshHandle> {
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

    // ---- governance (closed networks) ---------------------------------
    //
    // These wrap the engine's `NetworkCmd::*` variants for the
    // proposal lifecycle. Every method except `governance_state()`
    // round-trips through the driver loop so mutations stay serialised
    // with the rest of the engine's per-network operations.

    /// Snapshot the current signed governance state — kind + role
    /// assignments + the append-only transition log + pending
    /// proposals + spawned splits. Read-only.
    pub async fn governance_state(&self) -> Result<crate::network_state::NetworkState> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        self.state
            .cmd_tx
            .send(NetworkCmd::GovernanceSnapshot { reply })
            .map_err(|_| Error::Network("engine command queue closed".into()))?;
        rx.await
            .map_err(|_| Error::Network("engine dropped snapshot reply".into()))
    }

    /// Float a new signed transition. Returns the new proposal id
    /// so the caller can correlate with subsequent acks. The engine
    /// signs the canonical payload with the local identity,
    /// persists to pending, and broadcasts to active peers in one
    /// step; if the local signer set already satisfies the variant's
    /// quorum (e.g. founder self-election), the proposal ratifies
    /// before this call returns.
    pub async fn propose_transition(
        &self,
        variant: crate::network_state::TransitionVariant,
        mfa_code: Option<String>,
    ) -> Result<String> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        self.state
            .cmd_tx
            .send(NetworkCmd::ProposeTransition {
                variant,
                mfa_code,
                reply,
            })
            .map_err(|_| Error::Network("engine command queue closed".into()))?;
        rx.await
            .map_err(|_| Error::Network("engine dropped propose reply".into()))?
    }

    /// Sign a pending proposal floated by another peer (or by this
    /// device). The engine broadcasts the signed ack and attempts
    /// ratification atomically.
    pub async fn sign_proposal(&self, proposal_id: &str, mfa_code: Option<String>) -> Result<()> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        self.state
            .cmd_tx
            .send(NetworkCmd::SignProposal {
                proposal_id: proposal_id.to_string(),
                mfa_code,
                reply,
            })
            .map_err(|_| Error::Network("engine command queue closed".into()))?;
        rx.await
            .map_err(|_| Error::Network("engine dropped sign reply".into()))?
    }

    /// Deny a pending proposal. A single deny invalidates the
    /// proposal across the whole network; the engine signs the deny
    /// + broadcasts so other peers see the kill switch fire.
    pub async fn deny_proposal(&self, proposal_id: &str) -> Result<()> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        self.state
            .cmd_tx
            .send(NetworkCmd::DenyProposal {
                proposal_id: proposal_id.to_string(),
                reply,
            })
            .map_err(|_| Error::Network("engine command queue closed".into()))?;
        rx.await
            .map_err(|_| Error::Network("engine dropped deny reply".into()))?
    }

    /// Withdraw a proposal the local device floated. Engine drops
    /// from pending without broadcasting a deny; peers see the
    /// proposal disappear via the next state snapshot.
    pub async fn withdraw_proposal(&self, proposal_id: &str) -> Result<()> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        self.state
            .cmd_tx
            .send(NetworkCmd::WithdrawProposal {
                proposal_id: proposal_id.to_string(),
                reply,
            })
            .map_err(|_| Error::Network("engine command queue closed".into()))?;
        rx.await
            .map_err(|_| Error::Network("engine dropped withdraw reply".into()))?
    }

    /// Fire the proposer-initiated split fallback for a stuck close.
    /// Returns the deterministically-derived network id of the new
    /// closed network; the caller typically `join`s it straight
    /// away. Only callable by the proposer of the original
    /// open→closed proposal.
    pub async fn spawn_split(&self, proposal_id: &str) -> Result<String> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        self.state
            .cmd_tx
            .send(NetworkCmd::SpawnSplit {
                proposal_id: proposal_id.to_string(),
                reply,
            })
            .map_err(|_| Error::Network("engine command queue closed".into()))?;
        rx.await
            .map_err(|_| Error::Network("engine dropped split reply".into()))?
    }

    /// Announce a graceful departure to the room, then briefly wait for it
    /// to reach the relays. Peers tear our session down immediately on the
    /// `leave` (instead of waiting out the ~90 s heartbeat timeout), so a
    /// deliberate reconnect — leave-then-rejoin — doesn't strand them on a
    /// dead session whose ICE still falsely reports `Connected`.
    ///
    /// Call this on the *live* handle **before** the signaling driver is
    /// dropped (the registry drops it inside `remove`): once the driver is
    /// gone there's no socket left to publish on. Best-effort — the short
    /// flush window lets the publish hit the already-connected relay sockets
    /// without blocking teardown on a delivery confirmation the signaling
    /// layer never provides anyway.
    pub async fn announce_leave(&self) {
        self.request_departure();
        tokio::time::sleep(LEAVE_FLUSH).await;
    }

    /// Queue the departure broadcast without waiting for it to flush. Bulk
    /// teardown (daemon shutdown) emits one per network and then does a
    /// single combined flush before draining, rather than paying the
    /// per-network wait [`Self::announce_leave`] does.
    pub fn request_departure(&self) {
        self.state.announce_departure();
    }

    /// Reconnect in place — the non-destructive twin of a leave-then-rejoin.
    /// `peer == None` redials signaling and renegotiates ICE with every peer on
    /// this network; `peer == Some(id)` reconnects just that one peer (for a
    /// per-node refresh). Nothing is torn down and no `Leave` is announced, so
    /// peers keep their sessions and app-level state — the gentle recovery a
    /// "refresh / reconnect" control should drive instead of removing and
    /// re-adding the network. Fire-and-forget: the work runs on the engine
    /// driver so it's serialized with every other per-peer mutation.
    pub fn reconnect(&self, peer: Option<String>) {
        self.state.reconnect(peer);
    }

    /// Deliberately dial exactly one signaling-discovered peer by device id,
    /// opening the WebRTC session on demand. This is the manual-connect
    /// primitive a [`Silent`](crate::NetworkKind::Silent) network needs: on a
    /// Silent mesh the engine never dials just because a peer announced (a
    /// co-present peer surfaces as [`crate::PeerEvent::Sighted`] / in
    /// [`Self::peers`] with no session), so a connection is initiated only
    /// here or by answering an inbound offer. The local side always takes the
    /// offerer role, so a Silent peer — which never auto-dials — is reached by
    /// our offer and answers normally. Idempotent: a no-op if a live session
    /// already exists. Fire-and-forget past the queue hand-off — the dial runs
    /// on the engine driver, serialized with every other per-peer mutation.
    ///
    /// On a non-Silent network this still works (dials the peer if not already
    /// connected), but there it is rarely needed: those networks auto-dial on
    /// presence. `Ok(())` means the command was queued, not that the peer
    /// connected — observe [`crate::PeerEvent`]s for the outcome.
    pub async fn connect_peer(&self, device_id: &str) -> Result<()> {
        self.state
            .cmd_tx
            .send(NetworkCmd::ConnectPeer {
                device_id: device_id.to_string(),
                sticky: false,
                reply: None,
            })
            .map_err(|_| Error::Network("engine command queue closed".into()))?;
        Ok(())
    }

    /// Dial one peer and resolve when the link is genuinely ACTIVE (or
    /// fail with the terminal reason) — the observable twin of
    /// [`Self::connect_peer`], which only queues the dial. Bounded by
    /// `timeout`. `sticky` records a standing dial: the engine keeps a
    /// never-expiring reconnect intent for the peer and — the one
    /// exception to Silent's no-auto-dial rule — redials it whenever it
    /// announces, which is what lets a remote-support session survive
    /// the far end sleeping, moving networks, or rebooting without the
    /// application re-driving the dial.
    pub async fn connect_peer_wait(
        &self,
        device_id: &str,
        sticky: bool,
        timeout: std::time::Duration,
    ) -> Result<()> {
        match tokio::time::timeout(timeout, self.state.connect_peer_wait(device_id, sticky)).await {
            Ok(result) => result,
            Err(_) => Err(Error::Network(format!(
                "connect to {device_id} still pending after {timeout:?} (the dial keeps going{})",
                if sticky { "; the pin stays armed" } else { "" }
            ))),
        }
    }

    /// Open the lowest free media lane of `kind` toward `peer` and
    /// return its id — the explicit reservation twin of the write-time
    /// auto-open (writing to a closed lane opens it transparently).
    /// The new m-line goes live on the next coalesced renegotiation;
    /// writes before that are no-ops, exactly like stream start.
    pub async fn open_media_lane(
        &self,
        peer: &str,
        kind: crate::transport::webrtc::LaneKind,
    ) -> Result<u8> {
        self.state.media_lane_open(peer, kind).await
    }

    /// Close a media lane toward `peer`, releasing its track and (on
    /// the next renegotiation) its m-line send side. Idempotent — a
    /// lane that isn't open is a no-op, so teardown can't double-fault.
    pub async fn close_media_lane(
        &self,
        peer: &str,
        kind: crate::transport::webrtc::LaneKind,
        lane: u8,
    ) -> Result<()> {
        self.state.media_lane_close(peer, kind, lane).await
    }

    /// Point-in-time traffic accounting for this network: frames and
    /// bytes by class (keepalive / control / gossip / app), signaling
    /// publish and receive counts split into presence vs pairwise
    /// negotiation, forwarding duty, and the acked-delivery backlog.
    /// Two snapshots around an experiment are the honest comparison of
    /// two topologies.
    pub fn traffic(&self) -> crate::engine::traffic::TrafficSnapshot {
        self.state.traffic_snapshot()
    }

    /// Remove a standing dial recorded by `connect_peer_wait(…, sticky
    /// = true)` (or a config `pinned_peers` entry) — the peer stops
    /// being redialed on announce and its never-expiring intent is
    /// dropped. Does not tear down a live session.
    pub fn unpin_peer(&self, device_id: &str) {
        self.state.remove_sticky(device_id);
    }

    /// Send an application frame with the acknowledged-delivery
    /// contract: parked until the peer's link is up, retransmitted
    /// across session rebuilds, resolved when the peer's engine has
    /// delivered it to the application layer (or with an error at TTL /
    /// terminal failure / outbox backpressure). The everyday cure for
    /// "my first frame raced the data channel and vanished" — no
    /// application retry loop required.
    pub async fn send_reliable(
        &self,
        peer: &str,
        channel: &str,
        payload: serde_json::Value,
        ttl: Option<std::time::Duration>,
    ) -> Result<()> {
        self.state
            .send_channel_reliable(peer, channel, payload, ttl.map(|d| d.as_millis() as u64))
            .await
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
    /// How far this peer's wall clock reads from ours (ms; positive = the
    /// peer is ahead), estimated passively from the heartbeat pings it
    /// already sends (RTT-corrected median over a short window). `None`
    /// until its first inbound ping. `#[serde(default)]` so a snapshot
    /// from an older daemon still decodes.
    #[serde(default)]
    pub clock_skew_ms: Option<i64>,
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
    /// The ICE candidate pair the agent actually selected for
    /// sending packets, once known. Authoritative input for the
    /// graph's LAN/STUN/TURN classification — the counts above only
    /// describe what was tried, this describes what's in use. `None`
    /// until ICE reaches Connected/Completed.
    pub selected_pair: Option<SelectedCandidatePair>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    /// The injection seam adopts the caller's identity rather than the
    /// on-disk anchor: the opened mesh's device id is the injected key's
    /// public id. This is the path a phone uses to open the engine with a
    /// key from its Keychain/Keystore (built via `Identity::from_signing_key`,
    /// which `ephemeral()` also uses).
    #[tokio::test]
    async fn open_with_identity_adopts_the_injected_key() {
        let identity = Arc::new(Identity::ephemeral());
        let want = identity.public_id().to_string();

        let mesh = Mesh::open_with_identity(MeshConfig::default(), identity)
            .await
            .expect("open_with_identity");

        // The mesh's wire id derives from the injected key, not a disk anchor.
        assert_eq!(mesh.device_id(), want);
    }
}
