//! Daemon control protocol — line-delimited JSON over a local
//! interprocess socket (unix-domain socket on Unix, named pipe on
//! Windows). `myownmesh ctl …` clients and the GUI both talk to the
//! running daemon via this socket.
//!
//! Wire shape: one JSON object per line. Requests have `op` plus
//! op-specific fields; responses have `ok` (bool) plus
//! op-specific payload, or `error: string` on failure.
//!
//! Most ops are single-shot request → response. The exception is
//! [`Request::EventsSubscribe`], which converts the connection into a
//! one-way server-push stream: the daemon writes one JSON event per
//! line until the client disconnects. The GUI's Tauri backend uses
//! this to forward live mesh events into the frontend.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use interprocess::local_socket::{
    tokio::prelude::*, GenericFilePath, GenericNamespaced, ListenerOptions,
};
use myownmesh_core::{MeshConfig, MeshHandle, NetworkConfig, TopologyMode};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::registry::{NetworkRegistry, RemoveResult};

/// Default control socket name (Unix abstract or Windows named-pipe
/// segment). Overridable via `config.daemon.control_socket`.
#[allow(dead_code)]
pub fn default_socket_name() -> String {
    "myownmesh.sock".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Status,
    NetworksList,
    PeersList {
        network: String,
    },
    RosterList {
        network: String,
    },
    RosterApprove {
        network: String,
        device_id: String,
        label: Option<String>,
    },
    RosterRemove {
        network: String,
        device_id: String,
    },
    TopologySet {
        network: String,
        topology: String,
        hub: Option<String>,
    },
    IdentityShow,
    /// Return the full on-disk `MeshConfig`. Used by the GUI's
    /// import/export flow to surface saved networks (and read-only
    /// fields the registry summary doesn't carry — signaling
    /// relays, STUN/TURN servers, auto-approve).
    ConfigShow,
    /// Add a network: persist to config.json, join via the live
    /// `Mesh` handle, attach signaling, register. Returns the new
    /// network's summary. Fails if either the `id` or `network_id`
    /// already exists in the running daemon.
    NetworkAdd {
        config: NetworkConfig,
    },
    /// Remove a network: take it out of the registry, `leave()` the
    /// engine driver, drop the signaling handle, and persist the
    /// updated config.json. Idempotent — removing an unknown id is
    /// reported as success-with-warning.
    NetworkRemove {
        network: String,
    },
    /// Subscribe to the live event stream. The connection becomes a
    /// one-way server-push channel after this op; the daemon writes
    /// one JSON-encoded `MeshEvent` (or framing wrapper) per line
    /// until the client closes. Used by the GUI to render live peer
    /// state changes without polling.
    EventsSubscribe,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl Response {
    pub fn ok(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            error: None,
            data: Some(data),
        }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            data: None,
        }
    }
}

/// Resolve the platform-appropriate listener name. On Unix this
/// is `~/.myownmesh/daemon.sock`; on Windows it's a named-pipe
/// segment under the local namespace.
fn resolve_socket(custom: Option<PathBuf>) -> Result<SocketTarget> {
    if let Some(path) = custom {
        return Ok(SocketTarget::Path(path));
    }
    #[cfg(unix)]
    {
        let path = myownmesh_core::dirs::data_dir()
            .context("data_dir")?
            .join("daemon.sock");
        Ok(SocketTarget::Path(path))
    }
    #[cfg(not(unix))]
    {
        Ok(SocketTarget::Name(default_socket_name()))
    }
}

#[derive(Debug)]
enum SocketTarget {
    Path(PathBuf),
    #[allow(dead_code)]
    Name(String),
}

/// Start the control socket listener. Returns when the shutdown
/// broadcast fires.
pub async fn serve(
    mesh: MeshHandle,
    registry: Arc<NetworkRegistry>,
    custom: Option<PathBuf>,
    mut shutdown: broadcast::Receiver<()>,
) -> Result<()> {
    let target = resolve_socket(custom)?;
    let listener = bind_listener(&target)?;
    info!(?target, "control socket listening");

    let state = Arc::new(ControlState { mesh, registry });

    loop {
        tokio::select! {
            _ = shutdown.recv() => {
                info!("control socket shutting down");
                break;
            }
            res = listener.accept() => {
                match res {
                    Ok(stream) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, state).await {
                                debug!("control client error: {e:#}");
                            }
                        });
                    }
                    Err(e) => {
                        warn!("accept failed: {e}");
                    }
                }
            }
        }
    }

    Ok(())
}

fn bind_listener(target: &SocketTarget) -> Result<LocalSocketListener> {
    use interprocess::local_socket::Name;
    let name: Name = match target {
        SocketTarget::Path(p) => {
            // Remove stale socket if present so re-binds succeed.
            #[cfg(unix)]
            {
                let _ = std::fs::remove_file(p);
            }
            p.as_path()
                .to_fs_name::<GenericFilePath>()
                .context("control socket path → fs_name")?
        }
        SocketTarget::Name(n) => n
            .clone()
            .to_ns_name::<GenericNamespaced>()
            .context("control socket name → ns_name")?,
    };
    ListenerOptions::new()
        .name(name)
        .create_tokio()
        .context("create_tokio")
}

struct ControlState {
    mesh: MeshHandle,
    registry: Arc<NetworkRegistry>,
}

async fn handle_client(stream: LocalSocketStream, state: Arc<ControlState>) -> Result<()> {
    let (reader, mut writer) = stream.split();
    let reader = BufReader::new(reader);
    let mut lines = reader.lines();
    while let Some(line) = lines.next_line().await? {
        let request: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response::err(format!("parse: {e}"));
                let line = serde_json::to_string(&resp)? + "\n";
                writer.write_all(line.as_bytes()).await?;
                continue;
            }
        };
        // EventsSubscribe converts the connection into a one-way
        // stream. Dispatch directly so we can write multiple lines
        // without going through `Response`, and break out of the
        // request loop when it returns (client disconnected).
        if matches!(request, Request::EventsSubscribe) {
            // Initial ack so the client knows the subscription is
            // live before the first real event arrives.
            let ack = Response::ok(serde_json::json!({ "subscribed": true }));
            let line = serde_json::to_string(&ack)? + "\n";
            writer.write_all(line.as_bytes()).await?;
            run_events_stream(&state, &mut writer).await?;
            break;
        }
        let resp = dispatch(&state, request).await;
        let line = serde_json::to_string(&resp)? + "\n";
        writer.write_all(line.as_bytes()).await?;
    }
    Ok(())
}

async fn dispatch(state: &Arc<ControlState>, req: Request) -> Response {
    match req {
        Request::Status => Response::ok(serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "device_id": state.mesh.identity().display_id(),
            "joined_networks": state.mesh.joined_network_ids(),
        })),
        Request::IdentityShow => Response::ok(serde_json::json!({
            "device_id": state.mesh.identity().display_id(),
            "pubkey": state.mesh.identity().public_id(),
            "label": state.mesh.identity().label(),
        })),
        Request::NetworksList => {
            // Enriched payload: each network includes its phase,
            // topology, and labelling info. The CLI prints whatever
            // it gets; the GUI binds rich fields directly.
            let summaries = state.registry.summaries();
            Response::ok(serde_json::json!({ "networks": summaries }))
        }
        Request::PeersList { network } => match state.registry.get(&network) {
            Some(net) => Response::ok(serde_json::json!({ "peers": net.peers() })),
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::RosterList { network } => match state.registry.get(&network) {
            Some(net) => match net.roster_list().await {
                Ok(list) => Response::ok(serde_json::json!({ "roster": list })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::RosterApprove {
            network,
            device_id,
            label,
        } => match state.registry.get(&network) {
            Some(net) => match net
                .roster_approve(&device_id, label.as_deref().unwrap_or(""))
                .await
            {
                Ok(_) => Response::ok(serde_json::json!({ "approved": device_id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::RosterRemove { network, device_id } => match state.registry.get(&network) {
            Some(net) => match net.roster_remove(&device_id).await {
                Ok(_) => Response::ok(serde_json::json!({ "removed": device_id })),
                Err(e) => Response::err(e.to_string()),
            },
            None => Response::err(format!("unknown network: {network}")),
        },
        Request::TopologySet {
            network,
            topology,
            hub,
        } => {
            let mode = match parse_topology(&topology, hub.as_deref()) {
                Ok(m) => m,
                Err(msg) => return Response::err(msg),
            };
            match state.registry.get(&network) {
                Some(net) => match net.set_topology(mode).await {
                    Ok(_) => Response::ok(serde_json::json!({ "topology": topology })),
                    Err(e) => Response::err(e.to_string()),
                },
                None => Response::err(format!("unknown network: {network}")),
            }
        }
        Request::ConfigShow => match MeshConfig::load() {
            Ok(cfg) => Response::ok(serde_json::json!({ "config": cfg })),
            Err(e) => Response::err(e.to_string()),
        },
        Request::NetworkAdd { config } => network_add(state, config).await,
        Request::NetworkRemove { network } => network_remove(state, &network).await,
        Request::EventsSubscribe => {
            // Handled by `handle_client` before reaching dispatch.
            // If we somehow get here, surface the bug.
            Response::err("events_subscribe must be handled upstream")
        }
    }
}

/// Join a fresh network through the live mesh, attach signaling,
/// register the result, and persist the new config to disk. Each
/// step that mutates daemon-visible state is reversible up to the
/// last point we touch the on-disk config — config.json is updated
/// after the join + attach succeeds so a failed join leaves the
/// saved config untouched.
async fn network_add(state: &Arc<ControlState>, config: NetworkConfig) -> Response {
    // Reject duplicates against the running registry. We rely on
    // the registry's two-key indexing — checking both the local
    // config id and the wire-level network id covers the user
    // trying to add the same network twice (under any alias).
    if state.registry.contains(&config.id) {
        return Response::err(format!("config id '{}' already in use", config.id));
    }
    if state.registry.contains(&config.network_id) {
        return Response::err(format!(
            "network id '{}' already joined under a different config",
            config.network_id
        ));
    }

    // Join the live mesh first — if the engine refuses (bad
    // network id, etc.) we want to know before we touch disk.
    let joined = match state.mesh.join(config.clone()).await {
        Ok(j) => j,
        Err(e) => return Response::err(format!("join: {e}")),
    };

    // Take a summary BEFORE handing ownership to the registry so we
    // can return it in the response payload without re-locking.
    let summary = serde_json::json!({
        "config_id": joined.config_id(),
        "network_id": joined.network_id(),
        "phase": joined.current_phase(),
        "topology": joined.current_topology(),
    });

    // Attach the production signaling driver. A `None` here means
    // the bridge declined (e.g. signaling disabled in config); the
    // network still works for in-process drivers attached by tests.
    let nostr = {
        let net_state = joined.state();
        myownmesh_core::engine::attach_nostr(&net_state)
    };
    if nostr.is_none() {
        warn!(network = %config.network_id, "nostr attach returned no handle");
    }
    state.registry.insert(joined, nostr);

    // Persist to disk. We re-load the config rather than rely on
    // the in-memory copy from startup so concurrent edits (a user
    // hand-editing config.json) survive — we append to whatever's
    // on disk now. Best-effort: if save fails, the network is live
    // but won't re-join on next daemon restart. Surface the disk
    // error to the caller so the GUI can show it.
    if let Err(e) = persist_network_add(&config) {
        return Response::err(format!("network joined but config.json save failed: {e}"));
    }

    Response::ok(serde_json::json!({ "added": summary }))
}

/// Leave a live network and remove it from the on-disk config. The
/// remove call returns ownership of the `JoinedNetwork`; we run its
/// `leave()` to flush the engine driver cleanly. The signaling
/// driver dropped inside `registry.remove` tears down its own
/// tasks.
async fn network_remove(state: &Arc<ControlState>, key: &str) -> Response {
    let key_owned = key.to_string();
    match state.registry.remove(key) {
        RemoveResult::Removed(joined) => {
            let config_id = joined.config_id().to_string();
            let network_id = joined.network_id().to_string();
            if let Err(e) = joined.leave().await {
                warn!("leave({key_owned}) returned error: {e:#}");
            }
            if let Err(e) = persist_network_remove(&config_id, &network_id) {
                return Response::err(format!("network left but config.json save failed: {e}"));
            }
            Response::ok(serde_json::json!({ "removed": config_id }))
        }
        RemoveResult::StillBorrowed => {
            // Engine driver will exit on command-channel drop; we
            // still need to update disk so a restart doesn't
            // re-join. We don't know the network_id since we
            // couldn't unwrap; persist by the key we were given
            // and let the persist helper handle either alias.
            if let Err(e) = persist_network_remove(&key_owned, &key_owned) {
                return Response::err(format!("network removed but config.json save failed: {e}"));
            }
            Response::ok(
                serde_json::json!({ "removed": key_owned, "warning": "engine teardown deferred — request was in flight" }),
            )
        }
        RemoveResult::NotFound => Response::err(format!("unknown network: {key_owned}")),
    }
}

fn persist_network_add(net: &NetworkConfig) -> Result<()> {
    let mut cfg = MeshConfig::load().map_err(anyhow::Error::msg)?;
    // Append only if not already present — covers the case where
    // the user edited config.json by hand between daemon start and
    // this add, and added the same network there too.
    if !cfg
        .networks
        .iter()
        .any(|n| n.id == net.id || n.network_id == net.network_id)
    {
        cfg.networks.push(net.clone());
    }
    cfg.save().map_err(anyhow::Error::msg)?;
    Ok(())
}

fn persist_network_remove(config_id: &str, network_id: &str) -> Result<()> {
    let mut cfg = MeshConfig::load().map_err(anyhow::Error::msg)?;
    let before = cfg.networks.len();
    cfg.networks
        .retain(|n| n.id != config_id && n.network_id != network_id);
    if cfg.networks.len() != before {
        cfg.save().map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

fn parse_topology(name: &str, hub: Option<&str>) -> std::result::Result<TopologyMode, String> {
    match name {
        "ring" => Ok(TopologyMode::Ring { n_preferred: None }),
        "star" => {
            let hub = hub.ok_or_else(|| "star topology requires --hub <device_id>".to_string())?;
            Ok(TopologyMode::Star {
                hub: hub.to_string(),
            })
        }
        "full_mesh" | "fullmesh" => Ok(TopologyMode::FullMesh),
        other => Err(format!(
            "unknown topology '{other}' — expected ring | star | full_mesh"
        )),
    }
}

/// Stream mesh events to one connected subscriber. Returns when the
/// underlying writer breaks (client disconnected) or the engine's
/// broadcast channel closes (daemon shutting down).
async fn run_events_stream<W>(state: &Arc<ControlState>, writer: &mut W) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut rx = state.mesh.events();
    loop {
        match rx.recv().await {
            Ok(event) => {
                // Each event is framed with kind=event so the
                // subscriber can multiplex against other server
                // pushes in the future. The `event` field carries
                // the original `MeshEvent` JSON (peer / phase /
                // diag, internally tagged).
                let line = serde_json::to_string(&serde_json::json!({
                    "kind": "event",
                    "event": event,
                }))? + "\n";
                if writer.write_all(line.as_bytes()).await.is_err() {
                    return Ok(()); // client gone
                }
                if writer.flush().await.is_err() {
                    return Ok(());
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                // Slow subscriber; surface the gap so the GUI can
                // resync via a peers_list snapshot.
                let line = serde_json::to_string(&serde_json::json!({
                    "kind": "lagged",
                    "skipped": n,
                }))? + "\n";
                if writer.write_all(line.as_bytes()).await.is_err() {
                    return Ok(());
                }
            }
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}

/// Single shared `MeshHandle` storage for the ctl client. Mostly a
/// future-proofing hook so a follow-up can attach per-network
/// state without changing the protocol.
#[allow(dead_code)]
static CTL_STATE: Mutex<Option<Arc<ControlState>>> = parking_lot::const_mutex(None);
