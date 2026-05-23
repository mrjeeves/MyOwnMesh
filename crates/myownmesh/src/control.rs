//! Daemon control protocol — line-delimited JSON over a local
//! interprocess socket (unix-domain socket on Unix, named pipe on
//! Windows). `myownmesh ctl …` clients talk to the running
//! daemon via this socket.
//!
//! Wire shape: one JSON object per line. Requests have `op` plus
//! op-specific fields; responses have `ok` (bool) plus
//! op-specific payload, or `error: string` on failure.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use interprocess::local_socket::{
    tokio::prelude::*, GenericFilePath, GenericNamespaced, ListenerOptions,
};
use myownmesh_core::MeshHandle;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

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
    custom: Option<PathBuf>,
    mut shutdown: broadcast::Receiver<()>,
) -> Result<()> {
    let target = resolve_socket(custom)?;
    let listener = bind_listener(&target)?;
    info!(?target, "control socket listening");

    let state = Arc::new(ControlState { mesh });

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
        Request::NetworksList => Response::ok(serde_json::json!({
            "networks": state.mesh.joined_network_ids(),
        })),
        Request::PeersList { network } => {
            // For v1 we don't keep per-network MeshHandles addressable
            // from here — the ctl client gets the network id list,
            // and per-network peer detail is a follow-up. Returning
            // a structured "not yet wired" is more useful than
            // silently empty.
            Response::err(format!(
                "peers list for network '{network}' not wired in v1 — coming with the JoinedNetwork registry"
            ))
        }
        Request::RosterList { network } => {
            Response::err(format!("roster list ({network}) not wired in v1"))
        }
        Request::RosterApprove {
            network,
            device_id,
            label,
        } => {
            let _ = (network, device_id, label);
            Response::err("roster approve not wired in v1")
        }
        Request::RosterRemove { network, device_id } => {
            let _ = (network, device_id);
            Response::err("roster remove not wired in v1")
        }
        Request::TopologySet {
            network,
            topology,
            hub,
        } => {
            let _ = (network, topology, hub);
            Response::err("topology set not wired in v1")
        }
    }
}

/// Single shared `MeshHandle` storage for the ctl client. Mostly a
/// future-proofing hook so a follow-up can attach per-network
/// state without changing the protocol.
#[allow(dead_code)]
static CTL_STATE: Mutex<Option<Arc<ControlState>>> = parking_lot::const_mutex(None);
