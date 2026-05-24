//! Client half of the daemon's control protocol — see
//! `MyOwnMesh/crates/myownmesh/src/control.rs` for the
//! request/response shapes. Wire format is line-delimited JSON over a
//! local socket (unix-domain socket on Unix, named pipe on Windows).
//!
//! Two access shapes:
//!
//! - [`ControlClient::request`]: short-lived round trip. Opens a
//!   socket, writes one request, reads one response, closes. Used by
//!   every Tauri command except the event stream.
//!
//! - [`ControlClient::subscribe_events`]: long-lived stream. Opens a
//!   socket, writes `EventsSubscribe`, then keeps reading JSON lines
//!   and forwarding them to the caller's channel until the daemon
//!   disconnects.
//!
//! We intentionally don't pool connections — each round trip is cheap
//! against a local socket, and pooling makes the failure semantics
//! (daemon restart mid-session) harder for an embedder to reason
//! about.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use interprocess::local_socket::tokio::prelude::*;
#[cfg(unix)]
use interprocess::local_socket::GenericFilePath;
#[cfg(not(unix))]
use interprocess::local_socket::GenericNamespaced;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

/// Mirror of `myownmesh::control::Request`. Kept in sync by hand —
/// adding a variant here without the daemon side, or vice versa,
/// surfaces as a JSON parse error on the receiving end (the daemon's
/// dispatch returns `Response::err("parse: …")`).
#[derive(Debug, Serialize)]
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
    IdentitySetLabel {
        label: String,
    },
    NetworkIdGenerate,
    NetworkIdNormalize {
        input: String,
    },
    ConfigShow,
    NetworkAdd {
        config: serde_json::Value,
    },
    NetworkRemove {
        network: String,
    },
    EventsSubscribe,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Response {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

/// Where the daemon's control socket lives. Unix uses a filesystem
/// path under `~/.myownmesh/`; Windows uses a namespaced pipe segment
/// in the local namespace. Mirrors `myownmesh::control::SocketTarget`
/// so error messages and connect logic line up with the daemon side.
#[derive(Debug, Clone)]
enum SocketAddr {
    Path(PathBuf),
    #[allow(dead_code)] // Only constructed on Windows.
    Name(String),
}

impl fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocketAddr::Path(p) => write!(f, "{}", p.display()),
            SocketAddr::Name(n) => write!(f, "named pipe {n}"),
        }
    }
}

pub struct ControlClient {
    addr: SocketAddr,
}

impl ControlClient {
    /// Build a client bound to the default daemon socket location.
    /// Mirrors `myownmesh::control::resolve_socket`: a unix-domain
    /// socket file under `~/.myownmesh/` on Unix, a namespaced pipe
    /// `myownmesh.sock` on Windows. We recompute the address locally
    /// rather than depending on myownmesh-core so the GUI's build
    /// stays independent of the engine workspace.
    pub fn new() -> Result<Self> {
        #[cfg(unix)]
        {
            let home = dirs::home_dir().context("no home dir")?;
            let socket_path = home.join(".myownmesh").join("daemon.sock");
            Ok(Self {
                addr: SocketAddr::Path(socket_path),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                addr: SocketAddr::Name("myownmesh.sock".to_string()),
            })
        }
    }

    /// One-shot request → response. The daemon writes exactly one
    /// JSON line in reply, then keeps the connection open for
    /// further requests; we close after the first response since
    /// pooling isn't worth the complexity.
    pub async fn request(&self, req: &Request) -> Result<Response> {
        let stream = self.connect().await?;
        let (reader, mut writer) = stream.split();
        let mut reader = BufReader::new(reader);

        let line = serde_json::to_string(req)? + "\n";
        writer
            .write_all(line.as_bytes())
            .await
            .context("write request")?;
        writer.flush().await.context("flush request")?;

        let mut buf = String::new();
        let n = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut buf))
            .await
            .context("daemon response timed out")??;
        if n == 0 {
            bail!("daemon closed connection without a response");
        }
        let resp: Response =
            serde_json::from_str(buf.trim()).with_context(|| format!("parse response: {buf}"))?;
        Ok(resp)
    }

    /// Subscribe to the daemon's event stream. Spawns a task that
    /// forwards each incoming line to `tx`. Returns immediately
    /// after the initial ack so the caller can wire `rx` into a
    /// Tauri event emitter.
    pub async fn subscribe_events(&self, tx: mpsc::Sender<serde_json::Value>) -> Result<()> {
        let stream = self.connect().await?;
        let (reader, mut writer) = stream.split();
        let mut reader = BufReader::new(reader);

        let line = serde_json::to_string(&Request::EventsSubscribe)? + "\n";
        writer
            .write_all(line.as_bytes())
            .await
            .context("write subscribe")?;
        writer.flush().await.context("flush subscribe")?;

        // Read the initial ack — Response { ok: true, data: { subscribed: true } }.
        let mut ack = String::new();
        let n = reader.read_line(&mut ack).await.context("read ack")?;
        if n == 0 {
            bail!("daemon closed connection before sending subscribe ack");
        }
        let parsed: Response =
            serde_json::from_str(ack.trim()).with_context(|| format!("parse ack: {ack}"))?;
        if !parsed.ok {
            return Err(anyhow!(
                "subscribe rejected: {}",
                parsed.error.unwrap_or_else(|| "(no error)".into())
            ));
        }

        // Spawn the forwarding loop. The writer goes with the stream
        // — its lifetime is tied to `reader` via the `split`. We
        // keep it on the stack here to keep the connection open.
        tokio::spawn(async move {
            // Keep `writer` alive for the duration of the read loop;
            // dropping it closes the half-duplex on the server side
            // (the daemon then exits its write loop too).
            let _writer_keepalive = writer;
            let mut buf = String::new();
            loop {
                buf.clear();
                match reader.read_line(&mut buf).await {
                    Ok(0) => break, // daemon disconnected
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!("event stream read failed: {e}");
                        break;
                    }
                }
                let value: serde_json::Value = match serde_json::from_str(buf.trim()) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("malformed event line: {e} — {buf}");
                        continue;
                    }
                };
                if tx.send(value).await.is_err() {
                    break; // GUI side dropped the channel
                }
            }
        });

        Ok(())
    }

    async fn connect(&self) -> Result<LocalSocketStream> {
        let name = match &self.addr {
            SocketAddr::Path(p) => {
                #[cfg(unix)]
                {
                    p.as_path()
                        .to_fs_name::<GenericFilePath>()
                        .context("socket path → fs_name")?
                }
                #[cfg(not(unix))]
                {
                    let _ = p; // Path variant never constructed on non-Unix.
                    unreachable!("SocketAddr::Path on non-Unix")
                }
            }
            SocketAddr::Name(n) => {
                #[cfg(not(unix))]
                {
                    n.as_str()
                        .to_ns_name::<GenericNamespaced>()
                        .context("socket name → ns_name")?
                }
                #[cfg(unix)]
                {
                    let _ = n; // Name variant never constructed on Unix.
                    unreachable!("SocketAddr::Name on Unix")
                }
            }
        };
        LocalSocketStream::connect(name).await.context(format!(
            "connect daemon socket at {} — is `myownmesh serve` running?",
            self.addr
        ))
    }
}
