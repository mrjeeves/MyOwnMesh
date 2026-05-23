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

pub struct ControlClient {
    socket_path: PathBuf,
}

impl ControlClient {
    /// Build a client bound to the default daemon socket location.
    /// Mirrors `myownmesh_core::dirs::data_dir().join("daemon.sock")`
    /// — we recompute it locally rather than depending on
    /// myownmesh-core so the GUI's build stays independent of the
    /// engine workspace.
    pub fn new() -> Result<Self> {
        let home = dirs::home_dir().context("no home dir")?;
        let socket_path = home.join(".myownmesh").join("daemon.sock");
        Ok(Self { socket_path })
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
        let resp: Response = serde_json::from_str(buf.trim())
            .with_context(|| format!("parse response: {buf}"))?;
        Ok(resp)
    }

    /// Subscribe to the daemon's event stream. Spawns a task that
    /// forwards each incoming line to `tx`. Returns immediately
    /// after the initial ack so the caller can wire `rx` into a
    /// Tauri event emitter.
    pub async fn subscribe_events(
        &self,
        tx: mpsc::Sender<serde_json::Value>,
    ) -> Result<()> {
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
        #[cfg(unix)]
        let name = self
            .socket_path
            .as_path()
            .to_fs_name::<GenericFilePath>()
            .context("socket path → fs_name")?;
        #[cfg(not(unix))]
        let name = "myownmesh.sock"
            .to_ns_name::<GenericNamespaced>()
            .context("default → ns_name")?;
        LocalSocketStream::connect(name).await.context(format!(
            "connect daemon socket at {} — is `myownmesh serve` running?",
            self.socket_path.display()
        ))
    }
}
