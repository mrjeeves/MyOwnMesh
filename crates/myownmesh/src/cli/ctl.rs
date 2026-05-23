//! `myownmesh ctl …` — talk to a running daemon over its control
//! socket. Wire format is line-delimited JSON; see
//! [`crate::control`] for the request/response shapes.

use anyhow::{anyhow, bail, Context, Result};
use clap::Subcommand;
use interprocess::local_socket::tokio::prelude::*;
#[cfg(unix)]
use interprocess::local_socket::GenericFilePath;
#[cfg(not(unix))]
use interprocess::local_socket::GenericNamespaced;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::control::{Request, Response};

#[derive(Subcommand, Debug)]
pub enum CtlCmd {
    /// Print daemon status.
    Status,
    /// Networks: list / join / leave / topology.
    #[command(subcommand)]
    Networks(NetworksCmd),
    /// Per-peer info from the daemon.
    Peers {
        /// Network id to list peers from.
        network: String,
    },
    /// Roster ops on a saved network.
    #[command(subcommand)]
    Roster(RosterCmd),
}

#[derive(Subcommand, Debug)]
pub enum NetworksCmd {
    List,
    Join {
        network_id: String,
    },
    Leave {
        network_id: String,
    },
    Topology {
        network_id: String,
        /// `ring`, `star`, or `full_mesh`.
        topology: String,
        #[arg(long)]
        hub: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum RosterCmd {
    List {
        network: String,
    },
    Approve {
        network: String,
        device_id: String,
        #[arg(long)]
        label: Option<String>,
    },
    Remove {
        network: String,
        device_id: String,
    },
}

pub async fn run(cmd: CtlCmd) -> Result<()> {
    let request = match cmd {
        CtlCmd::Status => Request::Status,
        CtlCmd::Networks(NetworksCmd::List) => Request::NetworksList,
        CtlCmd::Networks(NetworksCmd::Join { network_id }) => {
            bail!(
                "join via ctl is not wired in v1 — edit config.json then restart, or call `myownmesh config edit` (target: {network_id})"
            );
        }
        CtlCmd::Networks(NetworksCmd::Leave { network_id }) => {
            bail!(
                "leave via ctl is not wired in v1 — edit config.json then restart (target: {network_id})"
            );
        }
        CtlCmd::Networks(NetworksCmd::Topology {
            network_id,
            topology,
            hub,
        }) => Request::TopologySet {
            network: network_id,
            topology,
            hub,
        },
        CtlCmd::Peers { network } => Request::PeersList { network },
        CtlCmd::Roster(RosterCmd::List { network }) => Request::RosterList { network },
        CtlCmd::Roster(RosterCmd::Approve {
            network,
            device_id,
            label,
        }) => Request::RosterApprove {
            network,
            device_id,
            label,
        },
        CtlCmd::Roster(RosterCmd::Remove { network, device_id }) => {
            Request::RosterRemove { network, device_id }
        }
    };
    let response = roundtrip(&request).await?;
    if !response.ok {
        let msg = response
            .error
            .unwrap_or_else(|| "(no error message)".into());
        bail!("daemon error: {msg}");
    }
    let body = response.data.unwrap_or(Value::Null);
    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
}

async fn roundtrip(request: &Request) -> Result<Response> {
    let stream = connect_socket().await?;
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);

    let line = serde_json::to_string(request)? + "\n";
    writer
        .write_all(line.as_bytes())
        .await
        .context("write request")?;
    writer.flush().await.context("flush")?;

    let mut buf = String::new();
    let n = reader.read_line(&mut buf).await.context("read response")?;
    if n == 0 {
        return Err(anyhow!("daemon closed connection without a response"));
    }
    let resp: Response =
        serde_json::from_str(buf.trim()).with_context(|| format!("parse response: {buf}"))?;
    Ok(resp)
}

async fn connect_socket() -> Result<LocalSocketStream> {
    let path = myownmesh_core::dirs::data_dir()
        .context("data_dir")?
        .join("daemon.sock");
    #[cfg(unix)]
    let name = path
        .as_path()
        .to_fs_name::<GenericFilePath>()
        .context("path → fs_name")?;
    #[cfg(not(unix))]
    let name = "myownmesh.sock"
        .to_ns_name::<GenericNamespaced>()
        .context("default → ns_name")?;
    let _ = path;
    LocalSocketStream::connect(name)
        .await
        .context("connect daemon socket — is `myownmesh serve` running?")
}
