//! `myownmesh ctl …` — talk to a running daemon over its control
//! socket. v1 here ships the argv shape; the IPC implementation
//! lands with the daemon's control-socket listener.

use anyhow::{bail, Result};
use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum CtlCmd {
    /// Print one-line daemon status.
    Status,
    /// Networks: list / join / leave / topology.
    #[command(subcommand)]
    Networks(NetworksCmd),
    /// Per-peer info from the daemon.
    Peers,
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
        /// `ring`, `star`, or `fullmesh`.
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

pub async fn run(_cmd: CtlCmd) -> Result<()> {
    bail!("ctl is not implemented yet — control socket lands with the engine");
}
