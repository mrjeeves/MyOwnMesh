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
use myownmesh_core::{NetworkConfig, ServicesConfig};
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
    /// Stream live connection-state transitions for a network as
    /// JSONL — one record per line, each carrying the full liveness
    /// snapshot (status, tier, ICE/PC state, selected-pair class,
    /// rtt). Runs until interrupted; redirect to a file to capture a
    /// session for `scripts/merge-traces.py`:
    ///
    ///   myownmesh ctl trace home > trace-$(hostname).jsonl
    Trace {
        /// Network id to trace.
        network: String,
    },
    /// Roster ops on a saved network.
    #[command(subcommand)]
    Roster(RosterCmd),
    /// Host infrastructure services for the mesh: relay / signaling /
    /// STUN / TURN.
    #[command(subcommand)]
    Services(ServicesCmd),
    /// Closed-network governance: state, proposals, signing, and the
    /// per-device custody MFA that guards owner/kind changes.
    #[command(subcommand)]
    Governance(GovernanceCmd),
}

#[derive(Subcommand, Debug)]
pub enum GovernanceCmd {
    /// Show governance state (kind, roles, transition log, pending).
    State { network: String },
    /// Propose a kind change. `to` is `open` or `closed`.
    ProposeKind {
        network: String,
        to: String,
        /// Custody second factor, if this device enrolled one (`mfa enroll`).
        #[arg(long)]
        mfa_code: Option<String>,
    },
    /// Propose granting `target` a role: `member` | `controller` | `owner`.
    GrantRole {
        network: String,
        target: String,
        role: String,
        #[arg(long)]
        mfa_code: Option<String>,
    },
    /// Propose revoking `target`'s role (back to member).
    RevokeRole {
        network: String,
        target: String,
        #[arg(long)]
        mfa_code: Option<String>,
    },
    /// Sign a pending proposal.
    Sign {
        network: String,
        proposal_id: String,
        #[arg(long)]
        mfa_code: Option<String>,
    },
    /// Deny a pending proposal (single-shot kill switch).
    Deny {
        network: String,
        proposal_id: String,
    },
    /// Withdraw a proposal this device floated.
    Withdraw {
        network: String,
        proposal_id: String,
    },
    /// Per-device custody MFA (TOTP) that gates governance authoring.
    #[command(subcommand)]
    Mfa(MfaCmd),
}

#[derive(Subcommand, Debug)]
pub enum MfaCmd {
    /// Enroll a TOTP authenticator for a network on this device. Prints the
    /// secret, an `otpauth://` URI (for a QR), and one-time recovery codes.
    Enroll { network: String },
    /// Report whether this device holds a custody lock for a network.
    Status { network: String },
    /// Remove the custody lock (requires a valid current code).
    Disable { network: String, code: String },
}

#[derive(Subcommand, Debug)]
pub enum ServicesCmd {
    /// Show which services this device hosts and their listen addresses.
    Status,
    /// Turn a service on: node | relay | signaling | stun | turn.
    /// `node` is mesh participation itself (off = pure-infrastructure
    /// box). TURN also needs credentials + a public IP — set those in
    /// config.json (or the GUI) first; an enabled-but-unconfigured TURN
    /// shows as not running.
    Enable {
        /// node | relay | signaling | stun | turn
        service: String,
    },
    /// Turn a service off: node | relay | signaling | stun | turn.
    Disable {
        /// node | relay | signaling | stun | turn
        service: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum NetworksCmd {
    List,
    /// Join a network by id: persists it to config.json with the
    /// default signaling / STUN / TURN setup and attaches it on the
    /// live daemon. For a custom setup, edit config.json or use the GUI.
    Join {
        network_id: String,
    },
    /// Leave a network: detaches it on the live daemon and removes it
    /// from config.json. Accepts the network id or local config id.
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
        // Services toggles are a read-modify-write against the live
        // config, so they take a dedicated path rather than one request.
        CtlCmd::Services(services_cmd) => return run_services(services_cmd).await,
        // Trace is a long-lived server-push stream, not a single
        // request/response, so it takes a dedicated streaming path.
        CtlCmd::Trace { network } => return run_trace(network).await,
        CtlCmd::Status => Request::Status,
        CtlCmd::Networks(NetworksCmd::List) => Request::NetworksList,
        CtlCmd::Networks(NetworksCmd::Join { network_id }) => {
            // Normalise client-side so the stored id matches what the
            // engine and `ctl networks list` use, and so an invalid id
            // fails with a clear message before we touch the daemon.
            let network_id = myownmesh_core::identity::normalize_network_id(&network_id)
                .with_context(|| format!("invalid network id '{network_id}'"))?;
            Request::NetworkAdd {
                config: NetworkConfig::from_network_id(network_id.clone(), network_id),
            }
        }
        CtlCmd::Networks(NetworksCmd::Leave { network_id }) => Request::NetworkRemove {
            network: network_id,
        },
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
        CtlCmd::Governance(GovernanceCmd::State { network }) => {
            Request::GovernanceState { network }
        }
        CtlCmd::Governance(GovernanceCmd::ProposeKind {
            network,
            to,
            mfa_code,
        }) => Request::GovernanceProposeKindChange {
            network,
            to: parse_kind(&to)?,
            mfa_code,
        },
        CtlCmd::Governance(GovernanceCmd::GrantRole {
            network,
            target,
            role,
            mfa_code,
        }) => Request::GovernanceProposeRoleGrant {
            network,
            target,
            role: parse_role(&role)?,
            mfa_code,
        },
        CtlCmd::Governance(GovernanceCmd::RevokeRole {
            network,
            target,
            mfa_code,
        }) => Request::GovernanceProposeRoleRevoke {
            network,
            target,
            mfa_code,
        },
        CtlCmd::Governance(GovernanceCmd::Sign {
            network,
            proposal_id,
            mfa_code,
        }) => Request::GovernanceSign {
            network,
            proposal_id,
            mfa_code,
        },
        CtlCmd::Governance(GovernanceCmd::Deny {
            network,
            proposal_id,
        }) => Request::GovernanceDeny {
            network,
            proposal_id,
        },
        CtlCmd::Governance(GovernanceCmd::Withdraw {
            network,
            proposal_id,
        }) => Request::GovernanceWithdraw {
            network,
            proposal_id,
        },
        CtlCmd::Governance(GovernanceCmd::Mfa(MfaCmd::Enroll { network })) => {
            Request::GovernanceMfaEnroll { network }
        }
        CtlCmd::Governance(GovernanceCmd::Mfa(MfaCmd::Status { network })) => {
            Request::GovernanceMfaStatus { network }
        }
        CtlCmd::Governance(GovernanceCmd::Mfa(MfaCmd::Disable { network, code })) => {
            Request::GovernanceMfaDisable { network, code }
        }
    };
    let response = roundtrip(&request).await?;
    print_response(response)
}

/// Parse a CLI network-kind argument.
fn parse_kind(s: &str) -> Result<myownmesh_core::NetworkKind> {
    match s.to_ascii_lowercase().as_str() {
        "open" => Ok(myownmesh_core::NetworkKind::Open),
        "closed" => Ok(myownmesh_core::NetworkKind::Closed),
        other => bail!("invalid kind '{other}' — expected open | closed"),
    }
}

/// Parse a CLI role argument.
fn parse_role(s: &str) -> Result<myownmesh_core::Role> {
    match s.to_ascii_lowercase().as_str() {
        "member" => Ok(myownmesh_core::Role::Member),
        "controller" => Ok(myownmesh_core::Role::Controller),
        "owner" => Ok(myownmesh_core::Role::Owner),
        other => bail!("invalid role '{other}' — expected member | controller | owner"),
    }
}

/// Pretty-print a daemon response's data payload, or bail on error.
fn print_response(response: Response) -> Result<()> {
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

/// Run a `services` subcommand. `status` is a plain request; `enable` /
/// `disable` are a read-modify-write: fetch the current services config,
/// flip the one service's `enabled` flag, and send it back.
async fn run_services(cmd: ServicesCmd) -> Result<()> {
    match cmd {
        ServicesCmd::Status => {
            let response = roundtrip(&Request::ServicesStatus).await?;
            print_response(response)
        }
        ServicesCmd::Enable { service } => set_service(&service, true).await,
        ServicesCmd::Disable { service } => set_service(&service, false).await,
    }
}

/// Open a connection-state trace stream and print each `ConnTrace`
/// record verbatim, one JSON object per line, until interrupted
/// (Ctrl-C) or the daemon shuts down. Output is clean JSONL by design
/// — pipe it straight into a file per machine and feed the files to
/// `scripts/merge-traces.py` to reconstruct a single cross-machine
/// timeline. See `docs/DEBUGGING-CONNECTIONS.md`.
async fn run_trace(network: String) -> Result<()> {
    let stream = connect_socket().await?;
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);

    let line = serde_json::to_string(&Request::TraceSubscribe { network })? + "\n";
    writer
        .write_all(line.as_bytes())
        .await
        .context("write trace request")?;
    writer.flush().await.context("flush")?;

    // First line back is the subscribe ack (or an error for an unknown
    // network); everything after is the trace stream.
    let mut buf = String::new();
    let n = reader.read_line(&mut buf).await.context("read ack")?;
    if n == 0 {
        return Err(anyhow!("daemon closed connection without an ack"));
    }
    let ack: Response =
        serde_json::from_str(buf.trim()).with_context(|| format!("parse ack: {buf}"))?;
    if !ack.ok {
        bail!(
            "daemon error: {}",
            ack.error.unwrap_or_else(|| "(no error message)".into())
        );
    }

    use std::io::Write as _;
    let mut stdout = std::io::stdout();
    loop {
        buf.clear();
        let n = reader
            .read_line(&mut buf)
            .await
            .context("read trace line")?;
        if n == 0 {
            break; // daemon closed the stream
        }
        // `buf` already includes the trailing newline — print verbatim
        // so the output is byte-for-byte the daemon's JSONL.
        print!("{buf}");
        let _ = stdout.flush();
    }
    Ok(())
}

async fn set_service(service: &str, enabled: bool) -> Result<()> {
    let status = roundtrip(&Request::ServicesStatus).await?;
    if !status.ok {
        bail!(
            "daemon error: {}",
            status.error.unwrap_or_else(|| "(no error message)".into())
        );
    }
    let data = status.data.unwrap_or(Value::Null);
    let config_val = data
        .get("config")
        .cloned()
        .ok_or_else(|| anyhow!("daemon status missing services config"))?;
    let mut services: ServicesConfig =
        serde_json::from_value(config_val).context("parse current services config")?;
    match service {
        "node" => services.node.enabled = enabled,
        "relay" => services.relay.enabled = enabled,
        "signaling" => services.signaling.enabled = enabled,
        "stun" => services.stun.enabled = enabled,
        "turn" => services.turn.enabled = enabled,
        other => {
            bail!("unknown service '{other}' — expected node | relay | signaling | stun | turn")
        }
    }
    // Capture the TURN port plan before `services` is moved, so we can
    // print the firewall checklist after a successful enable.
    let turn_help = if enabled && service == "turn" {
        Some((
            services.turn.port,
            services.turn.relay_port_min,
            services.turn.relay_port_max,
            services.turn.public_ip.clone(),
        ))
    } else {
        None
    };
    let response = roundtrip(&Request::ServicesSet { services }).await?;
    let ok = response.ok;
    print_response(response)?;
    if ok {
        if let Some((port, relay_min, relay_max, public_ip)) = turn_help {
            print_turn_firewall_help(port, relay_min, relay_max, &public_ip);
        }
    }
    Ok(())
}

/// Spell out the UDP ports a freshly-enabled TURN server needs reachable.
/// The #1 reason a self-hosted TURN "doesn't work" is that only the
/// control port (or nothing) is open — every relayed allocation flows
/// through a separate port in the relay range, and a cloud security group
/// blocks them even when the host firewall is off.
fn print_turn_firewall_help(port: u16, relay_min: u16, relay_max: u16, public_ip: &str) {
    println!();
    println!("TURN is on. For NAT'd peers to actually relay, these UDP ports must be");
    println!("reachable — at the host firewall AND your cloud/provider security group");
    println!("(a host firewall being inactive does NOT mean the provider lets them in):");
    println!("  • udp {port}  — STUN/TURN control");
    if relay_min == 0 {
        // Unbounded (default): relay sockets come from the OS ephemeral
        // range — open that whole range.
        println!("  • udp <OS ephemeral range>  — relay allocations (one port per active peer)");
        println!("    find your range:  sysctl net.ipv4.ip_local_port_range   (e.g. 32768 60999)");
        println!("ufw, if that's what you run (substitute your range):");
        println!("  sudo ufw allow {port}/udp");
        println!("  sudo ufw allow 32768:60999/udp");
        println!("(Want a smaller firewall rule? Pin services.turn.relay_port_min/max.)");
    } else {
        println!("  • udp {relay_min}:{relay_max}  — relay allocations (one port per active peer)");
        println!("ufw, if that's what you run:");
        println!("  sudo ufw allow {port}/udp");
        println!("  sudo ufw allow {relay_min}:{relay_max}/udp");
    }
    if public_ip.trim().is_empty() {
        println!(
            "Set services.turn.public_ip to this box's routable IP, too — TURN won't \
             start without it on a wildcard bind."
        );
    }
    println!("And point your stun./turn. DNS records at this box.");
}

/// Put the signaling relay behind a reverse proxy: enable it and bind it
/// to loopback so the only public door is the TLS one Caddy owns (no
/// plaintext `ws://host:4848` straight to the relay). Applied live via
/// the daemon — `ServicesSet` rebinds the listener without a restart.
/// Returns `Ok(true)` when applied, `Ok(false)` when the daemon isn't
/// reachable (the caller persists to config.json and asks for a restart
/// instead). Used by `myownmesh install caddy <domain>`.
pub(crate) async fn bind_signaling_loopback() -> Result<bool> {
    let status = match roundtrip(&Request::ServicesStatus).await {
        Ok(s) => s,
        Err(_) => return Ok(false), // daemon not running
    };
    if !status.ok {
        return Ok(false);
    }
    let Some(config_val) = status.data.unwrap_or(Value::Null).get("config").cloned() else {
        return Ok(false);
    };
    let mut services: ServicesConfig =
        serde_json::from_value(config_val).context("parse current services config")?;
    services.signaling.enabled = true;
    services.signaling.bind = "127.0.0.1".to_string();
    let response = roundtrip(&Request::ServicesSet { services }).await?;
    Ok(response.ok)
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
