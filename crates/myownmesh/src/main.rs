//! MyOwnMesh daemon + CLI entry point.
//!
//! Persona selection happens on the first argv inspection: with no
//! arguments we launch the desktop GUI (`myownmesh-gui`), matching
//! MyOwnLLM where a bare invocation opens the app. `serve` runs the
//! daemon in the foreground — the explicit headless entry point, and
//! what the GUI auto-spawns as its own child. Any other subcommand is
//! `ctl …`-style and addresses the running daemon via the control
//! socket.

use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};

mod cli;
mod control;
mod ipc;
mod registry;
mod services;

#[derive(Parser, Debug)]
#[command(name = "myownmesh", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the mesh daemon in the foreground (headless). The desktop
    /// GUI auto-spawns this; run it yourself on servers and headless
    /// boxes. A bare `myownmesh` (no subcommand) opens the GUI instead.
    Serve,
    /// Show this device's identity.
    Identity {
        #[command(subcommand)]
        action: cli::identity::IdentityCmd,
    },
    /// Talk to a running daemon over the control socket.
    Ctl {
        #[command(subcommand)]
        action: cli::ctl::CtlCmd,
    },
    /// Update MyOwnMesh. A bare `myownmesh update` fetches the latest
    /// release and updates the daemon and the desktop GUI together (like
    /// `myownllm update`); the subcommands drive the pieces by hand.
    Update {
        #[command(subcommand)]
        action: Option<cli::update::UpdateCmd>,
    },
    /// Install/start/stop/uninstall MyOwnMesh as a background OS service
    /// (systemd on Linux, launchd on macOS). Manages the daemon process
    /// lifecycle — distinct from `ctl services`, which toggles the mesh's
    /// own hosted relay/STUN/TURN/signaling roles.
    Service {
        /// Manage the system-wide service (root, starts at boot) instead
        /// of the default per-user service (no root, starts at login).
        #[arg(long, global = true)]
        system: bool,
        #[command(subcommand)]
        action: cli::service::ServiceCmd,
    },
    /// Open the config file in $EDITOR.
    Config {
        #[command(subcommand)]
        action: cli::config::ConfigCmd,
    },
}

fn main() -> ExitCode {
    // Apply any pending self-update FIRST so the swap happens before
    // sockets/file handles bind to the old binary.
    myownmesh_updater::apply_pending_if_any();

    let cli = Cli::parse();

    // Default log filter. We let our own crates speak at INFO and
    // downgrade every webrtc-rs sibling crate to ERROR — they emit
    // floods of WARN/INFO during normal ICE flow (every link-local
    // IPv6 address that won't bind, every `pingAllCandidates`
    // wakeup, every SRTP/SCTP teardown after a flapping connection)
    // that swamp the real signal. The meaningful state transitions
    // (`peer ACTIVE`, `ICE failed — Tier 4 immediately`, relay
    // connect/recovery) all come from our own code, so silencing
    // the sibling crates doesn't hide anything we care about.
    //
    // Power-user override: set `MYOWNMESH_LOG` to anything (e.g.
    // `info,webrtc_ice=debug`) to see the underlying chatter while
    // debugging a connectivity problem.
    let default_filter = concat!(
        "info,",
        "myownmesh=info,",
        "myownmesh_core=info,",
        "myownmesh_signaling=info,",
        "myownmesh_updater=info,",
        "webrtc=error,",
        "webrtc_ice=error,",
        "webrtc_mdns=error,",
        "webrtc_dtls=error,",
        "webrtc_sctp=error,",
        "webrtc_srtp=error,",
        "webrtc_data=error,",
        "webrtc_util=error,",
        "webrtc_media=error,",
        "interceptor=error,",
        "stun=error",
    );
    let log_level = std::env::var("MYOWNMESH_LOG").unwrap_or_else(|_| default_filter.to_string());
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(log_level))
        .with_target(false)
        .init();

    // Bare `myownmesh` (no subcommand) opens the desktop GUI, mirroring
    // MyOwnLLM where a bare invocation launches the app and subcommands
    // stay headless. The GUI launch is a synchronous process hand-off,
    // so we take it before building the tokio runtime the daemon and
    // ctl paths need. `myownmesh serve` remains the explicit daemon
    // entry point (and the GUI's own auto-spawn target).
    let Some(cmd) = cli.command else {
        return cli::gui::launch();
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to build tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    let result: Result<()> = runtime.block_on(async move {
        match cmd {
            Command::Serve => cli::serve::run().await,
            Command::Identity { action } => cli::identity::run(action).await,
            Command::Ctl { action } => cli::ctl::run(action).await,
            Command::Update { action } => cli::update::run(action).await,
            Command::Service { system, action } => cli::service::run(system, action).await,
            Command::Config { action } => cli::config::run(action).await,
        }
    });

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
