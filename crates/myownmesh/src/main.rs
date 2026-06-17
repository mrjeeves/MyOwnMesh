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
    /// Install helpers — currently the Caddy reverse proxy that fronts
    /// the signaling relay with TLS so peers can connect over wss://.
    Install {
        #[command(subcommand)]
        action: cli::caddy::InstallCmd,
    },
    /// Caddy reverse-proxy helpers (e.g. `caddy path` prints the
    /// Caddyfile location to edit).
    Caddy {
        #[command(subcommand)]
        action: cli::caddy::CaddyCmd,
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
    // (`peer ACTIVE`, `ICE failed — renegotiating`, relay
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
        "stun=error,",
        // TURN client socket binds emit a `bind() failed: Network is
        // unreachable` warning per candidate while the interface is down
        // (a macOS wake drops the network for a second or two). The engine
        // now holds ICE restarts off while offline so this is rare, but the
        // `turn` target wasn't pinned to error like its `stun` sibling —
        // pin it so any residual gather-during-outage stays quiet.
        "turn=error,",
        "webrtc_turn=error",
    );
    let log_level = match std::env::var("MYOWNMESH_LOG") {
        // Full override — power users get complete control of the filter.
        Ok(full) => full,
        Err(_) => {
            // Default filter (keeps the webrtc-rs sibling crates pinned to
            // ERROR so their per-candidate flood stays out of the log).
            // `MYOWNMESH_LOG_EXTRA` appends to it, so `just serve-trace`
            // and friends can bump *our* crates to debug WITHOUT re-listing
            // the whole default — and crucially without dropping the
            // webrtc quieting (the cause of the firehose when a recipe set
            // a bare `MYOWNMESH_LOG`). Later directives win on conflict, so
            // an extra `myownmesh_core=debug` overrides the default's
            // `myownmesh_core=info`.
            let mut filter = default_filter.to_string();
            if let Ok(extra) = std::env::var("MYOWNMESH_LOG_EXTRA") {
                let extra = extra.trim();
                if !extra.is_empty() {
                    filter.push(',');
                    filter.push_str(extra);
                }
            }
            filter
        }
    };
    // `MYOWNMESH_LOG_FORMAT=json` switches the daemon to line-delimited
    // JSON logs — one object per event, with the structured fields
    // (peer, ice, pc, tier, changed, …) the connection tracer emits
    // under the `conn_trace` target as first-class keys. That makes a
    // daemon log directly machine-parseable for cross-machine timeline
    // correlation (pair it with `ctl trace` for the pure ConnTrace
    // stream). Default stays the human-readable formatter.
    let json_logs = std::env::var("MYOWNMESH_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    if json_logs {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(tracing_subscriber::EnvFilter::new(log_level))
            .with_target(false)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(log_level))
            .with_target(false)
            .init();
    }

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
            Command::Install { action } => cli::caddy::run_install(action).await,
            Command::Caddy { action } => cli::caddy::run_caddy(action).await,
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
