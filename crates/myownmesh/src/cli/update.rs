//! `myownmesh update …` — self-update operations.
//!
//! The daemon stages verified updates in the background (see
//! `myownmesh-updater`); these subcommands drive that surface by hand:
//! force a check, apply what's staged, inspect status, or toggle the
//! background checks.

use anyhow::Result;
use clap::Subcommand;

use myownmesh_updater::{CheckOutcome, UpdateStatus};

#[derive(Subcommand, Debug)]
pub enum UpdateCmd {
    /// Check the release feed now and stage any permitted update.
    Check {
        /// Emit the outcome as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Apply a staged update (swaps the binary on disk; takes effect on
    /// the next daemon start).
    Apply,
    /// Show updater status: version, channel, policy, last check, staged.
    Status {
        /// Emit the status as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Enable automatic background update checks.
    Enable,
    /// Disable automatic background update checks.
    Disable,
}

pub async fn run(cmd: UpdateCmd) -> Result<()> {
    match cmd {
        UpdateCmd::Check { json } => {
            let outcome = myownmesh_updater::check_now(true).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&outcome)?);
            } else {
                render_outcome(&outcome);
            }
        }
        UpdateCmd::Apply => match myownmesh_updater::apply_now()? {
            Some(version) => {
                println!("Applied {version}. Restart the daemon to run the new binary.");
            }
            None => println!("No staged update to apply."),
        },
        UpdateCmd::Status { json } => {
            let status = myownmesh_updater::status()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                print_status(&status);
            }
        }
        UpdateCmd::Enable => {
            myownmesh_updater::set_enabled(true)?;
            println!("auto_update.enabled = true (background checks on).");
        }
        UpdateCmd::Disable => {
            myownmesh_updater::set_enabled(false)?;
            println!("auto_update.enabled = false (background checks off).");
            println!("Re-enable with `myownmesh update enable`.");
        }
    }
    Ok(())
}

fn render_outcome(outcome: &CheckOutcome) {
    match outcome {
        CheckOutcome::Disabled => {
            println!(
                "Self-update is disabled (auto_update.enabled=false or MYOWNMESH_AUTOUPDATE=0)."
            );
        }
        CheckOutcome::PackageManager => {
            println!(
                "Package-manager install detected; self-update is deferred to the system updater."
            );
        }
        CheckOutcome::NotDue => {
            // Only the background ticker produces this; `update check`
            // forces, so it won't normally be seen.
            println!("Not due for a check yet.");
        }
        CheckOutcome::UpToDate { current, latest } => {
            if current == latest {
                println!("Already on the latest version ({current}).");
            } else {
                println!("Already up to date — on {current} (latest published: {latest}).");
            }
        }
        CheckOutcome::PolicyBlocked {
            current,
            latest,
            policy,
        } => {
            println!(
                "{latest} is available (current {current}), but auto_apply='{policy}' does not \
                 permit this jump."
            );
            println!(
                "Set auto_apply=\"all\" in ~/.myownmesh/config.json, or run `myownmesh update apply` \
                 after staging to take it anyway."
            );
        }
        CheckOutcome::Staged { version } => {
            println!(
                "Staged {version}. Run `myownmesh update apply` (or restart the daemon) to switch."
            );
        }
    }
}

fn print_status(s: &UpdateStatus) {
    println!("Version    : {}", s.current_version);
    println!(
        "Install    : {}",
        match s.install_kind {
            myownmesh_updater::InstallKind::Raw => "raw (self-update eligible)",
            myownmesh_updater::InstallKind::PackageManager =>
                "package-manager (self-update deferred)",
        }
    );
    println!("Auto-update: {}", if s.enabled { "on" } else { "off" });
    println!("Channel    : {}", s.channel);
    println!("Apply      : {}", s.auto_apply);
    println!("Interval   : every {}h", s.check_interval_hours);
    println!(
        "Last check : {}",
        match s.last_check_at {
            Some(t) => format!("{t} (unix)"),
            None => "never".to_string(),
        }
    );
    println!(
        "Staged     : {}",
        s.staged_version.as_deref().unwrap_or("none")
    );
    println!("Feed       : {}", s.release_url);
}
