//! `myownmesh update …` — self-update operations.

use anyhow::Result;
use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum UpdateCmd {
    /// Hit the release feed now and stage anything new.
    Check,
    /// Apply a previously-staged update (restarts the process).
    Apply,
    /// Print updater status.
    Status,
}

pub async fn run(cmd: UpdateCmd) -> Result<()> {
    match cmd {
        UpdateCmd::Check => {
            let status = myownmesh_updater::force_check().await?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        UpdateCmd::Apply => {
            // The actual apply happens at process start via
            // apply_pending_if_any(); this just nudges the user to
            // restart. A future change can signal the daemon to
            // exit gracefully and let a supervisor re-exec.
            println!("staged updates are applied on next start; restart the daemon");
        }
        UpdateCmd::Status => {
            // Lightweight placeholder until updater::status() exists.
            println!("current_version: {}", env!("CARGO_PKG_VERSION"));
        }
    }
    Ok(())
}
