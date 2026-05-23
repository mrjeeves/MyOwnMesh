//! `myownmesh serve` — run the daemon in the foreground until SIGINT
//! or SIGTERM. The daemon owns:
//!
//! - One [`myownmesh_core::Mesh`] (once the engine lands)
//! - The updater tick loop (per [`myownmesh_updater::tick_forever`])
//! - The control-socket listener that `myownmesh ctl …` clients talk to
//!
//! Skeleton today; the actual mesh start happens once the engine is
//! filled in.

use anyhow::{Context, Result};
use myownmesh_core::MeshConfig;
use tracing::info;

pub async fn run() -> Result<()> {
    let cfg = MeshConfig::load().context("load config")?;
    info!(
        version = env!("CARGO_PKG_VERSION"),
        identity_path = ?cfg.identity_path,
        "daemon starting"
    );

    // Identity load (also generates on first run).
    let identity = myownmesh_core::identity::load_or_create().context("identity load")?;
    info!(device_id = %identity.display_id(), "identity ready");

    // Updater tick. Spawned even when disabled in config — the
    // task just exits early; cheaper than building conditional
    // task graphs.
    let _updater = tokio::spawn(myownmesh_updater::tick_forever());

    // TODO(engine): start the mesh engine here once
    // `myownmesh_core::handle::Mesh::open` exists. For now the
    // daemon just sits on the signal handler so the process is
    // observable and `myownmesh ctl status` returns "stopped".

    tokio::signal::ctrl_c().await.context("await SIGINT")?;
    info!("shutdown requested");
    Ok(())
}
