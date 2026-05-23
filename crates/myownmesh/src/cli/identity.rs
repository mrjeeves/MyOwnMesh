//! `myownmesh identity …` — inspect and edit the local device
//! identity. Lives in the bin (not the lib) so the library doesn't
//! depend on `clap` or any specific CLI shape.

use anyhow::{Context, Result};
use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum IdentityCmd {
    /// Print this device's Device ID (pubkey + display suffix).
    Show,
    /// Set the device label surfaced to peers.
    SetLabel { label: String },
}

pub async fn run(cmd: IdentityCmd) -> Result<()> {
    match cmd {
        IdentityCmd::Show => {
            let id = myownmesh_core::identity::load_or_create().context("identity load")?;
            println!("device_id:   {}", id.display_id());
            println!("pubkey:      {}", id.public_id());
            println!("label:       {}", id.label());
        }
        IdentityCmd::SetLabel { label } => {
            myownmesh_core::identity::set_label(&label).context("set label")?;
            println!("ok");
        }
    }
    Ok(())
}
