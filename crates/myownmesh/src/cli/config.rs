//! `myownmesh config …` — config-file helpers.

use std::process::Command;

use anyhow::{Context, Result};
use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
    /// Print the config path. Useful for chaining with $EDITOR.
    Path,
    /// Print the parsed config (with defaults filled in) as JSON.
    Show,
    /// Open the config file in $EDITOR. Falls back to $VISUAL,
    /// then `vi` / `notepad` on Windows.
    Edit,
}

pub async fn run(cmd: ConfigCmd) -> Result<()> {
    let path = myownmesh_core::dirs::config_path().context("resolve config path")?;
    match cmd {
        ConfigCmd::Path => println!("{}", path.display()),
        ConfigCmd::Show => {
            let cfg = myownmesh_core::MeshConfig::load().context("load config")?;
            println!("{}", serde_json::to_string_pretty(&cfg)?);
        }
        ConfigCmd::Edit => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            if !path.exists() {
                let cfg = myownmesh_core::MeshConfig::default();
                cfg.save().context("write default config")?;
            }
            let editor = std::env::var("EDITOR")
                .or_else(|_| std::env::var("VISUAL"))
                .unwrap_or_else(|_| {
                    if cfg!(windows) {
                        "notepad".to_string()
                    } else {
                        "vi".to_string()
                    }
                });
            let status = Command::new(&editor)
                .arg(&path)
                .status()
                .with_context(|| format!("spawn editor '{editor}'"))?;
            if !status.success() {
                anyhow::bail!("editor exited with non-zero status");
            }
        }
    }
    Ok(())
}
