//! `myownmesh config …` — config-file helpers.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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
                myownmesh_core::MeshConfig::transaction_at(&path, |_| Ok(()))
                    .context("write default config")?;
            }
            let baseline = std::fs::read(&path).context("read config before edit")?;
            let snapshot = edit_snapshot_path(&path)?;
            let mut snapshot_file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&snapshot)
                .with_context(|| format!("create edit snapshot {}", snapshot.display()))?;
            snapshot_file
                .write_all(&baseline)
                .with_context(|| format!("write edit snapshot {}", snapshot.display()))?;
            snapshot_file
                .flush()
                .with_context(|| format!("flush edit snapshot {}", snapshot.display()))?;
            drop(snapshot_file);
            let editor = std::env::var("EDITOR")
                .or_else(|_| std::env::var("VISUAL"))
                .unwrap_or_else(|_| {
                    if cfg!(windows) {
                        "notepad".to_string()
                    } else {
                        "vi".to_string()
                    }
                });
            let editor_status = Command::new(&editor)
                .arg(&snapshot)
                .status()
                .with_context(|| format!("spawn editor '{editor}'"));
            match editor_status {
                Ok(status) if status.success() => {}
                Ok(_) => {
                    let _ = std::fs::remove_file(&snapshot);
                    anyhow::bail!("editor exited with non-zero status");
                }
                Err(error) => {
                    let _ = std::fs::remove_file(&snapshot);
                    return Err(error);
                }
            }
            let edited = std::fs::read(&snapshot)
                .with_context(|| format!("read edit snapshot {}", snapshot.display()));
            let _ = std::fs::remove_file(&snapshot);
            let edited = edited?;
            let edited: myownmesh_core::MeshConfig =
                serde_json::from_slice(&edited).context("parse edited config")?;
            publish_edited_snapshot(&path, &baseline, edited)?;
        }
    }
    Ok(())
}

fn edit_snapshot_path(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("config path has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("config path has no file name"))?
        .to_string_lossy();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    Ok(parent.join(format!(".{name}.edit-{}-{stamp}.json", std::process::id())))
}

fn publish_edited_snapshot(
    path: &Path,
    baseline: &[u8],
    edited: myownmesh_core::MeshConfig,
) -> Result<()> {
    myownmesh_core::MeshConfig::transaction_at(path, |current| {
        let current_bytes = std::fs::read(path).map_err(|error| {
            myownmesh_core::Error::Config(format!("read {}: {error}", path.display()))
        })?;
        if current_bytes != baseline {
            return Err(myownmesh_core::Error::Config(format!(
                "config changed while editing: {}",
                path.display()
            )));
        }
        *current = edited;
        Ok(())
    })
    .context("publish edited config")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config_path() -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "myownmesh-cli-config-edit-{}-{stamp}.json",
            std::process::id()
        ))
    }

    fn remove_test_config(path: &Path) {
        let _ = std::fs::remove_file(path);
        let mut lock_name = path
            .file_name()
            .expect("test config has a file name")
            .to_os_string();
        lock_name.push(".lock");
        let _ = std::fs::remove_file(path.with_file_name(lock_name));
    }

    #[test]
    fn edit_publish_refuses_concurrent_writer_without_overwrite() {
        let path = test_config_path();
        myownmesh_core::MeshConfig::transaction_at(&path, |_| Ok(())).unwrap();
        let baseline = std::fs::read(&path).unwrap();

        myownmesh_core::MeshConfig::transaction_at(&path, |config| {
            config.services.turn.enabled = true;
            Ok(())
        })
        .unwrap();

        let mut edited = myownmesh_core::MeshConfig::default();
        edited.services.signaling.enabled = true;
        let error = publish_edited_snapshot(&path, &baseline, edited).unwrap_err();
        assert!(error.to_string().contains("publish edited config"));

        let current =
            myownmesh_core::MeshConfig::transaction_at(&path, |config| Ok(config.clone())).unwrap();
        assert!(current.services.turn.enabled);
        assert!(!current.services.signaling.enabled);
        remove_test_config(&path);
    }
}
