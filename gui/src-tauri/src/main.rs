//! MyOwnMesh GUI — Tauri shell.
//!
//! The GUI is a *client* of the headless daemon: it never embeds
//! `myownmesh-core` itself. Every operation surface bridges through
//! the daemon's local control socket (line-delimited JSON; see
//! `MyOwnMesh/crates/myownmesh/src/control.rs`). That keeps the GUI
//! build independent of the engine workspace and matches how the
//! existing `myownmesh ctl …` CLI talks to the daemon.
//!
//! Two surface kinds:
//!
//! 1. **Tauri commands** wrap one-shot control requests. The Svelte
//!    side calls `invoke("mesh_peers", { network })` and gets the
//!    daemon's response back as JSON.
//!
//! 2. **A background subscriber task** opens a long-lived event
//!    stream against the daemon, then re-emits each event as a
//!    Tauri event named `mesh://event`. The Svelte side listens on
//!    that and updates its reactive state.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod control_client;

use std::sync::Arc;

use control_client::{ControlClient, Request, Response};
use tauri::{AppHandle, Emitter, State};
use tokio::sync::mpsc;

/// Shared state that every Tauri command pulls from. One
/// ControlClient lives for the app's lifetime; each request opens
/// its own short-lived socket (no pooling — see `control_client.rs`).
struct AppState {
    client: Arc<ControlClient>,
}

/// Helper: turn a daemon `Response` into a result the JS side can
/// handle. Tauri serialises the Ok branch as the JSON payload and
/// the Err branch as a string the frontend can show in a toast.
fn unwrap_response(resp: Response) -> Result<serde_json::Value, String> {
    if !resp.ok {
        return Err(resp.error.unwrap_or_else(|| "(no error message)".into()));
    }
    Ok(resp.data.unwrap_or(serde_json::Value::Null))
}

#[tauri::command]
async fn mesh_status(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let resp = state
        .client
        .request(&Request::Status)
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_identity(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let resp = state
        .client
        .request(&Request::IdentityShow)
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_networks(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let resp = state
        .client
        .request(&Request::NetworksList)
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_peers(
    state: State<'_, AppState>,
    network: String,
) -> Result<serde_json::Value, String> {
    let resp = state
        .client
        .request(&Request::PeersList { network })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_roster_list(
    state: State<'_, AppState>,
    network: String,
) -> Result<serde_json::Value, String> {
    let resp = state
        .client
        .request(&Request::RosterList { network })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_roster_approve(
    state: State<'_, AppState>,
    network: String,
    device_id: String,
    label: Option<String>,
) -> Result<serde_json::Value, String> {
    let resp = state
        .client
        .request(&Request::RosterApprove {
            network,
            device_id,
            label,
        })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_roster_remove(
    state: State<'_, AppState>,
    network: String,
    device_id: String,
) -> Result<serde_json::Value, String> {
    let resp = state
        .client
        .request(&Request::RosterRemove { network, device_id })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_topology_set(
    state: State<'_, AppState>,
    network: String,
    topology: String,
    hub: Option<String>,
) -> Result<serde_json::Value, String> {
    let resp = state
        .client
        .request(&Request::TopologySet {
            network,
            topology,
            hub,
        })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

/// Background task that owns the daemon's event subscription. Each
/// incoming line becomes a `mesh://event` Tauri event on the frontend.
/// On disconnect we wait a beat and re-subscribe — the daemon may be
/// restarting or the user may have just started it after launching
/// the GUI.
async fn run_event_pump(app: AppHandle, client: Arc<ControlClient>) {
    loop {
        let (tx, mut rx) = mpsc::channel::<serde_json::Value>(256);
        match client.subscribe_events(tx).await {
            Ok(()) => {
                let _ = app.emit(
                    "mesh://subscription",
                    serde_json::json!({ "status": "live" }),
                );
                while let Some(value) = rx.recv().await {
                    let _ = app.emit("mesh://event", value);
                }
                // Subscription channel closed — daemon disconnected.
                let _ = app.emit(
                    "mesh://subscription",
                    serde_json::json!({ "status": "disconnected" }),
                );
            }
            Err(e) => {
                tracing::warn!("event subscribe failed: {e} — will retry");
                let _ = app.emit(
                    "mesh://subscription",
                    serde_json::json!({ "status": "disconnected", "error": e.to_string() }),
                );
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

fn main() {
    let log_level = std::env::var("MYOWNMESH_GUI_LOG")
        .unwrap_or_else(|_| "info,myownmesh_gui=info".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(log_level))
        .with_target(false)
        .init();

    let client = Arc::new(ControlClient::new().expect("resolve control socket path"));
    let state = AppState {
        client: client.clone(),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            mesh_status,
            mesh_identity,
            mesh_networks,
            mesh_peers,
            mesh_roster_list,
            mesh_roster_approve,
            mesh_roster_remove,
            mesh_topology_set,
        ])
        .setup(move |app| {
            let handle = app.handle().clone();
            let client = client.clone();
            tauri::async_runtime::spawn(async move {
                run_event_pump(handle, client).await;
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running MyOwnMesh GUI");
}
