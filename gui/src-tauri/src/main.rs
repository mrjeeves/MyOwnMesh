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
mod daemon_spawn;

use std::sync::Arc;

use control_client::{ControlClient, Request, Response};
use parking_lot::Mutex;
use tauri::{AppHandle, Emitter, Manager, RunEvent, State};
use tokio::sync::mpsc;

/// Shared state that every Tauri command pulls from. One
/// ControlClient lives for the app's lifetime; each request opens
/// its own short-lived socket (no pooling — see `control_client.rs`).
///
/// `daemon_child` holds the spawned `myownmesh serve` process (if
/// the GUI launched one); it's optional because the user may have
/// already had a daemon running, in which case we use that instead
/// of spawning a duplicate. Dropping the wrapped value at app exit
/// kills the child via its `Drop` impl.
///
/// `last_subscription_status` mirrors the most recent
/// `mesh://subscription` payload. The Tauri event system is
/// fire-and-forget — emits before the frontend's `listen()` is
/// registered are silently dropped. The Svelte client queries this
/// cache via `mesh_subscription_state` right after registering its
/// listener so it picks up the current state even if the "live"
/// event fired before it was ready. Initialised to `connecting` so
/// a query before the first emit returns the same value the UI is
/// already showing.
struct AppState {
    client: Arc<ControlClient>,
    daemon_child: Mutex<Option<daemon_spawn::DaemonChild>>,
    last_subscription_status: Mutex<serde_json::Value>,
}

/// Cache `value` and emit it as a `mesh://subscription` event. All
/// updates to the subscription state must go through here so the
/// `mesh_subscription_state` command always returns the most recent
/// payload regardless of listener timing.
fn update_subscription_status(handle: &AppHandle, value: serde_json::Value) {
    let state = handle.state::<AppState>();
    *state.last_subscription_status.lock() = value.clone();
    let _ = handle.emit("mesh://subscription", value);
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
async fn mesh_identity_set_label(
    state: State<'_, AppState>,
    label: String,
) -> Result<serde_json::Value, String> {
    let resp = state
        .client
        .request(&Request::IdentitySetLabel { label })
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

#[tauri::command]
async fn mesh_network_id_generate(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let resp = state
        .client
        .request(&Request::NetworkIdGenerate)
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_network_id_normalize(
    state: State<'_, AppState>,
    input: String,
) -> Result<serde_json::Value, String> {
    let resp = state
        .client
        .request(&Request::NetworkIdNormalize { input })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_config_show(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let resp = state
        .client
        .request(&Request::ConfigShow)
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_network_add(
    state: State<'_, AppState>,
    config: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let resp = state
        .client
        .request(&Request::NetworkAdd { config })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_network_remove(
    state: State<'_, AppState>,
    network: String,
) -> Result<serde_json::Value, String> {
    let resp = state
        .client
        .request(&Request::NetworkRemove { network })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

/// Write a `NetworkSettingsExport` envelope to disk. Pretty-printed
/// so the file is easy to inspect by hand. Import goes through a
/// native `<input type="file">` on the renderer side (matches the
/// MyOwnLLM pattern), so there's no symmetric `mesh_network_import_file`.
#[tauri::command]
async fn mesh_network_export_file(path: String, config: serde_json::Value) -> Result<(), String> {
    let body = serde_json::to_string_pretty(&config).map_err(|e| format!("serialise: {e}"))?;
    std::fs::write(&path, body).map_err(|e| format!("write {path}: {e}"))?;
    Ok(())
}

/// Return the most recent `mesh://subscription` payload. The Svelte
/// client calls this on init — right after registering the
/// `mesh://subscription` listener — so it picks up the current state
/// even if the backend's "live" emit fired before the listener was
/// registered (Tauri events are fire-and-forget and aren't replayed).
#[tauri::command]
fn mesh_subscription_state(state: State<'_, AppState>) -> serde_json::Value {
    state.last_subscription_status.lock().clone()
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
                update_subscription_status(&app, serde_json::json!({ "status": "live" }));
                while let Some(value) = rx.recv().await {
                    let _ = app.emit("mesh://event", value);
                }
                // Subscription channel closed — daemon disconnected.
                update_subscription_status(&app, serde_json::json!({ "status": "disconnected" }));
            }
            Err(e) => {
                tracing::warn!("event subscribe failed: {e} — will retry");
                update_subscription_status(
                    &app,
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

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            client: client.clone(),
            daemon_child: Mutex::new(None),
            last_subscription_status: Mutex::new(serde_json::json!({ "status": "connecting" })),
        })
        .invoke_handler(tauri::generate_handler![
            mesh_status,
            mesh_identity,
            mesh_identity_set_label,
            mesh_networks,
            mesh_peers,
            mesh_roster_list,
            mesh_roster_approve,
            mesh_roster_remove,
            mesh_topology_set,
            mesh_network_id_generate,
            mesh_network_id_normalize,
            mesh_config_show,
            mesh_network_add,
            mesh_network_remove,
            mesh_network_export_file,
            mesh_subscription_state,
        ])
        .setup(move |app| {
            let handle = app.handle().clone();
            let client = client.clone();
            // Auto-spawn the daemon before the event pump starts —
            // a fresh daemon needs a moment to bind the socket, and
            // running the pump before then just produces spurious
            // "subscribe failed" warnings. Once `ensure_daemon_running`
            // returns we know the listener is up (or we've timed out
            // waiting, in which case the pump's retry loop takes
            // over).
            tauri::async_runtime::spawn(async move {
                match daemon_spawn::ensure_daemon_running(&client).await {
                    Ok(child) => {
                        if let Some(child) = child {
                            let state = handle.state::<AppState>();
                            *state.daemon_child.lock() = Some(child);
                        }
                    }
                    Err(e) => {
                        tracing::error!("daemon auto-spawn failed: {e:#}");
                        update_subscription_status(
                            &handle,
                            serde_json::json!({
                                "status": "disconnected",
                                "error": format!("daemon auto-spawn failed: {e}"),
                            }),
                        );
                    }
                }
                run_event_pump(handle, client).await;
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building MyOwnMesh GUI")
        .run(|app, event| {
            // RunEvent::Exit fires after the last window closes (or
            // after we explicitly call `app.exit()`). Drop the
            // managed daemon child here so it's killed deterministically
            // — relying on `DaemonChild::Drop` alone wasn't enough
            // in practice: Tauri's process tear-down on Windows
            // can short-circuit destructors on managed state, which
            // left the spawned `myownmesh serve` orphaned every
            // time the user closed the GUI. Pull it out explicitly
            // so its Drop impl runs before we return from this
            // closure (and the OS reaps us).
            if let RunEvent::Exit = event {
                // Pull `take()` out of the `if let` scrutinee — under
                // Rust 2021 if-let temporary-scope rules the
                // `MutexGuard` lives until the end of the enclosing
                // block, which means past `state` going out of scope,
                // and the borrow checker rejects that. As a regular
                // `let` statement the guard drops at the `;`, leaving
                // a plain `Option<DaemonChild>` for the match.
                let state = app.state::<AppState>();
                let child = state.daemon_child.lock().take();
                if let Some(c) = child {
                    drop(c);
                }
            }
        });
}
