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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use control_client::{ControlClient, Request, Response, Role};
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
/// of spawning a duplicate. Exit explicitly consumes and observes the
/// child; `Drop` remains only an emergency fallback for abrupt teardown.
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
    event_pump: Mutex<Option<EventPump>>,
    daemon_lifecycle: Arc<DaemonLifecycle>,
    last_subscription_status: Mutex<serde_json::Value>,
}

struct EventPump {
    cancellation: control_client::EventPumpCancellation,
    join: tokio::task::JoinHandle<()>,
}

impl EventPump {
    fn start(app: AppHandle, client: Arc<ControlClient>) -> Self {
        let cancellation = control_client::EventPumpCancellation::new();
        let join = tokio::spawn(run_event_pump(app, client, cancellation.clone()));
        Self { cancellation, join }
    }

    async fn shutdown(self) {
        self.cancellation.cancel();
        if let Err(error) = self.join.await {
            tracing::error!("GUI event pump did not terminate cleanly: {error:#}");
        }
    }
}

/// Error envelope returned by Tauri commands. Keeping the daemon's response
/// data beside the human-readable error preserves refusal codes and marks a
/// lost post-write response as requiring an authoritative refresh.
#[derive(Debug, serde::Serialize)]
struct CommandError {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

type CommandResult<T> = std::result::Result<T, CommandError>;

impl CommandError {
    fn message(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            data: None,
        }
    }

    fn outcome_unknown(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            data: Some(serde_json::json!({ "outcome": "unknown" })),
        }
    }
}

impl From<control_client::RequestError> for CommandError {
    fn from(error: control_client::RequestError) -> Self {
        match error {
            control_client::RequestError::OutcomeUnknown => Self::outcome_unknown(
                "outcome unknown: the daemon may have committed the request; query state before retrying",
            ),
            control_client::RequestError::Transport(error) => Self::message(error.to_string()),
        }
    }
}

impl From<String> for CommandError {
    fn from(error: String) -> Self {
        if error.starts_with("outcome unknown:") {
            Self::outcome_unknown(error)
        } else {
            Self::message(error)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DaemonLifecyclePhase {
    Starting,
    RunningOwned,
    RunningExternal,
    Closing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StartupOutcome {
    Owned,
    External,
    Failed,
}

struct DaemonStartup {
    done: AtomicBool,
    outcome: Mutex<Option<StartupOutcome>>,
    notify: tokio::sync::Notify,
    completion_lock: std::sync::Mutex<()>,
    completion: std::sync::Condvar,
    #[cfg(test)]
    blocking_wait_started: AtomicBool,
    #[cfg(test)]
    blocking_wait_notify: tokio::sync::Notify,
}

#[cfg(test)]
struct PublicationGate {
    parked: AtomicBool,
    parked_notify: tokio::sync::Notify,
    release: tokio::sync::Notify,
    released: AtomicBool,
}

#[cfg(test)]
impl PublicationGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            parked: AtomicBool::new(false),
            parked_notify: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            released: AtomicBool::new(false),
        })
    }

    async fn wait_until_parked(&self) {
        while !self.parked.load(Ordering::Acquire) {
            let notified = self.parked_notify.notified();
            if self.parked.load(Ordering::Acquire) {
                break;
            }
            notified.await;
        }
    }

    fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.release.notify_waiters();
    }
}

impl DaemonStartup {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            done: AtomicBool::new(false),
            outcome: Mutex::new(None),
            notify: tokio::sync::Notify::new(),
            completion_lock: std::sync::Mutex::new(()),
            completion: std::sync::Condvar::new(),
            #[cfg(test)]
            blocking_wait_started: AtomicBool::new(false),
            #[cfg(test)]
            blocking_wait_notify: tokio::sync::Notify::new(),
        })
    }

    fn complete(&self, outcome: StartupOutcome) {
        *self.outcome.lock() = Some(outcome);
        self.done.store(true, Ordering::Release);
        self.notify.notify_waiters();
        self.completion.notify_all();
    }

    async fn wait(&self) {
        while !self.done.load(Ordering::Acquire) {
            let notified = self.notify.notified();
            if self.done.load(Ordering::Acquire) {
                break;
            }
            notified.await;
        }
    }

    fn wait_blocking(&self) {
        #[cfg(test)]
        {
            self.blocking_wait_started.store(true, Ordering::Release);
            self.blocking_wait_notify.notify_waiters();
        }
        let mut guard = self
            .completion_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !self.done.load(Ordering::Acquire) {
            guard = self
                .completion
                .wait(guard)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    fn outcome(&self) -> Option<StartupOutcome> {
        *self.outcome.lock()
    }

    #[cfg(test)]
    async fn wait_until_blocking_wait_started(&self) {
        while !self.blocking_wait_started.load(Ordering::Acquire) {
            let notified = self.blocking_wait_notify.notified();
            if self.blocking_wait_started.load(Ordering::Acquire) {
                break;
            }
            notified.await;
        }
    }
}

struct DaemonLifecycle {
    phase: Mutex<DaemonLifecyclePhase>,
    startup: Mutex<Option<Arc<DaemonStartup>>>,
    #[cfg(test)]
    publication_gate: Mutex<Option<Arc<PublicationGate>>>,
}

fn finish_exit(
    lifecycle: &DaemonLifecycle,
    child_slot: &Mutex<Option<daemon_spawn::DaemonChild>>,
    event_pump_slot: &Mutex<Option<EventPump>>,
) {
    let startup = lifecycle.begin_closing();
    let event_pump = event_pump_slot.lock().take();
    if let Some(event_pump) = event_pump {
        tauri::async_runtime::block_on(event_pump.shutdown());
    }
    let child = child_slot.lock().take();
    if let Some(child) = child {
        if let Err(error) = tauri::async_runtime::block_on(child.terminate_and_wait()) {
            tracing::error!("GUI-owned daemon did not terminate cleanly during Exit: {error:#}");
        }
    }
    if let Some(startup) = startup {
        startup.wait_blocking();
    }
}

impl DaemonLifecycle {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            phase: Mutex::new(DaemonLifecyclePhase::Starting),
            startup: Mutex::new(None),
            #[cfg(test)]
            publication_gate: Mutex::new(None),
        })
    }

    fn begin_startup(&self) -> Arc<DaemonStartup> {
        let startup = DaemonStartup::new();
        *self.startup.lock() = Some(Arc::clone(&startup));
        startup
    }

    fn begin_closing(&self) -> Option<Arc<DaemonStartup>> {
        *self.phase.lock() = DaemonLifecyclePhase::Closing;
        self.startup.lock().clone()
    }

    fn is_closing(&self) -> bool {
        *self.phase.lock() == DaemonLifecyclePhase::Closing
    }

    async fn publish_owned(
        &self,
        child_slot: &Mutex<Option<daemon_spawn::DaemonChild>>,
        child: daemon_spawn::DaemonChild,
    ) -> Result<(), daemon_spawn::DaemonChild> {
        #[cfg(test)]
        let gate = {
            let guard = self.publication_gate.lock();
            guard.clone()
        };
        #[cfg(test)]
        if let Some(gate) = gate {
            gate.parked.store(true, Ordering::Release);
            gate.parked_notify.notify_waiters();
            if !gate.released.load(Ordering::Acquire) {
                let notified = gate.release.notified();
                if !gate.released.load(Ordering::Acquire) {
                    notified.await;
                }
            }
        }
        let mut phase = self.phase.lock();
        if *phase != DaemonLifecyclePhase::Starting {
            return Err(child);
        }
        *phase = DaemonLifecyclePhase::RunningOwned;
        *child_slot.lock() = Some(child);
        Ok(())
    }

    fn publish_event_pump(
        &self,
        event_pump_slot: &Mutex<Option<EventPump>>,
        event_pump: EventPump,
    ) -> Result<(), EventPump> {
        let phase = self.phase.lock();
        if *phase == DaemonLifecyclePhase::Closing {
            return Err(event_pump);
        }
        *event_pump_slot.lock() = Some(event_pump);
        Ok(())
    }

    #[cfg(test)]
    fn install_publication_gate(&self) -> Arc<PublicationGate> {
        let gate = PublicationGate::new();
        *self.publication_gate.lock() = Some(Arc::clone(&gate));
        gate
    }

    fn publish_external(&self) -> bool {
        let mut phase = self.phase.lock();
        if *phase != DaemonLifecyclePhase::Starting {
            return false;
        }
        *phase = DaemonLifecyclePhase::RunningExternal;
        true
    }
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
/// the Err branch as an envelope retaining daemon refusal data.
fn unwrap_response(resp: Response) -> CommandResult<serde_json::Value> {
    if !resp.ok {
        return Err(CommandError {
            error: resp.error.unwrap_or_else(|| "(no error message)".into()),
            data: resp.data,
        });
    }
    Ok(resp.data.unwrap_or(serde_json::Value::Null))
}

#[tauri::command]
async fn mesh_status(state: State<'_, AppState>) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::Status)
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_identity(state: State<'_, AppState>) -> CommandResult<serde_json::Value> {
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
) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::IdentitySetLabel { label })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_networks(state: State<'_, AppState>) -> CommandResult<serde_json::Value> {
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
) -> CommandResult<serde_json::Value> {
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
) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::RosterList { network })
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
) -> CommandResult<serde_json::Value> {
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
async fn mesh_network_id_generate(state: State<'_, AppState>) -> CommandResult<serde_json::Value> {
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
) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::NetworkIdNormalize { input })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_config_show(state: State<'_, AppState>) -> CommandResult<serde_json::Value> {
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
) -> CommandResult<serde_json::Value> {
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
) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::NetworkRemove {
            network,
            // The GUI's ordinary remove keeps durable governance state. A
            // deliberate purge remains a separate daemon control operation.
            purge: false,
        })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

/// Danger Zone: forget every joined network at once (purges each network's
/// signed state + roster; keeps the device identity). The daemon exits after
/// responding so it reloads clean; the caller follows with `restart_app`.
#[tauri::command]
async fn mesh_forget_all_networks(state: State<'_, AppState>) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::ForgetAllNetworks)
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

/// Danger Zone: factory reset — wipe the entire state directory (identity,
/// config, all networks). The daemon exits so a fresh one mints a new identity;
/// the caller follows with `restart_app`.
#[tauri::command]
async fn mesh_factory_reset(state: State<'_, AppState>) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::FactoryReset)
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

/// Relaunch the whole app. The Danger Zone calls this right after a reset so
/// every layer restarts on the now-clean state — the daemon (which the reset
/// told to exit), the Tauri backend, and the webview — instead of any of them
/// serving a stale in-memory cache that would resurrect what was just wiped.
#[tauri::command]
async fn restart_app(app: AppHandle) -> CommandResult<()> {
    let (startup, child, client) = {
        let state = app.state::<AppState>();
        let startup = state.daemon_lifecycle.begin_closing();
        let child = state.daemon_child.lock().take();
        let client = Arc::clone(&state.client);
        (startup, child, client)
    };
    if let Some(startup) = startup.as_ref() {
        // Claim the same startup completion that setup owns. A late child is
        // either handed to the slot before this fence or reaped by the
        // startup task after it observes Closing.
        startup.wait().await;
    }
    if let Some(child) = child {
        // This is the exact process the GUI spawned. Waiting on its handle
        // observes terminal state without killing or racing a relaunch.
        child
            .wait_for_exit()
            .await
            .map_err(|error| error.to_string())?;
    } else if startup
        .as_ref()
        .and_then(|startup| startup.outcome())
        .is_some_and(|outcome| outcome == StartupOutcome::External)
    {
        // An externally-owned service is never killed by the GUI. Its control
        // listener is the only identity we own, so wait for that old listener
        // to become unavailable before restarting over it.
        daemon_spawn::wait_for_listener_terminal(&client)
            .await
            .map_err(|error| error.to_string())?;
    }
    app.restart();
    #[allow(unreachable_code)]
    Ok(())
}

/// Atomic in-place network edit. The daemon hot-applies label / topology
/// / auto-approve and only restarts transport for signaling/STUN/TURN
/// changes; the roster survives either way.
#[tauri::command]
async fn mesh_network_update(
    state: State<'_, AppState>,
    config: serde_json::Value,
) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::NetworkUpdate { config })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

/// Write a `NetworkSettingsExport` envelope to disk. Pretty-printed
/// so the file is easy to inspect by hand. Import goes through a
/// native `<input type="file">` on the renderer side (matches the
/// MyOwnLLM pattern), so there's no symmetric `mesh_network_import_file`.
#[tauri::command]
async fn mesh_network_export_file(path: String, config: serde_json::Value) -> CommandResult<()> {
    let body = serde_json::to_string_pretty(&config).map_err(|e| format!("serialise: {e}"))?;
    std::fs::write(&path, body).map_err(|e| format!("write {path}: {e}"))?;
    Ok(())
}

// ---- infrastructure services (relay / signaling / STUN / TURN) --------

#[tauri::command]
async fn mesh_services_status(state: State<'_, AppState>) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::ServicesStatus)
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_services_set(
    state: State<'_, AppState>,
    services: serde_json::Value,
) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::ServicesSet { services })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
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

// ---- closed-network governance ----------------------------------------
//
// Thin wrappers around the daemon's governance ops. The GUI calls
// these via `invoke(...)` and gets back the same shape the control
// protocol's `Response` carries — Ok branch is the JSON `data` payload,
// Err branch is the `error` string.

#[tauri::command]
async fn mesh_governance_propose_role_grant(
    state: State<'_, AppState>,
    network: String,
    target: String,
    role: Role,
    mfa_code: Option<String>,
) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::GovernanceProposeRoleGrant {
            network,
            target,
            role,
            mfa_code,
        })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_governance_propose_role_revoke(
    state: State<'_, AppState>,
    network: String,
    target: String,
    mfa_code: Option<String>,
) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::GovernanceProposeRoleRevoke {
            network,
            target,
            mfa_code,
        })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_governance_propose_evict(
    state: State<'_, AppState>,
    network: String,
    target: String,
    mfa_code: Option<String>,
) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::GovernanceProposeEvict {
            network,
            target,
            mfa_code,
        })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_governance_mfa_prepare(
    state: State<'_, AppState>,
    network: String,
) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::GovernanceMfaPrepare { network })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_governance_mfa_query(
    state: State<'_, AppState>,
    network: String,
    transaction_id: String,
) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::GovernanceMfaQuery {
            network,
            transaction_id,
        })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_governance_mfa_redeliver(
    state: State<'_, AppState>,
    network: String,
    transaction_id: String,
) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::GovernanceMfaRedeliver {
            network,
            transaction_id,
        })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_governance_mfa_commit(
    state: State<'_, AppState>,
    network: String,
    transaction_id: String,
) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::GovernanceMfaCommit {
            network,
            transaction_id,
        })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_governance_mfa_abort(
    state: State<'_, AppState>,
    network: String,
    transaction_id: String,
) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::GovernanceMfaAbort {
            network,
            transaction_id,
        })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_governance_mfa_status(
    state: State<'_, AppState>,
    network: String,
) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::GovernanceMfaStatus { network })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn mesh_governance_mfa_disable(
    state: State<'_, AppState>,
    network: String,
    code: String,
) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::GovernanceMfaDisable { network, code })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

// ---- self-update ------------------------------------------------------
//
// Thin pass-throughs to the daemon's updater. The daemon owns the actual
// check / stage / apply (it's the process whose binary gets swapped — the
// GUI is updated in lockstep beside it), so the GUI never touches the
// updater crate directly; it just surfaces status and forwards intent.

#[tauri::command]
async fn update_status(state: State<'_, AppState>) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::UpdateStatus)
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn update_check(state: State<'_, AppState>) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::UpdateCheck)
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn update_apply(state: State<'_, AppState>) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::UpdateApply)
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

#[tauri::command]
async fn update_set_prefs(
    state: State<'_, AppState>,
    prefs: serde_json::Value,
) -> CommandResult<serde_json::Value> {
    let resp = state
        .client
        .request(&Request::UpdateSetPrefs { prefs })
        .await
        .map_err(|e| e.to_string())?;
    unwrap_response(resp)
}

/// Background task that owns the daemon's event subscription. Each
/// incoming line becomes a `mesh://event` Tauri event on the frontend.
/// On disconnect we wait a beat and re-subscribe — the daemon may be
/// restarting or the user may have just started it after launching
/// the GUI.
async fn run_event_pump(
    app: AppHandle,
    client: Arc<ControlClient>,
    cancellation: control_client::EventPumpCancellation,
) {
    loop {
        if cancellation.is_cancelled() {
            break;
        }
        let (tx, mut rx) = mpsc::channel::<serde_json::Value>(256);
        let reader = match tokio::select! {
            biased;
            () = cancellation.cancelled() => break,
            result = client.subscribe_events(tx, cancellation.clone()) => result,
        } {
            Ok(reader) => {
                update_subscription_status(&app, serde_json::json!({ "status": "live" }));
                Some(reader)
            }
            Err(e) => {
                tracing::warn!("event subscribe failed: {e} — will retry");
                update_subscription_status(
                    &app,
                    serde_json::json!({ "status": "disconnected", "error": e.to_string() }),
                );
                None
            }
        };
        let Some(reader) = reader else {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => break,
                () = tokio::time::sleep(std::time::Duration::from_secs(2)) => {},
            }
            continue;
        };
        loop {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => break,
                value = rx.recv() => match value {
                    Some(value) => { let _ = app.emit("mesh://event", value); }
                    None => break,
                },
            }
        }
        if cancellation.is_cancelled() {
            let _ = reader.await;
            break;
        }
        if let Err(error) = reader.await {
            tracing::warn!("event stream task did not terminate cleanly: {error:#}");
        }
        // Subscription channel closed — daemon disconnected.
        update_subscription_status(&app, serde_json::json!({ "status": "disconnected" }));
        tokio::select! {
            biased;
            () = cancellation.cancelled() => break,
            () = tokio::time::sleep(std::time::Duration::from_secs(2)) => {},
        }
    }
}

/// Raspberry Pi (and other aarch64 Linux SBCs) ship GPU drivers — V3D on
/// the Pi — whose GL/EGL path WebKitGTK's accelerated compositor can't
/// drive cleanly. That one root fault surfaces as two very different bugs:
///
///   1. *Garbled rendering.* The compositor hands back scrambled frames —
///      torn scan-lines, or bars of color blocks where the page should be.
///      Disabling just the DMA-BUF renderer (WebKitGTK 2.42+'s zero-copy
///      buffer path) is enough for a mostly-static page, but this GUI's
///      node graph is an animated, pan/zoomed SVG — composited layers that
///      still route through the broken GL compositor and corrupt (the
///      "bars of color blocks" the map rendered as on the Pi).
///
///   2. *The whole desktop wedges.* Worse: spinning up that GL/EGL context
///      collides with the Pi's Wayland compositor and its buffer-sharing
///      model. While our window is open the session locks up — other
///      windows stop taking clicks, menus (even the reboot menu) won't
///      open, and the machine has to be power-cycled. Close the app, or
///      never open it, and the desktop behaves.
///
/// `WEBKIT_DISABLE_COMPOSITING_MODE=1` turns accelerated compositing off
/// entirely, so WebKit paints on the CPU and never creates the GL context
/// that corrupts frames *or* fights the system compositor — it fixes both
/// at once. We also keep `WEBKIT_DISABLE_DMABUF_RENDERER=1` set (moot once
/// compositing is off, but harmless, and it still covers a host that opts
/// accelerated compositing back on).
///
/// Scoped to Linux + aarch64, where the breakage lives; x86_64 desktops
/// keep the fast GPU path. Each var honors a value the user pre-set, so on
/// hardware without the bug the fast path is one override away:
/// `WEBKIT_DISABLE_COMPOSITING_MODE=0 WEBKIT_DISABLE_DMABUF_RENDERER=0 myownmesh`.
/// Kept in sync with MyOwnLLM, which hit the same breakage on Pi.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn workaround_pi_webkit_rendering() {
    for (key, value) in [
        ("WEBKIT_DISABLE_COMPOSITING_MODE", "1"),
        ("WEBKIT_DISABLE_DMABUF_RENDERER", "1"),
    ] {
        if std::env::var_os(key).is_none() {
            std::env::set_var(key, value);
        }
    }
}

fn main() {
    // Must run before WebKitGTK initialises its compositor (i.e. before
    // we build the Tauri window below), so set it first thing.
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    workaround_pi_webkit_rendering();

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
            event_pump: Mutex::new(None),
            daemon_lifecycle: DaemonLifecycle::new(),
            last_subscription_status: Mutex::new(serde_json::json!({ "status": "connecting" })),
        })
        .invoke_handler(tauri::generate_handler![
            mesh_status,
            mesh_identity,
            mesh_identity_set_label,
            mesh_networks,
            mesh_peers,
            mesh_roster_list,
            mesh_topology_set,
            mesh_network_id_generate,
            mesh_network_id_normalize,
            mesh_config_show,
            mesh_network_add,
            mesh_network_remove,
            mesh_network_update,
            mesh_network_export_file,
            mesh_services_status,
            mesh_services_set,
            mesh_subscription_state,
            mesh_governance_propose_role_grant,
            mesh_governance_propose_role_revoke,
            mesh_governance_propose_evict,
            mesh_governance_mfa_prepare,
            mesh_governance_mfa_query,
            mesh_governance_mfa_redeliver,
            mesh_governance_mfa_commit,
            mesh_governance_mfa_abort,
            mesh_governance_mfa_status,
            mesh_governance_mfa_disable,
            update_status,
            update_check,
            update_apply,
            update_set_prefs,
            mesh_forget_all_networks,
            mesh_factory_reset,
            restart_app,
        ])
        .setup(move |app| {
            let handle = app.handle().clone();
            let client = client.clone();
            let lifecycle = {
                let state = handle.state::<AppState>();
                Arc::clone(&state.daemon_lifecycle)
            };
            let startup = lifecycle.begin_startup();
            // Auto-spawn the daemon before the event pump starts —
            // a fresh daemon needs a moment to bind the socket, and
            // running the pump before then just produces spurious
            // "subscribe failed" warnings. Once `ensure_daemon_running`
            // returns we know the listener is up (or we've timed out
            // waiting, in which case the pump's retry loop takes
            // over).
            tauri::async_runtime::spawn(async move {
                let event_pump = EventPump::start(handle.clone(), client.clone());
                let state = handle.state::<AppState>();
                if let Err(event_pump) =
                    lifecycle.publish_event_pump(&state.event_pump, event_pump)
                {
                    event_pump.shutdown().await;
                    startup.complete(StartupOutcome::Failed);
                    return;
                }
                match daemon_spawn::ensure_daemon_running(&client).await {
                    Ok(child) => {
                        if let Some(child) = child {
                            let state = handle.state::<AppState>();
                            match lifecycle
                                .publish_owned(&state.daemon_child, child)
                                .await
                            {
                                Ok(()) => startup.complete(StartupOutcome::Owned),
                                Err(child) => {
                                    tracing::info!(
                                        "daemon startup completed after GUI close; reaping child"
                                    );
                                    if let Err(error) = child.terminate_and_wait().await {
                                        tracing::error!(
                                            "late daemon startup child did not terminate cleanly: {error:#}"
                                        );
                                    }
                                    startup.complete(StartupOutcome::Owned);
                                }
                            }
                        } else {
                            if !lifecycle.publish_external() {
                                startup.complete(StartupOutcome::External);
                                return;
                            }
                            startup.complete(StartupOutcome::External);
                        }
                    }
                    Err(e) => {
                        tracing::error!("daemon auto-spawn failed: {e:#}");
                        startup.complete(StartupOutcome::Failed);
                        if lifecycle.is_closing() {
                            return;
                        }
                        update_subscription_status(
                            &handle,
                            serde_json::json!({
                                "status": "disconnected",
                                "error": format!("daemon auto-spawn failed: {e}"),
                            }),
                        );
                    }
                }
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building MyOwnMesh GUI")
        .run(|app, event| {
            // RunEvent::Exit fires after the last window closes (or
            // after we explicitly call `app.exit()`). The shared
            // helper below consumes and observes the exact owned child
            // before this callback returns.
            // — relying on `DaemonChild::Drop` alone wasn't enough
            if let RunEvent::Exit = event {
                // Pull `take()` out of the `if let` scrutinee — under
                // Rust 2021 if-let temporary-scope rules the
                // `MutexGuard` lives until the end of the enclosing
                // block, which means past `state` going out of scope,
                // and the borrow checker rejects that. As a regular
                // `let` statement the guard drops at the `;`, leaving
                // a plain `Option<DaemonChild>` for the match.
                let state = app.state::<AppState>();
                finish_exit(
                    &state.daemon_lifecycle,
                    &state.daemon_child,
                    &state.event_pump,
                );
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_error_preserves_refusal_data_and_unknown_marker() {
        let refusal = unwrap_response(Response {
            ok: false,
            error: Some("request refused".into()),
            data: Some(serde_json::json!({ "code": "unauthorized_role" })),
        })
        .expect_err("refusal must be an error");
        let encoded = serde_json::to_value(refusal).expect("error serializes");
        assert_eq!(encoded["error"], "request refused");
        assert_eq!(encoded["data"]["code"], "unauthorized_role");

        let unknown = CommandError::from(control_client::RequestError::OutcomeUnknown);
        let encoded = serde_json::to_value(unknown).expect("unknown serializes");
        assert_eq!(encoded["data"]["outcome"], "unknown");
    }

    #[tokio::test]
    async fn closing_fences_late_owned_startup_publication() {
        let lifecycle = DaemonLifecycle::new();
        let startup = lifecycle.begin_startup();
        let child_slot = Mutex::new(None);

        assert!(lifecycle.begin_closing().is_some());
        assert!(!lifecycle.publish_external());
        assert!(lifecycle
            .publish_owned(&child_slot, daemon_spawn::DaemonChild::empty_for_test())
            .await
            .is_err());
        assert!(child_slot.lock().is_none());

        startup.complete(StartupOutcome::Owned);
        assert_eq!(startup.outcome(), Some(StartupOutcome::Owned));
    }

    #[test]
    fn startup_completion_remains_claimable_after_closing() {
        let lifecycle = DaemonLifecycle::new();
        let startup = lifecycle.begin_startup();
        let claimed = lifecycle.begin_closing().expect("startup cell retained");

        startup.complete(StartupOutcome::External);
        assert_eq!(claimed.outcome(), Some(StartupOutcome::External));
    }

    #[tokio::test]
    async fn exit_gate_reaps_late_child_before_slot_can_publish() {
        let lifecycle = DaemonLifecycle::new();
        let startup = lifecycle.begin_startup();
        let gate = lifecycle.install_publication_gate();
        let child_slot = Arc::new(Mutex::new(None));
        let publishing = {
            let lifecycle = Arc::clone(&lifecycle);
            let child_slot = Arc::clone(&child_slot);
            tokio::spawn(async move {
                let result = lifecycle
                    .publish_owned(&child_slot, daemon_spawn::DaemonChild::empty_for_test())
                    .await;
                if let Err(child) = result {
                    child.terminate_and_wait().await.expect("reap late child");
                    startup.complete(StartupOutcome::Owned);
                }
            })
        };

        gate.wait_until_parked().await;
        let claimed = lifecycle.begin_closing().expect("startup retained at Exit");
        gate.release();
        publishing.await.expect("publication task joined");
        claimed.wait().await;
        assert_eq!(claimed.outcome(), Some(StartupOutcome::Owned));
        assert!(child_slot.lock().is_none());
    }

    #[tokio::test]
    async fn exit_helper_waits_for_terminal_child_and_startup_completion() {
        let lifecycle = DaemonLifecycle::new();
        let startup = lifecycle.begin_startup();
        let startup_observer = Arc::clone(&startup);
        let gate = lifecycle.install_publication_gate();
        let witness = daemon_spawn::TerminalObservationWitness::new();
        let child_slot = Arc::new(Mutex::new(Some(
            daemon_spawn::DaemonChild::with_terminal_witness(Arc::clone(&witness)),
        )));
        let publishing = {
            let lifecycle = Arc::clone(&lifecycle);
            let child_slot = Arc::clone(&child_slot);
            tokio::spawn(async move {
                let result = lifecycle
                    .publish_owned(&child_slot, daemon_spawn::DaemonChild::empty_for_test())
                    .await;
                if let Err(child) = result {
                    child.terminate_and_wait().await.expect("reap late child");
                    startup.complete(StartupOutcome::Owned);
                }
            })
        };

        gate.wait_until_parked().await;
        let helper_done = Arc::new(AtomicBool::new(false));
        let helper = {
            let lifecycle = Arc::clone(&lifecycle);
            let child_slot = Arc::clone(&child_slot);
            let helper_done = Arc::clone(&helper_done);
            tokio::task::spawn_blocking(move || {
                let event_pump_slot = Mutex::new(None);
                finish_exit(&lifecycle, &child_slot, &event_pump_slot);
                helper_done.store(true, Ordering::Release);
            })
        };

        witness.wait_until_started();
        assert!(!helper_done.load(Ordering::Acquire));
        witness.release();
        witness.wait_until_terminal();
        startup_observer.wait_until_blocking_wait_started().await;
        assert!(!helper_done.load(Ordering::Acquire));
        gate.release();
        publishing.await.expect("publication task joined");
        helper.await.expect("Exit helper joined");
        assert!(helper_done.load(Ordering::Acquire));
        assert!(child_slot.lock().is_none());
    }
}
