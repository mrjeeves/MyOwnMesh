//! `myownmesh service …` — install / start / stop / uninstall MyOwnMesh
//! as a background OS service.
//!
//! This manages the **daemon process** (`myownmesh serve`) under the
//! host init system so it survives logout/reboot. It is deliberately
//! distinct from `myownmesh ctl services`, which toggles the mesh's own
//! *hosted* roles (relay / signaling / STUN / TURN) inside an
//! already-running daemon. Same word, two layers: this one is "should
//! the OS keep my daemon alive", that one is "what does my daemon host".
//!
//! Two scopes:
//!
//! - **user** (default) — a per-user service that needs no root, keeps
//!   state in `~/.myownmesh`, and starts at login. On Linux we also try
//!   to enable lingering so it runs while you're logged out.
//! - **system** (`--system`) — a root-owned service that starts at boot
//!   and runs with its own state under a system directory. Requires root
//!   (re-run under `sudo`).
//!
//! Two backends, picked by target OS in [`current_manager`]:
//!
//! - **Linux → systemd.** A `myownmesh.service` unit under
//!   `~/.config/systemd/user/` (user) or `/etc/systemd/system/` (system).
//!   The system unit runs unprivileged via `DynamicUser=yes` +
//!   `StateDirectory=`, so there's no account to create and `/var/lib/
//!   myownmesh` is owned correctly across restarts.
//! - **macOS → launchd.** A `com.myownmesh.daemon.plist` under
//!   `~/Library/LaunchAgents/` (user) or `/Library/LaunchDaemons/`
//!   (system).
//!
//! Windows and other targets aren't wired to a service manager; the
//! command returns an actionable pointer to the manual setup instead of
//! pretending to succeed.
//!
//! Almost everything here is a pure function — the unit/plist text, the
//! `systemctl`/`launchctl` argv vectors, the status parsers — so both
//! backends are unit-tested on every CI runner regardless of host OS.
//! The only OS-gated code is the one-line backend pick and the
//! effective-uid check.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use clap::Subcommand;

/// systemd unit / launchd job names. Stable identifiers — changing them
/// orphans previously-installed services, so they're constants.
const SYSTEMD_UNIT: &str = "myownmesh.service";
const LAUNCHD_LABEL: &str = "com.myownmesh.daemon";

#[derive(Subcommand, Debug)]
pub enum ServiceCmd {
    /// Install the background service and start it. Also sets it to start
    /// on its own — at login (user service) or at boot (`--system`).
    Install {
        /// Bake a `MYOWNMESH_LOG` filter into the service, e.g.
        /// `info,myownmesh=debug`. Omit to inherit the daemon's tuned
        /// default filter (our crates at info, webrtc noise silenced).
        #[arg(long, value_name = "FILTER")]
        log: Option<String>,
    },
    /// Start the installed service now.
    Start,
    /// Stop the running service. It stays installed and will start again
    /// on the next login/boot.
    Stop,
    /// Restart the service.
    Restart,
    /// Show whether the service is installed, enabled, and running.
    Status,
    /// Stop, disable, and remove the service.
    Uninstall,
}

/// Per-user vs system-wide install.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scope {
    User,
    System,
}

impl Scope {
    fn from_flag(system: bool) -> Self {
        if system {
            Scope::System
        } else {
            Scope::User
        }
    }

    fn label(self) -> &'static str {
        match self {
            Scope::User => "user",
            Scope::System => "system",
        }
    }

    /// The `--system` token to suggest in messages (empty for user scope),
    /// so copy-pasteable hints address the right scope.
    fn flag_hint(self) -> &'static str {
        match self {
            Scope::User => "",
            Scope::System => " --system",
        }
    }

    fn other(self) -> Self {
        match self {
            Scope::User => Scope::System,
            Scope::System => Scope::User,
        }
    }
}

/// Which init system this build drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Manager {
    Systemd,
    Launchd,
}

/// Resolved enabled/active words for a status read-out. `None` means
/// "couldn't determine" (e.g. the probe tool returned nothing).
struct ServiceState {
    enabled: Option<String>,
    active: Option<String>,
}

/// Start/stop/restart, sharing one code path.
#[derive(Clone, Copy)]
enum Lifecycle {
    Start,
    Stop,
    Restart,
}

impl Lifecycle {
    fn verb(self) -> &'static str {
        match self {
            Lifecycle::Start => "start",
            Lifecycle::Stop => "stop",
            Lifecycle::Restart => "restart",
        }
    }

    fn past(self) -> &'static str {
        match self {
            Lifecycle::Start => "Started",
            Lifecycle::Stop => "Stopped",
            Lifecycle::Restart => "Restarted",
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run(system: bool, cmd: ServiceCmd) -> Result<()> {
    let manager = current_manager()?;
    let scope = Scope::from_flag(system);

    // Fail clearly on a box whose init system we don't speak (e.g. a
    // container or a non-systemd Linux) rather than emitting confusing
    // "command not found" errors mid-operation.
    if !on_path(manager.tool()) {
        bail!(
            "`{tool}` was not found on your PATH.\n\n\
             `myownmesh service` manages {init} services, which this system \
             doesn't appear to use.\nSet the daemon up under your own init \
             system instead, pointing it at:\n  myownmesh serve",
            tool = manager.tool(),
            init = manager.init_name(),
        );
    }

    let home = home_dir()?;
    match cmd {
        ServiceCmd::Install { log } => install(manager, scope, &home, log),
        ServiceCmd::Start => lifecycle(manager, scope, &home, Lifecycle::Start),
        ServiceCmd::Stop => lifecycle(manager, scope, &home, Lifecycle::Stop),
        ServiceCmd::Restart => lifecycle(manager, scope, &home, Lifecycle::Restart),
        ServiceCmd::Status => status(manager, scope, &home),
        ServiceCmd::Uninstall => uninstall(manager, scope, &home),
    }
}

/// Pick the backend for the host OS. The supported arms compile to a
/// single block expression each; the unsupported arm is the only one
/// present on other targets and returns an actionable error.
fn current_manager() -> Result<Manager> {
    #[cfg(target_os = "linux")]
    {
        Ok(Manager::Systemd)
    }
    #[cfg(target_os = "macos")]
    {
        Ok(Manager::Launchd)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let msg = if cfg!(windows) {
            "`myownmesh service` isn't supported on Windows yet.\n\n\
             To run the daemon in the background on Windows, register `myownmesh serve`\n\
             as a startup task (Task Scheduler -> Create Task -> Triggers: \"At startup\"\n\
             or \"At log on\"), or wrap it with a service shim such as NSSM\n\
             (https://nssm.cc) or WinSW. Track native support upstream:\n\
             https://github.com/mrjeeves/MyOwnMesh/issues"
        } else {
            "`myownmesh service` supports Linux (systemd) and macOS (launchd) only.\n\
             Run the daemon under your platform's init system, pointing it at: myownmesh serve"
        };
        Err(anyhow!(msg))
    }
}

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------

fn install(manager: Manager, scope: Scope, home: &Path, log: Option<String>) -> Result<()> {
    ensure_privilege(scope, "install")?;

    // Resolve the binary the service should exec. A system service runs
    // as a different (or transient) user that can't reach a binary under
    // someone's home dir, so copy it to a shared location in that case.
    let src = std::env::current_exe()
        .context("locate the running myownmesh executable")?
        .canonicalize()
        .context("canonicalize the executable path")?;
    let (exec, copied) = stage_executable(scope, &src)?;

    let (env, state_dir) = compute_env(manager, scope, home, log);

    let unit_path = manager.unit_path(scope, home);
    let replacing = unit_path.exists();
    if let Some(parent) = unit_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let contents = manager.render(&exec, scope, &env, home);
    write_unit(&unit_path, &contents)?;

    // launchd writes the daemon's stdout/stderr to a log file; make sure
    // its directory exists so launchd doesn't refuse to start the job.
    if manager == Manager::Launchd {
        if let Some(parent) = manager.launchd_log_path(scope, home).parent() {
            std::fs::create_dir_all(parent).ok();
        }
    }

    for cmd in manager.install_cmds(scope, &unit_path) {
        run_checked(&cmd)?;
    }

    // A user systemd service dies with your session unless lingering is
    // on — fatal for a background mesh node on a box you SSH into. Best
    // effort: it may need polkit/root, so we report rather than abort.
    if manager == Manager::Systemd && scope == Scope::User {
        try_enable_linger();
    }

    println!(
        "{} MyOwnMesh as a {} service.",
        if replacing {
            "Reinstalled"
        } else {
            "Installed"
        },
        scope.label()
    );
    if let Some(dest) = &copied {
        println!(
            "  binary:  {} (copied so the service account can execute it)",
            dest.display()
        );
    }
    println!("  unit:    {}", unit_path.display());
    println!("  state:   {}", state_dir.display());
    print_state(manager, scope, home);
    Ok(())
}

/// Return the path to bake into the service and, if we copied the binary,
/// where to. User scope runs as the invoking user, so the current path is
/// fine. System scope needs a path readable by the service account; if the
/// binary already lives in a system prefix we use it, otherwise we copy it
/// into `/usr/local/lib/myownmesh/`.
fn stage_executable(scope: Scope, src: &Path) -> Result<(PathBuf, Option<PathBuf>)> {
    if scope == Scope::User || is_system_path(src) {
        return Ok((src.to_path_buf(), None));
    }
    let dir = PathBuf::from("/usr/local/lib/myownmesh");
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let dest = dir.join("myownmesh");
    std::fs::copy(src, &dest)
        .with_context(|| format!("copy {} -> {}", src.display(), dest.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("make {} executable", dest.display()))?;
    }
    Ok((dest.clone(), Some(dest)))
}

/// Environment baked into the unit, plus the state directory (for display).
///
/// - **System scope** pins a fixed state dir (a transient/root user has no
///   usable `$HOME`) and disables self-update, since the in-process updater
///   can't rewrite a root-owned binary and would only log failures.
/// - **User scope** inherits the daemon's defaults: it relies on `$HOME`
///   unless the caller already runs with a custom `MYOWNMESH_HOME`, which
///   we carry over so the service uses the same state they do.
///
/// `MYOWNMESH_LOG` is only set when `--log` is given; otherwise the daemon
/// applies its own tuned default filter (setting it to "info" here would
/// regress that by un-silencing the webrtc crates).
fn compute_env(
    manager: Manager,
    scope: Scope,
    home: &Path,
    log: Option<String>,
) -> (Vec<(String, String)>, PathBuf) {
    let mut env = Vec::new();
    let state_dir = match scope {
        Scope::System => {
            let dir = manager.system_state_dir();
            env.push(("MYOWNMESH_HOME".into(), dir.to_string_lossy().into_owned()));
            env.push(("MYOWNMESH_AUTOUPDATE".into(), "0".into()));
            dir
        }
        Scope::User => match env_var_nonempty("MYOWNMESH_HOME") {
            Some(custom) => {
                env.push(("MYOWNMESH_HOME".into(), custom.clone()));
                PathBuf::from(custom)
            }
            None => home.join(".myownmesh"),
        },
    };
    if let Some(filter) = log {
        env.push(("MYOWNMESH_LOG".into(), filter));
    }
    (env, state_dir)
}

// ---------------------------------------------------------------------------
// start / stop / restart
// ---------------------------------------------------------------------------

fn lifecycle(manager: Manager, scope: Scope, home: &Path, life: Lifecycle) -> Result<()> {
    ensure_privilege(scope, life.verb())?;
    let unit_path = manager.unit_path(scope, home);
    if !unit_path.exists() {
        bail!(
            "the {} service isn't installed.\nRun `myownmesh service{} install` first.",
            scope.label(),
            scope.flag_hint()
        );
    }
    for cmd in manager.lifecycle_cmds(scope, life) {
        run_checked(&cmd)?;
    }
    println!("{} the {} service.", life.past(), scope.label());
    print_state(manager, scope, home);
    Ok(())
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

fn status(manager: Manager, scope: Scope, home: &Path) -> Result<()> {
    let unit_path = manager.unit_path(scope, home);
    println!("MyOwnMesh ({} service)", scope.label());

    if !unit_path.exists() {
        println!("  status:  not installed");
        // If the *other* scope is installed, point there — a common
        // mix-up is checking `status` without the `--system` it was
        // installed with.
        if manager.unit_path(scope.other(), home).exists() {
            println!(
                "  note:    a {} service is installed; query it with \
                 `myownmesh service{} status`",
                scope.other().label(),
                scope.other().flag_hint()
            );
        }
        println!("  install: myownmesh service{} install", scope.flag_hint());
        return Ok(());
    }

    println!("  unit:    {}", unit_path.display());
    print_state(manager, scope, home);
    Ok(())
}

/// Shared status read-out used by install/start/stop/restart/status.
fn print_state(manager: Manager, scope: Scope, home: &Path) {
    let state = manager.probe_state(scope);
    if let Some(enabled) = state.enabled {
        println!("  enabled: {enabled}");
    }
    if let Some(active) = state.active {
        println!("  active:  {active}");
    }
    println!("  logs:    {}", manager.logs_hint(scope, home));
}

// ---------------------------------------------------------------------------
// uninstall
// ---------------------------------------------------------------------------

fn uninstall(manager: Manager, scope: Scope, home: &Path) -> Result<()> {
    ensure_privilege(scope, "uninstall")?;
    let unit_path = manager.unit_path(scope, home);
    if !unit_path.exists() {
        println!(
            "No {} service installed — nothing to remove.",
            scope.label()
        );
        return Ok(());
    }

    // Stop + disable before deleting the file. Best-effort: an
    // already-stopped or already-unloaded service makes these exit
    // non-zero, which shouldn't block removal.
    for cmd in manager.pre_uninstall_cmds(scope, &unit_path) {
        run_quiet(&cmd);
    }
    std::fs::remove_file(&unit_path).with_context(|| format!("remove {}", unit_path.display()))?;
    for cmd in manager.post_uninstall_cmds(scope) {
        run_quiet(&cmd);
    }

    // Drop the binary copy we made for a system install, if any.
    if scope == Scope::System {
        let copied = PathBuf::from("/usr/local/lib/myownmesh");
        if copied.exists() {
            std::fs::remove_dir_all(&copied).ok();
        }
    }

    println!("Uninstalled the {} service.", scope.label());
    Ok(())
}

// ---------------------------------------------------------------------------
// Manager backends — pure path / text / argv builders + status probes
// ---------------------------------------------------------------------------

impl Manager {
    fn tool(self) -> &'static str {
        match self {
            Manager::Systemd => "systemctl",
            Manager::Launchd => "launchctl",
        }
    }

    fn init_name(self) -> &'static str {
        match self {
            Manager::Systemd => "systemd",
            Manager::Launchd => "launchd",
        }
    }

    /// Absolute path of the unit/plist file for a scope.
    fn unit_path(self, scope: Scope, home: &Path) -> PathBuf {
        match (self, scope) {
            (Manager::Systemd, Scope::User) => home.join(".config/systemd/user").join(SYSTEMD_UNIT),
            (Manager::Systemd, Scope::System) => {
                PathBuf::from("/etc/systemd/system").join(SYSTEMD_UNIT)
            }
            (Manager::Launchd, Scope::User) => home
                .join("Library/LaunchAgents")
                .join(format!("{LAUNCHD_LABEL}.plist")),
            (Manager::Launchd, Scope::System) => {
                PathBuf::from("/Library/LaunchDaemons").join(format!("{LAUNCHD_LABEL}.plist"))
            }
        }
    }

    /// Fixed state directory for a system-scope service.
    fn system_state_dir(self) -> PathBuf {
        match self {
            // Matches `StateDirectory=myownmesh` (relative to /var/lib).
            Manager::Systemd => PathBuf::from("/var/lib/myownmesh"),
            Manager::Launchd => PathBuf::from("/Library/Application Support/MyOwnMesh"),
        }
    }

    /// Where launchd should write the daemon's stdout/stderr (launchd, unlike
    /// systemd's journal, sends them to `/dev/null` otherwise).
    fn launchd_log_path(self, scope: Scope, home: &Path) -> PathBuf {
        match scope {
            Scope::User => home.join("Library/Logs/myownmesh.log"),
            Scope::System => PathBuf::from("/Library/Logs/myownmesh.log"),
        }
    }

    fn render(self, exec: &Path, scope: Scope, env: &[(String, String)], home: &Path) -> String {
        match self {
            Manager::Systemd => render_systemd_unit(exec, scope, env),
            Manager::Launchd => {
                render_launchd_plist(exec, env, &self.launchd_log_path(scope, home))
            }
        }
    }

    /// Commands to run after writing the unit: reload + enable + start.
    fn install_cmds(self, scope: Scope, unit_path: &Path) -> Vec<Vec<String>> {
        match self {
            Manager::Systemd => vec![
                systemctl(scope, &["daemon-reload"]),
                // `enable --now` enables (auto-start) and starts in one shot.
                systemctl(scope, &["enable", "--now", SYSTEMD_UNIT]),
            ],
            // `load -w` loads the job, marks it enabled across reboots, and
            // (via RunAtLoad) starts it.
            Manager::Launchd => vec![launchctl(&["load", "-w", &path_arg(unit_path)])],
        }
    }

    fn lifecycle_cmds(self, scope: Scope, life: Lifecycle) -> Vec<Vec<String>> {
        match (self, life) {
            (Manager::Systemd, Lifecycle::Start) => {
                vec![systemctl(scope, &["start", SYSTEMD_UNIT])]
            }
            (Manager::Systemd, Lifecycle::Stop) => vec![systemctl(scope, &["stop", SYSTEMD_UNIT])],
            (Manager::Systemd, Lifecycle::Restart) => {
                vec![systemctl(scope, &["restart", SYSTEMD_UNIT])]
            }
            (Manager::Launchd, Lifecycle::Start) => vec![launchctl(&["start", LAUNCHD_LABEL])],
            (Manager::Launchd, Lifecycle::Stop) => vec![launchctl(&["stop", LAUNCHD_LABEL])],
            // launchd has no atomic restart for a loaded job; stop then
            // start. SIGTERM exits the daemon cleanly (code 0), which
            // KeepAlive{SuccessfulExit=false} treats as "stay down", so
            // the explicit start is what brings it back.
            (Manager::Launchd, Lifecycle::Restart) => vec![
                launchctl(&["stop", LAUNCHD_LABEL]),
                launchctl(&["start", LAUNCHD_LABEL]),
            ],
        }
    }

    fn pre_uninstall_cmds(self, scope: Scope, unit_path: &Path) -> Vec<Vec<String>> {
        match self {
            Manager::Systemd => vec![systemctl(scope, &["disable", "--now", SYSTEMD_UNIT])],
            Manager::Launchd => vec![launchctl(&["unload", "-w", &path_arg(unit_path)])],
        }
    }

    fn post_uninstall_cmds(self, scope: Scope) -> Vec<Vec<String>> {
        match self {
            Manager::Systemd => vec![systemctl(scope, &["daemon-reload"])],
            Manager::Launchd => vec![],
        }
    }

    fn logs_hint(self, scope: Scope, home: &Path) -> String {
        match self {
            Manager::Systemd => match scope {
                Scope::User => "journalctl --user -u myownmesh -f".to_string(),
                Scope::System => "journalctl -u myownmesh -f".to_string(),
            },
            Manager::Launchd => format!("tail -f {}", self.launchd_log_path(scope, home).display()),
        }
    }

    /// Query the live enabled/active state. Impure (spawns the probe
    /// commands); the parsing it delegates to is pure and unit-tested.
    fn probe_state(self, scope: Scope) -> ServiceState {
        match self {
            Manager::Systemd => {
                let (_, enabled_out, _) = capture(&systemctl(scope, &["is-enabled", SYSTEMD_UNIT]));
                let (_, active_out, _) = capture(&systemctl(scope, &["is-active", SYSTEMD_UNIT]));
                ServiceState {
                    enabled: parse_systemctl_word(&enabled_out),
                    active: parse_systemctl_word(&active_out),
                }
            }
            Manager::Launchd => {
                let (code, out, _) = capture(&launchctl(&["list", LAUNCHD_LABEL]));
                let (loaded, running) = parse_launchctl_list(code, &out);
                ServiceState {
                    enabled: Some(if loaded { "loaded" } else { "not loaded" }.to_string()),
                    active: Some(if running { "running" } else { "stopped" }.to_string()),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Unit / plist rendering (pure)
// ---------------------------------------------------------------------------

fn render_systemd_unit(exec: &Path, scope: Scope, env: &[(String, String)]) -> String {
    let system = scope == Scope::System;
    let mut s = String::new();

    s.push_str("[Unit]\n");
    s.push_str("Description=MyOwnMesh peer-to-peer mesh daemon\n");
    s.push_str("Documentation=https://github.com/mrjeeves/MyOwnMesh\n");
    if system {
        // network-online.target is a system target; ordering a user unit
        // against it is meaningless, so it's system-scope only.
        s.push_str("After=network-online.target\n");
        s.push_str("Wants=network-online.target\n");
    }

    s.push_str("\n[Service]\n");
    s.push_str("Type=simple\n");
    s.push_str(&format!(
        "ExecStart={} serve\n",
        systemd_quote(&exec.to_string_lossy())
    ));
    s.push_str("Restart=on-failure\n");
    s.push_str("RestartSec=5\n");
    // The daemon handles SIGTERM for a clean shutdown — systemd's default
    // stop signal, stated here for clarity.
    s.push_str("KillSignal=SIGTERM\n");
    s.push_str("TimeoutStopSec=20\n");

    if system {
        s.push('\n');
        s.push_str("# Run unprivileged under a systemd-managed transient user; StateDirectory\n");
        s.push_str("# gives it a stable, owned home at /var/lib/myownmesh across restarts.\n");
        s.push_str("DynamicUser=yes\n");
        s.push_str("StateDirectory=myownmesh\n");
    }

    for (key, value) in env {
        s.push_str(&format!("Environment={}\n", systemd_env(key, value)));
    }

    if system {
        s.push('\n');
        s.push_str("# Hardening\n");
        s.push_str("NoNewPrivileges=yes\n");
        s.push_str("ProtectSystem=strict\n");
        s.push_str("ProtectHome=yes\n");
        s.push_str("PrivateTmp=yes\n");
        s.push_str("ProtectKernelTunables=yes\n");
        s.push_str("ProtectControlGroups=yes\n");
        s.push_str("RestrictSUIDSGID=yes\n");
        s.push_str("RestrictRealtime=yes\n");
    }

    s.push_str("\n[Install]\n");
    s.push_str(if system {
        "WantedBy=multi-user.target\n"
    } else {
        "WantedBy=default.target\n"
    });
    s
}

/// Quote an `ExecStart` program path if it contains whitespace (systemd
/// splits unquoted command lines on spaces).
fn systemd_quote(path: &str) -> String {
    if path.contains(char::is_whitespace) {
        format!("\"{path}\"")
    } else {
        path.to_string()
    }
}

/// Render a single `Environment=` assignment, quoting the whole `KEY=value`
/// when the value contains whitespace (otherwise systemd would treat the
/// remainder as a second variable).
fn systemd_env(key: &str, value: &str) -> String {
    if value.contains(char::is_whitespace) {
        format!("\"{key}={value}\"")
    } else {
        format!("{key}={value}")
    }
}

fn render_launchd_plist(exec: &Path, env: &[(String, String)], log_path: &Path) -> String {
    let mut s = String::new();
    s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    s.push_str(
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
    );
    s.push_str("<plist version=\"1.0\">\n<dict>\n");

    s.push_str("    <key>Label</key>\n");
    s.push_str(&format!("    <string>{LAUNCHD_LABEL}</string>\n"));

    s.push_str("    <key>ProgramArguments</key>\n    <array>\n");
    s.push_str(&format!(
        "        <string>{}</string>\n",
        xml_escape(&exec.to_string_lossy())
    ));
    s.push_str("        <string>serve</string>\n");
    s.push_str("    </array>\n");

    // Start at load/login/boot, and keep it alive — but not after a clean
    // (SIGTERM) shutdown, so `stop` actually stops it.
    s.push_str("    <key>RunAtLoad</key>\n    <true/>\n");
    s.push_str("    <key>KeepAlive</key>\n    <dict>\n");
    s.push_str("        <key>SuccessfulExit</key>\n        <false/>\n");
    s.push_str("    </dict>\n");

    let log = xml_escape(&log_path.to_string_lossy());
    s.push_str("    <key>StandardOutPath</key>\n");
    s.push_str(&format!("    <string>{log}</string>\n"));
    s.push_str("    <key>StandardErrorPath</key>\n");
    s.push_str(&format!("    <string>{log}</string>\n"));

    if !env.is_empty() {
        s.push_str("    <key>EnvironmentVariables</key>\n    <dict>\n");
        for (key, value) in env {
            s.push_str(&format!(
                "        <key>{}</key>\n        <string>{}</string>\n",
                xml_escape(key),
                xml_escape(value)
            ));
        }
        s.push_str("    </dict>\n");
    }

    s.push_str("</dict>\n</plist>\n");
    s
}

fn xml_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// argv builders (pure)
// ---------------------------------------------------------------------------

/// `systemctl [--user] <args...>`.
fn systemctl(scope: Scope, args: &[&str]) -> Vec<String> {
    let mut cmd = vec!["systemctl".to_string()];
    if scope == Scope::User {
        cmd.push("--user".to_string());
    }
    cmd.extend(args.iter().map(|a| a.to_string()));
    cmd
}

/// `launchctl <args...>`.
fn launchctl(args: &[&str]) -> Vec<String> {
    let mut cmd = vec!["launchctl".to_string()];
    cmd.extend(args.iter().map(|a| a.to_string()));
    cmd
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

// ---------------------------------------------------------------------------
// status parsers (pure)
// ---------------------------------------------------------------------------

/// `systemctl is-enabled`/`is-active` print the state word (e.g. "enabled",
/// "active", "inactive", "failed") on stdout even when they exit non-zero.
/// Empty stdout means the probe couldn't run.
fn parse_systemctl_word(stdout: &str) -> Option<String> {
    let word = stdout.lines().next().unwrap_or("").trim();
    if word.is_empty() {
        None
    } else {
        Some(word.to_string())
    }
}

/// `launchctl list <label>` exits 0 with a dict when the job is loaded, and
/// the dict carries a `"PID" = N;` line only while it's running.
fn parse_launchctl_list(exit_code: i32, stdout: &str) -> (bool, bool) {
    let loaded = exit_code == 0;
    let running = loaded
        && stdout
            .lines()
            .any(|line| line.trim_start().starts_with("\"PID\""));
    (loaded, running)
}

// ---------------------------------------------------------------------------
// process + filesystem helpers
// ---------------------------------------------------------------------------

/// Run a command, surfacing its stdout/stderr, and fail if it does.
fn run_checked(argv: &[String]) -> Result<()> {
    let status = Command::new(&argv[0])
        .args(&argv[1..])
        .status()
        .map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                anyhow!(
                    "`{}` not found — is it installed and on your PATH?",
                    argv[0]
                )
            } else {
                anyhow!("failed to run `{}`: {e}", argv.join(" "))
            }
        })?;
    if !status.success() {
        bail!(
            "`{}` failed (exit {})",
            argv.join(" "),
            status_code(&status)
        );
    }
    Ok(())
}

/// Run a command, ignoring failure and output. For teardown steps that are
/// fine to be no-ops (already stopped/unloaded).
fn run_quiet(argv: &[String]) {
    let _ = Command::new(&argv[0]).args(&argv[1..]).output();
}

/// Run a command and capture (exit code, stdout, stderr). A failure to
/// spawn yields exit code -1 and empty output.
fn capture(argv: &[String]) -> (i32, String, String) {
    match Command::new(&argv[0]).args(&argv[1..]).output() {
        Ok(out) => (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ),
        Err(_) => (-1, String::new(), String::new()),
    }
}

fn status_code(status: &std::process::ExitStatus) -> String {
    status
        .code()
        .map(|c| c.to_string())
        .unwrap_or_else(|| "signal".to_string())
}

fn write_unit(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents).map_err(|e| {
        if e.kind() == ErrorKind::PermissionDenied {
            anyhow!(
                "permission denied writing {} — re-run with sudo for a --system service",
                path.display()
            )
        } else {
            anyhow!("write {}: {e}", path.display())
        }
    })
}

/// Best-effort `loginctl enable-linger <user>` so a user service keeps
/// running while logged out. Reports either way; never fatal.
fn try_enable_linger() {
    let Some(user) = current_username() else {
        println!(
            "  note:    run `sudo loginctl enable-linger <you>` to keep it \
             running while logged out"
        );
        return;
    };
    let (code, _, _) = capture(&[
        "loginctl".to_string(),
        "enable-linger".to_string(),
        user.clone(),
    ]);
    if code == 0 {
        println!("  linger:  enabled (keeps running while you're logged out)");
    } else {
        println!(
            "  note:    run `sudo loginctl enable-linger {user}` to keep it \
             running while logged out"
        );
    }
}

fn current_username() -> Option<String> {
    if let Some(user) = env_var_nonempty("USER").or_else(|| env_var_nonempty("LOGNAME")) {
        return Some(user);
    }
    let (code, out, _) = capture(&["id".to_string(), "-un".to_string()]);
    if code == 0 {
        let name = out.trim();
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    None
}

/// A system-scope operation must be root; fail fast with a copy-pasteable
/// sudo line rather than partway through.
fn ensure_privilege(scope: Scope, verb: &str) -> Result<()> {
    match privilege_hint(scope, is_root(), verb) {
        Some(msg) => Err(anyhow!(msg)),
        None => Ok(()),
    }
}

/// Pure decision behind [`ensure_privilege`]: a `--system` op by a non-root
/// caller gets a sudo hint; everything else is allowed. Split out so the
/// branch is unit-testable without a real euid.
fn privilege_hint(scope: Scope, is_root: bool, verb: &str) -> Option<String> {
    if scope == Scope::System && !is_root {
        Some(format!(
            "managing the system service requires root.\n\nRe-run with sudo:\n  \
             sudo myownmesh service --system {verb}"
        ))
    } else {
        None
    }
}

#[cfg(unix)]
fn is_root() -> bool {
    // Safe: geteuid has no preconditions and never fails.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

fn home_dir() -> Result<PathBuf> {
    dirs::home_dir().context("could not resolve your home directory")
}

fn env_var_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

/// True when `exe` lives in a system prefix readable by other accounts.
/// Used to decide whether a system service can exec the binary in place.
fn is_system_path(exe: &Path) -> bool {
    let path = exe.to_string_lossy();
    ["/usr/", "/opt/", "/bin/", "/sbin/"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// Whether an executable is reachable on PATH (manual scan so we only
/// accept entries that actually exist).
fn on_path(exe: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|dir| dir.join(exe).exists())
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // ---- systemd unit rendering ----

    #[test]
    fn systemd_user_unit_is_minimal() {
        let unit = render_systemd_unit(Path::new("/home/u/.local/bin/myownmesh"), Scope::User, &[]);
        assert!(unit.contains("ExecStart=/home/u/.local/bin/myownmesh serve"));
        assert!(unit.contains("WantedBy=default.target"));
        assert!(unit.contains("KillSignal=SIGTERM"));
        // User scope must not carry system-only directives.
        assert!(!unit.contains("DynamicUser"));
        assert!(!unit.contains("network-online.target"));
        assert!(!unit.contains("multi-user.target"));
    }

    #[test]
    fn systemd_system_unit_is_hardened() {
        let unit = render_systemd_unit(
            Path::new("/usr/local/bin/myownmesh"),
            Scope::System,
            &env(&[
                ("MYOWNMESH_HOME", "/var/lib/myownmesh"),
                ("MYOWNMESH_AUTOUPDATE", "0"),
            ]),
        );
        assert!(unit.contains("DynamicUser=yes"));
        assert!(unit.contains("StateDirectory=myownmesh"));
        assert!(unit.contains("Environment=MYOWNMESH_HOME=/var/lib/myownmesh"));
        assert!(unit.contains("Environment=MYOWNMESH_AUTOUPDATE=0"));
        assert!(unit.contains("After=network-online.target"));
        assert!(unit.contains("Wants=network-online.target"));
        assert!(unit.contains("NoNewPrivileges=yes"));
        assert!(unit.contains("ProtectSystem=strict"));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn systemd_quotes_paths_and_env_with_spaces() {
        let unit = render_systemd_unit(
            Path::new("/opt/My Apps/myownmesh"),
            Scope::User,
            &env(&[("MYOWNMESH_HOME", "/home/u/My Mesh")]),
        );
        assert!(unit.contains("ExecStart=\"/opt/My Apps/myownmesh\" serve"));
        assert!(unit.contains("Environment=\"MYOWNMESH_HOME=/home/u/My Mesh\""));
    }

    // ---- launchd plist rendering ----

    #[test]
    fn launchd_user_plist_has_no_env_block_when_empty() {
        let plist = render_launchd_plist(
            Path::new("/Users/u/.local/bin/myownmesh"),
            &[],
            Path::new("/Users/u/Library/Logs/myownmesh.log"),
        );
        assert!(plist.contains("<string>com.myownmesh.daemon</string>"));
        assert!(plist.contains("<string>/Users/u/.local/bin/myownmesh</string>"));
        assert!(plist.contains("<string>serve</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<string>/Users/u/Library/Logs/myownmesh.log</string>"));
        assert!(!plist.contains("EnvironmentVariables"));
    }

    #[test]
    fn launchd_system_plist_carries_env() {
        let plist = render_launchd_plist(
            Path::new("/usr/local/lib/myownmesh/myownmesh"),
            &env(&[
                ("MYOWNMESH_HOME", "/Library/Application Support/MyOwnMesh"),
                ("MYOWNMESH_AUTOUPDATE", "0"),
            ]),
            Path::new("/Library/Logs/myownmesh.log"),
        );
        assert!(plist.contains("<key>EnvironmentVariables</key>"));
        assert!(plist.contains("<key>MYOWNMESH_HOME</key>"));
        assert!(plist.contains("<string>/Library/Application Support/MyOwnMesh</string>"));
        assert!(plist.contains("<key>MYOWNMESH_AUTOUPDATE</key>"));
    }

    #[test]
    fn launchd_plist_escapes_xml() {
        let plist = render_launchd_plist(
            Path::new("/Users/a&b/myownmesh"),
            &[],
            Path::new("/tmp/log"),
        );
        assert!(plist.contains("/Users/a&amp;b/myownmesh"));
        assert!(!plist.contains("a&b/"));
    }

    #[test]
    fn xml_escape_covers_all_specials() {
        assert_eq!(
            xml_escape("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
    }

    // ---- path resolution ----

    #[test]
    fn unit_paths_per_scope() {
        let home = Path::new("/home/u");
        assert_eq!(
            Manager::Systemd.unit_path(Scope::User, home),
            Path::new("/home/u/.config/systemd/user/myownmesh.service")
        );
        assert_eq!(
            Manager::Systemd.unit_path(Scope::System, home),
            Path::new("/etc/systemd/system/myownmesh.service")
        );
        assert_eq!(
            Manager::Launchd.unit_path(Scope::User, home),
            Path::new("/home/u/Library/LaunchAgents/com.myownmesh.daemon.plist")
        );
        assert_eq!(
            Manager::Launchd.unit_path(Scope::System, home),
            Path::new("/Library/LaunchDaemons/com.myownmesh.daemon.plist")
        );
    }

    #[test]
    fn launchd_log_paths_per_scope() {
        let home = Path::new("/Users/u");
        assert_eq!(
            Manager::Launchd.launchd_log_path(Scope::User, home),
            Path::new("/Users/u/Library/Logs/myownmesh.log")
        );
        assert_eq!(
            Manager::Launchd.launchd_log_path(Scope::System, home),
            Path::new("/Library/Logs/myownmesh.log")
        );
    }

    #[test]
    fn is_system_path_classification() {
        assert!(is_system_path(Path::new("/usr/local/bin/myownmesh")));
        assert!(is_system_path(Path::new("/opt/homebrew/bin/myownmesh")));
        assert!(is_system_path(Path::new("/bin/myownmesh")));
        assert!(!is_system_path(Path::new("/home/u/.local/bin/myownmesh")));
        assert!(!is_system_path(Path::new("/Users/u/.cargo/bin/myownmesh")));
        assert!(!is_system_path(Path::new(
            "/home/u/MyOwnMesh/target/release/myownmesh"
        )));
    }

    // ---- argv builders ----

    #[test]
    fn systemctl_argv_threads_user_flag() {
        assert_eq!(
            systemctl(Scope::User, &["daemon-reload"]),
            vec!["systemctl", "--user", "daemon-reload"]
        );
        assert_eq!(
            systemctl(Scope::System, &["enable", "--now", SYSTEMD_UNIT]),
            vec!["systemctl", "enable", "--now", "myownmesh.service"]
        );
    }

    #[test]
    fn install_cmds_per_backend() {
        let path = Path::new("/etc/systemd/system/myownmesh.service");
        assert_eq!(
            Manager::Systemd.install_cmds(Scope::System, path),
            vec![
                vec!["systemctl", "daemon-reload"],
                vec!["systemctl", "enable", "--now", "myownmesh.service"],
            ]
        );
        let plist = Path::new("/Users/u/Library/LaunchAgents/com.myownmesh.daemon.plist");
        assert_eq!(
            Manager::Launchd.install_cmds(Scope::User, plist),
            vec![vec![
                "launchctl",
                "load",
                "-w",
                "/Users/u/Library/LaunchAgents/com.myownmesh.daemon.plist"
            ]]
        );
    }

    #[test]
    fn lifecycle_cmds_per_backend() {
        assert_eq!(
            Manager::Systemd.lifecycle_cmds(Scope::User, Lifecycle::Restart),
            vec![vec!["systemctl", "--user", "restart", "myownmesh.service"]]
        );
        assert_eq!(
            Manager::Launchd.lifecycle_cmds(Scope::User, Lifecycle::Restart),
            vec![
                vec!["launchctl", "stop", "com.myownmesh.daemon"],
                vec!["launchctl", "start", "com.myownmesh.daemon"],
            ]
        );
    }

    #[test]
    fn uninstall_cmds_per_backend() {
        let path = Path::new("/etc/systemd/system/myownmesh.service");
        assert_eq!(
            Manager::Systemd.pre_uninstall_cmds(Scope::System, path),
            vec![vec!["systemctl", "disable", "--now", "myownmesh.service"]]
        );
        assert_eq!(
            Manager::Systemd.post_uninstall_cmds(Scope::System),
            vec![vec!["systemctl", "daemon-reload"]]
        );
        let plist = Path::new("/Library/LaunchDaemons/com.myownmesh.daemon.plist");
        assert_eq!(
            Manager::Launchd.pre_uninstall_cmds(Scope::System, plist),
            vec![vec![
                "launchctl",
                "unload",
                "-w",
                "/Library/LaunchDaemons/com.myownmesh.daemon.plist"
            ]]
        );
        assert!(Manager::Launchd
            .post_uninstall_cmds(Scope::System)
            .is_empty());
    }

    // ---- status parsers ----

    #[test]
    fn parse_systemctl_word_takes_first_line() {
        assert_eq!(parse_systemctl_word("active\n"), Some("active".to_string()));
        assert_eq!(
            parse_systemctl_word("enabled\n"),
            Some("enabled".to_string())
        );
        assert_eq!(
            parse_systemctl_word("inactive"),
            Some("inactive".to_string())
        );
        assert_eq!(parse_systemctl_word(""), None);
        assert_eq!(parse_systemctl_word("\n"), None);
    }

    #[test]
    fn parse_launchctl_list_detects_loaded_and_running() {
        let running = "{\n\t\"PID\" = 4321;\n\t\"Label\" = \"com.myownmesh.daemon\";\n};\n";
        assert_eq!(parse_launchctl_list(0, running), (true, true));

        let loaded_idle = "{\n\t\"Label\" = \"com.myownmesh.daemon\";\n};\n";
        assert_eq!(parse_launchctl_list(0, loaded_idle), (true, false));

        // Not loaded: launchctl exits non-zero.
        assert_eq!(
            parse_launchctl_list(113, "Could not find service\n"),
            (false, false)
        );
    }

    // ---- scope helpers ----

    #[test]
    fn scope_helpers() {
        assert_eq!(Scope::from_flag(true), Scope::System);
        assert_eq!(Scope::from_flag(false), Scope::User);
        assert_eq!(Scope::System.flag_hint(), " --system");
        assert_eq!(Scope::User.flag_hint(), "");
        assert_eq!(Scope::User.other(), Scope::System);
    }

    #[test]
    fn privilege_hint_only_blocks_system_without_root() {
        // System + non-root: blocked, with a scope-correct sudo line.
        let hint = privilege_hint(Scope::System, false, "start").expect("should block");
        assert!(hint.contains("sudo myownmesh service --system start"));
        // System + root: allowed.
        assert!(privilege_hint(Scope::System, true, "start").is_none());
        // User scope never needs root.
        assert!(privilege_hint(Scope::User, false, "install").is_none());
    }

    // ---- env policy ----

    #[test]
    fn system_env_pins_state_and_disables_autoupdate() {
        let (env, state) = compute_env(
            Manager::Systemd,
            Scope::System,
            Path::new("/root"),
            Some("debug".to_string()),
        );
        assert_eq!(state, Path::new("/var/lib/myownmesh"));
        assert!(env.contains(&(
            "MYOWNMESH_HOME".to_string(),
            "/var/lib/myownmesh".to_string()
        )));
        assert!(env.contains(&("MYOWNMESH_AUTOUPDATE".to_string(), "0".to_string())));
        assert!(env.contains(&("MYOWNMESH_LOG".to_string(), "debug".to_string())));
    }

    #[test]
    fn user_env_defaults_to_home_and_no_overrides() {
        // Guard against a MYOWNMESH_HOME leaking in from the test env.
        let saved = std::env::var("MYOWNMESH_HOME").ok();
        std::env::remove_var("MYOWNMESH_HOME");

        let (env, state) = compute_env(Manager::Systemd, Scope::User, Path::new("/home/u"), None);
        assert_eq!(state, Path::new("/home/u/.myownmesh"));
        assert!(env.is_empty());

        if let Some(v) = saved {
            std::env::set_var("MYOWNMESH_HOME", v);
        }
    }
}
