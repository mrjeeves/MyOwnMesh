//! `myownmesh install caddy [<domain>]` and `myownmesh caddy path`.
//!
//! The signaling relay (`myownmesh serve` with `services.signaling`
//! enabled) speaks plain `ws://`. To expose it publicly over `wss://`
//! it needs TLS termination in front, and Caddy is the least-friction
//! option: it provisions and renews a Let's Encrypt certificate on its
//! own. The same installation adds Caddy Layer 4 for TURN TLS, enables
//! TURN-over-TCP, and converges the host firewall. These commands stand
//! that up without disturbing operator-owned Caddy configuration.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use clap::Subcommand;

use myownmesh_core::MeshConfig;

/// `myownmesh install …`
#[derive(Subcommand, Debug)]
pub enum InstallCmd {
    /// Install signaling WSS plus TURN TCP/TLS and firewall rules.
    ///
    /// With no DOMAIN it prints the install steps for your OS plus the
    /// reverse-proxy snippet to paste. With a DOMAIN (e.g. `myownmesh
    /// install caddy myownmesh.com`) it does the lot: installs Caddy if
    /// it's missing, writes a Caddy site that terminates TLS on 443 and
    /// proxies WebSocket upgrades to your relay, adds Caddy Layer 4 for
    /// `turns:` on 5349, enables TURN UDP/TCP on 3478, and converges UFW
    /// or firewalld. Safe to re-run: it only touches fenced managed blocks
    /// and backs the Caddyfile up first.
    Caddy {
        /// Domain the relay is served on. Omit to just print the steps.
        domain: Option<String>,
        /// DNS name used for TURN TLS. Defaults to `turn.DOMAIN`.
        #[arg(long)]
        turn_domain: Option<String>,
        /// Routable address advertised in TURN allocations. When omitted,
        /// the installer resolves TURN_DOMAIN.
        #[arg(long)]
        public_ip: Option<String>,
    },
}

/// `myownmesh caddy …`
#[derive(Subcommand, Debug)]
pub enum CaddyCmd {
    /// Print the path to the Caddyfile you edit for the reverse proxy.
    Path,
}

pub async fn run_install(cmd: InstallCmd) -> Result<()> {
    match cmd {
        InstallCmd::Caddy {
            domain,
            turn_domain,
            public_ip,
        } => match domain {
            Some(d) => {
                install_and_configure(&d, turn_domain.as_deref(), public_ip.as_deref()).await
            }
            None => {
                print_install_help();
                Ok(())
            }
        },
    }
}

pub async fn run_caddy(cmd: CaddyCmd) -> Result<()> {
    match cmd {
        CaddyCmd::Path => {
            let path = caddyfile_path();
            println!("{}", path.display());
            if !path.exists() {
                println!();
                println!("(doesn't exist yet — `myownmesh install caddy <domain>` creates it,");
                println!(" or make it by hand and add the block from `myownmesh install caddy`.)");
            }
            Ok(())
        }
    }
}

// ---- the "do it all" path ------------------------------------------------

async fn install_and_configure(
    domain: &str,
    turn_domain: Option<&str>,
    public_ip: Option<&str>,
) -> Result<()> {
    let host = normalize_domain(domain);
    if host.is_empty() {
        anyhow::bail!("couldn't parse a domain out of {domain:?}");
    }
    let port = signaling_port();
    let turn_host = turn_domain
        .map(normalize_domain)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("turn.{host}"));

    println!("Setting up Caddy as a wss:// reverse proxy for the signaling relay.");
    println!("  domain : {host}  (TLS on 443)");
    println!("  relay  : 127.0.0.1:{port}  (services.signaling, loopback)");
    println!("  TURN   : {turn_host}:3478 udp/tcp + :5349 TLS");
    println!();

    // 1. Ensure Caddy is present.
    if caddy_installed() {
        println!("✓ Caddy already installed.");
    } else {
        println!("Caddy not found — installing…");
        match try_install_caddy() {
            Ok(()) if caddy_installed() => println!("✓ Caddy installed."),
            Ok(()) => {
                println!();
                println!("Caddy still isn't on PATH. Finish the install, then re-run me:");
                print_manual_install_steps();
                anyhow::bail!("Caddy install incomplete");
            }
            Err(e) => {
                println!();
                println!("Couldn't install Caddy automatically: {e}");
                println!("Install it by hand, then re-run me:");
                print_manual_install_steps();
                anyhow::bail!("Caddy install incomplete");
            }
        }
    }

    ensure_caddy_layer4()?;

    // 2. Write / merge the Caddyfile (managed block only; backed up).
    let path = caddyfile_path();
    let path_existed = path.exists();
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let updated = upsert_managed_block(&existing, &host, &turn_host, port, 3478, 5349);
    if updated == existing {
        println!("✓ Caddyfile already up to date: {}", path.display());
    } else {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        if !existing.is_empty() {
            let backup = backup_path(&path);
            std::fs::write(&backup, &existing)
                .with_context(|| format!("back up to {}", backup.display()))?;
            println!("• Backed up existing Caddyfile → {}", backup.display());
        }
        std::fs::write(&path, &updated).with_context(|| format!("write {}", path.display()))?;
        println!("✓ Wrote reverse-proxy block to {}", path.display());
    }

    // 3. Reload (or start) Caddy.
    if let Err(error) = reload_caddy(&path) {
        if updated != existing {
            if path_existed {
                std::fs::write(&path, &existing)
                    .with_context(|| format!("restore {}", path.display()))?;
                let _ = reload_caddy(&path);
            } else {
                let _ = std::fs::remove_file(&path);
            }
        }
        return Err(error).context("Caddy configuration was rolled back");
    }

    // 4. Converge persisted and running services. Stream TURN remains opt-in
    //    for existing hosts and is enabled here together with TLS/firewalls.
    let services = persist_public_services(&turn_host, public_ip)?;
    match crate::cli::ctl::apply_services(services.clone()).await {
        Ok(true) => println!("✓ Signaling and UDP/TCP TURN applied to the running daemon."),
        Ok(false) => println!("• Services saved; restart MyOwnMesh to apply them."),
        Err(error) => println!("• Services saved but live apply failed: {error}"),
    }
    configure_firewall(
        services.turn.port,
        5349,
        services.turn.relay_port_min,
        services.turn.relay_port_max,
    );

    // 5. What's left for the user.
    println!();
    println!("Done. Peers can now point at  wss://{host}");
    println!();
    println!("Two things still have to be true for TLS to come up:");
    println!("  • DNS — an A/AAAA record for {host} resolves to this server's public IP.");
    println!("  • Firewall/cloud group: TCP 80,443,3478,5349; UDP 3478 and 49152:65535.");
    println!();
    println!(
        "Verify:  npx wscat -c wss://{host}   (a real WebSocket handshake — expect a connect)"
    );
    println!(
        "         curl -I https://{host}   (Caddy issues the cert on the first HTTPS request)"
    );
    #[cfg(all(unix, not(target_os = "macos")))]
    println!(
        "If it doesn't answer:  sudo systemctl status caddy  ·  sudo journalctl -u caddy -n 50"
    );
    Ok(())
}

/// Fallback for when the daemon isn't running: persist the loopback bind
/// (and enable signaling) to config.json so it takes effect on next start.
fn persist_public_services(
    turn_host: &str,
    public_ip: Option<&str>,
) -> Result<myownmesh_core::ServicesConfig> {
    use std::net::{IpAddr, ToSocketAddrs};

    let mut cfg = MeshConfig::load().unwrap_or_default();
    cfg.services.signaling.enabled = true;
    cfg.services.signaling.bind = "127.0.0.1".to_string();
    cfg.services.turn.enabled = true;
    cfg.services.turn.tcp_enabled = true;
    cfg.services.turn.bind = "0.0.0.0".to_string();
    cfg.services.turn.port = 3478;
    if cfg.services.turn.relay_port_min == 0 {
        cfg.services.turn.relay_port_min = 49152;
        cfg.services.turn.relay_port_max = 65535;
    } else {
        cfg.services.turn.relay_port_max = cfg
            .services
            .turn
            .relay_port_max
            .max(cfg.services.turn.relay_port_min);
    }
    let resolved = public_ip
        .map(str::parse::<IpAddr>)
        .transpose()
        .context("parse --public-ip")?
        .or_else(|| {
            if cfg.services.turn.public_ip.trim().is_empty() {
                (turn_host, 0)
                    .to_socket_addrs()
                    .ok()?
                    .map(|address| address.ip())
                    .find(IpAddr::is_ipv4)
            } else {
                cfg.services.turn.public_ip.parse().ok()
            }
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "could not resolve {turn_host}; create its A record or pass --public-ip"
            )
        })?;
    cfg.services.turn.public_ip = resolved.to_string();
    let services = cfg.services.clone();
    cfg.save().context("save config")?;
    Ok(services)
}

// ---- pure helpers (unit-tested) ------------------------------------------

/// Normalize a user-supplied domain/URL into a bare Caddy site address:
/// strip any scheme (`wss://`, `https://`, …), drop a path/query, and
/// trim a trailing dot. Leaves `host` or `host:port`.
fn normalize_domain(input: &str) -> String {
    let s = input.trim();
    let s = s
        .strip_prefix("wss://")
        .or_else(|| s.strip_prefix("ws://"))
        .or_else(|| s.strip_prefix("https://"))
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let s = s.split('/').next().unwrap_or(s);
    s.trim().trim_end_matches('.').to_string()
}

fn begin_marker(host: &str) -> String {
    format!("# >>> myownmesh-managed: {host}")
}
fn end_marker(host: &str) -> String {
    format!("# <<< myownmesh-managed: {host}")
}

/// The site block for `host`: proxy only WebSocket upgrades to the local
/// relay, and answer everything else (browsers, scanners, health checks)
/// with a plain 200 instead of letting the WS-only relay reject them with
/// an EOF — which Caddy would otherwise log as a 502 on every stray hit.
fn site_block(host: &str, turn_host: &str, port: u16) -> String {
    format!(
        "{host} {{\n\
         \t@ws {{\n\
         \t\theader Connection *Upgrade*\n\
         \t\theader Upgrade websocket\n\
         \t}}\n\
         \thandle @ws {{\n\
         \t\treverse_proxy 127.0.0.1:{port}\n\
         \t}}\n\
         \thandle {{\n\
         \t\trespond \"MyOwnMesh signaling relay — connect over wss://\" 200\n\
         \t}}\n\
         }}\n\n\
         {turn_host} {{\n\
         \trespond \"MyOwnMesh TURN relay — use turn:/turns:, not HTTPS\" 200\n\
         }}\n"
    )
}

/// Insert or replace *our* managed reverse-proxy block for `host` in an
/// existing Caddyfile, leaving every other line untouched. Idempotent:
/// running again with the same args yields identical output; running
/// with a new port rewrites just the block. We fence our block with
/// comment markers so user-authored config is never disturbed.
fn upsert_managed_block(
    existing: &str,
    host: &str,
    turn_host: &str,
    port: u16,
    turn_port: u16,
    turns_port: u16,
) -> String {
    let begin = begin_marker(host);
    let end = end_marker(host);
    let managed = format!("{begin}\n{}{end}\n", site_block(host, turn_host, port));

    if let (Some(b), Some(e)) = (existing.find(&begin), existing.find(&end)) {
        if e > b {
            let end_idx = e + end.len();
            // Swallow one trailing newline after the end marker so
            // repeated runs don't accrue blank lines.
            let after = existing[end_idx..]
                .strip_prefix('\n')
                .unwrap_or(&existing[end_idx..]);
            let mut out = String::with_capacity(existing.len());
            out.push_str(&existing[..b]);
            out.push_str(&managed);
            out.push_str(after);
            return upsert_layer4_global(&out, turn_host, turn_port, turns_port);
        }
    }

    // No managed block yet — append, separated by a blank line from any
    // preceding content.
    let mut out = existing.to_string();
    if !out.is_empty() && !out.ends_with("\n\n") {
        if out.ends_with('\n') {
            out.push('\n');
        } else {
            out.push_str("\n\n");
        }
    }
    out.push_str(&managed);
    upsert_layer4_global(&out, turn_host, turn_port, turns_port)
}

fn upsert_layer4_global(
    existing: &str,
    turn_host: &str,
    turn_port: u16,
    turns_port: u16,
) -> String {
    const BEGIN: &str = "# >>> myownmesh-turn-layer4";
    const END: &str = "# <<< myownmesh-turn-layer4";
    let block = format!(
        "{BEGIN}\n\
         layer4 {{\n\
         \ttcp/:{turns_port} {{\n\
         \t\t@turn tls sni {turn_host}\n\
         \t\troute @turn {{\n\
         \t\t\ttls\n\
         \t\t\tproxy tcp/127.0.0.1:{turn_port}\n\
         \t\t}}\n\
         \t}}\n\
         }}\n\
         {END}\n"
    );
    if let (Some(start), Some(end)) = (existing.find(BEGIN), existing.find(END)) {
        let after = end + END.len();
        let line_start = existing[..start]
            .rfind('\n')
            .map(|index| index + 1)
            .unwrap_or(0);
        let leading = &existing[line_start..start];
        let (replace_from, replacement) = if leading.chars().all(|ch| ch == ' ' || ch == '\t') {
            (line_start, indent(&block, leading))
        } else {
            (start, block)
        };
        return format!(
            "{}{}{}",
            &existing[..replace_from],
            replacement,
            existing[after..].trim_start_matches('\n')
        );
    }

    if let Some(offset) = global_options_open(existing) {
        let global = &existing[offset..];
        let mut depth = 0usize;
        for (relative, ch) in global.char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        let close = offset + relative;
                        return format!(
                            "{}\n{}{}",
                            &existing[..close],
                            indent(&block, "\t"),
                            &existing[close..]
                        );
                    }
                }
                _ => {}
            }
        }
    }
    format!("{{\n{}}}\n\n{existing}", indent(&block, "\t"))
}

/// Return the opening brace of Caddy's global-options block when it is the
/// first meaningful line. Leading comments are allowed and preserved. Caddy
/// permits exactly one global block and requires it before site blocks.
fn global_options_open(input: &str) -> Option<usize> {
    let mut offset = 0usize;
    for line in input.split_inclusive('\n') {
        let meaningful = line.trim_start();
        if meaningful.trim().is_empty() || meaningful.starts_with('#') {
            offset += line.len();
            continue;
        }
        return meaningful
            .starts_with('{')
            .then_some(offset + (line.len() - meaningful.len()));
    }
    None
}

fn backup_path(path: &Path) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".bak-{ts}"));
    PathBuf::from(name)
}

fn indent(s: &str, pad: &str) -> String {
    let mut out = String::new();
    for line in s.lines() {
        out.push_str(pad);
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Resolved signaling port from config; falls back to the 4848 default
/// when there's no config file yet.
fn signaling_port() -> u16 {
    MeshConfig::load()
        .unwrap_or_default()
        .services
        .signaling
        .port
}

// ---- environment probing / actions (best-effort, all echoed) -------------

fn caddyfile_path() -> PathBuf {
    let candidates = caddyfile_candidates();
    for c in &candidates {
        if c.exists() {
            return c.clone();
        }
    }
    candidates
        .into_iter()
        .next()
        .unwrap_or_else(|| PathBuf::from("Caddyfile"))
}

fn caddyfile_candidates() -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let mut v = Vec::new();
        if let Some(prefix) = brew_prefix() {
            v.push(PathBuf::from(format!("{prefix}/etc/Caddyfile")));
        }
        v.push(PathBuf::from("/opt/homebrew/etc/Caddyfile"));
        v.push(PathBuf::from("/usr/local/etc/Caddyfile"));
        v
    }
    #[cfg(target_os = "windows")]
    {
        vec![PathBuf::from(r"C:\Caddy\Caddyfile")]
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        vec![PathBuf::from("/etc/caddy/Caddyfile")]
    }
}

#[cfg(target_os = "macos")]
fn brew_prefix() -> Option<String> {
    let out = Command::new("brew").arg("--prefix").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn caddy_installed() -> bool {
    Command::new("caddy")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

const CADDY_LAYER4_PACKAGE: &str = "github.com/mholt/caddy-l4@v0.1.2";

fn caddy_has_layer4() -> bool {
    Command::new("caddy")
        .args(["list-modules", "--packages"])
        .output()
        .map(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("github.com/mholt/caddy-l4")
        })
        .unwrap_or(false)
}

fn ensure_caddy_layer4() -> Result<()> {
    if caddy_has_layer4() {
        println!("✓ Caddy Layer 4 module already installed.");
        return Ok(());
    }
    println!("Installing the pinned Caddy Layer 4 module for TURN TLS…");
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let managed_service = has_systemd_caddy();
        if managed_service {
            run_sudo("systemctl", &["stop", "caddy"]);
        }
        if !run_sudo(
            "caddy",
            &["add-package", CADDY_LAYER4_PACKAGE, "--keep-backup"],
        ) {
            if managed_service {
                run_sudo("systemctl", &["start", "caddy"]);
            }
            anyhow::bail!("failed to install {CADDY_LAYER4_PACKAGE}");
        }
    }
    #[cfg(not(all(unix, not(target_os = "macos"))))]
    if !run_echo(
        "caddy",
        &["add-package", CADDY_LAYER4_PACKAGE, "--keep-backup"],
    ) {
        anyhow::bail!("failed to install {CADDY_LAYER4_PACKAGE}");
    }
    if !caddy_has_layer4() {
        #[cfg(all(unix, not(target_os = "macos")))]
        if has_systemd_caddy() {
            run_sudo("systemctl", &["start", "caddy"]);
        }
        anyhow::bail!("Caddy was rebuilt but the Layer 4 module is still absent");
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    if has_systemd_caddy() {
        // `add-package` replaces the on-disk binary but does not restart the
        // running process. Bring the known-good old config back immediately;
        // the managed TURN config is validated and reloaded separately.
        run_sudo("systemctl", &["start", "caddy"]);
    }
    println!("✓ Caddy Layer 4 module installed.");
    Ok(())
}

fn configure_firewall(turn_port: u16, turns_port: u16, relay_min: u16, relay_max: u16) {
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let ufw_active = Command::new("ufw")
            .arg("status")
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).contains("Status: active"))
            .unwrap_or(false);
        if ufw_active {
            for rule in [
                "80/tcp".to_string(),
                "443/tcp".to_string(),
                format!("{turn_port}/udp"),
                format!("{turn_port}/tcp"),
                format!("{turns_port}/tcp"),
                format!("{relay_min}:{relay_max}/udp"),
            ] {
                run_sudo("ufw", &["allow", &rule]);
            }
            println!("✓ UFW rules converged.");
            return;
        }

        let firewalld_active = Command::new("systemctl")
            .args(["is-active", "firewalld"])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);
        if firewalld_active {
            for rule in [
                "80/tcp".to_string(),
                "443/tcp".to_string(),
                format!("{turn_port}/udp"),
                format!("{turn_port}/tcp"),
                format!("{turns_port}/tcp"),
                format!("{relay_min}-{relay_max}/udp"),
            ] {
                run_sudo("firewall-cmd", &["--permanent", "--add-port", &rule]);
            }
            run_sudo("firewall-cmd", &["--reload"]);
            println!("✓ firewalld rules converged.");
            return;
        }
    }
    println!(
        "• No active UFW/firewalld detected. Open TCP 80,443,{turn_port},{turns_port} and UDP {turn_port},{relay_min}:{relay_max} in the host firewall and cloud security group."
    );
}

fn reload_caddy(path: &Path) -> Result<()> {
    let cfg = path.to_string_lossy().to_string();

    // Validate first so a typo in the merged file can't take down a
    // running relay. Never apply a configuration that failed validation.
    if !run_echo(
        "caddy",
        &["validate", "--config", &cfg, "--adapter", "caddyfile"],
    ) {
        anyhow::bail!(
            "Caddy rejected {}; the running configuration was not changed",
            path.display()
        );
    }

    // A packaged Caddy (apt / dnf, or Homebrew) runs as a *managed
    // service* that owns the config path we just wrote — and that
    // service is what has to start to bind :443 and provision the
    // certificate. A bare `caddy reload` only talks to an
    // already-running instance, and `caddy start` as a normal user
    // can't bind :443. So drive the service manager first; that's the
    // step that was missing when "TLS isn't working" after install.
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if has_systemd_caddy() {
            // Start now and at boot, then load our config (reload is
            // graceful; restart is the fallback if reload can't).
            run_sudo("systemctl", &["enable", "--now", "caddy"]);
            if run_sudo("systemctl", &["reload", "caddy"])
                || run_sudo("systemctl", &["restart", "caddy"])
            {
                println!("✓ Caddy service is running with the new config.");
                return Ok(());
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if which("brew") && run_echo("brew", &["services", "restart", "caddy"]) {
            println!("✓ Caddy service restarted with the new config.");
            return Ok(());
        }
    }

    // No managed service detected — reload a running instance, else
    // launch one in the background.
    if run_echo(
        "caddy",
        &["reload", "--config", &cfg, "--adapter", "caddyfile"],
    ) {
        println!("✓ Reloaded Caddy.");
        return Ok(());
    }
    println!("• Reload didn't take (Caddy may not be running yet) — starting it…");
    if run_echo(
        "caddy",
        &["start", "--config", &cfg, "--adapter", "caddyfile"],
    ) {
        println!("✓ Started Caddy.");
        return Ok(());
    }
    println!();
    println!("Couldn't start Caddy automatically. Start it yourself:");
    #[cfg(all(unix, not(target_os = "macos")))]
    println!("    sudo systemctl enable --now caddy && sudo systemctl reload caddy");
    #[cfg(target_os = "macos")]
    println!("    brew services restart caddy");
    println!(
        "  or in the foreground:  caddy run --config {} --adapter caddyfile",
        path.display()
    );
    anyhow::bail!("Caddy could not be started with the managed configuration")
}

/// Whether this box runs Caddy as a systemd service — the packaged
/// install path on Debian/Ubuntu/Fedora. If so, that service (not a
/// bare `caddy` invocation) is what owns binding :443 and renewing the
/// cert, so the installer drives it through `systemctl`.
#[cfg(all(unix, not(target_os = "macos")))]
fn has_systemd_caddy() -> bool {
    if !which("systemctl") {
        return false;
    }
    Command::new("systemctl")
        .args(["list-unit-files", "caddy.service"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("caddy.service"))
        .unwrap_or(false)
}

fn try_install_caddy() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        if which("brew") {
            if run_echo("brew", &["install", "caddy"]) {
                return Ok(());
            }
            anyhow::bail!("`brew install caddy` failed");
        }
        anyhow::bail!("Homebrew not found — install it from https://brew.sh first");
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if which("pacman") && run_sudo("pacman", &["-S", "--noconfirm", "caddy"]) {
            return Ok(());
        }
        if which("dnf") && run_sudo("dnf", &["install", "-y", "caddy"]) {
            return Ok(());
        }
        if which("zypper") && run_sudo("zypper", &["install", "-y", "caddy"]) {
            return Ok(());
        }
        if which("apt-get") && install_caddy_apt() {
            return Ok(());
        }
        anyhow::bail!("no supported package manager produced caddy");
    }
    #[cfg(target_os = "windows")]
    {
        if which("choco") && run_echo("choco", &["install", "caddy", "-y"]) {
            return Ok(());
        }
        if which("scoop") && run_echo("scoop", &["install", "caddy"]) {
            return Ok(());
        }
        anyhow::bail!("install Chocolatey or Scoop, or grab Caddy from caddyserver.com");
    }
    #[cfg(not(any(unix, windows)))]
    {
        anyhow::bail!("unsupported platform — see https://caddyserver.com/docs/install");
    }
}

/// Debian/Ubuntu don't ship a current Caddy without its official APT
/// repo. These are the upstream steps verbatim (caddyserver.com).
#[cfg(all(unix, not(target_os = "macos")))]
fn install_caddy_apt() -> bool {
    run_sudo(
        "apt-get",
        &[
            "install",
            "-y",
            "debian-keyring",
            "debian-archive-keyring",
            "apt-transport-https",
            "curl",
        ],
    ) && run_sh(
        "curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
         | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg",
    ) && run_sh(
        "curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
         | sudo tee /etc/apt/sources.list.d/caddy-stable.list",
    ) && run_sudo("apt-get", &["update"])
        && run_sudo("apt-get", &["install", "-y", "caddy"])
}

/// Run a command, echoing it first; returns whether it succeeded.
fn run_echo(cmd: &str, args: &[&str]) -> bool {
    println!("    $ {cmd} {}", args.join(" "));
    match Command::new(cmd).args(args).status() {
        Ok(s) => s.success(),
        Err(e) => {
            println!("      ({cmd} failed to launch: {e})");
            false
        }
    }
}

/// Like [`run_echo`] but prefixes `sudo` unless we're already root.
#[cfg(all(unix, not(target_os = "macos")))]
fn run_sudo(cmd: &str, args: &[&str]) -> bool {
    if is_root() {
        run_echo(cmd, args)
    } else {
        let mut full = Vec::with_capacity(args.len() + 1);
        full.push(cmd);
        full.extend_from_slice(args);
        run_echo("sudo", &full)
    }
}

/// Run a shell pipeline (echoed). Used for the APT key/repo steps that
/// need a pipe; the privileged commands inside carry their own `sudo`.
#[cfg(all(unix, not(target_os = "macos")))]
fn run_sh(script: &str) -> bool {
    println!("    $ {script}");
    Command::new("sh")
        .arg("-c")
        .arg(script)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false)
}

fn which(cmd: &str) -> bool {
    #[cfg(unix)]
    {
        Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {cmd}"))
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        Command::new("where")
            .arg(cmd)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

// ---- printed guidance ----------------------------------------------------

fn print_install_help() {
    let port = signaling_port();
    let path = caddyfile_path();
    println!("Caddy provides signaling WSS and terminates TURN TLS on TCP 5349.");
    println!();
    println!("1) Install Caddy:");
    print_manual_install_steps();
    println!();
    println!("2) Add the Layer 4 module (idempotent):");
    println!("    caddy add-package {CADDY_LAYER4_PACKAGE} --keep-backup");
    println!();
    println!("3) Merge this into your Caddyfile ({}):", path.display());
    println!();
    print!(
        "{}",
        indent(
            &upsert_managed_block(
                "",
                "your-domain.example",
                "turn.your-domain.example",
                port,
                3478,
                5349,
            ),
            "    ",
        )
    );
    println!();
    println!(
        "4) Validate and reload:  caddy validate --config {} --adapter caddyfile && caddy reload --config {} --adapter caddyfile",
        path.display(),
        path.display()
    );
    println!();
    println!("5) Enable services.turn.tcp_enabled and open TCP 80,443,3478,5349 plus UDP 3478 and your relay range in both host and provider firewalls.");
    println!();
    println!("Or let me converge all of it for you:");
    println!("    sudo myownmesh install caddy your-domain.example --turn-domain turn.your-domain.example --public-ip 203.0.113.7");
    println!();
    println!("(`myownmesh caddy path` prints just the Caddyfile location.)");
}

fn print_manual_install_steps() {
    #[cfg(target_os = "macos")]
    {
        println!("    brew install caddy");
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        println!("    # Debian/Ubuntu:");
        println!("    sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl");
        println!("    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg");
        println!("    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list");
        println!("    sudo apt update && sudo apt install -y caddy");
        println!("    # Fedora:  sudo dnf install -y caddy");
        println!("    # Arch:    sudo pacman -S caddy");
    }
    #[cfg(target_os = "windows")]
    {
        println!("    choco install caddy        (or: scoop install caddy)");
    }
    #[cfg(not(any(unix, windows)))]
    {
        println!("    See https://caddyserver.com/docs/install");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_scheme_and_path() {
        assert_eq!(normalize_domain("wss://myownmesh.com"), "myownmesh.com");
        assert_eq!(
            normalize_domain("https://myownmesh.com/foo"),
            "myownmesh.com"
        );
        assert_eq!(normalize_domain("  myownmesh.com/  "), "myownmesh.com");
        assert_eq!(normalize_domain("ws://host:4848"), "host:4848");
        assert_eq!(normalize_domain("myownmesh.com."), "myownmesh.com");
    }

    #[test]
    fn site_block_targets_local_relay() {
        let b = site_block("myownmesh.com", "turn.myownmesh.com", 4848);
        assert!(b.contains("myownmesh.com {"));
        assert!(b.contains("reverse_proxy 127.0.0.1:4848"));
        // Only WebSocket upgrades are proxied; plain hits get a 200 so a
        // WS-only relay's EOF doesn't surface as a 502 on every stray hit.
        assert!(b.contains("header Connection *Upgrade*"));
        assert!(b.contains("handle @ws {"));
        assert!(b.contains("respond \"MyOwnMesh signaling relay"));
    }

    #[test]
    fn upsert_into_empty_has_all_parts() {
        let out = upsert_managed_block("", "myownmesh.com", "turn.myownmesh.com", 4848, 3478, 5349);
        assert!(out.contains("# >>> myownmesh-managed: myownmesh.com"));
        assert!(out.contains("myownmesh.com {"));
        assert!(out.contains("reverse_proxy 127.0.0.1:4848"));
        assert!(out.contains("# <<< myownmesh-managed: myownmesh.com"));
    }

    #[test]
    fn upsert_is_idempotent() {
        let once =
            upsert_managed_block("", "myownmesh.com", "turn.myownmesh.com", 4848, 3478, 5349);
        let twice = upsert_managed_block(
            &once,
            "myownmesh.com",
            "turn.myownmesh.com",
            4848,
            3478,
            5349,
        );
        assert_eq!(once, twice);
    }

    #[test]
    fn upsert_rewrites_port_in_place() {
        let v1 = upsert_managed_block("", "myownmesh.com", "turn.myownmesh.com", 4848, 3478, 5349);
        let v2 = upsert_managed_block(&v1, "myownmesh.com", "turn.myownmesh.com", 9000, 3478, 5349);
        assert!(v2.contains("reverse_proxy 127.0.0.1:9000"));
        assert!(!v2.contains("4848"));
        // Exactly one managed block (begin + end markers = 2 hits).
        assert_eq!(v2.matches("myownmesh-managed: myownmesh.com").count(), 2);
    }

    #[test]
    fn upsert_preserves_user_content() {
        let user = "example.org {\n\trespond \"hi\"\n}\n";
        let out = upsert_managed_block(
            user,
            "myownmesh.com",
            "turn.myownmesh.com",
            4848,
            3478,
            5349,
        );
        // Caddy's single global-options block must remain first, so adding
        // Layer 4 necessarily moves pre-existing site blocks below it.
        assert!(out.contains("respond \"hi\""));
        assert!(out.contains("myownmesh.com {"));
        // Second run leaves everything — user and managed — untouched.
        let again = upsert_managed_block(
            &out,
            "myownmesh.com",
            "turn.myownmesh.com",
            4848,
            3478,
            5349,
        );
        assert_eq!(out, again);
        assert!(again.contains("respond \"hi\""));
    }

    #[test]
    fn upsert_reuses_global_block_after_leading_comments() {
        let input = "# operator note\n\n{\n\temail ops@example.com\n}\n\nexample.org {\n\trespond \"hi\"\n}\n";
        let out = upsert_managed_block(
            input,
            "myownmesh.com",
            "turn.myownmesh.com",
            4848,
            3478,
            5349,
        );
        assert_eq!(out.matches("layer4 {").count(), 1);
        assert_eq!(out.matches("email ops@example.com").count(), 1);
        assert_eq!(out.matches("\n{\n").count(), 1);
        assert_eq!(
            out,
            upsert_managed_block(
                &out,
                "myownmesh.com",
                "turn.myownmesh.com",
                4848,
                3478,
                5349,
            )
        );
    }
}
