//! `myownmesh install caddy [<domain>]` and `myownmesh caddy path`.
//!
//! The signaling relay (`myownmesh serve` with `services.signaling`
//! enabled) speaks plain `ws://`. To expose it publicly over `wss://`
//! it needs TLS termination in front, and Caddy is the least-friction
//! option: it provisions and renews a Let's Encrypt certificate on its
//! own. These commands stand that up — print the steps, or, given a
//! domain, install Caddy, write signaling and TURN TLS blocks, and reload
//! Caddy so peers can connect over `wss://` and `turns://`.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use clap::Subcommand;

use myownmesh_core::MeshConfig;

/// `myownmesh install …`
#[derive(Subcommand, Debug)]
pub enum InstallCmd {
    /// Install Caddy for signaling WSS and TURN TLS.
    ///
    /// With no DOMAIN it prints the install steps for your OS plus the
    /// reverse-proxy snippet to paste. With a DOMAIN (e.g. `myownmesh
    /// install caddy myownmesh.com`) it does the lot: installs Caddy if
    /// it's missing, writes a Caddy site that terminates TLS on 443 and
    /// proxies WebSocket upgrades to your relay, binds the relay to
    /// loopback, and starts the Caddy service — so peers can reach it at
    /// `wss://DOMAIN`. Safe to re-run: it only touches its own managed
    /// block and backs the file up first.
    Caddy {
        /// Domain the relay is served on. Omit to just print the steps.
        domain: Option<String>,
        /// DNS name used for TURN TLS. Defaults to `turn.DOMAIN`.
        #[arg(long)]
        turn_domain: Option<String>,
        /// Routable address advertised in TURN allocations. When omitted,
        /// the installer resolves TURN_DOMAIN's IPv4 address.
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
    let config_path = myownmesh_core::dirs::config_path().context("resolve config path")?;
    install_and_configure_at(&config_path, domain, turn_domain, public_ip).await
}

async fn install_and_configure_at(
    config_path: &Path,
    domain: &str,
    turn_domain: Option<&str>,
    public_ip: Option<&str>,
) -> Result<()> {
    // Validate before any config-backed port lookup or signaling IPC.  In
    // particular, the no-daemon fallback must not quarantine/replace a bad
    // config before the installer has had a chance to refuse it.
    ensure_valid_config_for_transaction(config_path)?;
    let host = normalize_domain(domain);
    if host.is_empty() {
        anyhow::bail!("couldn't parse a domain out of {domain:?}");
    }
    let port = signaling_port();
    let turn_host = turn_domain
        .map(normalize_domain)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("turn.{host}"));
    let tls_proxy_port = turn_tls_proxy_port();
    if tls_proxy_port == 0 || tls_proxy_port == 3478 {
        anyhow::bail!(
            "invalid TURN TLS proxy port {tls_proxy_port}; it must be a nonzero port distinct from 3478"
        );
    }

    println!("Setting up Caddy as a wss:// reverse proxy for the signaling relay.");
    println!("  domain : {host}  (TLS on 443)");
    println!("  relay  : 127.0.0.1:{port}  (services.signaling, loopback)");
    println!(
        "  TURN   : {turn_host}:3478 UDP + :5349 TLS (loopback PROXYv2 backend :{tls_proxy_port})"
    );
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

    let caddy_binary_changed = ensure_caddy_layer4()?;

    // 2. Write / merge the Caddyfile (managed blocks only; backed up).
    let path = caddyfile_path();
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let updated = upsert_managed_block(&existing, &host, &turn_host, port, 5349, tls_proxy_port);
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

    // 3. Reload (or start) Caddy only when the binary/config/service state
    // requires it. An identical running install is already converged.
    let caddyfile_changed = updated != existing;
    let caddy_reload = if !caddy_apply_required(
        caddy_binary_changed,
        caddyfile_changed,
        caddy_service_running(),
    ) {
        println!("Caddy module, configuration, and service already converged.");
        Ok(())
    } else {
        reload_caddy(&path)
    };
    if let Err(error) = caddy_reload {
        if updated != existing {
            if !existing.is_empty() {
                std::fs::write(&path, &existing)
                    .with_context(|| format!("restore {}", path.display()))?;
                let _ = reload_caddy(&path);
            } else {
                let _ = std::fs::remove_file(&path);
            }
        }
        return Err(error).context("Caddy configuration was rolled back");
    }

    // 4. Harden the signaling relay: enable it and bind it to loopback so the only
    //    public door is Caddy's TLS — no plaintext ws://host:{port}
    //    straight to the relay. Applied live through the daemon when it's
    //    running; otherwise persisted to config for the next start.
    match crate::cli::ctl::bind_signaling_loopback().await {
        Ok(true) => println!(
            "✓ Signaling relay enabled and bound to 127.0.0.1 (reachable only via Caddy)."
        ),
        Ok(false) => match persist_signaling_loopback() {
            Ok(()) => println!(
                "✓ Set the signaling relay to 127.0.0.1 in config — restart the daemon (or `myownmesh \
                 serve`) to apply."
            ),
            Err(e) => println!(
                "• Couldn't update the signaling relay bind ({e}). Set services.signaling.bind = \
                 \"127.0.0.1\" yourself."
            ),
        },
        Err(e) => println!(
            "• Couldn't reach the daemon to bind the signaling relay to loopback: {e}"
        ),
    }

    // Persist last, because a live ServicesSet can return the daemon's prior
    // snapshot. This keeps the TURN TLS settings from being overwritten while
    // the signaling loopback bind is converged.
    let services = persist_public_services_at(config_path, &turn_host, public_ip, tls_proxy_port)?;
    println!(
        "Saved signaling loopback and TURN TLS backend settings (tcp_enabled=false, tls_proxy_enabled=true)."
    );
    println!(
        "Restart the daemon to bind TURN UDP :{} and loopback PROXYv2 :{}.",
        services.turn.port, services.turn.tls_proxy_port
    );
    configure_firewall(
        services.turn.port,
        5349,
        services.turn.relay_port_min,
        services.turn.relay_port_max,
        services.turn.tcp_enabled,
    )?;

    // 5. What's left for the user.
    println!();
    println!("Done. Peers can now point at  wss://{host}");
    println!();
    println!("Two things still have to be true for TLS to come up:");
    println!("  • DNS — an A/AAAA record for {host} resolves to this server's public IP.");
    println!("  • Firewall — inbound TCP 80 AND 443 open (Caddy needs 80 for the ACME challenge).");
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

/// Persist the public service plan. Caddy terminates public TURN TLS; the
/// daemon therefore keeps plaintext TCP disabled and exposes only its
/// separate loopback PROXYv2 backend.
fn ensure_valid_config_for_transaction(config_path: &Path) -> Result<()> {
    match std::fs::read(config_path) {
        Ok(raw) => {
            serde_json::from_slice::<MeshConfig>(&raw).with_context(|| {
                format!(
                    "refusing to overwrite invalid config {}; repair it or move it aside",
                    config_path.display()
                )
            })?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("read config {}", config_path.display()));
        }
    }

    // `transaction_at` uses the complete loader validation path, including
    // the current schema version, TURN policy, and every configured network
    // policy.  Return a private sentinel from the mutation closure so the
    // validated snapshot is never committed or reformatted.
    const VALIDATION_SENTINEL: &str = "caddy config validation complete";
    match MeshConfig::transaction_at::<()>(config_path, |_| {
        Err(myownmesh_core::Error::Config(VALIDATION_SENTINEL.into()))
    }) {
        Err(myownmesh_core::Error::Config(message)) if message == VALIDATION_SENTINEL => Ok(()),
        Err(error) => Err(anyhow::Error::new(error)).context("validate config"),
        Ok(()) => unreachable!("Caddy validation transaction must return its sentinel"),
    }
}

fn persist_public_services_at(
    config_path: &Path,
    turn_host: &str,
    public_ip: Option<&str>,
    tls_proxy_port: u16,
) -> Result<myownmesh_core::ServicesConfig> {
    use std::net::{IpAddr, ToSocketAddrs};

    // The transaction loader intentionally quarantines corrupt configs and
    // returns defaults.  Refuse before entering it so this installer never
    // replaces an invalid config with a default snapshot.
    ensure_valid_config_for_transaction(config_path)?;

    // DNS and explicit input parsing happen before the transaction lock.  A
    // current configured address remains authoritative when no override was
    // supplied; the candidate is needed only when that field is empty.
    let requested_ip = public_ip
        .map(str::parse::<IpAddr>)
        .transpose()
        .context("parse --public-ip")?;
    let dns_candidate = if requested_ip.is_none() {
        (turn_host, 0)
            .to_socket_addrs()
            .ok()
            .and_then(|addresses| addresses.map(|address| address.ip()).find(IpAddr::is_ipv4))
    } else {
        None
    };

    MeshConfig::transaction_at(config_path, |cfg| {
        let resolved = if let Some(ip) = requested_ip {
            ip
        } else if !cfg.services.turn.public_ip.trim().is_empty() {
            cfg.services
                .turn
                .public_ip
                .parse::<IpAddr>()
                .map_err(|error| {
                    myownmesh_core::Error::Config(format!(
                        "invalid configured TURN public_ip {:?}: {error}",
                        cfg.services.turn.public_ip
                    ))
                })?
        } else {
            dns_candidate.ok_or_else(|| {
                myownmesh_core::Error::Config(format!(
                    "could not resolve {turn_host}; create its A record or pass --public-ip"
                ))
            })?
        };
        cfg.services.signaling.enabled = true;
        cfg.services.signaling.bind = "127.0.0.1".to_string();
        cfg.services.turn.enabled = true;
        cfg.services.turn.tcp_enabled = false;
        cfg.services.turn.tls_proxy_enabled = true;
        cfg.services.turn.tls_proxy_port = tls_proxy_port;
        cfg.services.turn.port = 3478;
        cfg.services.turn.public_ip = resolved.to_string();
        Ok(cfg.services.clone())
    })
    .context("save config")
}

/// Fallback for when the daemon isn't running: persist the loopback bind
/// (and enable signaling) to config.json so it takes effect on next start.
fn persist_signaling_loopback() -> Result<()> {
    MeshConfig::transaction(|cfg| {
        cfg.services.signaling.enabled = true;
        cfg.services.signaling.bind = "127.0.0.1".to_string();
        Ok(())
    })
    .context("save config")
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
fn site_block(host: &str, port: u16) -> String {
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
         }}\n"
    )
}

/// A normal HTTPS site block makes Caddy obtain and load a certificate for a
/// distinct TURN hostname.  The response is intentionally harmless: TURN
/// traffic still uses the Layer 4 listener below, while this site supplies
/// Caddy's certificate automation for the SNI name.  When both services use
/// one hostname, the signaling site already enrolls that certificate and a
/// duplicate site block would be invalid.
fn turn_certificate_site_block(turn_host: &str) -> String {
    format!(
        "# >>> myownmesh-turn-certificate\n\
         {turn_host} {{\n\
         \trespond \"MyOwnMesh TURN TLS certificate enrollment endpoint\" 200\n\
         }}\n\
         # <<< myownmesh-turn-certificate\n"
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
    turns_port: u16,
    tls_proxy_port: u16,
) -> String {
    let begin = begin_marker(host);
    let end = end_marker(host);
    let turn_certificate = if turn_host == host {
        String::new()
    } else {
        turn_certificate_site_block(turn_host)
    };
    let managed = format!(
        "{begin}\n{}{}{end}\n",
        site_block(host, port),
        turn_certificate
    );

    if let Some((b, e, end_len)) = managed_block_bounds(existing) {
        if e > b {
            let end_idx = e + end_len;
            // Swallow one trailing newline after the end marker so
            // repeated runs don't accrue blank lines.
            let after = existing[end_idx..]
                .strip_prefix('\n')
                .unwrap_or(&existing[end_idx..]);
            let mut out = String::with_capacity(existing.len());
            out.push_str(&existing[..b]);
            out.push_str(&managed);
            out.push_str(after);
            return upsert_layer4_global(&out, turn_host, turns_port, tls_proxy_port);
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
    upsert_layer4_global(&out, turn_host, turns_port, tls_proxy_port)
}

/// Find our managed block independent of the domain embedded in its marker.
/// That lets changing `--domain` replace the old block instead of leaving a
/// stale signaling or TURN certificate site behind.
fn managed_block_bounds(existing: &str) -> Option<(usize, usize, usize)> {
    const BEGIN_PREFIX: &str = "# >>> myownmesh-managed:";
    const END_PREFIX: &str = "# <<< myownmesh-managed:";
    let begin = existing.find(BEGIN_PREFIX)?;
    let begin = existing[..begin]
        .rfind('\n')
        .map(|index| index + 1)
        .unwrap_or(0);
    let end = existing[begin..].find(END_PREFIX)? + begin;
    let end_len = existing[end..].find('\n').unwrap_or(existing.len() - end);
    Some((begin, end, end_len))
}

fn turn_tls_proxy_port() -> u16 {
    MeshConfig::load()
        .unwrap_or_default()
        .services
        .turn
        .tls_proxy_port
}

/// Insert or replace the fenced global Caddy Layer 4 route used for TURN
/// over TLS.  The public listener terminates TLS and forwards PROXY protocol
/// v2 to the daemon's separate loopback listener; it never targets UDP/TCP
/// 3478 and the backend port is not a firewall surface.
fn upsert_layer4_global(
    existing: &str,
    turn_host: &str,
    turns_port: u16,
    tls_proxy_port: u16,
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
         \t\t\tproxy {{\n\
         \t\t\t\tproxy_protocol v2\n\
         \t\t\t\tupstream 127.0.0.1:{tls_proxy_port}\n\
         \t\t\t}}\n\
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

    // Caddy permits one global options block before site blocks. Put Layer 4
    // inside it when present; otherwise create the required global block.
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

fn ensure_caddy_layer4() -> Result<bool> {
    if caddy_has_layer4() {
        println!("Caddy Layer 4 module already installed.");
        return Ok(false);
    }
    println!("Installing the pinned Caddy Layer 4 module for TURN TLS...");
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let managed_service = has_systemd_caddy();
        if managed_service {
            run_sudo("systemctl", &["stop", "caddy"]);
        }
        let installed = run_sudo(
            "caddy",
            &["add-package", CADDY_LAYER4_PACKAGE, "--keep-backup"],
        );
        if managed_service {
            run_sudo("systemctl", &["start", "caddy"]);
        }
        if !installed {
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
        anyhow::bail!("Caddy was rebuilt but the Layer 4 module is still absent");
    }
    println!("Caddy Layer 4 module installed.");
    Ok(true)
}

fn caddy_apply_required(module_changed: bool, config_changed: bool, running: bool) -> bool {
    module_changed || config_changed || !running
}

fn caddy_service_running() -> bool {
    #[cfg(all(unix, not(target_os = "macos")))]
    if has_systemd_caddy() {
        return Command::new("systemctl")
            .args(["is-active", "--quiet", "caddy"])
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
    }

    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], 2019)),
        std::time::Duration::from_millis(500),
    )
    .is_ok()
}

fn configure_firewall(
    turn_port: u16,
    turns_port: u16,
    relay_min: u16,
    relay_max: u16,
    tcp_enabled: bool,
) -> Result<()> {
    let mut ports = vec![
        "80/tcp".to_string(),
        "443/tcp".to_string(),
        format!("{turns_port}/tcp"),
        format!("{turn_port}/udp"),
    ];
    if tcp_enabled {
        ports.push(format!("{turn_port}/tcp"));
    }
    if relay_min != 0 {
        ports.push(format!("{relay_min}:{relay_max}/udp"));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let ufw_active = Command::new("ufw")
            .arg("status")
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).contains("Status: active"))
            .unwrap_or(false);
        if ufw_active {
            for port in &ports {
                if !run_sudo_bounded("ufw", &["allow", port.as_str()], 30) {
                    anyhow::bail!("failed to apply UFW rule {port}");
                }
            }
            if relay_min == 0 {
                println!(
                    "Caddy/TURN base UFW rules converged; add the OS ephemeral UDP relay range manually (loopback 3479 remains private)."
                );
            } else {
                println!("Caddy/TURN UFW rules converged (loopback 3479 remains private).");
            }
            return Ok(());
        }
        let firewalld_active = Command::new("systemctl")
            .args(["is-active", "firewalld"])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);
        if firewalld_active {
            for port in &ports {
                if !run_sudo_bounded(
                    "firewall-cmd",
                    &["--permanent", "--add-port", port.as_str()],
                    30,
                ) {
                    anyhow::bail!("failed to apply firewalld rule {port}");
                }
            }
            if !run_sudo_bounded("firewall-cmd", &["--reload"], 30) {
                anyhow::bail!("failed to reload firewalld");
            }
            if relay_min == 0 {
                println!(
                    "Caddy/TURN base firewalld rules converged; add the OS ephemeral UDP relay range manually (loopback 3479 remains private)."
                );
            } else {
                println!("Caddy/TURN firewalld rules converged (loopback 3479 remains private).");
            }
            return Ok(());
        }
    }

    let relay = if relay_min == 0 {
        "the OS ephemeral UDP relay range".to_string()
    } else {
        format!("UDP {relay_min}:{relay_max} relay range")
    };
    println!(
        "No active host firewall detected. Open TCP 80,443,5349 and UDP {turn_port} plus {relay} in the host firewall and provider security group; never open TCP 3479."
    );
    Ok(())
}

fn reload_caddy(path: &Path) -> Result<()> {
    let cfg = path.to_string_lossy().to_string();

    // Validate first so a typo in the merged file can't take down a
    // running relay. Validation failure is returned before any reload.
    let caddy_valid = run_echo_bounded(
        "caddy",
        &["validate", "--config", &cfg, "--adapter", "caddyfile"],
        15,
    );
    if !caddy_valid {
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
            run_sudo_bounded("systemctl", &["enable", "--now", "caddy"], 30);
            if run_sudo_bounded("systemctl", &["reload", "caddy"], 15)
                || run_sudo_bounded("systemctl", &["restart", "caddy"], 30)
            {
                println!("✓ Caddy service is running with the new config.");
                return Ok(());
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if which("brew") && run_echo_bounded("brew", &["services", "restart", "caddy"], 30) {
            println!("✓ Caddy service restarted with the new config.");
            return Ok(());
        }
    }

    // No managed service detected — reload a running instance, else
    // launch one in the background.
    if run_echo_bounded(
        "caddy",
        &["reload", "--config", &cfg, "--adapter", "caddyfile"],
        15,
    ) {
        println!("✓ Reloaded Caddy.");
        return Ok(());
    }
    println!("• Reload didn't take (Caddy may not be running yet) — starting it…");
    if run_echo_bounded(
        "caddy",
        &["start", "--config", &cfg, "--adapter", "caddyfile"],
        30,
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
    anyhow::bail!("couldn't start or reload Caddy")
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

#[cfg(all(unix, not(target_os = "macos")))]
fn run_sudo_bounded(cmd: &str, args: &[&str], timeout_secs: u64) -> bool {
    if is_root() {
        run_echo_bounded(cmd, args, timeout_secs)
    } else {
        let mut full = Vec::with_capacity(args.len() + 1);
        full.push(cmd);
        full.extend_from_slice(args);
        run_echo_bounded("sudo", &full, timeout_secs)
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
    println!("Caddy fronts your plain-ws signaling relay with TLS so peers can use wss://.");
    println!();
    println!("1) Install Caddy:");
    print_manual_install_steps();
    println!();
    println!("2) Add this to your Caddyfile ({}):", path.display());
    println!();
    print!(
        "{}",
        indent(
            &upsert_layer4_global("", "turn.your-domain.example", 5349, 3479),
            "    "
        )
    );
    print!(
        "{}",
        indent(&site_block("your-domain.example", port), "    ")
    );
    print!(
        "{}",
        indent(
            &turn_certificate_site_block("turn.your-domain.example"),
            "    "
        )
    );
    println!();
    println!(
        "3) Reload:  caddy reload --config {} --adapter caddyfile",
        path.display()
    );
    println!();
    println!("Or let me do all three for you:");
    println!("    myownmesh install caddy your-domain.example");
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

/// Run a service-management command with a hard upper bound. A wedged
/// service manager must not strand the installer; a timed-out child is
/// killed before the caller reports failure.
fn run_echo_bounded(cmd: &str, args: &[&str], timeout_secs: u64) -> bool {
    println!("    $ {cmd} {} (timeout {timeout_secs}s)", args.join(" "));
    let mut child = match Command::new(cmd).args(args).spawn() {
        Ok(child) => child,
        Err(error) => {
            println!("      ({cmd} failed to launch: {error})");
            return false;
        }
    };
    let deadline = std::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(timeout_secs))
        .unwrap_or_else(std::time::Instant::now);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                println!("      ({cmd} exceeded {timeout_secs}s)");
                return false;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                println!("      ({cmd} status failed: {error})");
                return false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn test_config_path(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "myownmesh-caddy-{label}-{}-{id}.json",
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
        let b = site_block("myownmesh.com", 4848);
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
        let out = upsert_managed_block("", "myownmesh.com", "turn.myownmesh.com", 4848, 5349, 3479);
        assert!(out.contains("# >>> myownmesh-managed: myownmesh.com"));
        assert!(out.contains("myownmesh.com {"));
        assert!(out.contains("turn.myownmesh.com {"));
        assert!(out.contains("reverse_proxy 127.0.0.1:4848"));
        assert!(out.contains("# <<< myownmesh-managed: myownmesh.com"));
    }

    #[test]
    fn upsert_is_idempotent() {
        let once =
            upsert_managed_block("", "myownmesh.com", "turn.myownmesh.com", 4848, 5349, 3479);
        let twice = upsert_managed_block(
            &once,
            "myownmesh.com",
            "turn.myownmesh.com",
            4848,
            5349,
            3479,
        );
        assert_eq!(once, twice);
    }

    #[test]
    fn upsert_rewrites_port_in_place() {
        let v1 = upsert_managed_block("", "myownmesh.com", "turn.myownmesh.com", 4848, 5349, 3479);
        let v2 = upsert_managed_block(&v1, "myownmesh.com", "turn.myownmesh.com", 9000, 5349, 3479);
        assert!(v2.contains("reverse_proxy 127.0.0.1:9000"));
        assert!(!v2.contains("4848"));
        // Exactly one managed block (begin + end markers = 2 hits).
        assert_eq!(v2.matches("myownmesh-managed: myownmesh.com").count(), 2);
    }

    #[test]
    fn distinct_turn_host_has_one_certificate_site() {
        let out = upsert_managed_block("", "myownmesh.com", "turn.myownmesh.com", 4848, 5349, 3479);
        assert_eq!(out.matches("turn.myownmesh.com {").count(), 1);
        assert_eq!(out.matches("myownmesh-turn-certificate").count(), 2);
        assert!(out.contains("TURN TLS certificate enrollment endpoint"));
    }

    #[test]
    fn same_turn_and_signaling_host_has_no_duplicate_site() {
        let out = upsert_managed_block("", "myownmesh.com", "myownmesh.com", 4848, 5349, 3479);
        assert_eq!(out.matches("myownmesh.com {").count(), 1);
        assert!(!out.contains("myownmesh-turn-certificate"));
    }

    #[test]
    fn changing_host_replaces_managed_certificate_site() {
        let old = upsert_managed_block(
            "",
            "old.example.com",
            "turn.old.example.com",
            4848,
            5349,
            3479,
        );
        let updated = upsert_managed_block(
            &old,
            "new.example.com",
            "turn.new.example.com",
            4848,
            5349,
            3479,
        );
        assert!(!updated.lines().any(|line| line == "old.example.com {"));
        assert!(!updated.lines().any(|line| line == "turn.old.example.com {"));
        assert!(updated.lines().any(|line| line == "new.example.com {"));
        assert!(updated.lines().any(|line| line == "turn.new.example.com {"));
        assert_eq!(updated.matches("myownmesh-managed:").count(), 2);
    }

    #[test]
    fn upsert_preserves_user_content() {
        let user = "example.org {\n\trespond \"hi\"\n}\n";
        let out = upsert_managed_block(
            user,
            "myownmesh.com",
            "turn.myownmesh.com",
            4848,
            5349,
            3479,
        );
        // The required global Layer 4 block precedes site blocks; the
        // operator-owned site remains byte-for-byte intact and in-order.
        assert!(out.contains(user));
        assert!(out.contains("respond \"hi\""));
        assert!(out.contains("myownmesh.com {"));
        // Second run leaves everything — user and managed — untouched.
        let again = upsert_managed_block(
            &out,
            "myownmesh.com",
            "turn.myownmesh.com",
            4848,
            5349,
            3479,
        );
        assert_eq!(out, again);
        assert!(again.contains("respond \"hi\""));
    }

    #[test]
    fn layer4_uses_isolated_proxyv2_backend() {
        let out = upsert_layer4_global("", "turn.myownmesh.com", 5349, 3479);
        assert!(out.contains("layer4 {"));
        assert!(out.contains("tls sni turn.myownmesh.com"));
        assert!(out.contains("proxy_protocol v2"));
        assert!(out.contains("upstream 127.0.0.1:3479"));
        assert!(!out.contains("127.0.0.1:3478"));
        assert_eq!(out.matches("myownmesh-turn-layer4").count(), 2);
    }

    #[test]
    fn layer4_upsert_is_idempotent_and_preserves_global_block() {
        let global = "{\n\tgrace_period 5s\n}\n\nexample.com {\n\trespond ok\n}\n";
        let once = upsert_layer4_global(global, "turn.example.com", 5349, 3479);
        let twice = upsert_layer4_global(&once, "turn.example.com", 5349, 3479);
        assert_eq!(once, twice);
        assert!(twice.starts_with("{\n"));
        assert!(twice.contains("grace_period 5s"));
        assert!(twice.contains("upstream 127.0.0.1:3479"));
    }

    #[test]
    fn identical_running_install_skips_caddy_reload() {
        assert!(!caddy_apply_required(false, false, true));
        assert!(caddy_apply_required(true, false, true));
        assert!(caddy_apply_required(false, true, true));
        assert!(caddy_apply_required(false, false, false));
    }

    #[tokio::test]
    async fn install_caller_rejects_invalid_config_before_side_effects() {
        let path = test_config_path("invalid");
        let before = br#"{"version": "not-a-number"}"#.to_vec();
        std::fs::write(&path, &before).expect("write invalid config");

        let result = install_and_configure_at(
            &path,
            "turn.example.com",
            Some("turn.example.com"),
            Some("203.0.113.8"),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(std::fs::read(&path).expect("read preserved config"), before);
        remove_test_config(&path);
    }

    #[tokio::test]
    async fn install_caller_rejects_unsupported_version_before_side_effects() {
        let path = test_config_path("unsupported-version");
        let mut config = MeshConfig::default();
        config.version = myownmesh_core::config::CONFIG_VERSION + 1;
        let before = serde_json::to_vec_pretty(&config).expect("serialize unsupported config");
        std::fs::write(&path, &before).expect("write unsupported config");

        let result = install_and_configure_at(&path, "turn.example.com", None, None).await;
        assert!(result.is_err());
        assert_eq!(std::fs::read(&path).expect("read preserved config"), before);
        remove_test_config(&path);
    }

    #[tokio::test]
    async fn install_caller_rejects_semantic_invalid_config_before_side_effects() {
        let path = test_config_path("semantic-invalid");
        let mut config = MeshConfig::default();
        config.services.turn.tcp_auth_timeout_ms = 0;
        let before = serde_json::to_vec_pretty(&config).expect("serialize invalid config");
        std::fs::write(&path, &before).expect("write invalid config");

        let result = install_and_configure_at(&path, "turn.example.com", None, None).await;
        assert!(result.is_err());
        assert_eq!(std::fs::read(&path).expect("read preserved config"), before);
        remove_test_config(&path);
    }

    #[test]
    fn public_service_transaction_preserves_disjoint_current_fields() {
        let path = test_config_path("disjoint");
        let mut config = MeshConfig {
            event_capacity: 73,
            ..MeshConfig::default()
        };
        config.services.turn.public_ip = "203.0.113.9".to_string();
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&config).expect("serialize test config"),
        )
        .expect("write test config");

        let services = persist_public_services_at(&path, "turn.invalid", None, 3479)
            .expect("transaction preserves current config");
        let current = MeshConfig::transaction_at(&path, |cfg| Ok(cfg.clone()))
            .expect("read transaction result");
        assert_eq!(current.event_capacity, 73);
        assert_eq!(current.services.turn.public_ip, "203.0.113.9");
        assert_eq!(services.turn.public_ip, "203.0.113.9");
        assert!(current.services.signaling.enabled);
        assert_eq!(current.services.signaling.bind, "127.0.0.1");
        remove_test_config(&path);
    }
}
