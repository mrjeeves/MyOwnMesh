//! `myownmesh install caddy [<domain>]` and `myownmesh caddy path`.
//!
//! The signaling relay (`myownmesh serve` with `services.signaling`
//! enabled) speaks plain `ws://`. To expose it publicly over `wss://`
//! it needs TLS termination in front, and Caddy is the least-friction
//! option: it provisions and renews a Let's Encrypt certificate on its
//! own. These commands stand that up — print the steps, or, given a
//! domain, install Caddy, write the reverse-proxy site block pointed at
//! the relay, and reload Caddy so peers can connect over `wss://`.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use clap::Subcommand;

use myownmesh_core::MeshConfig;

/// `myownmesh install …`
#[derive(Subcommand, Debug)]
pub enum InstallCmd {
    /// Install the Caddy reverse proxy in front of the signaling relay.
    ///
    /// With no DOMAIN it prints the install steps for your OS plus the
    /// reverse-proxy snippet to paste. With a DOMAIN (e.g. `myownmesh
    /// install caddy myownmesh.com`) it does the lot: installs Caddy if
    /// it's missing, writes a `DOMAIN { reverse_proxy 127.0.0.1:<port> }`
    /// block pointed at your relay, and reloads Caddy — so peers can
    /// reach the relay over `wss://DOMAIN`. Safe to re-run: it only ever
    /// touches its own managed block and backs the file up first.
    Caddy {
        /// Domain the relay is served on. Omit to just print the steps.
        domain: Option<String>,
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
        InstallCmd::Caddy { domain } => match domain {
            Some(d) => install_and_configure(&d),
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

fn install_and_configure(domain: &str) -> Result<()> {
    let host = normalize_domain(domain);
    if host.is_empty() {
        anyhow::bail!("couldn't parse a domain out of {domain:?}");
    }
    let port = signaling_port();

    println!("Setting up Caddy as a wss:// reverse proxy for the signaling relay.");
    println!("  domain : {host}");
    println!("  relay  : 127.0.0.1:{port}  (services.signaling)");
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

    // 2. Write / merge the Caddyfile (managed block only; backed up).
    let path = caddyfile_path();
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let updated = upsert_managed_block(&existing, &host, port);
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
    reload_caddy(&path);

    // 4. What's left for the user.
    println!();
    println!("Done. Peers can now point at  wss://{host}");
    println!();
    println!("For it to work end to end, make sure:");
    println!("  • DNS — an A/AAAA record for {host} resolves to this server's public IP.");
    println!("  • Firewall — inbound TCP 80 and 443 are open (80 is the ACME challenge).");
    println!("  • Relay — `myownmesh serve` is running with services.signaling.enabled = true.");
    println!();
    println!("Verify:  curl -I https://{host}");
    Ok(())
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

/// The reverse-proxy site block for `host` → local relay `port`.
fn site_block(host: &str, port: u16) -> String {
    format!("{host} {{\n\treverse_proxy 127.0.0.1:{port}\n}}\n")
}

/// Insert or replace *our* managed reverse-proxy block for `host` in an
/// existing Caddyfile, leaving every other line untouched. Idempotent:
/// running again with the same args yields identical output; running
/// with a new port rewrites just the block. We fence our block with
/// comment markers so user-authored config is never disturbed.
fn upsert_managed_block(existing: &str, host: &str, port: u16) -> String {
    let begin = begin_marker(host);
    let end = end_marker(host);
    let managed = format!("{begin}\n{}{end}\n", site_block(host, port));

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
            return out;
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
    out
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

fn reload_caddy(path: &Path) {
    let cfg = path.to_string_lossy().to_string();
    if run_echo(
        "caddy",
        &["reload", "--config", &cfg, "--adapter", "caddyfile"],
    ) {
        println!("✓ Reloaded Caddy.");
        return;
    }
    println!("• Reload didn't take (Caddy may not be running yet) — starting it…");
    if run_echo(
        "caddy",
        &["start", "--config", &cfg, "--adapter", "caddyfile"],
    ) {
        println!("✓ Started Caddy.");
        return;
    }
    println!();
    println!("Couldn't reload or start Caddy automatically. Start it yourself:");
    println!(
        "    caddy run --config {} --adapter caddyfile",
        path.display()
    );
    #[cfg(target_os = "macos")]
    println!("  or:  brew services restart caddy");
    #[cfg(all(unix, not(target_os = "macos")))]
    println!("  or:  sudo systemctl enable --now caddy");
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
    println!("Caddy fronts your plain-ws signaling relay with TLS so peers can use wss://.");
    println!();
    println!("1) Install Caddy:");
    print_manual_install_steps();
    println!();
    println!("2) Add this to your Caddyfile ({}):", path.display());
    println!();
    print!(
        "{}",
        indent(&site_block("your-domain.example", port), "    ")
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
        let b = site_block("myownmesh.com", 4848);
        assert!(b.contains("myownmesh.com {"));
        assert!(b.contains("reverse_proxy 127.0.0.1:4848"));
    }

    #[test]
    fn upsert_into_empty_has_all_parts() {
        let out = upsert_managed_block("", "myownmesh.com", 4848);
        assert!(out.contains("# >>> myownmesh-managed: myownmesh.com"));
        assert!(out.contains("myownmesh.com {"));
        assert!(out.contains("reverse_proxy 127.0.0.1:4848"));
        assert!(out.contains("# <<< myownmesh-managed: myownmesh.com"));
    }

    #[test]
    fn upsert_is_idempotent() {
        let once = upsert_managed_block("", "myownmesh.com", 4848);
        let twice = upsert_managed_block(&once, "myownmesh.com", 4848);
        assert_eq!(once, twice);
    }

    #[test]
    fn upsert_rewrites_port_in_place() {
        let v1 = upsert_managed_block("", "myownmesh.com", 4848);
        let v2 = upsert_managed_block(&v1, "myownmesh.com", 9000);
        assert!(v2.contains("reverse_proxy 127.0.0.1:9000"));
        assert!(!v2.contains("4848"));
        // Exactly one managed block (begin + end markers = 2 hits).
        assert_eq!(v2.matches("myownmesh-managed: myownmesh.com").count(), 2);
    }

    #[test]
    fn upsert_preserves_user_content() {
        let user = "example.org {\n\trespond \"hi\"\n}\n";
        let out = upsert_managed_block(user, "myownmesh.com", 4848);
        assert!(out.starts_with("example.org {"));
        assert!(out.contains("respond \"hi\""));
        assert!(out.contains("myownmesh.com {"));
        // Second run leaves everything — user and managed — untouched.
        let again = upsert_managed_block(&out, "myownmesh.com", 4848);
        assert_eq!(out, again);
        assert!(again.contains("respond \"hi\""));
    }
}
