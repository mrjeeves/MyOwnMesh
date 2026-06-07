//! `myownmesh` with no subcommand — launch the desktop GUI.
//!
//! MyOwnMesh ships the GUI (`myownmesh-gui`, a Tauri app) and the
//! daemon (`myownmesh`, this binary) as *separate* executables —
//! unlike MyOwnLLM, where a single binary is both the GUI and the
//! CLI. To give the same "run it with no arguments and the app opens"
//! experience, a bare `myownmesh` locates the `myownmesh-gui` binary
//! and hands off to it. The GUI in turn auto-spawns `myownmesh serve`
//! as its child (see the GUI's `daemon_spawn.rs`), so launching the
//! GUI is the only thing the user needs to do.
//!
//! Binary discovery mirrors the GUI's own daemon lookup, inverted:
//!
//! 1. `MYOWNMESH_GUI_BIN` environment variable (manual override).
//! 2. Alongside this executable (`myownmesh-gui` next to `myownmesh`)
//!    — the layout the release bundles ship both halves in.
//! 3. `myownmesh-gui` (or `myownmesh-gui.exe`) on `$PATH`.
//! 4. Dev artefacts in the GUI's own Cargo workspace:
//!    `gui/src-tauri/target/{debug,release}/myownmesh-gui`.

use std::path::PathBuf;
use std::process::{Command, ExitCode};

/// Bare `myownmesh` → open the desktop GUI. Returns the process exit
/// code so `main` can propagate it.
pub fn launch() -> ExitCode {
    // On a headless box the GUI's webview can't attach to a display
    // and the process would exit without printing anything — which
    // looks identical to "the command did nothing". Bail early with a
    // pointer at the headless-friendly entry points, the same way
    // MyOwnLLM does for a bare invocation with no display. The mesh
    // daemon is explicitly meant to run on servers, so this path
    // matters more here than it does for the LLM.
    #[cfg(target_os = "linux")]
    if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
        eprintln!("myownmesh: no DISPLAY or WAYLAND_DISPLAY — can't open the desktop GUI.");
        eprintln!();
        eprintln!("On a headless box, run the daemon directly instead:");
        eprintln!("  myownmesh serve            # run the mesh daemon in the foreground");
        eprintln!("  myownmesh service install  # ...or run it as a background service");
        eprintln!("  myownmesh ctl status       # query a running daemon");
        eprintln!("  myownmesh identity show    # print this device's id");
        eprintln!();
        eprintln!("On a desktop session, ensure DISPLAY (X11) or WAYLAND_DISPLAY is set.");
        return ExitCode::FAILURE;
    }

    let gui = match find_gui_binary() {
        Some(p) => p,
        None => {
            eprintln!("myownmesh: couldn't find the `myownmesh-gui` desktop app.");
            eprintln!();
            eprintln!("Install the GUI bundle from the releases page, point");
            eprintln!("MYOWNMESH_GUI_BIN at its path, or run the daemon headless with");
            eprintln!("`myownmesh serve`. From a source checkout, `just dev` runs the GUI.");
            return ExitCode::FAILURE;
        }
    };

    // Spawn the GUI and wait for it. Inheriting stdio (the default for
    // `Command`) keeps the terminal attached to the app for its
    // lifetime — its logs stream here and Ctrl-C brings it down — the
    // same single-process feel as MyOwnLLM, where the bare invocation
    // *is* the GUI event loop. The GUI tears down its own spawned
    // daemon on exit, so the whole tree comes down together.
    match Command::new(&gui).status() {
        Ok(status) => {
            // Propagate a clean/failing exit where we can. A
            // signal-terminated GUI reports no code (e.g. Ctrl-C, or
            // the user force-quitting the window) — treat that as
            // success so a normal close isn't surfaced as an error.
            match status.code() {
                Some(0) | None => ExitCode::SUCCESS,
                Some(_) => ExitCode::FAILURE,
            }
        }
        Err(e) => {
            eprintln!("myownmesh: failed to launch {}: {e}", gui.display());
            ExitCode::FAILURE
        }
    }
}

/// Platform-specific name of the GUI executable.
fn gui_exe_name() -> &'static str {
    if cfg!(windows) {
        "myownmesh-gui.exe"
    } else {
        "myownmesh-gui"
    }
}

/// Locate the `myownmesh-gui` binary using the documented search order.
fn find_gui_binary() -> Option<PathBuf> {
    let exe = gui_exe_name();

    // 1. Explicit override. Skip a stale path that no longer exists so
    //    a leftover env var can't wedge the launch.
    if let Some(p) = std::env::var_os("MYOWNMESH_GUI_BIN") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }

    // 2. Next to this binary — the release bundles install the daemon
    //    and the GUI side by side, so the sibling path is the common
    //    case for an installed copy.
    if let Ok(current) = std::env::current_exe() {
        if let Some(candidate) = current.parent().map(|dir| dir.join(exe)) {
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    // 3. PATH lookup. Done manually (rather than leaning on `Command`'s
    //    implicit search) so we skip non-existent stale entries and
    //    only return a path we've confirmed exists.
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(exe);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    // 4. Dev artefacts. The GUI is its own Cargo workspace under
    //    `gui/src-tauri`, so its binary builds to
    //    `gui/src-tauri/target/{debug,release}/`. CARGO_MANIFEST_DIR
    //    here is `crates/myownmesh`; the repo root is two parents up.
    //    Debug first, then release — `just dev` builds a debug GUI.
    for profile in ["debug", "release"] {
        if let Some(p) = workspace_gui_path(profile, exe) {
            if p.exists() {
                return Some(p);
            }
        }
    }

    None
}

fn workspace_gui_path(profile: &str, exe: &str) -> Option<PathBuf> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = PathBuf::from(manifest_dir)
        .parent()? // crates/
        .parent()? // MyOwnMesh/
        .join("gui")
        .join("src-tauri")
        .join("target")
        .join(profile)
        .join(exe);
    Some(path)
}
