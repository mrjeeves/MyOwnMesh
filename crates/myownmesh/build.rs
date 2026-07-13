//! Embed a Windows version resource into `myownmesh.exe`.
//!
//! A bare cargo-built exe carries NO version metadata — no product name,
//! no company, no file description. Anti-malware ML heuristics (the
//! `Trojan:Win32/Bearfoos.A!ml`-style detections) score anonymous,
//! unsigned, networked binaries markedly worse than identified ones, and
//! the daemon is the most RAT-shaped artifact this project ships. This
//! embeds the standard VERSIONINFO block so the exe names itself; code
//! signing (Trusted Signing in the release pipeline) is the other half.
//!
//! Host-gated on purpose: build scripts compile for the HOST, and the
//! release matrix builds the Windows zip on a Windows runner, so
//! `cfg(target_os = "windows")` here pairs with the
//! `[target.'cfg(windows)'.build-dependencies]` gate in Cargo.toml. A
//! cross-compile from a non-Windows host would skip the resource — none
//! of our lanes do that today.

fn main() {
    #[cfg(target_os = "windows")]
    embed_windows_version_resource();
}

#[cfg(target_os = "windows")]
fn embed_windows_version_resource() {
    // FileVersion / ProductVersion are auto-derived from CARGO_PKG_VERSION.
    let mut res = winresource::WindowsResource::new();
    res.set("ProductName", "MyOwnMesh");
    res.set("FileDescription", "MyOwnMesh mesh networking daemon");
    res.set("CompanyName", "MyOwnMesh");
    res.set("InternalName", "myownmesh");
    res.set("OriginalFilename", "myownmesh.exe");
    if let Err(e) = res.compile() {
        // Never fail the build over metadata — surface it and move on.
        println!("cargo:warning=embedding the Windows version resource failed: {e}");
    }
}
