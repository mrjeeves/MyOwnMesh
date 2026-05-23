# Install dev prerequisites for MyOwnMesh on Windows.
#
# Currently: just Rust (via rustup). The crate set is pure Rust with
# no system deps required for `cargo build --workspace`.
#
# Idempotent: re-running is cheap and safe.

$ErrorActionPreference = "Stop"

function Bold([string]$msg) {
    Write-Host $msg -ForegroundColor White
}

function Ensure-Rustup {
    if (Get-Command rustup -ErrorAction SilentlyContinue) {
        return
    }
    Bold "-> installing rustup (Rust toolchain manager)"
    $installer = Join-Path $env:TEMP "rustup-init.exe"
    Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $installer
    & $installer -y --no-modify-path
    if ($LASTEXITCODE -ne 0) { throw "rustup-init failed with code $LASTEXITCODE" }
    # Add Cargo bin to PATH for this session so subsequent rustup calls work.
    $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
}

function Ensure-Toolchain {
    Bold "-> ensuring pinned toolchain is installed"
    rustup show
    if ($LASTEXITCODE -ne 0) { throw "rustup show failed" }
}

function Ensure-Components {
    Bold "-> ensuring rustfmt + clippy are installed"
    rustup component add rustfmt clippy 2>$null | Out-Null
}

Ensure-Rustup
Ensure-Toolchain
Ensure-Components
Bold "OK setup complete - try 'just build'"
