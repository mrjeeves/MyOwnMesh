# Install dev prerequisites for MyOwnMesh on Windows.
#
# Currently: just Rust (via rustup). The crate set is pure Rust with
# no system deps required for `cargo build --workspace`.
#
# Idempotent: re-running is cheap and safe.

# Default ErrorActionPreference is "Stop" so missing cmdlets / typos
# raise loudly. We DELIBERATELY do not set it globally — under "Stop",
# PowerShell treats any stderr output from a native command as a
# terminating error, and `rustup` writes status lines like "info:
# component X is up to date" to stderr. Use `Invoke-Native` below
# for native commands; cmdlets get the default Stop behavior.

function Bold([string]$msg) {
    Write-Host $msg -ForegroundColor White
}

# Run a native executable, ignoring its stderr-as-error semantics.
# Tunnels through cmd.exe so PowerShell never sees the stderr stream
# directly — the alternative ($ErrorActionPreference = "Continue"
# around every call) is fragile and easy to forget.
function Invoke-Native {
    param([Parameter(Mandatory)] [string] $Exe, [string[]] $Args)
    $argLine = ($Args | ForEach-Object { '"' + $_ + '"' }) -join ' '
    # cmd /c runs the command, prints both stdout and stderr to the
    # console, and returns the process exit code as cmd's exit code.
    & cmd.exe /c "$Exe $argLine"
    return $LASTEXITCODE
}

function Ensure-Rustup {
    if (Get-Command rustup -ErrorAction SilentlyContinue) {
        return
    }
    Bold "-> installing rustup (Rust toolchain manager)"
    $installer = Join-Path $env:TEMP "rustup-init.exe"
    Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $installer
    $code = Invoke-Native -Exe $installer -Args @("-y", "--no-modify-path")
    if ($code -ne 0) { throw "rustup-init failed with code $code" }
    # Add Cargo bin to PATH for this session so subsequent rustup calls work.
    $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
}

function Ensure-Toolchain {
    Bold "-> ensuring pinned toolchain is installed"
    $code = Invoke-Native -Exe "rustup" -Args @("show")
    if ($code -ne 0) { throw "rustup show failed ($code)" }
}

function Ensure-Components {
    Bold "-> ensuring rustfmt + clippy are installed"
    # rustup writes "info: component X is up to date" to stderr on
    # the no-op path. Invoke-Native shields us from PowerShell's
    # native-stderr-as-error behavior.
    $code = Invoke-Native -Exe "rustup" -Args @("component", "add", "rustfmt", "clippy")
    if ($code -ne 0) { throw "rustup component add failed ($code)" }
}

# Make missing cmdlets / typos in THIS script abort, but not native-
# command stderr (see comment at top).
$ErrorActionPreference = "Stop"

Ensure-Rustup
Ensure-Toolchain
Ensure-Components
Bold "OK setup complete - try 'just build'"
