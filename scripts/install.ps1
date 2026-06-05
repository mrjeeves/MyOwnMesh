# MyOwnMesh end-user installer (Windows).
#
# Tries (in order):
#   1. Download a pre-built release binary from GitHub for the current platform.
#   2. Fall back to building from source via cargo.
#
# Installs both the `myownmesh` daemon/CLI and the `myownmesh-gui`
# desktop app (the GUI is small and makes a bare `myownmesh` open the
# app — pass -NoGui for a daemon-only install).
#
# Usage (PowerShell):
#   irm https://raw.githubusercontent.com/mrjeeves/MyOwnMesh/main/scripts/install.ps1 | iex
#   iex "& { $(irm https://raw.githubusercontent.com/mrjeeves/MyOwnMesh/main/scripts/install.ps1) } -Serve"
#   .\scripts\install.ps1 -DryRun
#   .\scripts\install.ps1 -NoGui      # daemon only, skip the desktop GUI

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Serve,
    [switch]$FromSource,
    [switch]$NoGui,
    [string]$Prefix = "$env:LOCALAPPDATA\Programs\MyOwnMesh",
    [string]$Repo = $(if ($env:MYOWNMESH_REPO) { $env:MYOWNMESH_REPO } else { "mrjeeves/MyOwnMesh" })
)

$ErrorActionPreference = "Stop"

function Log($msg)  { Write-Host "==> $msg" -ForegroundColor Cyan }
function Warn($msg) { Write-Host "!!! $msg" -ForegroundColor Yellow }
function Err($msg)  { Write-Host "xxx $msg" -ForegroundColor Red }

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "x86_64" }
    "ARM64" { "aarch64" }
    default { $env:PROCESSOR_ARCHITECTURE.ToLower() }
}
$asset = "myownmesh-windows-$arch.zip"
$guiAsset = "myownmesh-gui-windows-$arch.zip"

function Install-FromZip([string]$zipPath) {
    if (-not (Test-Path $Prefix)) {
        New-Item -ItemType Directory -Force -Path $Prefix | Out-Null
    }
    Expand-Archive -Path $zipPath -DestinationPath $Prefix -Force
    $exe = Join-Path $Prefix "myownmesh.exe"
    if (-not (Test-Path $exe)) {
        throw "myownmesh.exe not found in $zipPath after extraction"
    }
    Log "Installed: $exe"

    # Add prefix to user PATH if it isn't already there.
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not ($userPath -split ";" | Where-Object { $_ -ieq $Prefix })) {
        Log "Adding $Prefix to user PATH"
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$Prefix", "User")
        $env:Path = "$env:Path;$Prefix"
    }
}

function Install-GuiFromZip([string]$zipPath) {
    if (-not (Test-Path $Prefix)) {
        New-Item -ItemType Directory -Force -Path $Prefix | Out-Null
    }
    Expand-Archive -Path $zipPath -DestinationPath $Prefix -Force
    $exe = Join-Path $Prefix "myownmesh-gui.exe"
    if (-not (Test-Path $exe)) {
        throw "myownmesh-gui.exe not found in $zipPath after extraction"
    }
    Log "Installed: $exe"
}

function Try-Release {
    $api = "https://api.github.com/repos/$Repo/releases/latest"
    Log "Looking up latest release: $api"
    try {
        $release = Invoke-RestMethod -Uri $api -Headers @{ "User-Agent" = "myownmesh-installer" }
    } catch {
        Warn "GitHub releases unreachable (or no release yet): $($_.Exception.Message)"
        return $false
    }
    $match = $release.assets | Where-Object { $_.name -eq $asset } | Select-Object -First 1
    if (-not $match) {
        Warn "No release asset matched $asset."
        return $false
    }
    $url = $match.browser_download_url
    Log "Downloading $url"
    if ($DryRun) { Log "(dry-run) would download $url"; return $true }

    $tmp = New-Item -ItemType Directory -Force -Path (Join-Path $env:TEMP "myownmesh-install-$([guid]::NewGuid())")
    try {
        $zip = Join-Path $tmp $asset
        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
        $shaUrl = "$url.sha256"
        try {
            $shaFile = "$zip.sha256"
            Invoke-WebRequest -Uri $shaUrl -OutFile $shaFile -UseBasicParsing
            $expected = (Get-Content $shaFile -Raw).Split()[0].Trim().ToLower()
            $actual = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
            if ($expected -ne $actual) {
                throw "SHA256 mismatch: expected $expected, got $actual"
            }
            Log "SHA256 OK"
        } catch {
            Warn "No SHA256 sidecar or check failed; skipping integrity check."
        }
        Install-FromZip $zip
        return $true
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

# Best-effort GUI install: fetch the portable `myownmesh-gui` zip and
# drop it next to the daemon. Returns $false (without aborting the
# overall install) if the asset is missing, unreachable, or the
# download fails — the daemon is the half that must succeed.
function Try-ReleaseGui {
    $api = "https://api.github.com/repos/$Repo/releases/latest"
    try {
        $release = Invoke-RestMethod -Uri $api -Headers @{ "User-Agent" = "myownmesh-installer" }
    } catch {
        Warn "GitHub releases unreachable; skipping GUI."
        return $false
    }
    $match = $release.assets | Where-Object { $_.name -eq $guiAsset } | Select-Object -First 1
    if (-not $match) {
        Warn "No GUI asset matched $guiAsset in the latest release."
        return $false
    }
    $url = $match.browser_download_url
    Log "Downloading $url"
    if ($DryRun) { Log "(dry-run) would download $url"; return $true }

    $tmp = New-Item -ItemType Directory -Force -Path (Join-Path $env:TEMP "myownmesh-gui-install-$([guid]::NewGuid())")
    try {
        $zip = Join-Path $tmp $guiAsset
        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
        $shaUrl = "$url.sha256"
        try {
            $shaFile = "$zip.sha256"
            Invoke-WebRequest -Uri $shaUrl -OutFile $shaFile -UseBasicParsing
            $expected = (Get-Content $shaFile -Raw).Split()[0].Trim().ToLower()
            $actual = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
            if ($expected -ne $actual) {
                throw "SHA256 mismatch: expected $expected, got $actual"
            }
            Log "SHA256 OK"
        } catch {
            Warn "No SHA256 sidecar or check failed for GUI; skipping integrity check."
        }
        Install-GuiFromZip $zip
        return $true
    } catch {
        Warn "GUI download/install failed: $($_.Exception.Message)"
        return $false
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

function Build-FromSource {
    Log "Building from source…"
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Err "cargo not found. Install Rust via https://rustup.rs first."
        exit 1
    }
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Err "git is required to build from source."
        exit 1
    }
    if ((Test-Path "Cargo.toml") -and (Test-Path "crates\myownmesh")) {
        $repoDir = (Get-Location).Path
        Log "Using current directory as source: $repoDir"
    } else {
        $repoDir = Join-Path $env:TEMP "MyOwnMesh-$([guid]::NewGuid())"
        Log "Cloning into $repoDir"
        if (-not $DryRun) { git clone --depth 1 "https://github.com/$Repo.git" $repoDir }
    }
    if ($DryRun) { Log "(dry-run) would build in $repoDir"; return }

    Push-Location $repoDir
    try {
        cargo build --release --bin myownmesh
        $built = Join-Path $repoDir "target\release\myownmesh.exe"
        if (-not (Test-Path $built)) {
            Err "Build did not produce $built"
            exit 1
        }
        if (-not (Test-Path $Prefix)) {
            New-Item -ItemType Directory -Force -Path $Prefix | Out-Null
        }
        Copy-Item -Force $built (Join-Path $Prefix "myownmesh.exe")
        Log "Installed: $(Join-Path $Prefix 'myownmesh.exe')"

        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if (-not ($userPath -split ";" | Where-Object { $_ -ieq $Prefix })) {
            [Environment]::SetEnvironmentVariable("Path", "$userPath;$Prefix", "User")
            $env:Path = "$env:Path;$Prefix"
        }
    } finally {
        Pop-Location
    }
}

$installedFromRelease = $false
if ($FromSource -or -not (Try-Release)) {
    Build-FromSource
} else {
    $installedFromRelease = $true
}

# Desktop GUI (myownmesh-gui). On by default; -NoGui skips it. Only
# attempted on the release path — building the GUI from source needs
# the full Tauri/pnpm toolchain, out of scope for this installer.
if (-not $NoGui) {
    if ($installedFromRelease) {
        if (-not (Try-ReleaseGui)) {
            Warn "GUI binary not installed; a bare 'myownmesh' will print a hint until it is. Re-run the installer later, or build it from gui\."
        }
    } elseif ($DryRun) {
        Log "(dry-run) would install the GUI binary ($guiAsset) next to myownmesh"
    } else {
        Warn "Built the daemon from source; skipping the GUI binary (needs the Tauri/pnpm toolchain)."
        Warn "Build it with:  cd gui; pnpm install; pnpm tauri build"
    }
}

if ($Serve -and -not $DryRun) {
    Log "Launching myownmesh serve…"
    & (Join-Path $Prefix "myownmesh.exe") serve
    exit $LASTEXITCODE
}

if (-not $NoGui) {
    Log "Done. Try: myownmesh (opens the GUI) | myownmesh serve | myownmesh ctl status"
} else {
    Log "Done. Try: myownmesh serve | myownmesh ctl status | myownmesh identity show"
}
Log "Open a new terminal so the updated PATH takes effect."
