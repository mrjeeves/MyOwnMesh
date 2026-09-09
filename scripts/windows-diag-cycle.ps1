# Test-environment handoff. Run through an independent interactive task/window,
# never as a child of the AMS connection being replaced. No services/settings
# or GUI/game processes are changed. Build first, then activate explicitly.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Stage','Activate','Rollback','Probe')][string]$Action,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-zA-Z0-9-]{1,70}$')][string]$RunId,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExpectedCommit,
    [ValidateSet('Legacy','Guarded')][string]$NackMode = 'Legacy'
)
$ErrorActionPreference = 'Stop'
$meshRepo = 'C:\Users\Admin\MyOwnMesh-video-test'
$amsRepo = 'C:\Users\Admin\AllMyStuff-video-test'
$runsRoot = 'C:\Users\Admin\video-diag-runs'
$run = Join-Path $runsRoot $RunId
$env:CARGO_HOME = 'C:\Users\Admin\.cargo'
$env:RUSTUP_HOME = 'C:\Users\Admin\.rustup'
$env:PATH = "$env:CARGO_HOME\bin;$env:PATH"
$env:MYOWNMESH_HOME = 'C:\Users\Admin\.myownmesh'
$env:ALLMYSTUFF_HOME = 'C:\Users\Admin\.allmystuff'
$env:ALLMYSTUFF_USER_HOME = 'C:\Users\Admin'
$env:ALLMYSTUFF_AUTOUPDATE = '0'
$env:MYOWNMESH_AUTOUPDATE = '0'
$env:ALLMYSTUFF_CWD_LOG = '1'

function Save-State([string]$phase, [string]$detail) {
    [ordered]@{phase=$phase;detail=$detail;utc=[DateTime]::UtcNow.ToString('o');commit=$ExpectedCommit;mode=$NackMode} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $run 'status.json') -Encoding UTF8
    Write-Host "$phase : $detail"
}
function Git-Checked([string]$repo, [string[]]$gitArgs) {
    $result = & git -c "safe.directory=$repo" -C $repo @gitArgs
    if ($LASTEXITCODE -ne 0) { throw "git failed in $repo" }
    return $result
}
function Get-Pair([switch]$AllowMissing) {
    $result = @(Get-CimInstance Win32_Process -Filter "Name='allmystuff-serve.exe' OR Name='myownmesh.exe'")
    $amsCount = @($result | Where-Object Name -eq 'allmystuff-serve.exe').Count
    $meshCount = @($result | Where-Object Name -eq 'myownmesh.exe').Count
    if ((-not $AllowMissing -and ($amsCount -ne 1 -or $meshCount -ne 1)) -or $amsCount -gt 1 -or $meshCount -gt 1) {
        throw 'Expected exactly one diagnostic AMS and one diagnostic Mesh; inspect processes first'
    }
    foreach ($p in $result) {
        $allowed = $p.ExecutablePath -eq "$amsRepo\node\target\release\allmystuff-serve.exe" -or
            $p.ExecutablePath -eq "$meshRepo\target\release\myownmesh.exe" -or
            $p.ExecutablePath.StartsWith("$runsRoot\", [StringComparison]::OrdinalIgnoreCase)
        if (-not $allowed) { throw "Refusing non-diagnostic process: $($p.ExecutablePath)" }
        [ordered]@{name=$p.Name;pid=$p.ProcessId;path=$p.ExecutablePath;created=$p.CreationDate.ToUniversalTime().ToString('o')}
    }
}
function Assert-SameProcess($item) {
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$($item.pid)"
    if (-not $p -or $p.ExecutablePath -ne $item.path -or $p.CreationDate.ToUniversalTime().ToString('o') -ne $item.created) {
        throw "Process changed since staging: $($item.name)"
    }
}
function Stop-Pair($pair) {
    foreach ($item in $pair) { Assert-SameProcess $item }
    $ams = @($pair | Where-Object name -eq 'allmystuff-serve.exe')[0]
    $mesh = @($pair | Where-Object name -eq 'myownmesh.exe')[0]
    # AMS owns the Mesh child/job. Stop this exact test backend, then only
    # its previously verified child if it survives the owner's termination.
    if ($ams) { Stop-Process -Id $ams.pid -ErrorAction Stop }
    Start-Sleep -Milliseconds 700
    if ($mesh -and (Get-Process -Id $mesh.pid -ErrorAction SilentlyContinue)) {
        Assert-SameProcess $mesh
        Stop-Process -Id $mesh.pid -ErrorAction Stop
    }
    $until = [DateTime]::UtcNow.AddSeconds(5)
    $ids = @($pair | ForEach-Object { $_.pid })
    while ($ids.Count -and (Get-Process -Id $ids -ErrorAction SilentlyContinue) -and [DateTime]::UtcNow -lt $until) {
        Start-Sleep -Milliseconds 100
    }
    if (Get-Process -Name allmystuff-serve,myownmesh -ErrorAction SilentlyContinue) {
        throw 'A backend remains or another owner appeared; no unverified process will be stopped'
    }
}
function Launch-Pair([string]$directory, [string]$mode) {
    $env:MYOWNMESH_BIN = Join-Path $directory 'myownmesh.exe'
    $env:ALLMYSTUFF_SERVE_BIN = Join-Path $directory 'allmystuff-serve.exe'
    $env:MYOWNMESH_DIAG_LEGACY_NACK_HISTORY = if ($mode -eq 'Legacy') { '1' } else { '0' }
    Set-Location $amsRepo
    $Host.UI.RawUI.WindowTitle = "AMS diagnostic $RunId - NACK $mode"
    return Start-Process -FilePath $env:ALLMYSTUFF_SERVE_BIN -NoNewWindow -PassThru
}
function Wait-Ready($ams, [string]$directory) {
    $until = [DateTime]::UtcNow.AddSeconds(25)
    while ([DateTime]::UtcNow -lt $until) {
        $ams.Refresh()
        if ($ams.HasExited) { return $false }
        $mesh = @(Get-CimInstance Win32_Process -Filter "Name='myownmesh.exe'" | Where-Object { $_.ExecutablePath -eq "$directory\myownmesh.exe" })
        if ($mesh.Count -eq 1) {
            # Windows PowerShell Start-Process can lose ExitCode after the
            # redirected child exits. Own the Process handle directly.
            $info = New-Object System.Diagnostics.ProcessStartInfo
            $info.FileName = "$directory\myownmesh.exe"
            $info.Arguments = 'ctl status'
            $info.UseShellExecute = $false
            $info.CreateNoWindow = $true
            $info.RedirectStandardOutput = $true
            $info.RedirectStandardError = $true
            $probe = [Diagnostics.Process]::Start($info)
            try {
                $output = $probe.StandardOutput.ReadToEndAsync()
                $errors = $probe.StandardError.ReadToEndAsync()
                if ($probe.WaitForExit(2500)) {
                    $output.Result | Set-Content -LiteralPath "$run\probe.json" -Encoding UTF8
                    $errors.Result | Set-Content -LiteralPath "$run\probe-error.txt" -Encoding UTF8
                    if ($probe.ExitCode -eq 0) {
                        $status = $output.Result | ConvertFrom-Json
                        if ($status.device_id) { return $true }
                    }
                } else { $probe.Kill(); $probe.WaitForExit() }
            } finally { $probe.Dispose() }
        }
        Start-Sleep -Milliseconds 300
    }
    return $false
}

if ($Action -eq 'Stage') {
    if (Test-Path $run) { throw "Run already exists: $run" }
    if ((Git-Checked $meshRepo @('rev-parse','HEAD')) -ne $ExpectedCommit) { throw 'Unexpected Mesh commit' }
    if (@(Git-Checked $meshRepo @('status','--porcelain')).Count) { throw 'Mesh checkout is dirty' }
    $pair = @(Get-Pair)
    $previousMode = 'Guarded'
    $previousMesh = @($pair | Where-Object name -eq 'myownmesh.exe')[0]
    if ($previousMesh.path.StartsWith("$runsRoot\", [StringComparison]::OrdinalIgnoreCase)) {
        $active = Get-Content -LiteralPath "$runsRoot\active.json" -Raw | ConvertFrom-Json
        if ($previousMesh.path -ne "$($active.directory)\myownmesh.exe") { throw 'Cannot verify current A/B mode' }
        $previousMode = $active.mode
    }
    New-Item -ItemType Directory -Path "$run\rollback" -Force | Out-Null
    Start-Transcript -Path "$run\build.log" | Out-Null
    try {
        Save-State 'building' 'Running test remains untouched; measurements during compilation are not comparable'
        foreach ($item in $pair) { Copy-Item -LiteralPath $item.path -Destination "$run\rollback\$($item.name)" }
        $ams = @($pair | Where-Object name -eq 'allmystuff-serve.exe')[0]
        Copy-Item -LiteralPath $ams.path -Destination "$run\allmystuff-serve.exe"
        Push-Location $meshRepo
        try {
            & cargo build --release --locked -j 2 -p myownmesh --features diagnostic-cycle --bin myownmesh-diag
            if ($LASTEXITCODE -ne 0) { throw 'Diagnostic build failed; existing processes left running' }
        } finally { Pop-Location }
        Copy-Item -LiteralPath "$meshRepo\target\release\myownmesh-diag.exe" -Destination "$run\myownmesh.exe"
        $artifacts = @(Get-ChildItem $run -Recurse -Filter '*.exe' | ForEach-Object {
            [ordered]@{path=$_.FullName;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
        })
        [ordered]@{commit=$ExpectedCommit;mode=$NackMode;previousMode=$previousMode;previous=$pair;artifacts=$artifacts} |
            ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "$run\manifest.json" -Encoding UTF8
        # Verify the independent activation script itself is fixed for this run.
        Copy-Item -LiteralPath $PSCommandPath -Destination "$run\cycle.ps1"
        Save-State 'ready' 'Both binaries staged and hashed; original pair still running. Activate explicitly.'
    } catch { Save-State 'build-failed' $_.Exception.Message; throw }
    finally { Stop-Transcript | Out-Null }
    exit
}

$manifest = Get-Content -LiteralPath "$run\manifest.json" -Raw | ConvertFrom-Json
if ($manifest.commit -ne $ExpectedCommit) { throw 'Stage manifest commit mismatch' }
foreach ($artifact in $manifest.artifacts) {
    if ((Get-FileHash -LiteralPath $artifact.path -Algorithm SHA256).Hash -ne $artifact.sha256) { throw 'Staged artifact changed' }
}
if ($Action -eq 'Probe') {
    $pair = @(Get-Pair)
    $ams = @($pair | Where-Object name -eq 'allmystuff-serve.exe')[0]
    $directory = Split-Path -Parent $ams.path
    foreach ($item in $pair) {
        Assert-SameProcess $item
        if ($item.path -ne "$directory\$($item.name)") { throw 'Backend directories differ' }
    }
    if (-not (Wait-Ready (Get-Process -Id $ams.pid) $directory)) { throw 'Readiness probe failed; processes left untouched' }
    Write-Host "Readiness passed; processes left untouched: $directory"
    exit
}
Start-Transcript -Path "$run\activate-$Action-$NackMode.log" -Append | Out-Null
try {
    $pair = @(Get-Pair)
    if ($Action -eq 'Activate') {
        # A failed activation may already have restored this slot's saved
        # binaries with new PIDs. Permit that exact hashed pair on retry.
        $savedPair = @($pair | Where-Object { $_.path -eq "$run\rollback\$($_.name)" })
        if ($savedPair.Count -ne 2) {
            foreach ($item in $manifest.previous) { Assert-SameProcess $item }
        }
        $directory = $run
        $mode = $NackMode
    } else {
        if (@($pair | Where-Object { -not $_.path.StartsWith("$run\", [StringComparison]::OrdinalIgnoreCase) }).Count) { throw 'Rollback requires this run to be active' }
        $directory = "$run\rollback"
        $mode = $manifest.previousMode
    }
    Save-State 'switching' "Stopping only the verified test backend pair; mode=$mode"
    Stop-Pair $pair
    $newAms = Launch-Pair $directory $mode
    if (-not (Wait-Ready $newAms $directory)) {
        # Do not kill any competing/unverified owner. If our pair is still
        # present, restore the exact saved artifacts automatically.
        $failed = @(Get-Pair -AllowMissing)
        if (@($failed | Where-Object { -not $_.path.StartsWith("$directory\", [StringComparison]::OrdinalIgnoreCase) }).Count) { throw 'Unexpected backend owner; inspect before rollback' }
        Stop-Pair $failed
        Save-State 'restoring' 'New backend health check failed; restoring saved binaries'
        $newAms = Launch-Pair "$run\rollback" $manifest.previousMode
        if (-not (Wait-Ready $newAms "$run\rollback")) { throw 'Saved backend failed readiness check; inspect this console' }
        $directory = "$run\rollback"
        $mode = $manifest.previousMode
        Save-State 'rolled-back' 'Saved backend restored; no GUI, game, or settings changes'
    } else {
        Save-State 'active' "AMS and Mesh responding; NACK=$mode. Resume/reconnect the existing test."
    }
    [ordered]@{directory=$directory;mode=$mode;commit=$ExpectedCommit;utc=[DateTime]::UtcNow.ToString('o')} |
        ConvertTo-Json | Set-Content -LiteralPath "$runsRoot\active.json" -Encoding UTF8
} catch { Save-State 'activation-failed' $_.Exception.Message; throw }
finally { Stop-Transcript | Out-Null }
