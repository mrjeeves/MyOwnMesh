[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet("callback-flow", "direct", "turn", "media", "reconnect", "multi-peer", "multi-mesh", "all")]
    [string]$Scenario,

    [ValidateRange(1, [int]::MaxValue)]
    [Nullable[int]]$Samples,

    [ValidateRange(1, [int]::MaxValue)]
    [Nullable[int]]$Flows,

    [ValidateRange(1, [int]::MaxValue)]
    [Nullable[int]]$PayloadBytes,

    [ValidateRange(1, [int]::MaxValue)]
    [Nullable[int]]$MultiPeerCount,

    [ValidateRange(1, [int]::MaxValue)]
    [Nullable[int]]$MultiMeshCount,

    [ValidateRange(1, [int]::MaxValue)]
    [Nullable[int]]$CandidatesPerMesh
)

$ErrorActionPreference = "Stop"

$repoPath = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$repoWsl = (& wsl.exe -d Ubuntu-24.04 -- wslpath -a $repoPath).Trim()
if (-not $repoWsl) {
    throw "Could not resolve the repository path inside WSL."
}
if ($repoWsl.Contains("'")) {
    throw "The repository path cannot contain a single quote."
}
$quotedRepo = "'$repoWsl'"
$targetDir = "/tmp/mom-arc03f"

function Invoke-MeasuredTest {
    param(
        [Parameter(Mandatory)]
        [string]$Label,

        [Parameter(Mandatory)]
        [string]$CargoTargetArguments,

        [Parameter(Mandatory)]
        [string]$TestName,

        [switch]$Ignored,

        [hashtable]$Environment = @{}
    )

    $environmentPrefix = @(
        "CARGO_TARGET_DIR=$targetDir",
        "CARGO_INCREMENTAL=0",
        "CARGO_PROFILE_TEST_DEBUG=0"
    )
    $buildCommand = "cd $quotedRepo && env $($environmentPrefix -join ' ') /root/.cargo/bin/cargo test $CargoTargetArguments --no-run --message-format=json"
    $buildOutput = & wsl.exe -d Ubuntu-24.04 -- bash -lc $buildCommand
    if ($LASTEXITCODE -ne 0) {
        throw "Measurement scenario '$Label' failed to build with exit code $LASTEXITCODE."
    }

    $executables = @(
        foreach ($line in $buildOutput) {
            try {
                $record = $line | ConvertFrom-Json -ErrorAction Stop
                if ($record.reason -eq "compiler-artifact" -and $record.executable) {
                    $record.executable
                }
            } catch {
                continue
            }
        }
    )
    if ($executables.Count -ne 1) {
        throw "Measurement scenario '$Label' expected one test executable and found $($executables.Count)."
    }

    foreach ($entry in $Environment.GetEnumerator()) {
        $environmentPrefix += "$($entry.Key)=$($entry.Value)"
    }
    $ignoredArgument = if ($Ignored) { " --ignored" } else { "" }
    $testExecutable = $executables[0]
    if ($testExecutable.Contains("'")) {
        throw "The test executable path cannot contain a single quote."
    }
    $command = "cd $quotedRepo && env $($environmentPrefix -join ' ') /usr/bin/time -v '$testExecutable' '$TestName' --exact$ignoredArgument --nocapture --test-threads=1"

    Write-Output "arc03f_measurement_begin scenario=$Label commit=$(git -C $repoPath rev-parse HEAD)"
    & wsl.exe -d Ubuntu-24.04 -- bash -lc $command
    if ($LASTEXITCODE -ne 0) {
        throw "Measurement scenario '$Label' failed with exit code $LASTEXITCODE."
    }
    Write-Output "arc03f_measurement_end scenario=$Label"
}

$selected = if ($Scenario -eq "all") {
    @("callback-flow", "direct", "turn", "media", "reconnect", "multi-peer", "multi-mesh")
} else {
    @($Scenario)
}

if ($selected -contains "callback-flow") {
    if ($null -eq $Samples -or $null -eq $Flows -or $null -eq $PayloadBytes) {
        throw "callback-flow requires explicit -Samples, -Flows, and -PayloadBytes workload inputs."
    }
}
if ($selected -contains "multi-peer" -and $null -eq $MultiPeerCount) {
    throw "multi-peer requires an explicit -MultiPeerCount workload input."
}
if ($selected -contains "multi-mesh" -and ($null -eq $MultiMeshCount -or $null -eq $CandidatesPerMesh)) {
    throw "multi-mesh requires explicit -MultiMeshCount and -CandidatesPerMesh workload inputs."
}

foreach ($item in $selected) {
    switch ($item) {
        "callback-flow" {
            Invoke-MeasuredTest -Label $item -Environment @{
                MYOWNMESH_ARC03_OBSERVE_SAMPLES = $Samples
                MYOWNMESH_ARC03_OBSERVE_FLOWS = $Flows
                MYOWNMESH_ARC03_OBSERVE_PAYLOAD_BYTES = $PayloadBytes
            } -CargoTargetArguments "-p myownmesh-core --lib" -TestName "transport::webrtc::tests::v4_arc03_measure_callback_classes_without_selecting_a_budget" -Ignored
        }
        "direct" {
            Invoke-MeasuredTest -Label $item -Environment @{
                MYOWNMESH_ARC03_OBSERVE_RAW = 1
            } -CargoTargetArguments "-p myownmesh-core --lib" -TestName "transport::webrtc::tests::loopback_handshake_opens_data_channel"
        }
        "turn" {
            Invoke-MeasuredTest -Label $item -Environment @{
                MYOWNMESH_ARC03_OBSERVE_RAW = 1
            } -CargoTargetArguments "-p myownmesh-services --test turn_webrtc_endpoint_auth" -TestName "turn_selected_session_authenticates_endpoints_before_bidirectional_data"
        }
        "media" {
            Invoke-MeasuredTest -Label $item -CargoTargetArguments "-p myownmesh-core --lib" -TestName "transport::webrtc::tests::lanes_are_lifecycle_managed_not_pre_pooled"
        }
        "reconnect" {
            Invoke-MeasuredTest -Label $item -CargoTargetArguments "-p myownmesh-core --test reconnect_in_place" -TestName "in_place_reconnect_does_not_announce_a_leave"
        }
        "multi-peer" {
            Invoke-MeasuredTest -Label $item -Environment @{
                SILENT_SCALE_SPOKES = $MultiPeerCount
            } -CargoTargetArguments "-p myownmesh-core --test silent_area_scale" -TestName "silent_area_soak" -Ignored
        }
        "multi-mesh" {
            Invoke-MeasuredTest -Label $item -Environment @{
                MYOWNMESH_ARC03_OBSERVE_MESHES = $MultiMeshCount
                MYOWNMESH_ARC03_OBSERVE_CANDIDATES_PER_MESH = $CandidatesPerMesh
            } -CargoTargetArguments "-p myownmesh-core --lib" -TestName "runtime::attempt::tests::v4_arc03f_measure_multi_mesh_connector_scopes_without_selecting_a_budget" -Ignored
        }
    }
}

Write-Output "No production capacity, weight, close-observation, or flow value is proposed by this raw measurement run."
