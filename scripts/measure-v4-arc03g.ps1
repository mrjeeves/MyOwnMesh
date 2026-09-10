[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet(
        "callback-flow",
        "flow-fairness",
        "direct",
        "turn",
        "data-only",
        "h264",
        "opus",
        "reconnect",
        "multi-peer",
        "multi-mesh",
        "close-success",
        "close-error",
        "candidate-burst",
        "all"
    )]
    [string]$Scenario,

    [Parameter(Mandatory)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$Repeats,

    [ValidateRange(1, [int]::MaxValue)]
    [Nullable[int]]$Samples,

    [ValidateRange(1, [int]::MaxValue)]
    [Nullable[int]]$Flows,

    [ValidateRange(1, [int]::MaxValue)]
    [Nullable[int]]$PayloadBytes,

    [ValidateRange(1, [int]::MaxValue)]
    [Nullable[int]]$SaturatedUnits,

    [ValidateRange(1, [int]::MaxValue)]
    [Nullable[int]]$LatencyUnits,

    [ValidateRange(1, [int]::MaxValue)]
    [Nullable[int]]$MultiPeerCount,

    [ValidateRange(1, [int]::MaxValue)]
    [Nullable[int]]$MultiMeshCount,

    [ValidateRange(1, [int]::MaxValue)]
    [Nullable[int]]$CandidatesPerMesh,

    [ValidateRange(1, [int]::MaxValue)]
    [Nullable[int]]$CandidateCount
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
$targetDir = "/tmp/mom-arc03g-measure"
$sourceCommit = (git -C $repoPath rev-parse HEAD).Trim()

function Invoke-WslBash {
    param(
        [Parameter(Mandatory)]
        [string]$Command
    )

    # Windows PowerShell 5 maps a native program's stderr to its error stream.
    # Cargo and /usr/bin/time both use stderr for ordinary status output, so
    # ErrorActionPreference=Stop would otherwise abort a successful run before
    # LASTEXITCODE can be checked.
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = @(& wsl.exe -d Ubuntu-24.04 -- bash -lc $Command 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    [pscustomobject]@{
        ExitCode = $exitCode
        Output = $output
    }
}

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
        "CARGO_PROFILE_DEV_DEBUG=0",
        "CARGO_PROFILE_TEST_DEBUG=0"
    )
    $buildCommand = "cd $quotedRepo && env $($environmentPrefix -join ' ') /root/.cargo/bin/cargo test $CargoTargetArguments --no-run --message-format=json"
    $buildResult = Invoke-WslBash -Command $buildCommand
    if ($buildResult.ExitCode -ne 0) {
        $buildResult.Output | Write-Output
        throw "Measurement scenario '$Label' failed to build with exit code $($buildResult.ExitCode)."
    }
    $buildOutput = $buildResult.Output

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

    $listCommand = "cd $quotedRepo && '$testExecutable' '$TestName' --exact$ignoredArgument --list"
    $listResult = Invoke-WslBash -Command $listCommand
    if ($listResult.ExitCode -ne 0) {
        $listResult.Output | Write-Output
        throw "Measurement scenario '$Label' failed to enumerate its exact test."
    }
    $listOutput = $listResult.Output
    $expectedListing = "${TestName}: test"
    $listedTests = @($listOutput | Where-Object { $_ -eq $expectedListing })
    if ($listedTests.Count -ne 1) {
        throw "Measurement scenario '$Label' expected one exact test and found $($listedTests.Count)."
    }

    for ($iteration = 0; $iteration -lt $Repeats; $iteration++) {
        $command = "cd $quotedRepo && env $($environmentPrefix -join ' ') MYOWNMESH_ARC03_OBSERVE_ITERATION=$iteration /usr/bin/time -v '$testExecutable' '$TestName' --exact$ignoredArgument --nocapture --test-threads=1"
        Write-Output "arc03g_measurement_begin scenario=$Label iteration=$iteration commit=$sourceCommit"
        $runResult = Invoke-WslBash -Command $command
        $runResult.Output | Write-Output
        if ($runResult.ExitCode -ne 0) {
            throw "Measurement scenario '$Label' iteration $iteration failed with exit code $($runResult.ExitCode)."
        }
        Write-Output "arc03g_measurement_end scenario=$Label iteration=$iteration"
    }
}

$selected = if ($Scenario -eq "all") {
    @(
        "callback-flow",
        "flow-fairness",
        "direct",
        "turn",
        "data-only",
        "h264",
        "opus",
        "reconnect",
        "multi-peer",
        "multi-mesh",
        "close-success",
        "close-error",
        "candidate-burst"
    )
} else {
    @($Scenario)
}

if ($selected -contains "callback-flow") {
    if ($null -eq $Samples -or $null -eq $Flows -or $null -eq $PayloadBytes) {
        throw "callback-flow requires explicit -Samples, -Flows, and -PayloadBytes inputs."
    }
}
if ($selected -contains "flow-fairness") {
    if ($null -eq $SaturatedUnits -or $null -eq $LatencyUnits -or $null -eq $PayloadBytes) {
        throw "flow-fairness requires explicit -SaturatedUnits, -LatencyUnits, and -PayloadBytes inputs."
    }
}
if ($selected -contains "multi-peer" -and $null -eq $MultiPeerCount) {
    throw "multi-peer requires an explicit -MultiPeerCount input."
}
if ($selected -contains "multi-mesh" -and ($null -eq $MultiMeshCount -or $null -eq $CandidatesPerMesh)) {
    throw "multi-mesh requires explicit -MultiMeshCount and -CandidatesPerMesh inputs."
}
if ($selected -contains "candidate-burst" -and $null -eq $CandidateCount) {
    throw "candidate-burst requires an explicit -CandidateCount input."
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
        "flow-fairness" {
            Invoke-MeasuredTest -Label $item -Environment @{
                MYOWNMESH_ARC03_OBSERVE_SATURATED_UNITS = $SaturatedUnits
                MYOWNMESH_ARC03_OBSERVE_LATENCY_UNITS = $LatencyUnits
                MYOWNMESH_ARC03_OBSERVE_PAYLOAD_BYTES = $PayloadBytes
            } -CargoTargetArguments "-p myownmesh-core --lib" -TestName "transport::webrtc::tests::v4_arc03g_measure_saturated_flow_fairness_without_selecting_budget" -Ignored
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
        "data-only" {
            Invoke-MeasuredTest -Label $item -Environment @{
                MYOWNMESH_ARC03_OBSERVE_RAW = 1
            } -CargoTargetArguments "-p myownmesh-core --lib" -TestName "transport::webrtc::tests::v4_arc03h_data_only_and_generic_realtime_without_flows_allocate_no_media_lines" -Ignored
        }
        "h264" {
            Invoke-MeasuredTest -Label $item -CargoTargetArguments "-p myownmesh-core --lib" -TestName "transport::webrtc::tests::v4_arc03_guarded_video_reordered_unit_transfers_exact_output_claim"
        }
        "opus" {
            Invoke-MeasuredTest -Label $item -CargoTargetArguments "-p myownmesh-core --lib" -TestName "transport::webrtc::session_flow::tests::v4_macro1_a_an_encoding_names_a_family_not_a_payload_type"
        }
        "reconnect" {
            Invoke-MeasuredTest -Label $item -CargoTargetArguments "-p myownmesh-core --features transport-lab --test reconnect_in_place" -TestName "in_place_reconnect_does_not_announce_a_leave"
        }
        "multi-peer" {
            Invoke-MeasuredTest -Label $item -Environment @{
                SILENT_SCALE_SPOKES = $MultiPeerCount
            } -CargoTargetArguments "-p myownmesh-core --features transport-lab --test silent_area_scale" -TestName "silent_area_soak" -Ignored
        }
        "multi-mesh" {
            Invoke-MeasuredTest -Label $item -Environment @{
                MYOWNMESH_ARC03_OBSERVE_MESHES = $MultiMeshCount
                MYOWNMESH_ARC03_OBSERVE_CANDIDATES_PER_MESH = $CandidatesPerMesh
                MYOWNMESH_ARC03_OBSERVE_RAW = 1
            } -CargoTargetArguments "-p myownmesh-core --lib" -TestName "runtime::attempt::tests::v4_arc03_mesh_scopes_share_one_grant_and_creation_does_not_multiply_it"
        }
        "close-success" {
            Invoke-MeasuredTest -Label $item -Environment @{
                MYOWNMESH_ARC03_OBSERVE_RAW = 1
            } -CargoTargetArguments "-p myownmesh-core --lib" -TestName "transport::webrtc::tests::v4_arc03_cancelled_construction_closes_partial_native_peer" -Ignored
        }
        "close-error" {
            Invoke-MeasuredTest -Label $item -Environment @{
                MYOWNMESH_ARC03_OBSERVE_RAW = 1
            } -CargoTargetArguments "-p myownmesh-core --lib" -TestName "transport::webrtc::tests::v4_arc03_cancelled_construction_with_native_close_error_retains_exact_claim" -Ignored
        }
        "candidate-burst" {
            Invoke-MeasuredTest -Label $item -Environment @{
                MYOWNMESH_ARC03_OBSERVE_CANDIDATES = $CandidateCount
            } -CargoTargetArguments "-p myownmesh-core --lib" -TestName "transport::webrtc::tests::v4_arc03g_measure_candidate_burst_without_selecting_budget" -Ignored
        }
    }
}

Write-Output "Raw observations only. No production capacity, weight, queue, byte, or flow value is proposed."
