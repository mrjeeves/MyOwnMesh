# Native Windows observations for the explicitly owned live-device processes.
# The host driver owns launch/cancellation. This collector never sends signals.
# A new owner may register creationTimeUtcTicks=null. Its first observation is
# unconfirmed/Freeze until a new manifest pins the returned ticks. The driver
# must retain its original ChildProcess and check it has not exited before
# registration and before pinning; PID alone is not a launch ownership proof.
# This is cooperative telemetry, not an OS reservation/enforcement mechanism.
# Synchronous OS reads/stdout can stall: the driver must also guard the sampler
# heartbeat/deadline independently and stop only its own sessions on failure.
[CmdletBinding()]
param([string]$PolicyPath, [string]$ManifestPath)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-ResourceKeys($Value, [string[]]$Keys) {
    if ($null -eq $Value -or $Value -isnot [pscustomobject]) { throw 'invalid_object' }
    $actual = @($Value.PSObject.Properties.Name)
    if ($actual.Count -ne $Keys.Count) { throw 'invalid_keys' }
    foreach ($key in $Keys) { if ($actual -cnotcontains $key) { throw 'invalid_keys' } }
}

function Assert-ResourceInteger($Value, [long]$Minimum, [long]$Maximum) {
    if ($null -eq $Value -or $Value -is [bool] -or $Value -is [string] -or
        $Value -isnot [ValueType]) { throw 'invalid_integer' }
    $number = [double]$Value
    if ([double]::IsNaN($number) -or [double]::IsInfinity($number) -or
        $number -lt $Minimum -or $number -gt $Maximum -or [Math]::Floor($number) -ne $number) {
        throw 'invalid_integer'
    }
}

function Assert-ResourceCounter($Value) {
    if ($null -eq $Value -or $Value -is [bool] -or $Value -is [string] -or
        $Value -isnot [ValueType]) { throw 'invalid_counter' }
    $number = [double]$Value
    if ([double]::IsNaN($number) -or [double]::IsInfinity($number) -or $number -lt 0) {
        throw 'invalid_counter'
    }
}

function Assert-ResourceLabel($Value) {
    if ($Value -isnot [string] -or $Value -cnotmatch '^[A-Za-z0-9_.-]{1,64}$') {
        throw 'invalid_label'
    }
}

function Read-ResourceJson([string]$Path, [int]$MaxBytes) {
    # A shared read permits atomic replacement; a partially rewritten file is
    # refused. No size_hint or file-length-controlled unbounded allocation.
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        if ($stream.Length -gt $MaxBytes) { throw 'input_limit' }
        $bytes = New-Object byte[] ($MaxBytes + 1)
        $count = 0
        do {
            $read = $stream.Read($bytes, $count, $bytes.Length - $count)
            $count += $read
        } while ($read -gt 0 -and $count -le $MaxBytes)
        if ($count -gt $MaxBytes) { throw 'input_limit' }
        $utf8 = New-Object Text.UTF8Encoding($false, $true)
        return ($utf8.GetString($bytes, 0, $count) | ConvertFrom-Json)
    } finally { $stream.Dispose() }
}

function Assert-ResourcePolicy($Policy) {
    Assert-ResourceKeys $Policy @('schema','runId','artifactRoot','maxRegisteredOwners',
        'maxLiveProcesses','maxFiles','maxInputBytes','maxOutputBytes','maxSamples',
        'maxDurationMs','sampleIntervalMs','maxSweepMs','maxManifestAgeMs',
        'maxPrivateBytes','maxWorkingSetBytes','minAvailablePhysicalBytes',
        'minAvailableCommitBytes','maxArtifactBytes','maxLogBytes','minDiskFreeBytes')
    if ($Policy.schema -cne 'myownmesh-resource-policy/v1') { throw 'policy_schema' }
    Assert-ResourceLabel $Policy.runId
    foreach ($key in @('maxPrivateBytes','maxWorkingSetBytes','minAvailablePhysicalBytes',
        'minAvailableCommitBytes','maxArtifactBytes','maxLogBytes','minDiskFreeBytes')) {
        Assert-ResourceInteger $Policy.$key 1 9007199254740991
    }
    Assert-ResourceInteger $Policy.maxRegisteredOwners 1 4096
    Assert-ResourceInteger $Policy.maxLiveProcesses 1 $Policy.maxRegisteredOwners
    Assert-ResourceInteger $Policy.maxFiles 0 32768
    Assert-ResourceInteger $Policy.maxInputBytes 1 16777216
    Assert-ResourceInteger $Policy.maxOutputBytes 2048 9007199254740991
    Assert-ResourceInteger $Policy.maxSamples 1 100000
    Assert-ResourceInteger $Policy.maxDurationMs 1 86400000
    Assert-ResourceInteger $Policy.sampleIntervalMs 1 60000
    Assert-ResourceInteger $Policy.maxSweepMs 1 $Policy.maxDurationMs
    Assert-ResourceInteger $Policy.maxManifestAgeMs 1 $Policy.maxDurationMs
    if ($Policy.artifactRoot -isnot [string] -or $Policy.artifactRoot.Length -gt 1024 -or
        $Policy.artifactRoot -cnotmatch '^[A-Za-z]:[\\/]') { throw 'artifact_root' }
    $root = [IO.Path]::GetFullPath($Policy.artifactRoot).TrimEnd('\','/')
    if ($root.Length -le 3) { throw 'artifact_root' }
    return $Policy
}

function Get-ResourceFilePath([string]$Root, $Path) {
    if ($Path -isnot [string] -or $Path.Length -gt 1024 -or
        $Path -cnotmatch '^[A-Za-z]:[\\/]' -or $Path.Substring(2).Contains(':')) {
        throw 'file_path'
    }
    $full = [IO.Path]::GetFullPath($Path)
    $prefix = [IO.Path]::GetFullPath($Root).TrimEnd('\','/') + '\'
    if (!$full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'file_path' }
    return $full
}

function Assert-ResourceManifest($Manifest, $Policy) {
    Assert-ResourceKeys $Manifest @('schema','runId','revision','phase','owners','files')
    if ($Manifest.schema -cne 'myownmesh-owned-resources/v1' -or
        $Manifest.runId -cne $Policy.runId) { throw 'manifest_schema' }
    Assert-ResourceInteger $Manifest.revision 1 9007199254740991
    if (@('startup','warm','steady','teardown','complete') -cnotcontains $Manifest.phase) {
        throw 'manifest_phase'
    }
    if ($Manifest.owners -isnot [Array] -or $Manifest.files -isnot [Array] -or
        $Manifest.owners.Count -gt $Policy.maxRegisteredOwners -or
        $Manifest.files.Count -gt $Policy.maxFiles) { throw 'manifest_count' }
    $ids = @{}; $pids = @{}; $paths = @{}
    foreach ($owner in $Manifest.owners) {
        Assert-ResourceKeys $owner @('ownerId','nodeId','role','pid','creationTimeUtcTicks','terminalRequired')
        Assert-ResourceLabel $owner.ownerId
        Assert-ResourceLabel $owner.nodeId
        if (@('daemon','controller','helper') -cnotcontains $owner.role) { throw 'owner_role' }
        Assert-ResourceInteger $owner.pid 1 2147483647
        if ($owner.terminalRequired -isnot [bool]) { throw 'owner_identity' }
        if ($null -ne $owner.creationTimeUtcTicks) {
            if ($owner.creationTimeUtcTicks -isnot [string] -or
                $owner.creationTimeUtcTicks -cnotmatch '^[1-9][0-9]{0,18}$') { throw 'owner_identity' }
            $ticks = 0L
            if (![long]::TryParse($owner.creationTimeUtcTicks, [ref]$ticks) -or
                $ticks -gt [DateTime]::MaxValue.Ticks) { throw 'owner_identity' }
        }
        if ($ids.ContainsKey($owner.ownerId) -or $pids.ContainsKey([string]$owner.pid)) {
            throw 'duplicate_owner'
        }
        $ids[$owner.ownerId] = $true; $pids[[string]$owner.pid] = $true
    }
    foreach ($file in $Manifest.files) {
        Assert-ResourceKeys $file @('path','kind')
        if (@('main','wal','shm','journal','log','evidence') -cnotcontains $file.kind) {
            throw 'file_kind'
        }
        $full = Get-ResourceFilePath $Policy.artifactRoot $file.path
        if ($paths.ContainsKey($full)) { throw 'duplicate_file' }
        $paths[$full] = $true
    }
}

function New-ResourceState {
    return @{ owners=@{}; lastRevision=0L; lastManifestJson=$null; lastRevisionAt=0.0;
        files=@(); phase='startup'; accepted=$false; outputBytes=0L; samples=0;
        stopLatched=$false; evidenceFailures=0 }
}

function Update-ResourceManifest($State, $Manifest, $Policy, [double]$Now) {
    Assert-ResourceManifest $Manifest $Policy
    $json = $Manifest | ConvertTo-Json -Depth 8 -Compress
    if ($Manifest.revision -lt $State.lastRevision -or
        ($Manifest.revision -eq $State.lastRevision -and $json -cne $State.lastManifestJson)) {
        throw 'manifest_revision'
    }
    if ($Manifest.revision -eq $State.lastRevision) { return }
    $present = @{}; $newCount = 0; $pins = @{}
    foreach ($owner in $Manifest.owners) {
        $present[$owner.ownerId] = $true
        $encoded = $owner | ConvertTo-Json -Compress
        if ($State.owners.ContainsKey($owner.ownerId)) {
            $entry = $State.owners[$owner.ownerId]
            if ($entry.identity -cne $encoded) {
                $expected = $entry.identity | ConvertFrom-Json
                if ($null -ne $expected.creationTimeUtcTicks -or $entry.exited -or
                    $null -eq $entry.capturedTicks -or
                    $owner.creationTimeUtcTicks -cne $entry.capturedTicks) { throw 'owner_changed' }
                $expected.creationTimeUtcTicks = $entry.capturedTicks
                if (($expected | ConvertTo-Json -Compress) -cne $encoded) { throw 'owner_changed' }
                $pins[$owner.ownerId] = $owner
            }
        } else { $newCount++ }
    }
    if ($State.owners.Count + $newCount -gt $Policy.maxRegisteredOwners) { throw 'registration_limit' }
    foreach ($key in $State.owners.Keys) {
        if (!$present.ContainsKey($key) -and !$State.owners[$key].exited) {
            throw 'owner_removed_before_exit'
        }
    }
    # Registered artifact paths remain in the budget through teardown. Missing
    # transient sidecars are allowed, but omitting a log cannot hide its bytes.
    $nextFiles = @{}
    foreach ($file in $Manifest.files) {
        $nextFiles[(Get-ResourceFilePath $Policy.artifactRoot $file.path)] = $file.kind
    }
    foreach ($file in $State.files) {
        $path = Get-ResourceFilePath $Policy.artifactRoot $file.path
        if (!$nextFiles.ContainsKey($path) -or $nextFiles[$path] -cne $file.kind) {
            throw 'registered_file_removed_or_changed'
        }
    }
    foreach ($owner in $Manifest.owners) {
        if (!$State.owners.ContainsKey($owner.ownerId)) {
            $State.owners[$owner.ownerId] = @{ descriptor=$owner;
                identity=($owner | ConvertTo-Json -Compress); handle=$null;
                exited=$false; previous=$null; capturedTicks=$null; openAttempted=$false }
        }
    }
    foreach ($key in $pins.Keys) {
        $State.owners[$key].descriptor = $pins[$key]
        $State.owners[$key].identity = ($pins[$key] | ConvertTo-Json -Compress)
    }
    $State.files = $Manifest.files
    $State.phase = $Manifest.phase
    $State.lastRevision = $Manifest.revision
    $State.lastManifestJson = $json
    $State.lastRevisionAt = $Now
    $State.accepted = $true
}

function Get-ResourceCompletion($State) {
    $all = $State.accepted; $required = $State.accepted; $live = @(); $exited = @()
    $requiredCount = 0
    foreach ($key in @($State.owners.Keys | Sort-Object)) {
        $entry = $State.owners[$key]
        if ($entry.descriptor.terminalRequired) { $requiredCount++ }
        if ($null -eq $entry.descriptor.creationTimeUtcTicks) { $all=$false; $required=$false }
        if ($entry.exited) { $exited += $key } else {
            $all = $false; $live += $key
            if ($entry.descriptor.terminalRequired) { $required = $false }
        }
    }
    if ($requiredCount -eq 0) { $all=$false; $required=$false }
    return @{ observedAllExited=$all; observedRequiredExited=$required;
        liveOwnerIds=$live; exitedOwnerIds=$exited }
}

function Get-ResourceSweep($State, $Policy, $Hooks, [double]$Started) {
    $reasons = New-Object 'Collections.Generic.List[string]'
    $decision = 'Continue'
    $rows = New-Object 'Collections.Generic.List[object]'
    $byRole = @{}
    $private = 0.0; $working = 0.0; $live = 0; $complete = $true
    foreach ($key in @($State.owners.Keys | Sort-Object)) {
        $entry = $State.owners[$key]; $owner = $entry.descriptor
        if ($entry.exited) { continue }
        try {
            if ($null -eq $entry.handle) {
                if ($entry.openAttempted) { throw 'owner_capture_failed' }
                $entry.openAttempted=$true
                $entry.handle = & $Hooks.OpenOwner $owner
                if ($null -eq $entry.handle) { throw 'owner_capture_failed' }
            }
            $value = & $Hooks.ReadOwner $entry.handle $owner
            if ($value.status -ceq 'exited') {
                $entry.exited = $true
                & $Hooks.CloseOwner $entry.handle
                $entry.handle = $null
                $rows.Add([pscustomobject]@{ownerId=$key; role=$owner.role; pid=$owner.pid; status='exited'})
                continue
            }
            if ($value.status -cne 'alive' -or
                ($null -ne $owner.creationTimeUtcTicks -and $value.creationTimeUtcTicks -cne $owner.creationTimeUtcTicks) -or
                ($null -ne $entry.capturedTicks -and $value.creationTimeUtcTicks -cne $entry.capturedTicks)) {
                throw 'process_identity'
            }
            $ticks = 0L
            if ($value.creationTimeUtcTicks -isnot [string] -or
                ![long]::TryParse($value.creationTimeUtcTicks, [ref]$ticks) -or
                $ticks -le 0 -or $ticks -gt [DateTime]::MaxValue.Ticks) { throw 'process_identity' }
            $entry.capturedTicks = $value.creationTimeUtcTicks
            $registrationState='confirmed'
            if ($null -eq $owner.creationTimeUtcTicks) {
                $complete=$false; $reasons.Add('owner_unconfirmed'); $registrationState='unconfirmed'
            }
            foreach ($metric in @('privateBytes','workingSetBytes','peakWorkingSetBytes')) {
                Assert-ResourceInteger $value.$metric 0 9007199254740991
            }
            $now = & $Hooks.Now
            Assert-ResourceCounter $now
            Assert-ResourceCounter $value.cpuSeconds
            $cpu = [double]$value.cpuSeconds
            if ([double]::IsNaN($cpu) -or [double]::IsInfinity($cpu) -or $cpu -lt 0) { throw 'cpu_counter' }
            $delta = $null; $interval = $null; $cores = $null
            if ($null -ne $entry.previous) {
                $delta = $cpu - $entry.previous.cpu
                $interval = ($now - $entry.previous.at) / 1000
                if ($delta -lt 0 -or $interval -le 0) { throw 'counter_regression' }
                $cores = $delta / $interval
            }
            $entry.previous = @{cpu=$cpu; at=$now}
            $private += $value.privateBytes; $working += $value.workingSetBytes; $live++
            if ($private -gt 9007199254740991 -or $working -gt 9007199254740991) { throw 'aggregate_overflow' }
            if (!$byRole.ContainsKey($owner.role)) {
                $byRole[$owner.role] = @{count=0; privateBytes=0.0; workingSetBytes=0.0;
                    cpuDeltaSeconds=0.0; cpuDeltaAvailableCount=0}
            }
            $role = $byRole[$owner.role]
            $role.count++; $role.privateBytes += $value.privateBytes; $role.workingSetBytes += $value.workingSetBytes
            if ($null -ne $delta) { $role.cpuDeltaSeconds += $delta; $role.cpuDeltaAvailableCount++ }
            $rows.Add([pscustomobject]@{ownerId=$key; nodeId=$owner.nodeId; role=$owner.role;
                pid=$owner.pid; creationTimeUtcTicks=$entry.capturedTicks; status='alive';
                registrationState=$registrationState;
                monoMs=$now; cpuSeconds=$cpu; cpuDeltaSeconds=$delta; intervalSeconds=$interval;
                cpuCores=$cores; privateBytes=$value.privateBytes; workingSetBytes=$value.workingSetBytes;
                peakWorkingSetBytes=$value.peakWorkingSetBytes})
        } catch {
            $complete = $false; $reasons.Add('process_unavailable')
            $rows.Add([pscustomobject]@{ownerId=$key; role=$owner.role; pid=$owner.pid; status='unavailable'})
        }
    }
    foreach ($role in $byRole.Values) {
        if ($role.cpuDeltaAvailableCount -ne $role.count) { $role.cpuDeltaSeconds = $null }
    }
    $hostMemory = $null; $disk = $null; $collector = $null
    try {
        $hostMemory = & $Hooks.ReadHost
        foreach ($key in @('availablePhysicalBytes','availableCommitBytes')) {
            Assert-ResourceInteger $hostMemory.$key 0 9007199254740991
        }
        if ($hostMemory.availablePhysicalBytes -lt $Policy.minAvailablePhysicalBytes) { $reasons.Add('physical_floor'); $decision='StopTrial' }
        if ($hostMemory.availableCommitBytes -lt $Policy.minAvailableCommitBytes) { $reasons.Add('commit_floor'); $decision='StopTrial' }
    } catch { $hostMemory=$null; $complete=$false; $reasons.Add('host_memory_unavailable') }
    try {
        $collector = & $Hooks.ReadCollector
        foreach ($key in @('privateBytes','workingSetBytes')) { Assert-ResourceInteger $collector.$key 0 9007199254740991 }
        foreach ($key in @('cpuSeconds','cpuDeltaSeconds','intervalMs')) { Assert-ResourceCounter $collector.$key }
        $private += $collector.privateBytes; $working += $collector.workingSetBytes
        Assert-ResourceInteger $private 0 9007199254740991
        Assert-ResourceInteger $working 0 9007199254740991
    } catch { $collector=$null; $complete=$false; $reasons.Add('collector_unavailable') }
    try {
        $disk = & $Hooks.ReadDisk $Policy.artifactRoot
        Assert-ResourceInteger $disk.availableBytes 0 9007199254740991
        if ($disk.availableBytes -lt $Policy.minDiskFreeBytes) { $reasons.Add('disk_floor'); $decision='StopTrial' }
    } catch { $disk=$null; $complete=$false; $reasons.Add('disk_unavailable') }
    $files = New-Object 'Collections.Generic.List[object]'
    $artifact = 0.0; $fileBytes = @{main=0.0;wal=0.0;shm=0.0;journal=0.0;log=0.0;evidence=0.0}
    foreach ($file in $State.files) {
        try {
            $value = & $Hooks.ReadFile $Policy.artifactRoot $file.path
            if ($value.status -ceq 'absent') {
                if ($file.kind -ceq 'main') { $reasons.Add('main_absent'); $complete=$false }
            } elseif ($value.status -ceq 'present') {
                Assert-ResourceInteger $value.bytes 0 9007199254740991
                $fileBytes[$file.kind] += $value.bytes
                $artifact += $value.bytes
                if ($artifact -gt 9007199254740991) { throw 'artifact_overflow' }
            } else { throw 'file_unavailable' }
            $files.Add([pscustomobject]@{path=$file.path;kind=$file.kind;status=$value.status;bytes=$value.bytes})
        } catch {
            $complete=$false; $reasons.Add('file_unavailable')
            $files.Add([pscustomobject]@{path=$file.path;kind=$file.kind;status='unavailable';bytes=$null})
        }
    }
    if ($private -gt $Policy.maxPrivateBytes) { $reasons.Add('private_limit'); $decision='StopTrial' }
    if ($working -gt $Policy.maxWorkingSetBytes) { $reasons.Add('working_set_limit'); $decision='StopTrial' }
    $notExited = @($State.owners.Values | Where-Object { !$_.exited }).Count
    if ($notExited -gt $Policy.maxLiveProcesses) { $reasons.Add('process_limit'); $decision='StopTrial' }
    if ($artifact -gt $Policy.maxArtifactBytes) { $reasons.Add('artifact_limit'); $decision='StopTrial' }
    if ($fileBytes.log -gt $Policy.maxLogBytes) { $reasons.Add('log_limit'); $decision='StopTrial' }
    $ended = & $Hooks.Now
    Assert-ResourceCounter $ended
    if ($ended -lt $Started) { throw 'clock_regression' }
    if ($ended - $Started -gt $Policy.maxSweepMs) { $complete=$false; $reasons.Add('sweep_overrun') }
    if (!$State.accepted -or $ended - $State.lastRevisionAt -gt $Policy.maxManifestAgeMs) {
        $complete=$false; $reasons.Add('manifest_stale')
    }
    if (!$complete -and $decision -ceq 'Continue') { $decision='Freeze' }
    if ($decision -ceq 'StopTrial') { $State.stopLatched=$true }
    if ($State.stopLatched) { $decision='StopTrial' }
    $completion = Get-ResourceCompletion $State
    return [pscustomobject]@{kind='sample';schema='myownmesh-resource-observation/v1';runId=$Policy.runId;
        lastAcceptedRevision=$State.lastRevision;phase=$State.phase;sampleIndex=$State.samples;
        startedMonoMs=$Started;endedMonoMs=$ended;collectionDurationMs=($ended-$Started);
        complete=$complete;decision=$decision;reasons=@($reasons | Select-Object -Unique);
        registeredCount=$State.owners.Count;notObservedExitedCount=$notExited;observedLiveCount=$live;processes=$rows.ToArray();roles=$byRole;
        aggregatePrivateBytes=$private;aggregateWorkingSetBytes=$working;aggregateIncludesCollector=$true;
        aggregateComplete=$complete;collector=$collector;hostMemory=$hostMemory;disk=$disk;
        files=$files.ToArray();fileBytesByKind=$fileBytes;observedArtifactBytes=$artifact;
        observedAllExited=$completion.observedAllExited;observedRequiredExited=$completion.observedRequiredExited;
        exitedOwnerIds=$completion.exitedOwnerIds;liveOwnerIds=$completion.liveOwnerIds}
}

function Write-ResourceRecord($State, $Policy, $Hooks, $Record, [bool]$Terminal=$false) {
    $line = $Record | ConvertTo-Json -Depth 12 -Compress
    $bytes = [Text.Encoding]::UTF8.GetByteCount($line + [Environment]::NewLine)
    # Reserve bounded space for a small terminal record, even at output refusal.
    $reserve = 0; if (!$Terminal) { $reserve=2048 }
    if ($State.outputBytes + $bytes + $reserve -gt $Policy.maxOutputBytes) { return $false }
    & $Hooks.Emit $line
    $State.outputBytes += $bytes
    return $true
}

function Invoke-ResourceCollector($Policy, $Hooks) {
    $null = Assert-ResourcePolicy $Policy
    $state = New-ResourceState
    $started = & $Hooks.Now
    Assert-ResourceCounter $started
    $outcome = 'sample_limit'; $lastDecision='Freeze'
    try {
        while ($state.samples -lt $Policy.maxSamples) {
            $now = & $Hooks.Now
            Assert-ResourceCounter $now
            if ($now -lt $started) { throw 'clock_regression' }
            if ($now - $started -ge $Policy.maxDurationMs) { $outcome='duration_limit'; break }
            $manifestError = $false
            try {
                $manifest = & $Hooks.ReadManifest
                Update-ResourceManifest $state $manifest $Policy $now
            } catch { $manifestError=$true }
            $sample = Get-ResourceSweep $state $Policy $Hooks $now
            if ($manifestError) {
                $sample.complete=$false; $sample.aggregateComplete=$false
                $sample.reasons += 'manifest_invalid'
                if ($sample.decision -ceq 'Continue') { $sample.decision='Freeze' }
            }
            $lastDecision=$sample.decision
            # Bootstrap confirmation is an intentional launch freeze, not a
            # censored measurement. Other incomplete samples remain failures.
            if (@($sample.reasons | Where-Object { $_ -cne 'owner_unconfirmed' }).Count -gt 0) {
                $state.evidenceFailures++
            }
            if (!(Write-ResourceRecord $state $Policy $Hooks $sample)) { $outcome='output_limit'; break }
            $state.samples++
            if ($state.phase -ceq 'complete' -and $sample.complete -and $sample.observedRequiredExited) {
                $outcome='complete'; break
            }
            $nowAfter = & $Hooks.Now
            # No overlapping sweeps and no catch-up burst after an overrun.
            $delay = [Math]::Max(0, $Policy.sampleIntervalMs - ($nowAfter - $now))
            $delay = [Math]::Min($delay, [Math]::Max(0, $Policy.maxDurationMs - ($nowAfter-$started)))
            if ($delay -gt 0) { & $Hooks.Sleep ([int][Math]::Ceiling($delay)) }
        }
        $completion = Get-ResourceCompletion $state
        $success = $outcome -ceq 'complete' -and !$state.stopLatched -and
            $lastDecision -ceq 'Continue' -and $state.evidenceFailures -eq 0
        $terminal = [pscustomobject]@{kind='terminal';schema='myownmesh-resource-observation/v1';
            runId=$Policy.runId;outcome=$outcome;success=$success;
            decision=$(if($success){'Continue'}else{'StopTrial'});
            lastAcceptedRevision=$state.lastRevision;samples=$state.samples;evidenceFailures=$state.evidenceFailures;
            elapsedMs=((& $Hooks.Now)-$started);observedAllExited=$completion.observedAllExited;
            observedRequiredExited=$completion.observedRequiredExited;liveOwnerCount=$completion.liveOwnerIds.Count}
        if (!(Write-ResourceRecord $state $Policy $Hooks $terminal $true)) { return 2 }
        if ($success) { return 0 } else { return 2 }
    } finally {
        foreach ($entry in $state.owners.Values) {
            if ($null -ne $entry.handle) { & $Hooks.CloseOwner $entry.handle }
        }
    }
}

function New-NativeResourceHooks($Policy, [string]$ManifestFile) {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'windows_required' }
    if ($null -eq ('LiveDeviceResourceNative' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class LiveDeviceResourceNative {
    [StructLayout(LayoutKind.Sequential)] public struct Performance {
        public uint Size; public UIntPtr CommitTotal, CommitLimit, CommitPeak;
        public UIntPtr PhysicalTotal, PhysicalAvailable, SystemCache, KernelTotal;
        public UIntPtr KernelPaged, KernelNonpaged, PageSize;
        public uint HandleCount, ProcessCount, ThreadCount;
    }
    [DllImport("psapi.dll", SetLastError=true)]
    public static extern bool GetPerformanceInfo(ref Performance info, uint size);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool GetDiskFreeSpaceEx(string path, out ulong available,
        out ulong total, out ulong free);
}
'@
    }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $collectorProcess = [Diagnostics.Process]::GetCurrentProcess()
    $collectorPrevious = @{cpu=$collectorProcess.TotalProcessorTime.TotalSeconds; at=0.0}
    return @{
        Now={ $watch.Elapsed.TotalMilliseconds }.GetNewClosure()
        Sleep={param($ms) [Threading.Thread]::Sleep($ms)}
        Emit={param($line) [Console]::Out.WriteLine($line); [Console]::Out.Flush()}
        ReadManifest={Read-ResourceJson $ManifestFile ([int]$Policy.maxInputBytes)}.GetNewClosure()
        OpenOwner={param($owner)
            if ($owner.pid -eq $PID) { throw 'collector_registered_twice' }
            $process = [Diagnostics.Process]::GetProcessById([int]$owner.pid)
            try {
                $null = $process.Handle
                if ($null -ne $owner.creationTimeUtcTicks -and
                    $process.StartTime.ToUniversalTime().Ticks.ToString() -cne $owner.creationTimeUtcTicks) {
                    throw 'process_identity'
                }
                return $process
            } catch { $process.Dispose(); throw }
        }
        ReadOwner={param($process,$owner)
            $process.Refresh()
            if ($process.HasExited) { return @{status='exited'} }
            $ticks = $process.StartTime.ToUniversalTime().Ticks.ToString()
            $value = @{status='alive';creationTimeUtcTicks=$ticks;
                cpuSeconds=$process.TotalProcessorTime.TotalSeconds;
                privateBytes=$process.PrivateMemorySize64;workingSetBytes=$process.WorkingSet64;
                peakWorkingSetBytes=$process.PeakWorkingSet64}
            if ($process.HasExited) { return @{status='exited'} }
            return $value
        }
        CloseOwner={param($process) $process.Dispose()}
        ReadCollector={
            $collectorProcess.Refresh()
            $at = $watch.Elapsed.TotalMilliseconds
            $cpu = $collectorProcess.TotalProcessorTime.TotalSeconds
            $result = @{pid=$collectorProcess.Id;cpuSeconds=$cpu;
                cpuDeltaSeconds=($cpu-$collectorPrevious.cpu);intervalMs=($at-$collectorPrevious.at);
                privateBytes=$collectorProcess.PrivateMemorySize64;
                workingSetBytes=$collectorProcess.WorkingSet64}
            $collectorPrevious.cpu=$cpu; $collectorPrevious.at=$at
            return $result
        }.GetNewClosure()
        ReadHost={
            $value = New-Object LiveDeviceResourceNative+Performance
            $size = [Runtime.InteropServices.Marshal]::SizeOf($value)
            $value.Size=$size
            if (![LiveDeviceResourceNative]::GetPerformanceInfo([ref]$value,$size)) { throw 'host_memory_unavailable' }
            $page=$value.PageSize.ToUInt64()
            return @{totalPhysicalBytes=($value.PhysicalTotal.ToUInt64()*$page);
                commitUsedBytes=($value.CommitTotal.ToUInt64()*$page);
                commitLimitBytes=($value.CommitLimit.ToUInt64()*$page);
                availablePhysicalBytes=($value.PhysicalAvailable.ToUInt64()*$page);
                availableCommitBytes=(($value.CommitLimit.ToUInt64()-$value.CommitTotal.ToUInt64())*$page)}
        }
        ReadDisk={param($root)
            [uint64]$available=0; [uint64]$total=0; [uint64]$free=0
            if (![LiveDeviceResourceNative]::GetDiskFreeSpaceEx($root,[ref]$available,[ref]$total,[ref]$free)) { throw 'disk_unavailable' }
            return @{availableBytes=$available}
        }
        ReadFile={param($root,$file)
            $full=Get-ResourceFilePath $root $file
            $parent=[IO.Path]::GetDirectoryName($full)
            $rootFull=[IO.Path]::GetFullPath($root).TrimEnd('\','/')
            while ($parent.Length -ge $rootFull.Length) {
                $directory=Get-Item -LiteralPath $parent -Force -ErrorAction Stop
                if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse_path' }
                if ($parent -ieq $rootFull) { break }
                $parent=[IO.Path]::GetDirectoryName($parent)
            }
            try { $info=Get-Item -LiteralPath $full -Force -ErrorAction Stop }
            catch [System.Management.Automation.ItemNotFoundException] { return @{status='absent';bytes=$null} }
            if ($info.PSIsContainer -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'file_kind' }
            return @{status='present';bytes=$info.Length}
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
        if (![IO.Path]::IsPathRooted($PolicyPath) -or ![IO.Path]::IsPathRooted($ManifestPath)) { throw 'input_path' }
        $policy = Assert-ResourcePolicy (Read-ResourceJson $PolicyPath 65536)
        $hooks = New-NativeResourceHooks $policy $ManifestPath
        exit (Invoke-ResourceCollector $policy $hooks)
    } catch {
        # No exception text: it may contain host paths or arbitrary input text.
        [Console]::Out.WriteLine('{"kind":"terminal","success":false,"decision":"StopTrial","outcome":"collector_failure","lastAcceptedRevision":null,"observedAllExited":false,"observedRequiredExited":false}')
        exit 2
    }
}
