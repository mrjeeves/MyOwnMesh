# Finite, injected-reader controls. No native processes, sleeps, files or Pester.
# Manager executes separately; dot-sourcing the implementation never starts it.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../live-device-resources.ps1')

function Assert-Equal($Actual, $Expected) {
    if ($Actual -cne $Expected) { throw "expected [$Expected], got [$Actual]" }
}
function Assert-True($Value) { if (!$Value) { throw 'assertion_failed' } }
function Assert-Throws([scriptblock]$Body) {
    $caught = $false
    try { & $Body } catch { $caught = $true }
    if (!$caught) { throw 'expected_refusal' }
}
function Copy-Value($Value) { return ($Value | ConvertTo-Json -Depth 12 -Compress | ConvertFrom-Json) }
function New-TestPolicy {
    return [pscustomobject]@{
        schema='myownmesh-resource-policy/v1';runId='fake-run';artifactRoot='C:\lab\resources';
        maxRegisteredOwners=4;maxLiveProcesses=4;maxFiles=4;maxInputBytes=65536;
        maxOutputBytes=100000;maxSamples=4;maxDurationMs=1000;sampleIntervalMs=10;
        maxSweepMs=100;maxManifestAgeMs=100;maxPrivateBytes=1000;maxWorkingSetBytes=1000;
        minAvailablePhysicalBytes=100;minAvailableCommitBytes=100;
        maxArtifactBytes=1000;maxLogBytes=500;minDiskFreeBytes=100
    }
}
function New-TestOwner([string]$Id='daemon-1', [int]$ProcessNumber=10, [bool]$Required=$true) {
    return [pscustomobject]@{ownerId=$Id;nodeId='node-1';role='daemon';pid=$ProcessNumber;
        creationTimeUtcTicks='638000000000000000';terminalRequired=$Required}
}
function New-TestManifest($Owner) {
    return [pscustomobject]@{schema='myownmesh-owned-resources/v1';runId='fake-run';revision=1;
        phase='startup';owners=@($Owner);files=@()}
}
function New-FakeReaders($Manifest) {
    $fake = @{
        now=0.0; opens=0; closes=0; reads=0; manifestReads=0; sleepCalls=0; records=(New-Object 'Collections.Generic.List[string]');
        manifest=$Manifest; ownerValues=@{}; fileValue=@{status='present';bytes=10};
        hostValue=@{availablePhysicalBytes=1000;availableCommitBytes=1000};
        diskValue=@{availableBytes=1000};
        collectorValue=@{cpuSeconds=1.0;cpuDeltaSeconds=0.1;intervalMs=10.0;privateBytes=5;workingSetBytes=6};
        readCost=0.0; throwOwner=$false; throwHost=$false; completeOnSecond=$false; recoverOnSecond=$false
    }
    foreach ($owner in $Manifest.owners) {
        $fake.ownerValues[$owner.ownerId]=@{status='alive';creationTimeUtcTicks='638000000000000000';
            cpuSeconds=2.0;privateBytes=20;workingSetBytes=30;peakWorkingSetBytes=40}
    }
    $hooks = @{
        Now={ $fake.now }.GetNewClosure()
        Sleep={param($ms) $fake.now += $ms; $fake.sleepCalls++}.GetNewClosure()
        Emit={param($line) $fake.records.Add($line)}.GetNewClosure()
        ReadManifest={
            $fake.manifestReads++
            if ($fake.completeOnSecond -and $fake.manifestReads -eq 2) {
                $fake.manifest=($fake.manifest | ConvertTo-Json -Depth 8 -Compress | ConvertFrom-Json)
                $fake.manifest.revision=2; $fake.manifest.phase='complete'
                if ($fake.recoverOnSecond) { $fake.throwOwner=$false }
                foreach ($owner in $fake.manifest.owners) {
                    if ($owner.terminalRequired) { $fake.ownerValues[$owner.ownerId].status='exited' }
                }
            }
            return $fake.manifest
        }.GetNewClosure()
        OpenOwner={param($owner) $fake.opens++; return @{id=$owner.ownerId}}.GetNewClosure()
        ReadOwner={param($handle,$owner)
            $fake.reads++; $fake.now += $fake.readCost
            if ($fake.throwOwner) { throw 'injected_unavailable' }
            return $fake.ownerValues[$handle.id]
        }.GetNewClosure()
        CloseOwner={param($handle) $fake.closes++}.GetNewClosure()
        ReadHost={if ($fake.throwHost) { throw 'injected_unavailable' }; return $fake.hostValue}.GetNewClosure()
        ReadCollector={ $fake.collectorValue }.GetNewClosure()
        ReadDisk={param($root) return $fake.diskValue}.GetNewClosure()
        ReadFile={param($root,$path) return $fake.fileValue}.GetNewClosure()
    }
    return @{data=$fake;hooks=$hooks}
}
function New-Fixture {
    $policy=New-TestPolicy; $manifest=New-TestManifest (New-TestOwner)
    $fake=New-FakeReaders $manifest; $state=New-ResourceState
    Update-ResourceManifest $state $manifest $policy 0
    return @{policy=$policy;manifest=$manifest;fake=$fake;state=$state}
}
function Get-TestSweep($Fixture) {
    return Get-ResourceSweep $Fixture.state $Fixture.policy $Fixture.fake.hooks $Fixture.fake.data.now
}
function Invoke-Control([string]$Name,[scriptblock]$Body) {
    & $Body
    $script:passed++
    Write-Output "PASS $Name"
}
$script:passed=0

Invoke-Control 'exact policy keys and finite dimensions' {
    $policy=New-TestPolicy
    $null=Assert-ResourcePolicy $policy
    $missing=Copy-Value $policy; $missing.PSObject.Properties.Remove('maxLogBytes')
    Assert-Throws { Assert-ResourcePolicy $missing }
    $extra=Copy-Value $policy; $extra | Add-Member -NotePropertyName unexpected -NotePropertyValue 1
    Assert-Throws { Assert-ResourcePolicy $extra }
    foreach ($invalid in @([double]::NaN,[double]::PositiveInfinity,0,'100')) {
        $bad=Copy-Value $policy; $bad.maxPrivateBytes=$invalid
        Assert-Throws { Assert-ResourcePolicy $bad }
    }
}
Invoke-Control 'unconfirmed capture then exact pin, no replacement lookup' {
    $f=New-Fixture
    $f.manifest.owners[0].creationTimeUtcTicks=$null
    $f.state=New-ResourceState
    Update-ResourceManifest $f.state $f.manifest $f.policy 0
    $first=Get-TestSweep $f
    Assert-Equal $first.decision 'Freeze'
    Assert-Equal $first.processes[0].registrationState 'unconfirmed'
    Assert-Equal $first.processes[0].creationTimeUtcTicks '638000000000000000'
    $pin=Copy-Value $f.manifest; $pin.revision=2
    $pin.owners[0].creationTimeUtcTicks=$first.processes[0].creationTimeUtcTicks
    $wrong=Copy-Value $pin; $wrong.owners[0].creationTimeUtcTicks='638000000000000001'
    Assert-Throws { Update-ResourceManifest $f.state $wrong $f.policy 10 }
    Update-ResourceManifest $f.state $pin $f.policy 10
    $f.fake.data.now=10
    Assert-Equal (Get-TestSweep $f).decision 'Continue'
    Assert-Equal $f.fake.data.opens 1
    $reset=Copy-Value $pin; $reset.revision=3; $reset.owners[0].creationTimeUtcTicks=$null
    Assert-Throws { Update-ResourceManifest $f.state $reset $f.policy 20 }
}
Invoke-Control 'creation mismatch is unavailable, never zero or successor adoption' {
    $f=New-Fixture
    $f.fake.data.ownerValues['daemon-1'].creationTimeUtcTicks='638000000000000001'
    $sample=Get-TestSweep $f
    Assert-Equal $sample.decision 'Freeze'; Assert-True (!$sample.aggregateComplete)
    Assert-Equal $sample.processes[0].status 'unavailable'
    $f.fake.data.now=10; $null=Get-TestSweep $f
    Assert-Equal $f.fake.data.opens 1
}
Invoke-Control 'observed exit before removal, bounded registration history' {
    $f=New-Fixture; $null=Get-TestSweep $f
    $removed=Copy-Value $f.manifest; $removed.revision=2; $removed.owners=@()
    Assert-Throws { Update-ResourceManifest $f.state $removed $f.policy 1 }
    $f.fake.data.ownerValues['daemon-1'].status='exited'
    $f.fake.data.now=10; $sample=Get-TestSweep $f
    Assert-True $sample.observedRequiredExited
    Update-ResourceManifest $f.state $removed $f.policy 10
    $null=Get-TestSweep $f
    Assert-Equal $f.fake.data.opens 1; Assert-Equal $f.fake.data.closes 1
    $f.policy.maxRegisteredOwners=1
    $removed.revision=3; $removed.owners=@((New-TestOwner 'second' 11))
    Assert-Throws { Update-ResourceManifest $f.state $removed $f.policy 20 }
}
Invoke-Control 'CPU uses observed irregular interval, first delta unavailable' {
    $f=New-Fixture; $first=Get-TestSweep $f
    Assert-True ($null -eq $first.processes[0].cpuDeltaSeconds)
    $f.fake.data.now=2500; $f.policy.maxManifestAgeMs=3000
    $f.fake.data.ownerValues['daemon-1'].cpuSeconds=3.25
    $second=Get-TestSweep $f
    Assert-Equal $second.processes[0].intervalSeconds 2.5
    Assert-Equal $second.processes[0].cpuDeltaSeconds 1.25
    Assert-Equal $second.processes[0].cpuCores 0.5
    $f.fake.data.now=2600; $f.fake.data.ownerValues['daemon-1'].cpuSeconds=1
    Assert-Equal (Get-TestSweep $f).decision 'Freeze'
}
Invoke-Control 'unavailable process and host remain explicit incomplete observations' {
    $f=New-Fixture; $f.fake.data.throwOwner=$true; $f.fake.data.throwHost=$true
    $sample=Get-TestSweep $f
    Assert-Equal $sample.decision 'Freeze'; Assert-True (!$sample.complete)
    Assert-True ($sample.reasons -contains 'process_unavailable')
    Assert-True ($sample.reasons -contains 'host_memory_unavailable')
    Assert-True ($null -eq $sample.hostMemory)
}
Invoke-Control 'null CPU and collector counters are not zero measurements' {
    $f=New-Fixture; $f.fake.data.ownerValues['daemon-1'].cpuSeconds=$null
    Assert-Equal (Get-TestSweep $f).decision 'Freeze'
    $f=New-Fixture; $f.fake.data.collectorValue.cpuDeltaSeconds=[double]::NaN
    Assert-Equal (Get-TestSweep $f).decision 'Freeze'
}
Invoke-Control 'aggregate includes collector and guards exact N versus N plus one' {
    foreach ($dimension in @('maxPrivateBytes','maxWorkingSetBytes')) {
        $f=New-Fixture
        $limit=25; if ($dimension -ceq 'maxWorkingSetBytes') { $limit=36 }
        $f.policy.$dimension=$limit
        $sample=Get-TestSweep $f
        Assert-Equal $sample.decision 'Continue'; Assert-True $sample.aggregateIncludesCollector
        Assert-Equal $sample.roles.daemon.privateBytes 20
        $f.policy.$dimension=$limit-1; $f.fake.data.now=10
        Assert-Equal (Get-TestSweep $f).decision 'StopTrial'
        $f.policy.$dimension=1000; $f.fake.data.now=20
        Assert-Equal (Get-TestSweep $f).decision 'StopTrial'
    }
}
Invoke-Control 'physical and commit floors exact N and N minus one' {
    foreach ($dimension in @('availablePhysicalBytes','availableCommitBytes')) {
        $f=New-Fixture; $f.fake.data.hostValue[$dimension]=100
        Assert-Equal (Get-TestSweep $f).decision 'Continue'
        $f.fake.data.hostValue[$dimension]=99; $f.fake.data.now=10
        Assert-Equal (Get-TestSweep $f).decision 'StopTrial'
    }
}
Invoke-Control 'disk floor exact N and N minus one' {
    $f=New-Fixture; $f.fake.data.diskValue.availableBytes=100
    Assert-Equal (Get-TestSweep $f).decision 'Continue'
    $f.fake.data.diskValue.availableBytes=99; $f.fake.data.now=10
    Assert-Equal (Get-TestSweep $f).decision 'StopTrial'
}
Invoke-Control 'log and total artifact ceilings N and N plus one' {
    foreach ($dimension in @('maxLogBytes','maxArtifactBytes')) {
        $f=New-Fixture; $manifest=Copy-Value $f.manifest; $manifest.revision=2
        $manifest.files=@([pscustomobject]@{path='C:\lab\resources\daemon.log';kind='log'})
        Update-ResourceManifest $f.state $manifest $f.policy 0
        $f.policy.$dimension=10
        Assert-Equal (Get-TestSweep $f).decision 'Continue'
        $f.fake.data.fileValue.bytes=11; $f.fake.data.now=10
        Assert-Equal (Get-TestSweep $f).decision 'StopTrial'
        $manifest.revision=3; $manifest.files=@()
        Assert-Throws { Update-ResourceManifest $f.state $manifest $f.policy 20 }
    }
}
Invoke-Control 'missing WAL is absent; missing main is incomplete' {
    foreach ($kind in @('main','wal')) {
        $f=New-Fixture; $manifest=Copy-Value $f.manifest; $manifest.revision=2
        $manifest.files=@([pscustomobject]@{path='C:\lab\resources\store';kind=$kind})
        Update-ResourceManifest $f.state $manifest $f.policy 0
        $f.fake.data.fileValue=@{status='absent';bytes=$null}
        $sample=Get-TestSweep $f
        if ($kind -ceq 'main') { Assert-Equal $sample.decision 'Freeze' }
        else { Assert-Equal $sample.decision 'Continue' }
        Assert-True ($null -eq $sample.files[0].bytes)
    }
}
Invoke-Control 'revision immutability, sweep overrun and stale heartbeat' {
    $f=New-Fixture; $changed=Copy-Value $f.manifest; $changed.phase='warm'
    Assert-Throws { Update-ResourceManifest $f.state $changed $f.policy 0 }
    $f.fake.data.readCost=101
    $sample=Get-TestSweep $f
    Assert-Equal $sample.collectionDurationMs 101
    Assert-Equal $sample.decision 'Freeze'
    Assert-True ($sample.reasons -contains 'sweep_overrun')
    Assert-True ($sample.reasons -contains 'manifest_stale')
}
Invoke-Control 'empty complete manifest cannot provide vacuous terminal evidence' {
    $f=New-Fixture; $f.fake.data.manifest.owners=@(); $f.fake.data.manifest.phase='complete'
    $f.policy.maxSamples=1
    Assert-Equal (Invoke-ResourceCollector $f.policy $f.fake.hooks) 2
    $terminal=$f.fake.data.records[$f.fake.data.records.Count-1] | ConvertFrom-Json
    Assert-True (!$terminal.observedRequiredExited)
    Assert-Equal $terminal.outcome 'sample_limit'
}
Invoke-Control 'terminal binds revision and required exits, not controller lifetime' {
    $policy=New-TestPolicy; $manifest=New-TestManifest (New-TestOwner)
    $controller=New-TestOwner 'host' 11 $false; $controller.role='controller'
    $manifest.owners += $controller
    $fake=New-FakeReaders $manifest; $fake.data.completeOnSecond=$true
    Assert-Equal (Invoke-ResourceCollector $policy $fake.hooks) 0
    $terminal=$fake.data.records[$fake.data.records.Count-1] | ConvertFrom-Json
    Assert-True $terminal.success; Assert-True $terminal.observedRequiredExited
    Assert-True (!$terminal.observedAllExited); Assert-Equal $terminal.lastAcceptedRevision 2
    Assert-Equal $terminal.samples 2; Assert-Equal $fake.data.closes 2
}
Invoke-Control 'finite sample, duration and output exhaustion remain failed evidence' {
    foreach ($limit in @('samples','duration','output')) {
        $f=New-Fixture
        switch ($limit) {
            'samples' { $f.policy.maxSamples=1 }
            'duration' { $f.policy.maxDurationMs=1; $f.policy.maxSweepMs=1; $f.policy.maxManifestAgeMs=1 }
            'output' { $f.policy.maxOutputBytes=2048 }
        }
        Assert-Equal (Invoke-ResourceCollector $f.policy $f.fake.hooks) 2
        $terminal=$f.fake.data.records[$f.fake.data.records.Count-1] | ConvertFrom-Json
        Assert-True (!$terminal.success); Assert-Equal $terminal.decision 'StopTrial'
        Assert-Equal $f.fake.data.opens 1; Assert-Equal $f.fake.data.closes 1
        Assert-True ($f.fake.data.records.Count -le $f.policy.maxSamples+1)
    }
}

Invoke-Control 'an incomplete first sample cannot turn into successful terminal evidence' {
    $f=New-Fixture; $f.fake.data.completeOnSecond=$true; $f.fake.data.throwOwner=$true
    $f.fake.data.recoverOnSecond=$true
    Assert-Equal (Invoke-ResourceCollector $f.policy $f.fake.hooks) 2
    $terminal=$f.fake.data.records[$f.fake.data.records.Count-1] | ConvertFrom-Json
    Assert-Equal $terminal.evidenceFailures 1; Assert-True (!$terminal.success)
    Assert-Equal $terminal.outcome 'complete'; Assert-True $terminal.observedRequiredExited
}

Invoke-Control 'process count N and N plus one, no signal hook' {
    $policy=New-TestPolicy; $policy.maxLiveProcesses=1
    $manifest=New-TestManifest (New-TestOwner)
    $state=New-ResourceState; $fake=New-FakeReaders $manifest
    Update-ResourceManifest $state $manifest $policy 0
    Assert-Equal (Get-ResourceSweep $state $policy $fake.hooks 0).decision 'Continue'
    $manifest=Copy-Value $manifest; $manifest.revision=2
    $manifest.owners += (New-TestOwner 'daemon-2' 11)
    $fake.data.ownerValues['daemon-2']=@{status='alive';creationTimeUtcTicks='638000000000000000';
        cpuSeconds=0.0;privateBytes=20;workingSetBytes=30;peakWorkingSetBytes=40}
    Update-ResourceManifest $state $manifest $policy 10; $fake.data.now=10
    Assert-Equal (Get-ResourceSweep $state $policy $fake.hooks 10).decision 'StopTrial'
    Assert-True (!$fake.hooks.ContainsKey('Kill')); Assert-True (!$fake.hooks.ContainsKey('Signal'))
}

Write-Output "Passed $script:passed finite controls. Native OS self-sampling is a separate manager-run check."
