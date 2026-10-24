param(
    [string]$Root = "$env:LOCALAPPDATA\onec-toolkit",
    [int]$AgentPid = 0,
    [int]$StartDelaySeconds = 0,
    [switch]$DetachedHandoff,
    [string]$ArchiveUrl = '',
    [string]$ArchiveFile = '',
    [string]$ArchiveSha256 = '',
    [string]$PackageVersion = '',
    [string]$Target = ''
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$updaterScriptPath = $MyInvocation.MyCommand.Path

if ($StartDelaySeconds -gt 0) { Start-Sleep -Seconds $StartDelaySeconds }
if ($DetachedHandoff -and ($AgentPid -le 0)) {
    throw 'Detached handoff requires a positive -AgentPid.'
}
if (([string]::IsNullOrEmpty($ArchiveUrl) -eq [string]::IsNullOrEmpty($ArchiveFile)) -or
    [string]::IsNullOrEmpty($ArchiveSha256) -or
    [string]::IsNullOrEmpty($PackageVersion) -or
    [string]::IsNullOrEmpty($Target)) {
    throw 'Exact package selection is required: provide exactly one of -ArchiveUrl or -ArchiveFile, plus -ArchiveSha256, -PackageVersion, and -Target. Automatic latest updates are retired.'
}

$binDir = Join-Path $Root 'bin'
$agentDir = Join-Path $Root 'agent'
$currentAgent = Join-Path $binDir 'onec-agent.exe'
$agentConfigPath = Join-Path $agentDir 'agent.json'
$metadataPath = Join-Path $Root 'install.json'
$supervisorLock = Join-Path $agentDir 'supervisor.lock'
$maintenance = Join-Path $agentDir 'maintenance'
$maintenanceGate = Join-Path $agentDir 'maintenance.gate'
$updateLog = Join-Path $agentDir 'update-events.log'
$runnerPath = Join-Path $Root 'scripts\Run-OnecAgent.ps1'
$pidFile = Join-Path $agentDir 'agent.pid'

if (-not (Test-Path $currentAgent)) { throw "Missing $currentAgent" }
if (-not (Test-Path $metadataPath)) { throw "Missing $metadataPath" }

function New-Utf8NoBom {
    New-Object System.Text.UTF8Encoding($false)
}

function Write-Utf8NoBom([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, (New-Utf8NoBom))
}

function Write-UpdateLog([string]$Message) {
    $line = [DateTime]::UtcNow.ToString('o') + ' ' + $Message + [Environment]::NewLine
    try { [IO.File]::AppendAllText($updateLog, $line, (New-Utf8NoBom)) } catch { }
}

function Get-MaintenanceMarkerState {
    try { [void][IO.File]::GetAttributes($maintenance) }
    catch [IO.FileNotFoundException] { return 'absent' }
    catch [IO.DirectoryNotFoundException] { return 'absent' }
    catch { return 'unknown' }
    try {
        $text = [IO.File]::ReadAllText($maintenance).Trim()
        $parts = $text.Split('|')
        if (($parts.Length -ne 4) -or ($parts[0] -ne 'v1')) { return 'unknown' }
        $ownerPid = 0
        $ownerStartTicks = [Int64]0
        if ((-not [int]::TryParse($parts[1], [ref]$ownerPid)) -or
            (-not [Int64]::TryParse($parts[2], [ref]$ownerStartTicks)) -or
            ($ownerPid -le 0) -or ($ownerStartTicks -le 0) -or
            (($parts[3] -ne 'update') -and ($parts[3] -ne 'install'))) { return 'unknown' }
        try {
            $owner = [Diagnostics.Process]::GetProcessById($ownerPid)
        } catch [ArgumentException] {
            return 'orphan'
        }
        try {
            if ($owner.HasExited) { return 'orphan' }
            if ($owner.StartTime.ToUniversalTime().Ticks -ne $ownerStartTicks) { return 'orphan' }
            return 'live'
        } catch {
            return 'unknown'
        } finally {
            $owner.Dispose()
        }
    } catch {
        return 'unknown'
    }
}

function New-MaintenanceMarker([string]$Kind) {
    $gate = $null
    try {
        $gate = [IO.File]::Open($maintenanceGate, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    } catch [IO.IOException] {
        throw 'Unable to acquire the maintenance ownership gate.'
    }
    try {
        $state = Get-MaintenanceMarkerState
        if ($state -eq 'live') { throw 'A live update/install process owns the maintenance marker.' }
        if ($state -eq 'unknown') { throw 'The maintenance marker owner cannot be verified; preserving it.' }
        if ($state -eq 'orphan') {
            [IO.File]::Delete($maintenance)
            Write-UpdateLog 'maintenance_orphan_recovered before_new_owner'
        }
        $startTicks = [Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().Ticks
        $text = 'v1|' + [string]$PID + '|' + [string]$startTicks + '|' + $Kind + [Environment]::NewLine
        $temporaryMarker = $maintenance + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
        $stream = [IO.File]::Open($temporaryMarker, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $bytes = (New-Utf8NoBom).GetBytes($text)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
        } finally { $stream.Dispose() }
        [IO.File]::Move($temporaryMarker, $maintenance)
        return $text.Trim()
    } finally { if ($null -ne $gate) { $gate.Dispose() } }
}

function Remove-OwnedMaintenanceMarker([string]$OwnerText) {
    if ([string]::IsNullOrEmpty($OwnerText)) { return }
    $gate = $null
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while (($null -eq $gate) -and ([DateTime]::UtcNow -lt $deadline)) {
        try { $gate = [IO.File]::Open($maintenanceGate, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
        catch [IO.IOException] { Start-Sleep -Milliseconds 100 }
        catch { break }
    }
    if ($null -eq $gate) {
        Write-UpdateLog 'maintenance_cleanup_failed gate_unavailable'
        return
    }
    try {
        if ([IO.File]::Exists($maintenance)) {
            $current = [IO.File]::ReadAllText($maintenance).Trim()
            if ([string]::Equals($current, $OwnerText, [StringComparison]::Ordinal)) {
                [IO.File]::Delete($maintenance)
            } else {
                Write-UpdateLog 'maintenance_cleanup_skipped owner_changed'
            }
        }
    } catch {
        Write-UpdateLog ('maintenance_cleanup_failed ' + $_.Exception.Message)
    } finally { if ($null -ne $gate) { $gate.Dispose() } }
}

function Get-Serializer {
    Add-Type -AssemblyName System.Web.Extensions
    New-Object System.Web.Script.Serialization.JavaScriptSerializer
}

function Test-SupervisorRunning {
    $probe = $null
    try {
        $probe = [IO.File]::Open(
            $supervisorLock,
            [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
        return $false
    } catch [IO.IOException] {
        return $true
    } finally {
        if ($null -ne $probe) { $probe.Dispose() }
    }
}

function Get-ManagedAgentProcesses {
    $managedPath = [IO.Path]::GetFullPath($currentAgent)
    $processes = New-Object System.Collections.ArrayList
    try {
        $candidates = Get-WmiObject -Class Win32_Process -Filter "Name='onec-agent.exe'" -ErrorAction Stop
    } catch {
        throw ('Unable to inspect onec-agent processes through WMI; refusing update: ' + $_.Exception.Message)
    }

    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrEmpty([string]$candidate.ExecutablePath)) {
            throw 'WMI returned a onec-agent process without an executable path; refusing update because ownership is unknown.'
        }
        try {
            $candidatePath = [IO.Path]::GetFullPath([string]$candidate.ExecutablePath)
        } catch {
            throw 'WMI returned an invalid onec-agent executable path; refusing update because ownership is unknown.'
        }
        if (-not [string]::Equals($candidatePath, $managedPath, [StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        $role = Get-ManagedAgentRole ([string]$candidate.CommandLine) $candidatePath

        $candidatePid = 0
        if (-not [int]::TryParse([string]$candidate.ProcessId, [ref]$candidatePid) -or ($candidatePid -le 0)) {
            throw 'WMI returned a managed onec-agent process without a valid PID; refusing update.'
        }
        $parentPid = 0
        if (-not [int]::TryParse([string]$candidate.ParentProcessId, [ref]$parentPid) -or ($parentPid -lt 0)) {
            throw 'WMI returned a managed onec-agent process without a valid parent PID; refusing update.'
        }
        $process = $null
        try {
            $process = [Diagnostics.Process]::GetProcessById($candidatePid)
            if ($process.HasExited) { continue }
            $startTicks = $process.StartTime.ToUniversalTime().Ticks
            $wmiStartTicks = $candidate.ConvertToDateTime($candidate.CreationDate).ToUniversalTime().Ticks
            if (-not (Test-ManagedAgentStartIdentity $startTicks $wmiStartTicks)) {
                throw ('Managed onec-agent PID ' + [string]$candidatePid + ' changed identity during inspection; refusing update.')
            }
            [void]$processes.Add(@{
                pid = $candidatePid
                parent_pid = $parentPid
                start_ticks = $startTicks
                role = $role
            })
        } catch [ArgumentException] {
            # The process exited between WMI enumeration and PID binding.
            continue
        } catch {
            throw ('Unable to verify managed onec-agent PID ' + [string]$candidatePid + '; refusing update: ' + $_.Exception.Message)
        } finally {
            if ($null -ne $process) { $process.Dispose() }
        }
    }
    return ,$processes
}

# INV-206-smoke-role-start
function Get-ManagedAgentRole([string]$CommandLine, [string]$ExecutablePath) {
    if ([string]::IsNullOrEmpty($CommandLine)) {
        throw 'WMI returned a managed onec-agent process without a command line; refusing update because its role is unknown.'
    }
    $quotedExecutable = '"' + $ExecutablePath + '"'
    if ($CommandLine.StartsWith($quotedExecutable, [StringComparison]::OrdinalIgnoreCase)) {
        $arguments = $CommandLine.Substring($quotedExecutable.Length).Trim()
    } elseif ($CommandLine.StartsWith($ExecutablePath + ' ', [StringComparison]::OrdinalIgnoreCase)) {
        $arguments = $CommandLine.Substring($ExecutablePath.Length).Trim()
    } else {
        throw 'WMI command line does not identify the managed onec-agent executable; refusing update because its role is unknown.'
    }

    $runMatch = [Text.RegularExpressions.Regex]::Match(
        $arguments,
        '^run\s+--config\s+(?:"([^"]+)"|(\S+))$'
    )
    if ($runMatch.Success) {
        $configValue = if ($runMatch.Groups[1].Success) { $runMatch.Groups[1].Value } else { $runMatch.Groups[2].Value }
        try { $candidateConfig = [IO.Path]::GetFullPath($configValue) }
        catch { throw 'WMI command line has an invalid managed agent config path; refusing update because its role is unknown.' }
        if ([string]::Equals($candidateConfig, [IO.Path]::GetFullPath($agentConfigPath), [StringComparison]::OrdinalIgnoreCase)) {
            return 'agent-run'
        }
        throw 'WMI command line runs onec-agent with an unexpected config path; refusing update because its role is unknown.'
    }

    if ([Text.RegularExpressions.Regex]::IsMatch(
        $arguments,
        '^__sshd-host\s+--program\s+(?:"[^"]+"|\S+)\s+--config\s+(?:"[^"]+"|\S+)\s+--start-event\s+(?:"[^"]+"|\S+)$'
    )) {
        return 'sshd-host'
    }
    throw 'WMI command line has an unknown onec-agent role; refusing update.'
}
# INV-206-smoke-role-end

# INV-206-smoke-time-start
function Test-ManagedAgentStartIdentity([Int64]$ProcessStartTicks, [Int64]$WmiStartTicks) {
    if (($ProcessStartTicks -le 0) -or ($WmiStartTicks -le 0)) { return $false }
    return ([Math]::Abs($ProcessStartTicks - $WmiStartTicks) -le 9)
}
# INV-206-smoke-time-end

function Assert-ManagedAgentOwnership([bool]$SupervisorRunning, [int]$ExpectedAgentPid) {
    $managedProcesses = Get-ManagedAgentProcesses
    if ($managedProcesses.Count -eq 0) { return }

    foreach ($managedProcess in $managedProcesses) {
        Write-UpdateLog (
            'managed_process_observed role=' + [string]$managedProcess['role'] +
            ' pid=' + [string]$managedProcess['pid'] +
            ' start_ticks=' + [string]$managedProcess['start_ticks']
        )
    }
    $mainAgents = @($managedProcesses | Where-Object { $_['role'] -eq 'agent-run' })
    $helpers = @($managedProcesses | Where-Object { $_['role'] -eq 'sshd-host' })
    if ($mainAgents.Count -eq 0) {
        throw 'Managed sshd helper process(es) remain without a verified main agent owner. Inspect the logged PIDs and resolve the orphan before rerunning the update.'
    }
    if (-not $SupervisorRunning) {
        throw 'A managed onec-agent process is still running without its supervisor lock. Close the orphan agent through the owning user session, confirm it exits, then rerun the update.'
    }
    if ($mainAgents.Count -ne 1) {
        throw 'Multiple managed onec-agent main processes are running under one supervisor lock. Inspect the listed PIDs and resolve ownership before rerunning the update.'
    }

    $ownedAgentPid = $ExpectedAgentPid
    if ($ownedAgentPid -le 0) {
        $ownedAgentPid = 0
        if ((-not (Test-Path $pidFile)) -or
            (-not [int]::TryParse([IO.File]::ReadAllText($pidFile).Trim(), [ref]$ownedAgentPid)) -or
            ($ownedAgentPid -le 0)) {
            throw 'The supervisor lock is active, but agent.pid does not identify a managed agent process; refusing update.'
        }
    }
    if ([int]$mainAgents[0]['pid'] -ne $ownedAgentPid) {
        throw ('The supervisor ownership PID ' + [string]$ownedAgentPid + ' does not match the running managed agent PID ' + [string]$mainAgents[0]['pid'] + '; refusing update.')
    }
    foreach ($helper in $helpers) {
        if ([int]$helper['parent_pid'] -ne [int]$mainAgents[0]['pid']) {
            throw ('Managed sshd helper PID ' + [string]$helper['pid'] + ' is not a child of the verified managed agent; refusing update.')
        }
    }
}

function Wait-SupervisorStopped([int]$Seconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (-not (Test-SupervisorRunning)) { return }
        Start-Sleep -Milliseconds 500
    }
    throw "onec-agent supervisor did not stop within $Seconds seconds."
}

function Test-AgentAutostart {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
        'Software\Microsoft\Windows\CurrentVersion\Run'
    )
    if ($null -eq $key) { return $false }
    try { return $null -ne $key.GetValue('onec-agent', $null) }
    finally { $key.Close() }
}

function Start-AgentSupervisor {
    if (-not (Test-Path $runnerPath)) { return }
    $powershell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' +
        $runnerPath + '" -Root "' + $Root + '"'
    Start-Process -FilePath $powershell -ArgumentList $arguments -WindowStyle Hidden | Out-Null
}

function Stop-Agent([int]$PidValue) {
    if ($PidValue -le 0) { return }
    $process = Get-Process -Id $PidValue -ErrorAction SilentlyContinue
    if ($null -eq $process) { return }
    if ($process.ProcessName -ne 'onec-agent') {
        throw "Refusing to stop PID $PidValue because it is not onec-agent."
    }
    Stop-Process -Id $PidValue -Force
    try { $process.WaitForExit(15000) | Out-Null } catch { }
    if ($null -ne (Get-Process -Id $PidValue -ErrorAction SilentlyContinue)) {
        throw "onec-agent process $PidValue did not stop within 15 seconds."
    }
}

function Start-DetachedUpdater(
    [int]$CurrentAgentPid,
    [string]$SelectedArchiveUrl,
    [string]$SelectedArchiveFile,
    [string]$SelectedArchiveSha256,
    [string]$SelectedPackageVersion,
    [string]$SelectedTarget
) {
    if ($CurrentAgentPid -le 0) {
        throw 'Cannot delegate update without the current onec-agent PID.'
    }
    $powershell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $selectionArguments = ' -ArchiveSha256 ' + $SelectedArchiveSha256 +
        ' -PackageVersion ' + $SelectedPackageVersion +
        ' -Target ' + $SelectedTarget
    if (-not [string]::IsNullOrEmpty($SelectedArchiveUrl)) {
        $selectionArguments += ' -ArchiveUrl "' + $SelectedArchiveUrl + '"'
    } else {
        $selectionArguments += ' -ArchiveFile "' + $SelectedArchiveFile + '"'
    }
    $commandLine = '"' + $powershell +
        '" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "' + $updaterScriptPath +
        '" -Root "' + $Root + '" -AgentPid ' + [string]$CurrentAgentPid +
        ' -StartDelaySeconds 2 -DetachedHandoff' + $selectionArguments
    $result = ([WmiClass]'Win32_Process').Create($commandLine)
    if (($null -eq $result) -or ([int]$result.ReturnValue -ne 0)) {
        $code = if ($null -eq $result) { -1 } else { [int]$result.ReturnValue }
        throw "Failed to start detached onec-toolkit updater; return_value=$code"
    }
    return [int]$result.ProcessId
}

function Get-AgentServiceStatus([string]$AgentPath) {
    $text = (& $AgentPath service-status | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'onec-agent service-status failed.' }
    return (Get-Serializer).DeserializeObject($text)
}

function Stop-AgentService([string]$AgentPath) {
    & $AgentPath stop-service | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'onec-agent stop-service failed.' }
}

function Start-AgentService([string]$AgentPath) {
    & $AgentPath start-service | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'onec-agent start-service failed.' }
}

function Test-UpdatePreflight {
    $text = (& $currentAgent __self-update --root $Root --preflight | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "onec-agent __self-update --preflight failed with exit code $LASTEXITCODE."
    }
    if ([string]::IsNullOrEmpty($text)) {
        throw 'onec-agent __self-update --preflight returned an empty response.'
    }
    $payload = (Get-Serializer).DeserializeObject($text)
    if (($null -eq $payload) -or (-not $payload.ContainsKey('status'))) {
        throw 'onec-agent __self-update --preflight returned an invalid response.'
    }
    $status = [string]$payload['status']
    if ($status -eq 'ready') { return $true }
    if ($status -eq 'deferred_active_jobs') {
        Write-UpdateLog ('update_deferred result=' + $text)
        Write-Host $text
        return $false
    }
    throw "onec-agent __self-update --preflight returned unsupported status: $status"
}

$metadata = (Get-Serializer).DeserializeObject([IO.File]::ReadAllText($metadataPath))
$persistenceMode = 'user-session'
if ($metadata.ContainsKey('persistence_mode')) {
    $persistenceMode = [string]$metadata['persistence_mode']
}
if (($persistenceMode -ne 'user-session') -and ($persistenceMode -ne 'windows-service')) {
    throw "Unsupported persistence_mode in install.json: $persistenceMode"
}

$invokedBySupervisor = $AgentPid -gt 0
$supervisorWasRunning = Test-SupervisorRunning
$autostartEnabled = Test-AgentAutostart
$maintenanceOwned = $null
$serviceWasRunning = $false
$serviceStoppedForUpdate = $false
$tempRoot = $null

try {
    Write-UpdateLog (
        'update_started pid=' + [string]$PID +
        ' detached_handoff=' + [string][bool]$DetachedHandoff +
        ' agent_pid=' + [string]$AgentPid +
        ' target=' + $Target + ' package_version=' + $PackageVersion
    )

    if (-not (Test-UpdatePreflight)) { return }

    if ($persistenceMode -eq 'user-session') {
        Assert-ManagedAgentOwnership $supervisorWasRunning $AgentPid
    }

    if (
        ($persistenceMode -eq 'user-session') -and
        (-not $invokedBySupervisor) -and
        (-not $DetachedHandoff) -and
        $supervisorWasRunning
    ) {
        $recordedAgentPid = 0
        if (Test-Path $pidFile) {
            [int]::TryParse([IO.File]::ReadAllText($pidFile).Trim(), [ref]$recordedAgentPid) |
                Out-Null
        }
        if ($recordedAgentPid -le 0) {
            throw 'Running user-session supervisor has no valid managed agent.pid for detached update.'
        }
        $detachedPid = Start-DetachedUpdater $recordedAgentPid $ArchiveUrl $ArchiveFile $ArchiveSha256 $PackageVersion $Target
        Write-UpdateLog (
            'update_delegated detached_pid=' + [string]$detachedPid +
            ' agent_pid=' + [string]$recordedAgentPid
        )
        Write-Host "onec-toolkit update delegated to detached process $detachedPid."
        return
    }

    $tempRoot = Join-Path $env:TEMP ('onec-toolkit-self-update-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
    $tempAgent = Join-Path $tempRoot 'onec-agent.exe'
    Copy-Item -Force $currentAgent $tempAgent

    if ($persistenceMode -eq 'windows-service') {
        $serviceStatus = Get-AgentServiceStatus $currentAgent
        if (-not [bool]$serviceStatus['installed']) {
            throw 'install.json requires windows-service persistence but the onec-agent service is not installed.'
        }
        $serviceWasRunning = [string]$serviceStatus['state'] -ne 'stopped'
        if ($serviceWasRunning) {
            Stop-AgentService $currentAgent
            $serviceStoppedForUpdate = $true
        }
    } elseif ($DetachedHandoff) {
        if (-not $supervisorWasRunning) {
            throw 'Detached user-session update lost its supervisor before maintenance handoff.'
        }
        $maintenanceOwned = New-MaintenanceMarker 'update'
        Write-UpdateLog ('maintenance_requested agent_pid=' + [string]$AgentPid)
        Wait-SupervisorStopped 30
        Write-UpdateLog 'supervisor_quiesced'
    } elseif ($invokedBySupervisor) {
        Stop-Agent $AgentPid
        Write-UpdateLog ('agent_stopped_directly agent_pid=' + [string]$AgentPid)
    }

    $updateArguments = @('__self-update', '--root', $Root)
    if (-not [string]::IsNullOrEmpty($ArchiveUrl)) {
        $updateArguments += @('--archive-url', $ArchiveUrl)
    } else {
        $updateArguments += @('--archive-file', $ArchiveFile)
    }
    $updateArguments += @('--archive-sha256', $ArchiveSha256, '--package-version', $PackageVersion, '--target', $Target)

    Write-UpdateLog ('rust_update_started target=' + $Target + ' package_version=' + $PackageVersion)
    $resultText = (& $tempAgent @updateArguments | Out-String).Trim()
    $updateCode = $LASTEXITCODE
    if ($updateCode -ne 0) {
        throw "onec-agent __self-update failed with exit code $updateCode."
    }
    $result = (Get-Serializer).DeserializeObject($resultText)
    if (($null -eq $result) -or (-not $result.ContainsKey('status'))) {
        throw 'onec-agent __self-update returned an invalid response.'
    }
    $resultStatus = [string]$result['status']
    if ($resultStatus -eq 'deferred_active_jobs') {
        Write-UpdateLog ('rust_update_deferred result=' + $resultText)
        if (-not [string]::IsNullOrEmpty($resultText)) { Write-Host $resultText }
        return
    }
    if (($resultStatus -ne 'updated') -and ($resultStatus -ne 'up_to_date')) {
        throw "onec-agent __self-update returned unsupported status: $resultStatus"
    }
    if ($resultStatus -eq 'updated') {
        $publishedRunner = Join-Path $binDir 'Run-OnecAgent.ps1'
        if (-not (Test-Path $publishedRunner)) {
            throw "Updated runtime is missing $publishedRunner"
        }
        Copy-Item -Force $publishedRunner $runnerPath
    }
    if (-not [string]::IsNullOrEmpty($resultText)) { Write-Host $resultText }
    Write-UpdateLog ('rust_update_completed result=' + $resultText)
} catch {
    Write-UpdateLog ('update_failed error=' + $_.Exception.Message)
    throw
} finally {
    if ($null -ne $tempRoot) {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $tempRoot
    }
    if ($maintenanceOwned) {
        Remove-OwnedMaintenanceMarker $maintenanceOwned
        if ($supervisorWasRunning -or $autostartEnabled) {
            Start-AgentSupervisor
        }
    }
    if (($persistenceMode -eq 'windows-service') -and $serviceStoppedForUpdate) {
        Start-AgentService (Join-Path $binDir 'onec-agent.exe')
    }
}
