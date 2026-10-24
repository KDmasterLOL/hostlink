param(
    [string]$Root = "$env:LOCALAPPDATA\onec-toolkit"
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$bin = Join-Path $Root 'bin\onec-agent.exe'
$agentDirectory = Join-Path $Root 'agent'
$config = Join-Path $Root 'agent\agent.json'
$pidFile = Join-Path $Root 'agent\agent.pid'
$lockPath = Join-Path $Root 'agent\supervisor.lock'
$maintenance = Join-Path $Root 'agent\maintenance'
$maintenanceGate = Join-Path $Root 'agent\maintenance.gate'
$logPath = Join-Path $Root 'agent\supervisor.log'
$agentEventLog = Join-Path $Root 'agent\agent-events.log'

function Write-SupervisorLog([string]$Message) {
    $line = [DateTime]::UtcNow.ToString('o') + ' ' + $Message + "`r`n"
    try { [IO.File]::AppendAllText($logPath, $line) } catch { }
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

function Get-MaintenanceStateUnderGate {
    $gate = $null
    try {
        $gate = [IO.File]::Open($maintenanceGate, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    } catch {
        Write-SupervisorLog 'maintenance_check_failed gate_unavailable'
        return 'unknown'
    }
    try {
        $state = Get-MaintenanceMarkerState
        if ($state -eq 'orphan') {
            [IO.File]::Delete($maintenance)
            Write-SupervisorLog 'maintenance_orphan_recovered owner_process_absent_or_reused'
            return 'absent'
        }
        return $state
    } catch {
        Write-SupervisorLog ('maintenance_check_failed ' + $_.Exception.Message)
        return 'unknown'
    } finally { if ($null -ne $gate) { $gate.Dispose() } }
}

if (-not (Test-Path $agentDirectory)) { throw "Missing $agentDirectory" }

$lock = $null
try {
    try {
        $lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    } catch [IO.IOException] {
        # Another logon/session already owns the user-mode agent supervisor.
        return
    }

    Write-SupervisorLog ('supervisor_started pid=' + [string]$PID)
    $maintenanceState = Get-MaintenanceStateUnderGate
    if ($maintenanceState -eq 'live') {
        Write-SupervisorLog 'supervisor_stopped maintenance_marker_owner_live'
        return
    }
    if ($maintenanceState -eq 'unknown') {
        Write-SupervisorLog 'supervisor_stopped maintenance_marker_owner_unverifiable'
        return
    }
    if (-not (Test-Path $bin)) { throw "Missing $bin" }
    if (-not (Test-Path $config)) { throw "Missing $config" }
    while ($true) {
        $maintenanceState = Get-MaintenanceStateUnderGate
        if ($maintenanceState -eq 'live') {
            Write-SupervisorLog 'supervisor_stopped maintenance_marker_owner_live'
            return
        }
        if ($maintenanceState -eq 'unknown') {
            Write-SupervisorLog 'supervisor_stopped maintenance_marker_owner_unverifiable'
            return
        }
        if (-not (Test-Path $bin)) { throw "Missing $bin" }
        $agentArguments = 'run --config "' + $config + '"'
        try {
            $env:ONEC_AGENT_EVENT_LOG = $agentEventLog
            $agent = Start-Process -FilePath $bin -ArgumentList $agentArguments -WindowStyle Hidden -PassThru
            Write-SupervisorLog ('agent_started pid=' + [string]$agent.Id)
        } catch {
            Write-SupervisorLog ('agent_start_failed ' + $_.Exception.Message)
            Start-Sleep -Seconds 15
            continue
        }
        [IO.File]::WriteAllText($pidFile, ([string]$agent.Id + "`n"))

        while (-not $agent.HasExited) {
            Start-Sleep -Seconds 15
            if (Test-Path $maintenance) {
                try { Stop-Process -Id $agent.Id -Force -ErrorAction SilentlyContinue } catch { }
                try { $agent.WaitForExit(15000) | Out-Null } catch { }
                break
            }
        }

        try {
            if ($agent.HasExited) {
                Write-SupervisorLog ('agent_exited pid=' + [string]$agent.Id + ' exit_code=' + [string]$agent.ExitCode)
            }
        } catch {
            Write-SupervisorLog ('agent_exit_status_failed pid=' + [string]$agent.Id + ' error=' + $_.Exception.Message)
        }
        Remove-Item -Force -ErrorAction SilentlyContinue $pidFile
        $maintenanceState = Get-MaintenanceStateUnderGate
        if ($maintenanceState -eq 'live') {
            Write-SupervisorLog 'supervisor_stopped maintenance_marker_owner_live'
            return
        }
        if ($maintenanceState -eq 'unknown') {
            Write-SupervisorLog 'supervisor_stopped maintenance_marker_owner_unverifiable'
            return
        }
        Write-SupervisorLog 'agent_restart_scheduled delay_seconds=5'
        Start-Sleep -Seconds 5
    }
} finally {
    if ($null -ne $lock) {
        Remove-Item -Force -ErrorAction SilentlyContinue $pidFile
        $lock.Dispose()
    }
}
