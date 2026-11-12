# One-time transition from the Windows 0.2.4 Agent to a verified raw Agent.
# Run in the Agent user's interactive session, or through its existing SSH session.
# The executable and its SHA-256 must come from the reviewed release candidate.
param(
    [string]$Binary,
    [string]$Sha256,
    [string]$Version,
    [switch]$Worker,
    [string]$Stage,
    [string]$TaskName
)

$ErrorActionPreference = 'Stop'
$root = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'HostLink\Agent'
$installed = Join-Path $root 'bin\hostlink-agent.exe'
$config = Join-Path $root 'state\agent.json'

if (-not $Worker) {
  try {
    if ($Sha256 -notmatch '^[0-9a-fA-F]{64}$' -or $Version -notmatch '^\d+\.\d+\.\d+$') {
        throw 'Provide the candidate SHA-256 and version.'
    }
    $identity = & $installed binary-info
    if ($LASTEXITCODE -ne 0 -or $identity -notmatch '"version":"0\.2\.4"') {
        throw 'This migration requires the installed Agent version 0.2.4.'
    }
    if ($identity -notmatch '"target":"([^"]+)"') { throw 'Installed Agent target is missing.' }
    $target = $Matches[1]
    $sha = [Security.Cryptography.SHA256]::Create()
    $file = [IO.File]::OpenRead((Resolve-Path $Binary).Path)
    try { $actual = ([BitConverter]::ToString($sha.ComputeHash($file))).Replace('-', '') }
    finally { $file.Close(); $sha.Clear() }
    if ($actual -ine $Sha256) { throw 'Candidate SHA-256 does not match.' }
    $identity = & $Binary binary-info
    if ($LASTEXITCODE -ne 0 -or $identity -notmatch ('"version":"' + [Regex]::Escape($Version) + '"')) {
        throw 'Candidate version does not match.'
    }
    if ($identity -notmatch ('"target":"' + [Regex]::Escape($target) + '"')) {
        throw 'Candidate target does not match the installed Agent.'
    }
    $id = [Guid]::NewGuid().ToString('N')
    $stage = Join-Path $root ('.migration-0.2.4-' + $id)
    New-Item -ItemType Directory -Path $stage | Out-Null
    Copy-Item $Binary (Join-Path $stage 'new.exe')
    Copy-Item $installed (Join-Path $stage 'old.exe')
    Copy-Item $MyInvocation.MyCommand.Path (Join-Path $stage 'migration.ps1')
    $sha = [Security.Cryptography.SHA256]::Create()
    $file = [IO.File]::OpenRead((Join-Path $stage 'new.exe'))
    try { $actual = ([BitConverter]::ToString($sha.ComputeHash($file))).Replace('-', '') }
    finally { $file.Close(); $sha.Clear() }
    if ($actual -ine $Sha256) { throw 'Staged candidate SHA-256 does not match.' }
    $scheduler = New-Object -ComObject 'Schedule.Service'
    $scheduler.Connect()
    $folder = $scheduler.GetFolder('\')
    $task = $scheduler.NewTask(0)
    $task.Settings.Enabled = $true
    $task.Settings.ExecutionTimeLimit = 'PT15M'
    $task.Principal.LogonType = 3
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $task.Principal.UserId = $sid
    $action = $task.Actions.Create(0)
    $action.Path = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $taskName = 'HostLinkMigration-' + $id
    $action.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + (Join-Path $stage 'migration.ps1') + '" -Worker -Stage "' + $stage + '" -TaskName ' + $taskName + ' -Sha256 ' + $Sha256
    $registered = $folder.RegisterTaskDefinition($taskName, $task, 2, $sid, $null, 3)
    $null = $registered.Run($null)
    Write-Output ('Migration started; reconnect and check version. Result: ' + (Join-Path $stage 'result.txt'))
    exit 0
  } catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
  }
}

$old = Join-Path $Stage 'old.exe'
$new = Join-Path $Stage 'new.exe'
$result = Join-Path $Stage 'result.txt'
if ($TaskName -notmatch '^HostLinkMigration-([0-9a-f]{32})$') { throw 'Invalid migration task.' }
$id = $Matches[1]
if ($Sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'Invalid candidate SHA-256.' }
$expectedStage = Join-Path $root ('.migration-0.2.4-' + $id)
if ((Resolve-Path $Stage).Path -ine (Resolve-Path $expectedStage).Path) { throw 'Invalid migration stage.' }
$sha = [Security.Cryptography.SHA256]::Create()
$file = [IO.File]::OpenRead($new)
try { $actual = ([BitConverter]::ToString($sha.ComputeHash($file))).Replace('-', '') }
finally { $file.Close(); $sha.Clear() }
if ($actual -ine $Sha256) { throw 'Staged candidate SHA-256 does not match.' }
$removed = $false
try {
    # Let the originating SSH command return before its Agent task is stopped.
    Start-Sleep -Seconds 3
    & $old service remove --root $root
    if ($LASTEXITCODE -ne 0) { throw 'Could not remove the owned Agent task.' }
    $removed = $true
    # Scheduler can report a stopped task before Windows releases its image.
    $copied = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        try {
            Copy-Item -Force -ErrorAction Stop $new $installed
            $copied = $true
            break
        } catch [IO.IOException] {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $copied) { throw 'Agent image remained locked after task removal.' }
    & $installed service install --root $root --config $config
    if ($LASTEXITCODE -ne 0) { throw 'Could not register the new Agent task.' }
    & $installed service start --root $root
    if ($LASTEXITCODE -ne 0) { throw 'Could not start the new Agent task.' }
    Set-Content $result 'Migration completed; verify the Agent connection and version.'
} catch {
    $message = $_.Exception.Message
    if ($removed) {
        try {
            # 0.2.4 returns exit 1 for a missing or stopped task, even when
            # its status query succeeded; distinguish those states by output.
            $previousPreference = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try { $status = & $old service status --root $root }
            finally { $ErrorActionPreference = $previousPreference }
            $statusText = $status | Out-String
            if ($statusText -match 'installed=true') {
                & $old service remove --root $root
                if ($LASTEXITCODE -ne 0) { throw 'Could not remove the new Agent task during recovery.' }
            } elseif ($statusText -notmatch 'installed=false') {
                throw 'Could not inspect the Agent task during recovery.'
            }
            # A failed overwrite can leave the original image intact and still
            # locked. Do not overwrite it merely to restore the task.
            $sha = [Security.Cryptography.SHA256]::Create()
            $file = [IO.File]::OpenRead($old)
            try { $oldHash = [BitConverter]::ToString($sha.ComputeHash($file)) }
            finally { $file.Close() }
            $file = [IO.File]::OpenRead($installed)
            try { $installedHash = [BitConverter]::ToString($sha.ComputeHash($file)) }
            finally { $file.Close(); $sha.Clear() }
            if ($oldHash -ne $installedHash) { Copy-Item -Force $old $installed }
            & $installed service install --root $root --config $config
            if ($LASTEXITCODE -ne 0) { throw 'Could not restore the old Agent task.' }
            & $installed service start --root $root
            if ($LASTEXITCODE -ne 0) { throw 'Could not restart the old Agent.' }
            Set-Content $result ('Migration failed; old Agent restarted: ' + $message)
        } catch {
            Set-Content $result ('Migration and recovery failed: ' + $message + '; ' + $_.Exception.Message)
        }
    } else {
        try { & $old service start --root $root } catch { }
        Set-Content $result ('Migration failed before task removal: ' + $message)
    }
} finally {
    $scheduler = New-Object -ComObject 'Schedule.Service'
    $scheduler.Connect()
    $scheduler.GetFolder('\').DeleteTask($TaskName, 0)
}
