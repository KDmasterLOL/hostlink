param(
    [string]$ExpectedDisposableSid,
    [string]$ExpectedDisposableProfile,
    [string]$ProtectedWorkSid,
    [string]$ProtectedWorkProfile,
    [switch]$RunAcceptance
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$runKey = 'Software\Microsoft\Windows\CurrentVersion\Run'
$optInName = 'HOSTLINK_WINDOWS_LIFECYCLE_DISPOSABLE'
$savedOptIn = [Environment]::GetEnvironmentVariable($optInName, 'Process')
$harnessEnvironment = @(
    'HOSTLINK_WINDOWS_LIFECYCLE_EXPECTED_SID',
    'HOSTLINK_WINDOWS_LIFECYCLE_EXPECTED_PROFILE',
    'HOSTLINK_WINDOWS_LIFECYCLE_PROTECTED_WORK_SID',
    'HOSTLINK_WINDOWS_LIFECYCLE_AGENT_SHA256'
)
$savedHarnessEnvironment = @{}
foreach ($name in $harnessEnvironment) {
    $savedHarnessEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
[Environment]::SetEnvironmentVariable($optInName, $null, 'Process')

function Get-RunValues {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($runKey, $false)
    if ($null -eq $key) { return @{} }
    try {
        $values = @{}
        foreach ($name in $key.GetValueNames()) {
            $values[$name] = [string]$key.GetValue($name, $null, 'DoNotExpandEnvironmentNames')
        }
        return $values
    }
    finally { $key.Dispose() }
}

function Assert-SameRunValues($before, $after) {
    $beforeJson = ConvertTo-Json -InputObject $before -Compress -Depth 4
    $afterJson = ConvertTo-Json -InputObject $after -Compress -Depth 4
    if ($beforeJson -cne $afterJson) {
        throw 'HKCU Run values changed; Task Scheduler lifecycle must never write Run values.'
    }
}

# Read-only snapshot of all visible root-folder tasks, including hidden tasks.
function Get-TaskValues {
    $scheduler = New-Object -ComObject 'Schedule.Service'
    $scheduler.Connect()
    $folder = $scheduler.GetFolder('\')
    $values = @{}
    foreach ($task in $folder.GetTasks(1)) { $values[[string]$task.Name] = [string]$task.Xml }
    return $values
}
function Assert-SameTaskValues($before, $after) {
    if ($before.Count -ne $after.Count) { throw 'Root Task Scheduler task count changed after lifecycle teardown.' }
    foreach ($name in $before.Keys) {
        if (-not $after.ContainsKey($name) -or $before[$name] -cne $after[$name]) {
            throw ('Foreign or unresolved Task Scheduler task changed: ' + $name)
        }
    }
}
$taskValuesBefore = $null
$runValuesBefore = $null
try {
    $runValuesBefore = Get-RunValues
    $taskValuesBefore = Get-TaskValues
    if (-not $RunAcceptance) {
        Write-Output 'Preflight-only: no test opt-in was set and no lifecycle test was invoked.'
        return
    }

    foreach ($required in @($ExpectedDisposableSid, $ExpectedDisposableProfile, $ProtectedWorkSid, $ProtectedWorkProfile)) {
        if ([string]::IsNullOrWhiteSpace($required)) { throw 'RunAcceptance requires disposable and protected WORK identity values.' }
    }
    if ($ExpectedDisposableSid -notmatch '^S-1-5-21-(\d+-){2,}\d+$' -or $ExpectedDisposableSid -eq $ProtectedWorkSid) {
        throw 'ExpectedDisposableSid must be a distinct local/domain user SID, not SYSTEM or WORK.'
    }
    if ([string]::Equals([IO.Path]::GetFullPath($ExpectedDisposableProfile).TrimEnd('\'), [IO.Path]::GetFullPath($ProtectedWorkProfile).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Disposable profile path must differ from the protected WORK profile.'
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.User.Value -ne $ExpectedDisposableSid) { throw 'Current process SID is not the explicitly verified disposable SID.' }
    if ($identity.User.Value -eq 'S-1-5-18') { throw 'SYSTEM execution is forbidden.' }
    $adminSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    foreach ($group in $identity.Groups) {
        if ($group -eq $adminSid) { throw 'The disposable account must not belong to local Administrators.' }
    }
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated execution is forbidden.' }

    $actualProfile = [IO.Path]::GetFullPath([Environment]::GetFolderPath('UserProfile')).TrimEnd('\')
    $expectedProfile = [IO.Path]::GetFullPath($ExpectedDisposableProfile).TrimEnd('\')
    if (-not [string]::Equals($actualProfile, $expectedProfile, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The OS-resolved current user profile differs from ExpectedDisposableProfile.'
    }
    if ([string]::Equals($actualProfile, [IO.Path]::GetFullPath($ProtectedWorkProfile).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to use the protected WORK profile.'
    }
    if ($env:USERPROFILE -and -not [string]::Equals([IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\'), $actualProfile, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'USERPROFILE differs from the OS-resolved user profile.'
    }
    $os = Get-WmiObject Win32_OperatingSystem
    if ($os.Version -notlike '10.0.*' -or [int]$os.BuildNumber -lt 22000) {
        throw 'This acceptance runner is restricted to Windows 11 build 22000 or newer; Windows 7 is a separate gate.'
    }
    if (-not (Test-Path (Join-Path $actualProfile 'NTUSER.DAT') -PathType Leaf)) {
        throw 'The disposable user profile is not loaded as a real Windows profile.'
    }

    Push-Location $repoRoot
    try {
        if ($env:CARGO_TARGET_DIR) {
            $targetDir = $env:CARGO_TARGET_DIR
            if (-not [IO.Path]::IsPathRooted($targetDir)) { $targetDir = Join-Path $repoRoot $targetDir }
        }
        else { $targetDir = Join-Path $repoRoot 'target' }
        & cargo build --locked -p hostlink-agent --bin hostlink-agent
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
        & cargo test --locked -p hostlink-agent --test agent_lifecycle_windows --no-run
        if ($LASTEXITCODE -ne 0) { throw "Windows lifecycle harness compilation failed with exit code $LASTEXITCODE" }

        $agent = Join-Path $targetDir 'debug\hostlink-agent.exe'
        if (-not (Test-Path $agent -PathType Leaf)) { throw 'Expected cargo-built hostlink-agent.exe was not found.' }
        $agentHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $agent).Hash.ToLowerInvariant()
        $env:HOSTLINK_WINDOWS_LIFECYCLE_EXPECTED_SID = $ExpectedDisposableSid
        $env:HOSTLINK_WINDOWS_LIFECYCLE_EXPECTED_PROFILE = $actualProfile
        $env:HOSTLINK_WINDOWS_LIFECYCLE_PROTECTED_WORK_SID = $ProtectedWorkSid
        $env:HOSTLINK_WINDOWS_LIFECYCLE_AGENT_SHA256 = $agentHash

        # Set the destructive opt-in only after identity, profile, OS and build checks pass.
        Set-Item -Path ("Env:{0}" -f $optInName) -Value '1'
        & cargo test --locked -p hostlink-agent --test agent_lifecycle_windows current_user_lifecycle_installs_reports_and_removes_only_its_disposable_root -- --ignored --exact --nocapture
        $testExit = $LASTEXITCODE
        $afterHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $agent).Hash.ToLowerInvariant()
        if ($afterHash -ne $agentHash) { throw 'Cargo Agent binary changed during native acceptance.' }
        if ($testExit -ne 0) { throw "Native lifecycle acceptance failed with exit code $testExit" }

        $remaining = Get-WmiObject Win32_Process -Filter "Name = 'hostlink-agent.exe'" | Where-Object {
            $_.ExecutablePath -and $_.ExecutablePath.StartsWith((Join-Path $actualProfile 'AppData\Local\HostLink Lifecycle Test'), [StringComparison]::OrdinalIgnoreCase)
        }
        if ($remaining) { throw 'A disposable lifecycle Agent process remains after test teardown.' }
        Assert-SameRunValues $runValuesBefore (Get-RunValues)
        Assert-SameTaskValues $taskValuesBefore (Get-TaskValues)
        Write-Output ("NATIVE WINDOWS 11 ACCEPTANCE PASS; SID={0}; PROFILE={1}; Agent SHA-256={2}" -f $ExpectedDisposableSid, $actualProfile, $agentHash)
    }
    finally { Pop-Location }
}
finally {
    [Environment]::SetEnvironmentVariable($optInName, $savedOptIn, 'Process')
    foreach ($name in $harnessEnvironment) {
        [Environment]::SetEnvironmentVariable($name, $savedHarnessEnvironment[$name], 'Process')
    }
    if ($null -ne $taskValuesBefore) { Assert-SameTaskValues $taskValuesBefore (Get-TaskValues) }
    if ($null -ne $runValuesBefore) { Assert-SameRunValues $runValuesBefore (Get-RunValues) }
}
