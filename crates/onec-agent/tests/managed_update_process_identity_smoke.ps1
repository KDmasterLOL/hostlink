param(
    [string]$UpdaterPath = ''
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrEmpty($UpdaterPath)) {
    $scriptDirectory = [IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
    $UpdaterPath = Join-Path $scriptDirectory '..\assets\Update-OnecToolkit.ps1'
}

function Get-MarkedFunctionSource([string]$Source, [string]$FunctionName, [string]$EndMarker) {
    $functionStart = $Source.IndexOf('function ' + $FunctionName, [StringComparison]::Ordinal)
    if ($functionStart -lt 0) { throw ('Missing production function: ' + $FunctionName) }
    $functionEnd = $Source.IndexOf($EndMarker, $functionStart, [StringComparison]::Ordinal)
    if ($functionEnd -lt 0) { throw ('Missing production function marker: ' + $EndMarker) }
    return $Source.Substring($functionStart, $functionEnd - $functionStart)
}

$source = [IO.File]::ReadAllText([IO.Path]::GetFullPath($UpdaterPath))
$roleSource = Get-MarkedFunctionSource $source 'Get-ManagedAgentRole' '# INV-206-smoke-role-end'
$timeSource = Get-MarkedFunctionSource $source 'Test-ManagedAgentStartIdentity' '# INV-206-smoke-time-end'
Invoke-Expression $roleSource
Invoke-Expression $timeSource

$exe = 'C:\Owned Root\bin\onec-agent.exe'
$agentConfigPath = 'C:\Owned Root\agent\agent.json'
$mainCommandLine = '"' + $exe + '" run --config "' + $agentConfigPath + '"'
$helperCommandLine = '"' + $exe + '" __sshd-host --program "C:\Program Files\OpenSSH\sshd.exe" --config "C:\Owned Root\agent\sshd_config" --start-event "Local\onec_toolkit_sshd_start_1_1"'

if ((Get-ManagedAgentRole $mainCommandLine $exe) -ne 'agent-run') {
    throw 'Production role parser did not recognize the managed run --config process.'
}
if ((Get-ManagedAgentRole $helperCommandLine $exe) -ne 'sshd-host') {
    throw 'Production role parser did not recognize the owned __sshd-host child.'
}

$unknownRoleRejected = $false
try { [void](Get-ManagedAgentRole ('"' + $exe + '" --unexpected') $exe) }
catch { $unknownRoleRejected = $true }
if (-not $unknownRoleRejected) { throw 'Production role parser accepted an unknown commandline.' }

$wrongConfigRejected = $false
try { [void](Get-ManagedAgentRole ('"' + $exe + '" run --config "C:\Other Root\agent.json"') $exe) }
catch { $wrongConfigRejected = $true }
if (-not $wrongConfigRejected) { throw 'Production role parser accepted a different config path.' }

if (-not (Test-ManagedAgentStartIdentity 10000 9991)) {
    throw 'Production start-time comparison rejected the native 9-tick observation.'
}
if (-not (Test-ManagedAgentStartIdentity 10000 9994)) {
    throw 'Production start-time comparison rejected the native 6-tick observation.'
}
if (Test-ManagedAgentStartIdentity 10000 9990) {
    throw 'Production start-time comparison accepted a 10-tick difference.'
}
if (Test-ManagedAgentStartIdentity 0 0) {
    throw 'Production start-time comparison accepted an unknown zero identity.'
}

# Exercise the actual ownership preflight on mocked process observations without
# enumerating or stopping any installed agent, service, or supervisor.
$guardSource = Get-MarkedFunctionSource $source 'Assert-ManagedAgentOwnership' 'function Wait-SupervisorStopped'
Invoke-Expression $guardSource
function Get-ManagedAgentProcesses { return ,$script:observedProcesses }
function Write-UpdateLog([string]$Message) { }
function Set-ObservedProcesses([object[]]$Processes) {
    $script:observedProcesses = New-Object System.Collections.ArrayList
    foreach ($p in $Processes) { [void]$script:observedProcesses.Add($p) }
}
function Assert-OwnershipRejected([string]$Label, [bool]$SupervisorRunning, [int]$ExpectedPid) {
    $rejected = $false
    try { Assert-ManagedAgentOwnership $SupervisorRunning $ExpectedPid }
    catch { $rejected = $true }
    if (-not $rejected) { throw ('Expected ownership refusal: ' + $Label) }
}
$main = @{role='agent-run';pid=101;parent_pid=50;start_ticks=10000}
$helper = @{role='sshd-host';pid=102;parent_pid=101;start_ticks=10001}
Set-ObservedProcesses @()
Assert-ManagedAgentOwnership $false 0
Set-ObservedProcesses @($main, $helper)
Assert-ManagedAgentOwnership $true 101
Assert-OwnershipRejected 'orphan main' $false 101
Assert-OwnershipRejected 'supervisor PID disagreement' $true 999
Set-ObservedProcesses @($main, @{role='sshd-host';pid=102;parent_pid=999;start_ticks=10001})
Assert-OwnershipRejected 'helper belongs to another process' $true 101
Set-ObservedProcesses @($helper)
Assert-OwnershipRejected 'helper without verified main agent' $true 101
Set-ObservedProcesses @($main, @{role='agent-run';pid=103;parent_pid=50;start_ticks=10002})
Assert-OwnershipRejected 'multiple main agents' $true 101

Write-Output 'INV-206 production role, time and ownership preflight smoke passed.'
