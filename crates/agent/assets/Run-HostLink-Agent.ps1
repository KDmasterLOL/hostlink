param()
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($null -eq $identity -or $null -eq $identity.User) { throw 'A current user identity is required.' }
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) {
    throw 'HostLink Agent must run unelevated in the interactive user session.'
}
$bin = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $bin
$agent = Join-Path $bin 'hostlink-agent.exe'
$config = Join-Path (Join-Path $root 'state') 'agent.json'
function Assert-CurrentUserOnly([string]$Path, [Security.Principal.SecurityIdentifier]$Sid) {
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Agent installation paths may not be reparse points.' }
    $acl = $item.GetAccessControl()
    if (-not $acl.GetOwner([Security.Principal.SecurityIdentifier]).Equals($Sid) -or -not $acl.AreAccessRulesProtected) { throw 'Agent installation owner or ACL is unsafe.' }
    foreach ($rule in $acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and -not $rule.IdentityReference.Equals($Sid)) { throw 'Agent installation ACL grants access to another identity.' }
    }
}
foreach ($path in @($root, $config)) {
    if (-not (Test-Path -LiteralPath $path)) { throw 'The user-owned Agent installation is incomplete.' }
    Assert-CurrentUserOnly $path $identity.User
}
# The updater publishes a nonsecret bundle with self_update's native ACLs.
# Keep root/state private, and reject links for both bundle paths.
foreach ($path in @($bin, $agent)) {
    $item = Get-Item -LiteralPath $path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Agent bundle paths may not be reparse points.' }
}
if (-not (Test-Path -LiteralPath $bin -PathType Container)) { throw 'Agent bin directory is missing.' }
if (-not (Test-Path -LiteralPath $config -PathType Leaf) -or -not (Test-Path -LiteralPath $agent -PathType Leaf)) { throw 'Agent executable or configuration is missing.' }
Write-Output 'Starting HostLink Agent in the current user session. Press Ctrl-C to stop.'
& $agent run --config $config
if ($LASTEXITCODE -ne 0) { throw 'HostLink Agent exited with an error.' }
