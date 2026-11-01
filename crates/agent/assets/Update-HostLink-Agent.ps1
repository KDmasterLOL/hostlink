param(
    [Parameter(Mandatory=$true)][string]$Updater,
    [string]$Version
)
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($null -eq $identity -or $null -eq $identity.User) { throw 'A current user identity is required.' }
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) { throw 'Agent updates must run unelevated in the interactive user session.' }

# Run only after service stop/remove, using a verified copy outside bin beneath
# the Agent root. The Rust updater reads the target's private GitHub credential
# and owns exact release selection, manifest checks, locks and publication.
$scriptDirectory = [IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
$root = [IO.Directory]::GetParent($scriptDirectory).FullName
$arguments = @('update', '--root', $root)
if (-not [string]::IsNullOrEmpty($Version)) { $arguments += @('--version', $Version) }
& $Updater @arguments
if ($LASTEXITCODE -ne 0) { throw ('Agent update failed with exit code ' + $LASTEXITCODE) }
