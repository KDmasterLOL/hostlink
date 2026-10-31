param(
    [Parameter(Mandatory=$true)][string]$Url,
    [Parameter(Mandatory=$true)][string]$Sha256,
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter(Mandatory=$true)][string]$Version,
    [Parameter(Mandatory=$true)][string]$Updater
)
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($null -eq $identity -or $null -eq $identity.User) { throw 'A current user identity is required.' }
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) { throw 'Agent updates must run unelevated in the interactive user session.' }

# Run only after service stop/remove, using a verified copy outside bin beneath the
# Agent root. The Rust updater owns admission, pins, URL validation and publication.
$scriptDirectory = [IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
$root = [IO.Directory]::GetParent($scriptDirectory).FullName
& $Updater update --root $root --url $Url --sha256 $Sha256 --target $Target --version $Version
if ($LASTEXITCODE -ne 0) { throw ('Agent update failed with exit code ' + $LASTEXITCODE) }
