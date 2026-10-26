param(
    [Parameter(Mandatory=$true)][string]$Archive,
    [Parameter(Mandatory=$true)][string]$Sha256,
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter(Mandatory=$true)][string]$Version
)
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($null -eq $identity -or $null -eq $identity.User) { throw 'A current user identity is required.' }
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) { throw 'Agent updates must run unelevated in the interactive user session.' }

# The Agent currently has no Windows stopped-process launcher handoff. This script
# deliberately cannot publish an executable or claim that an update succeeded.
if ($Sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Sha256 must be a lowercase SHA-256 digest.' }
if ($Version -notmatch '^\d+\.\d+\.\d+([+-][0-9A-Za-z.-]+)?$') { throw 'Version must be an exact semantic version.' }
if (@('x86_64-pc-windows-msvc','x86_64-win7-windows-msvc','i686-win7-windows-msvc') -cnotcontains $Target) { throw 'Unsupported Windows Agent target.' }
if (-not [IO.Path]::IsPathRooted($Archive) -or -not [IO.File]::Exists($Archive)) { throw 'Archive must be an existing local file.' }
throw 'Unsupported: Windows Agent replacement requires the stopped-runtime launcher handoff; no files were changed.'
