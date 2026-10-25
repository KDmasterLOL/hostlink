param(
    [Parameter(Mandatory=$true)][string]$ArchiveFile,
    [Parameter(Mandatory=$true)][string]$ArchiveSha256,
    [Parameter(Mandatory=$true)][string]$PackageVersion,
    [Parameter(Mandatory=$true)][string]$Target
)

$ErrorActionPreference = 'Stop'
if ($ArchiveSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'ArchiveSha256 must be a 64-character SHA-256 digest.' }
if ($PackageVersion -notmatch '^\d+\.\d+\.\d+([+-][0-9A-Za-z.-]+)?$') { throw 'PackageVersion must be an exact semantic version.' }
$supportedTargets = @('x86_64-pc-windows-msvc', 'x86_64-win7-windows-msvc', 'i686-win7-windows-msvc')
if ($supportedTargets -cnotcontains $Target) { throw 'Unsupported Windows package target.' }
# The .NET 4 Is64BitOperatingSystem property is unavailable to PowerShell 2 / CLR 2.
$is64BitOS = ([IntPtr]::Size -eq 8) -or ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64')
if (-not $is64BitOS -and $Target.StartsWith('x86_64-')) {
    throw 'A 64-bit Agent package cannot be installed on a 32-bit Windows operating system.'
}
if (-not [IO.Path]::IsPathRooted($ArchiveFile)) { throw 'ArchiveFile must be an absolute path inside the HostLink Agent root.' }

$localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
if ([string]::IsNullOrEmpty($localAppData)) { throw 'The current user''s LocalAppData directory is unavailable.' }
$root = [IO.Path]::GetFullPath([IO.Path]::Combine($localAppData, 'HostLink\Agent'))
$archive = [IO.Path]::GetFullPath($ArchiveFile)
$prefix = $root.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $archive.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'ArchiveFile must be contained by the HostLink Agent root.' }
if (-not [IO.File]::Exists($archive)) { throw 'ArchiveFile does not name an existing regular file.' }
if (([IO.File]::GetAttributes($archive) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'ArchiveFile must not be a reparse point.' }
if ((New-Object IO.FileInfo($archive)).Length -gt 536870912) { throw 'ArchiveFile exceeds the 512 MiB limit.' }
$agent = Join-Path $root 'hostlink-agent\bin\hostlink-agent.exe'
foreach ($directory in @($root, (Join-Path $root 'hostlink-agent'), (Join-Path $root 'hostlink-agent\bin'))) {
    if (-not [IO.Directory]::Exists($directory)) { throw ('HostLink Agent directory is missing: ' + $directory) }
    if (([IO.File]::GetAttributes($directory) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw ('HostLink Agent directory must not be a reparse point: ' + $directory) }
}
if (-not [IO.File]::Exists($agent)) { throw 'Installed HostLink Agent executable is missing.' }
if (([IO.File]::GetAttributes($agent) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Installed HostLink Agent executable must not be a reparse point.' }

& $agent __self-update --root $root --agent-only --archive-file $archive --archive-sha256 $ArchiveSha256 --package-version $PackageVersion --target $Target
exit $LASTEXITCODE
