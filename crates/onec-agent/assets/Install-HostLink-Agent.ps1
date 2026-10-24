param(
    [Parameter(Mandatory=$true)][string]$ArchiveFile,
    [Parameter(Mandatory=$true)][string]$ArchiveSha256,
    [Parameter(Mandatory=$true)][string]$PackageVersion,
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter(Mandatory=$true)][string]$ConfigFile
)

$ErrorActionPreference = 'Stop'

$supportedTargets = @(
    'x86_64-pc-windows-msvc',
    'x86_64-win7-windows-msvc',
    'i686-win7-windows-msvc'
)
if ($supportedTargets -cnotcontains $Target) { throw 'Unsupported Windows package target.' }
if ((-not [Environment]::Is64BitOperatingSystem) -and $Target.StartsWith('x86_64-')) {
    throw 'A 64-bit Agent package cannot be installed on a 32-bit Windows operating system.'
}
if ($PackageVersion -notmatch '^\d+\.\d+\.\d+([+-][0-9A-Za-z.-]+)?$') {
    throw 'PackageVersion must be an exact semantic version.'
}
if ($ArchiveSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'ArchiveSha256 must be a 64-character SHA-256 digest.' }
if (-not [IO.Path]::IsPathRooted($ArchiveFile)) { throw 'ArchiveFile must be an absolute path.' }
if (-not [IO.Path]::IsPathRooted($ConfigFile)) { throw 'ConfigFile must be an absolute path.' }

$localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
if ([string]::IsNullOrEmpty($localAppData)) { throw 'The current user's LocalAppData directory is unavailable.' }
$root = [IO.Path]::GetFullPath([IO.Path]::Combine($localAppData, 'HostLink\Agent'))
if ([IO.Directory]::Exists($root) -or [IO.File]::Exists($root)) {
    throw 'HostLink Agent install requires a fresh root. Existing roots are never adopted.'
}

$archive = [IO.Path]::GetFullPath($ArchiveFile)
$config = [IO.Path]::GetFullPath($ConfigFile)
if (-not [IO.File]::Exists($archive)) { throw 'ArchiveFile does not name an existing regular file.' }
if (-not [IO.File]::Exists($config)) { throw 'ConfigFile does not name an existing regular file.' }
if (([IO.File]::GetAttributes($archive) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'ArchiveFile must not be a reparse point.'
}
if (([IO.File]::GetAttributes($config) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'ConfigFile must not be a reparse point.'
}
if ((New-Object IO.FileInfo($archive)).Length -gt 536870912) { throw 'ArchiveFile exceeds the 512 MiB limit.' }
if ((New-Object IO.FileInfo($config)).Length -gt 262144) { throw 'ConfigFile exceeds the 256 KiB limit.' }

function Get-Sha256Stream([IO.Stream]$Stream) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

# Windows 7 PowerShell 2 has no Expand-Archive. Read only the exact package inventory and
# write each member to a fixed destination; archive paths are never used as filesystem paths.
try {
    $compressionAssembly = [Reflection.Assembly]::LoadWithPartialName('System.IO.Compression')
    if ($null -eq $compressionAssembly) {
        throw 'Compression assemblies were not found.'
    }
} catch {
    throw 'Agent package extraction requires .NET Framework 4.5 or later on Windows 7.'
}

$bundleName = 'hostlink-agent-' + $Target
$expectedNames = @(
    ($bundleName + '/hostlink-agent.exe'),
    ($bundleName + '/Install-HostLink-Agent.ps1'),
    ($bundleName + '/Run-HostLink-Agent.ps1'),
    ($bundleName + '/Update-HostLink-Agent.ps1')
)
$stage = Join-Path ([IO.Path]::GetTempPath()) ('hostlink-agent-install-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($stage)
try {
if (([IO.File]::GetAttributes($stage) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Temporary Agent staging directory must not be a reparse point.'
}
$archiveStream = $null
$zip = $null
try {
    $archiveStream = [IO.File]::Open($archive, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    if ($archiveStream.Length -gt 536870912) { throw 'ArchiveFile exceeds the 512 MiB limit.' }
    $actualSha256 = Get-Sha256Stream $archiveStream
    if ($actualSha256 -ne $ArchiveSha256.ToLowerInvariant()) { throw 'Archive SHA-256 does not match ArchiveSha256.' }
    $archiveStream.Position = 0
    $zip = New-Object IO.Compression.ZipArchive($archiveStream, [IO.Compression.ZipArchiveMode]::Read, $false)
    if ($zip.Entries.Count -ne $expectedNames.Count) { throw 'Agent package must contain exactly four files.' }
    $seen = @{}
    $expandedTotal = 0L
    foreach ($entry in $zip.Entries) {
        if ($expectedNames -cnotcontains $entry.FullName) { throw ('Unexpected package entry: ' + $entry.FullName) }
        if ($seen.ContainsKey($entry.FullName)) { throw ('Duplicate package entry: ' + $entry.FullName) }
        if ($entry.FullName.EndsWith('/')) { throw 'Directory entries are not allowed in the Agent package.' }
        if (($entry.Length -le 0) -or ($entry.Length -gt 268435456)) { throw 'Package entry has an invalid size.' }
        $expandedTotal += $entry.Length
        if ($expandedTotal -gt 536870912) { throw 'Expanded Agent package exceeds the 512 MiB limit.' }
        $seen.Add($entry.FullName, $entry)
    }
    foreach ($name in $expectedNames) {
        if (-not $seen.ContainsKey($name)) { throw ('Missing package entry: ' + $name) }
    }

    $stagedBin = Join-Path $stage 'bin'
    $stagedScripts = Join-Path $stage 'scripts'
    [void][IO.Directory]::CreateDirectory($stagedBin)
    [void][IO.Directory]::CreateDirectory($stagedScripts)
    foreach ($name in $expectedNames) {
        if ($name.EndsWith('/hostlink-agent.exe')) {
            $destination = Join-Path $stagedBin 'hostlink-agent.exe'
        } else {
            $scriptName = [IO.Path]::GetFileName($name)
            $destination = Join-Path $stagedScripts $scriptName
        }
        $entryStream = $seen[$name].Open()
        $output = [IO.File]::Open($destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $buffer = New-Object byte[] 65536
            $copied = 0L
            while (($read = $entryStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $copied += $read
                if ($copied -gt $seen[$name].Length) { throw 'Package entry expanded beyond its declared size.' }
                $output.Write($buffer, 0, $read)
            }
            if ($copied -ne $seen[$name].Length) { throw 'Package entry length did not match its ZIP metadata.' }
        } finally { $output.Dispose(); $entryStream.Dispose() }
    }
} finally {
    if ($null -ne $zip) { $zip.Dispose() }
    if ($null -ne $archiveStream) { $archiveStream.Dispose() }
}

$candidate = Join-Path $stage 'bin\hostlink-agent.exe'
& $candidate check --config $config
if ($LASTEXITCODE -ne 0) { throw "Agent config health check failed with exit code $LASTEXITCODE." }

$parent = [IO.Path]::GetDirectoryName($root)
if ([IO.Directory]::Exists($parent)) {
    if (([IO.File]::GetAttributes($parent) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'HostLink parent directory must not be a reparse point.'
    }
} else {
    [void][IO.Directory]::CreateDirectory($parent)
}
if ([IO.Directory]::Exists($root) -or [IO.File]::Exists($root)) {
    throw 'HostLink Agent root appeared during install; refusing to adopt it.'
}
try {
    [void][IO.Directory]::CreateDirectory($root)
    if (([IO.File]::GetAttributes($root) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'New HostLink Agent root unexpectedly resolved to a reparse point.'
    }
    $stagedArchive = Join-Path $root '.hostlink-agent-bootstrap.zip'
    [IO.File]::Copy($archive, $stagedArchive, $false)
    & $candidate __self-update --root $root --agent-only --archive-file $stagedArchive --archive-sha256 $actualSha256 --package-version $PackageVersion --target $Target
    if ($LASTEXITCODE -ne 0) { throw "Agent-only package install failed with exit code $LASTEXITCODE." }
    [IO.File]::Delete($stagedArchive)
    $installedAgent = Join-Path $root ('hostlink-agent\bin\' + $(if ($Target -like '*windows*') { 'hostlink-agent.exe' } else { 'hostlink-agent' }))
    & $installedAgent check --config $config
    if ($LASTEXITCODE -ne 0) { throw "Installed Agent config health check failed with exit code $LASTEXITCODE." }
} catch {
    throw ('Install stopped with an owned incomplete fresh root at ' + $root + '. Inspect and remove that root before retrying. ' + $_.Exception.Message)
}

Write-Host ('HostLink Agent installed in the fresh user root: ' + $root)
Write-Host ('Run explicitly with: powershell.exe -NoProfile -File "' + (Join-Path $root 'hostlink-agent\bin\Run-HostLink-Agent.ps1') + '" -ConfigFile "' + $config + '"')
} finally {
    if ([IO.Directory]::Exists($stage)) { [IO.Directory]::Delete($stage, $true) }
}
