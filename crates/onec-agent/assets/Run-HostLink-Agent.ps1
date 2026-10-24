param([Parameter(Mandatory=$true)][string]$ConfigFile)

$ErrorActionPreference = 'Stop'
$localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
if ([string]::IsNullOrEmpty($localAppData)) { throw 'The current user''s LocalAppData directory is unavailable.' }
$root = [IO.Path]::GetFullPath([IO.Path]::Combine($localAppData, 'HostLink\Agent'))
$installRoot = Join-Path $root 'hostlink-agent'
$metadataPath = Join-Path $installRoot 'install.json'
$bin = Join-Path $installRoot 'bin'
$agent = Join-Path $bin 'hostlink-agent.exe'
if (-not [IO.Directory]::Exists($root)) { throw 'HostLink Agent user root is missing.' }
if (([IO.File]::GetAttributes($root) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'HostLink Agent root must not be a reparse point.' }
foreach ($directory in @($installRoot, $bin)) {
    if (-not [IO.Directory]::Exists($directory)) { throw ('HostLink Agent directory is missing: ' + $directory) }
    if (([IO.File]::GetAttributes($directory) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw ('HostLink Agent directory must not be a reparse point: ' + $directory) }
}
if (-not [IO.File]::Exists($metadataPath)) { throw 'HostLink Agent install metadata is missing.' }
if (([IO.File]::GetAttributes($metadataPath) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'HostLink Agent install metadata must not be a reparse point.' }
if ((New-Object IO.FileInfo($metadataPath)).Length -gt 1048576) { throw 'HostLink Agent install metadata exceeds the 1 MiB limit.' }
if (-not [IO.File]::Exists($agent)) { throw 'Installed HostLink Agent executable is missing.' }
if (([IO.File]::GetAttributes($agent) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Installed HostLink Agent executable must not be a reparse point.' }
if (-not [IO.Path]::IsPathRooted($ConfigFile)) { throw 'ConfigFile must be an absolute path.' }
$config = [IO.Path]::GetFullPath($ConfigFile)
if (-not [IO.File]::Exists($config)) { throw 'ConfigFile does not name an existing regular file.' }
if (([IO.File]::GetAttributes($config) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'ConfigFile must not be a reparse point.' }
if ((New-Object IO.FileInfo($config)).Length -gt 262144) { throw 'ConfigFile exceeds the 256 KiB limit.' }

$metadata = [IO.File]::ReadAllText($metadataPath)
if ($metadata -notmatch '"target"\s*:\s*"(x86_64-pc-windows-msvc|x86_64-win7-windows-msvc|i686-win7-windows-msvc)"') { throw 'HostLink Agent target metadata is invalid.' }
$expectedFiles = @('hostlink-agent.exe', 'Install-HostLink-Agent.ps1', 'Run-HostLink-Agent.ps1', 'Update-HostLink-Agent.ps1')
foreach ($name in $expectedFiles) {
    $escaped = [Regex]::Escape($name)
    $pattern = '"' + $escaped + '"\s*:\s*\{\s*(?:"size"\s*:\s*\d+\s*,\s*"sha256"\s*:\s*"([0-9a-f]{64})"|"sha256"\s*:\s*"([0-9a-f]{64})"\s*,\s*"size"\s*:\s*\d+)'
    if ($metadata -match $pattern) {
        $expected = $matches[1]
        if ([String]::IsNullOrEmpty($expected)) { $expected = $matches[2] }
    } else { throw ('HostLink Agent integrity metadata is missing ' + $name) }
    $path = Join-Path $bin $name
    if (-not [IO.File]::Exists($path)) { throw ('Installed HostLink Agent file is missing: ' + $name) }
    if (([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw ('Installed HostLink Agent file is unsafe: ' + $name) }
    $sha = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($path)
    try { $actual = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Dispose(); $sha.Clear() }
    if ($actual -ne $expected) { throw ('Installed HostLink Agent file digest mismatch: ' + $name) }
}

& $agent check --config $config
if ($LASTEXITCODE -ne 0) { throw "HostLink Agent config health check failed with exit code $LASTEXITCODE." }
& $agent run --config $config
exit $LASTEXITCODE
