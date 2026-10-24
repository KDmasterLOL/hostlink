param(
    [Parameter(Mandatory=$true)][string]$ArchiveFile,
    [Parameter(Mandatory=$true)][string]$ArchiveSha256,
    [Parameter(Mandatory=$true)][string]$PackageVersion,
    [Parameter(Mandatory=$true)][string]$Target,
    [string]$ConfigFile,
    [string]$HubUrl,
    [string]$EnrollmentTokenFile
)

$ErrorActionPreference = 'Stop'

$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($null -eq $currentIdentity -or $null -eq $currentIdentity.User -or @('S-1-5-18', 'S-1-5-19', 'S-1-5-20') -contains $currentIdentity.User.Value) {
    throw 'HostLink Agent bootstrap cannot run as a built-in service account.'
}
if (-not [Environment]::UserInteractive -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) {
    throw 'HostLink Agent bootstrap requires an interactive user session.'
}
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'HostLink Agent bootstrap must run unelevated in the target user session.'
}

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
$enrollmentMode = (-not [string]::IsNullOrEmpty($HubUrl)) -or (-not [string]::IsNullOrEmpty($EnrollmentTokenFile))
if ($enrollmentMode) {
    if ([string]::IsNullOrEmpty($HubUrl) -or [string]::IsNullOrEmpty($EnrollmentTokenFile) -or -not [string]::IsNullOrEmpty($ConfigFile)) {
        throw 'Enrollment mode requires HubUrl and EnrollmentTokenFile together and cannot be combined with ConfigFile.'
    }
    if (-not [IO.Path]::IsPathRooted($EnrollmentTokenFile)) { throw 'EnrollmentTokenFile must be an absolute path.' }
    if ($HubUrl -notmatch '^https://[^/?#]+(/.*)?$' -or $HubUrl.Contains('@') -or $HubUrl.Contains('?') -or $HubUrl.Contains('#')) {
        throw 'HubUrl must be an HTTPS Hub origin or enrollment endpoint.'
    }
} else {
    if ([string]::IsNullOrEmpty($ConfigFile) -or -not [IO.Path]::IsPathRooted($ConfigFile)) { throw 'ConfigFile must be an absolute path in manual configuration mode.' }
}

$localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
if ([string]::IsNullOrEmpty($localAppData)) { throw 'The current user's LocalAppData directory is unavailable.' }
$root = [IO.Path]::GetFullPath([IO.Path]::Combine($localAppData, 'HostLink\Agent'))
if ([IO.Directory]::Exists($root) -or [IO.File]::Exists($root)) {
    throw 'HostLink Agent install requires a fresh root. Existing roots are never adopted.'
}

$archive = [IO.Path]::GetFullPath($ArchiveFile)
$config = $null
if (-not $enrollmentMode) { $config = [IO.Path]::GetFullPath($ConfigFile) }
if (-not [IO.File]::Exists($archive)) { throw 'ArchiveFile does not name an existing regular file.' }
if (-not $enrollmentMode -and -not [IO.File]::Exists($config)) { throw 'ConfigFile does not name an existing regular file.' }
if (([IO.File]::GetAttributes($archive) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'ArchiveFile must not be a reparse point.'
}
if (-not $enrollmentMode -and ([IO.File]::GetAttributes($config) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'ConfigFile must not be a reparse point.'
}
if ($enrollmentMode) {
    $tokenPath = [IO.Path]::GetFullPath($EnrollmentTokenFile)
    if (-not [IO.File]::Exists($tokenPath)) { throw 'EnrollmentTokenFile does not name an existing private file.' }
    if (([IO.File]::GetAttributes($tokenPath) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'EnrollmentTokenFile must not be a reparse point.' }
    if ((New-Object IO.FileInfo($tokenPath)).Length -gt 4096) { throw 'EnrollmentTokenFile exceeds the 4 KiB limit.' }
}
if ((New-Object IO.FileInfo($archive)).Length -gt 536870912) { throw 'ArchiveFile exceeds the 512 MiB limit.' }
if (-not $enrollmentMode -and (New-Object IO.FileInfo($config)).Length -gt 262144) { throw 'ConfigFile exceeds the 256 KiB limit.' }

# The updater always checks <root>/jobs for active work. Manual configurations must use
# that same durable store; otherwise an update could interrupt running jobs unnoticed.
if (-not $enrollmentMode) {
    try {
        Add-Type -AssemblyName System.Web.Extensions
        $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $manualConfig = $serializer.DeserializeObject([IO.File]::ReadAllText($config))
        if ($null -eq $manualConfig -or -not $manualConfig.ContainsKey('jobs_dir')) {
            throw 'Missing jobs_dir.'
        }
        $configuredJobs = [string]$manualConfig['jobs_dir']
        if ([string]::IsNullOrEmpty($configuredJobs) -or $configuredJobs.Trim().Length -eq 0) {
            throw 'Empty jobs_dir.'
        }
        $jobsValue = if ([IO.Path]::IsPathRooted($configuredJobs)) { $configuredJobs } else { [IO.Path]::Combine([IO.Path]::GetDirectoryName($config), $configuredJobs) }
        $jobsCanonical = [IO.Path]::GetFullPath($jobsValue)
        $expectedJobs = [IO.Path]::GetFullPath((Join-Path $root 'jobs'))
        if (-not $jobsCanonical.Equals($expectedJobs, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Foreign jobs_dir.'
        }
    } catch {
        throw 'Manual ConfigFile must set jobs_dir to this fresh HostLink Agent root\jobs; the updater cannot safely verify active work in another directory.'
    }
}

function Get-Sha256Stream([IO.Stream]$Stream) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

# Windows 7 PowerShell 2 has no Expand-Archive. Read only the exact package inventory and
# write each member to a fixed destination; archive paths are never used as filesystem paths.
try {
    $compressionAssembly = [Reflection.Assembly]::LoadWithPartialName('System.IO.Compression')
    if ($null -eq $compressionAssembly -or $null -eq $compressionAssembly.GetType('System.IO.Compression.ZipArchive', $false)) {
        throw 'System.IO.Compression.ZipArchive is unavailable.'
    }
} catch {
    throw 'Agent ZIP extraction requires System.IO.Compression.ZipArchive from .NET Framework 4.5 or later. Windows 7 PowerShell 2 on CLR 2 is not verified and may not provide this type; no fallback extractor is bundled.'
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
    try {
        $zip = New-Object IO.Compression.ZipArchive($archiveStream, [IO.Compression.ZipArchiveMode]::Read, $false)
    } catch {
        throw 'Agent ZIP extraction requires System.IO.Compression.ZipArchive from .NET Framework 4.5 or later. Windows 7 PowerShell 2 on CLR 2 is not verified and may not provide this type; no fallback extractor is bundled.'
    }
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
$parent = [IO.Path]::GetDirectoryName($root)
if ($enrollmentMode) {
    if (-not [IO.Directory]::Exists($parent)) { [void][IO.Directory]::CreateDirectory($parent) }
    if (([IO.File]::GetAttributes($parent) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'HostLink parent directory must not be a reparse point.' }
    $stateDir = Join-Path $parent ('.hostlink-agent-enrollment-' + [Guid]::NewGuid().ToString('N'))
    $prepareArguments = @('__prepare-enrollment', '--hub-url', $HubUrl, '--token-file', $tokenPath, '--state-dir', $stateDir)
    & $candidate @prepareArguments
    if ($LASTEXITCODE -ne 0) { throw 'Agent enrollment failed or its outcome is uncertain. Do not reuse this token; create a new invite before another attempt.' }
    $config = Join-Path $stateDir 'agent.json'
    & $candidate check --config $config
    if ($LASTEXITCODE -ne 0) { throw 'Enrolled Agent config health check failed. Do not reuse this token; create a new invite before another attempt.' }
} else {
    & $candidate check --config $config
    if ($LASTEXITCODE -ne 0) { throw "Agent config health check failed with exit code $LASTEXITCODE." }
}

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
    $jobsRoot = Join-Path $root 'jobs'
    $jobsSecurity = New-Object Security.AccessControl.DirectorySecurity
    $jobsSecurity.SetAccessRuleProtection($true, $false)
    $jobsInheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $jobsRule = New-Object Security.AccessControl.FileSystemAccessRule($currentIdentity.User, [Security.AccessControl.FileSystemRights]::FullControl, $jobsInheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
    [void]$jobsSecurity.AddAccessRule($jobsRule)
    [void][IO.Directory]::CreateDirectory($jobsRoot, $jobsSecurity)
    if (([IO.File]::GetAttributes($jobsRoot) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'HostLink Agent jobs directory must not be a reparse point.'
    }
    $stagedArchive = Join-Path $root '.hostlink-agent-bootstrap.zip'
    [IO.File]::Copy($archive, $stagedArchive, $false)
    & $candidate __self-update --root $root --agent-only --archive-file $stagedArchive --archive-sha256 $actualSha256 --package-version $PackageVersion --target $Target
    if ($LASTEXITCODE -ne 0) { throw "Agent-only package install failed with exit code $LASTEXITCODE." }
    [IO.File]::Delete($stagedArchive)
    if ($enrollmentMode) {
        $publishedState = Join-Path $root 'agent'
        if ([IO.Directory]::Exists($publishedState) -or [IO.File]::Exists($publishedState)) { throw 'Agent state publication target already exists.' }
        [IO.Directory]::Move($stateDir, $publishedState)
        $config = Join-Path $publishedState 'agent.json'
    }
    $installedAgent = Join-Path $root ('hostlink-agent\bin\' + $(if ($Target -like '*windows*') { 'hostlink-agent.exe' } else { 'hostlink-agent' }))
    & $installedAgent check --config $config
    if ($LASTEXITCODE -ne 0) { throw "Installed Agent config health check failed with exit code $LASTEXITCODE." }
} catch {
    throw ('Install stopped with an owned incomplete fresh root at ' + $root + '. Inspect and remove that root before retrying. ' + $_.Exception.Message)
}

Write-Host ('HostLink Agent installed in the fresh user root: ' + $root)
Write-Host ('Run explicitly with: powershell.exe -NoProfile -File "' + (Join-Path $root 'hostlink-agent\bin\Run-HostLink-Agent.ps1') + '" -ConfigFile "' + $config + '"')
} finally {
    if ($enrollmentMode -and $null -ne $stateDir -and [IO.Directory]::Exists($stateDir)) { [IO.Directory]::Delete($stateDir, $true) }
    if ([IO.Directory]::Exists($stage)) { [IO.Directory]::Delete($stage, $true) }
}
