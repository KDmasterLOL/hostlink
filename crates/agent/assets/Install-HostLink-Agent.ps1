param(
    [Parameter(Mandatory=$true)][string]$HubUrl,
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][string]$SshUser,
    [Parameter(Mandatory=$true)][string]$AgentUri,
    [Parameter(Mandatory=$true)][string]$AgentSha256,
    [Parameter(Mandatory=$true)][string]$AgentVersion,
    [Parameter(Mandatory=$true)][string]$ArchiveUri,
    [Parameter(Mandatory=$true)][string]$ArchiveSha256,
    [Parameter(Mandatory=$true)][string]$Target,
    [switch]$NoRun
)

$ErrorActionPreference = 'Stop'
Set-PSDebug -Off

# BEGIN GITHUB BOOTSTRAP HELPERS
# Shared verbatim with the Controller renderer; compatible with PowerShell 2/.NET 3.5.
function Assert-GitHubAsset([string]$Url) {
    if ($Url -cnotmatch '\Ahttps://api\.github\.com/repos/KDmasterLOL/hostlink/releases/assets/[1-9][0-9]*\z') { throw 'Expected a HostLink GitHub API release asset URL.' }
}
function Assert-NoReparse([string]$Path) {
    $part = New-Object IO.DirectoryInfo($Path)
    while ($null -ne $part) {
        if (([IO.File]::GetAttributes($part.FullName) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Credential ancestor must not be a reparse point.' }
        $part = $part.Parent
    }
}
function Set-PrivateDirectory([string]$Path, [Security.Principal.SecurityIdentifier]$Sid) {
    if ([IO.Directory]::Exists($Path) -or [IO.File]::Exists($Path)) { throw 'Bootstrap staging path already exists.' }
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetOwner($Sid)
    $security.SetAccessRuleProtection($true, $false)
    # SQLite creates DB/WAL/SHM itself: child files must inherit only this SID.
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($Sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    [void]$security.AddAccessRule($rule)
    [void][IO.Directory]::CreateDirectory($Path, $security)
    Assert-PrivateDirectory $Path $Sid
}
function Assert-PrivateDirectory([string]$Path, [Security.Principal.SecurityIdentifier]$Sid) {
    $directory = New-Object IO.DirectoryInfo($Path)
    if (-not $directory.Exists -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Private directory is missing or a reparse point.' }
    $acl = $directory.GetAccessControl()
    if (-not $acl.GetOwner([Security.Principal.SecurityIdentifier]).Equals($Sid) -or -not $acl.AreAccessRulesProtected) { throw 'Private directory owner or ACL is unsafe.' }
    $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    if ($rules.Count -ne 1) { throw 'Private directory must have exactly one current-user ACL entry.' }
    $rule = $rules[0]
    if (-not $rule.IdentityReference.Equals($Sid) -or
        $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
        $rule.InheritanceFlags -ne ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit) -or
        $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { throw 'Private directory ACL differs from owner-only policy.' }
}
function Get-GitHubCredential([bool]$Provision) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity -or $null -eq $identity.User -or @('S-1-5-18','S-1-5-19','S-1-5-20') -contains $identity.User.Value) { throw 'Bootstrap requires a normal interactive user.' }
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) { throw 'Bootstrap must run unelevated in the current user session.' }
    $sid = $identity.User
    $appData = $env:APPDATA
    if ([string]::IsNullOrEmpty($appData) -or -not [IO.Path]::IsPathRooted($appData) -or -not [IO.Directory]::Exists($appData)) { throw 'Current-user APPDATA is unavailable.' }
    Assert-NoReparse $appData
    $base = New-Object IO.DirectoryInfo($appData)
    $baseAcl = $base.GetAccessControl()
    if (-not $baseAcl.GetOwner([Security.Principal.SecurityIdentifier]).Equals($sid)) { throw 'APPDATA must be owned by the current user.' }
    $writeMask = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $baseAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and ($rule.FileSystemRights -band $writeMask) -ne 0 -and -not $rule.IdentityReference.Equals($sid) -and @('S-1-5-18','S-1-5-32-544') -notcontains $rule.IdentityReference.Value) { throw 'APPDATA is writable by another user.' }
    }
    $hostDirectory = Join-Path $appData 'HostLink'
    $credentialDirectory = Join-Path $hostDirectory 'credentials'
    foreach ($directory in @($hostDirectory, $credentialDirectory)) {
        if (-not [IO.Directory]::Exists($directory) -and $Provision) { Set-PrivateDirectory $directory $sid }
        Assert-NoReparse $directory
        Assert-PrivateDirectory $directory $sid
    }
    $path = Join-Path $credentialDirectory 'github-token'
    # GetAttributes observes reparse points; only a genuine missing file permits prompting.
    $missing = $false
    try { $attributes = [IO.File]::GetAttributes($path) }
    catch [IO.FileNotFoundException] { $missing = $true }
    if ($missing) {
        if (-not $Provision) { throw 'Provision the target GitHub credential through the invite bootstrap first.' }
        $secure = Read-Host 'GitHub fine-grained PAT (HostLink Contents:Read only)' -AsSecureString
        $pointer = [IntPtr]::Zero
        $bytes = $null
        $stream = $null
        try {
            if ($secure.Length -lt 1 -or $secure.Length -gt 1024) { throw 'Invalid GitHub credential size.' }
            $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            $bytes = New-Object byte[] $secure.Length
            for ($i = 0; $i -lt $bytes.Length; $i++) {
                $low = [Runtime.InteropServices.Marshal]::ReadByte($pointer, 2 * $i)
                $high = [Runtime.InteropServices.Marshal]::ReadByte($pointer, 2 * $i + 1)
                if ($high -ne 0 -or -not (($low -ge 48 -and $low -le 57) -or ($low -ge 65 -and $low -le 90) -or ($low -ge 97 -and $low -le 122) -or $low -eq 95)) { throw 'Invalid GitHub credential format.' }
                $bytes[$i] = $low
            }
            $security = New-Object Security.AccessControl.FileSecurity
            $security.SetOwner($sid)
            $security.SetAccessRuleProtection($true, $false)
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')
            [void]$security.AddAccessRule($rule)
            # Atomic CreateNew with a protected DACL; never create a readable secret then fix ACLs.
            $stream = New-Object IO.FileStream($path, [IO.FileMode]::CreateNew, [Security.AccessControl.FileSystemRights]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::None, $security)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
        } finally {
            if ($null -ne $stream) { $stream.Close() }
            if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
            if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
            $secure.Dispose()
        }
        $attributes = [IO.File]::GetAttributes($path)
    }
    if (($attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Directory)) -ne 0) { throw 'GitHub credential must be a regular file, not a reparse point.' }
    $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $acl = $stream.GetAccessControl()
        if (-not $acl.AreAccessRulesProtected -or -not $acl.GetOwner([Security.Principal.SecurityIdentifier]).Equals($sid)) { throw 'Unsafe GitHub credential owner or ACL.' }
        $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
        if ($rules.Count -ne 1 -or -not $rules[0].IdentityReference.Equals($sid) -or $rules[0].AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rules[0].FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or $rules[0].InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or $rules[0].PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { throw 'GitHub credential must have a protected owner-only DACL.' }
        if ($stream.Length -lt 1 -or $stream.Length -gt 1024) { throw 'Invalid GitHub credential size.' }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $count = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($count -eq 0) { throw 'GitHub credential read failed.' }
            $offset += $count
        }
        foreach ($b in $bytes) { if (-not (($b -ge 48 -and $b -le 57) -or ($b -ge 65 -and $b -le 90) -or ($b -ge 97 -and $b -le 122) -or $b -eq 95)) { throw 'Invalid GitHub credential format.' } }
        return [Text.Encoding]::ASCII.GetString($bytes)
    } finally {
        if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
        $stream.Close()
    }
}
function Get-GitHubAsset([string]$Url, [string]$Destination, [long]$MaximumBytes, [int]$DeadlineSeconds) {
    Assert-GitHubAsset $Url
    $credential = Get-GitHubCredential $false
    $response = $null; $output = $null; $inputStream = $null; $request = $null; $created = $false; $complete = $false
    $clock = [Diagnostics.Stopwatch]::StartNew()
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
        for ($hop = 0; $hop -le 1; $hop++) {
            $remaining = [int]($DeadlineSeconds * 1000 - $clock.ElapsedMilliseconds)
            if ($remaining -le 0) { throw 'Download deadline exceeded.' }
            $request = [Net.HttpWebRequest]::Create((New-Object Uri($Url)))
            $request.AllowAutoRedirect = $false
            $request.UseDefaultCredentials = $false
            $request.Method = 'GET'
            $request.UserAgent = 'HostLink-bootstrap'
            $request.Accept = 'application/octet-stream'
            $request.Timeout = [Math]::Min(30000, $remaining)
            $request.ReadWriteTimeout = [Math]::Min(30000, $remaining)
            if ($hop -eq 0) { $request.Headers['Authorization'] = 'Bearer ' + $credential }
            $response = $request.GetResponse()
            $credential = $null
            if ([int]$response.StatusCode -eq 200) { break }
            if ([int]$response.StatusCode -ne 302 -or $hop -ne 0) { throw 'Download response rejected.' }
            $Url = $response.Headers['Location']
            if ($Url -cnotmatch '\Ahttps://(release-assets|objects)\.githubusercontent\.com/[^\s\\#]+\z') { throw 'Download redirect destination rejected.' }
            $response.Close(); $response = $null
        }
        if ($response.ContentLength -gt $MaximumBytes) { throw 'Download size limit exceeded.' }
        $inputStream = $response.GetResponseStream()
        if ([string]::IsNullOrEmpty($Destination)) { $output = New-Object IO.MemoryStream }
        else { $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None); $created = $true }
        $buffer = New-Object byte[] 65536
        $total = 0L
        while ($true) {
            $remaining = [int]($DeadlineSeconds * 1000 - $clock.ElapsedMilliseconds)
            if ($remaining -le 0) { throw 'Download deadline exceeded.' }
            $inputStream.ReadTimeout = [Math]::Min(30000, $remaining)
            $count = $inputStream.Read($buffer, 0, $buffer.Length)
            if ($clock.ElapsedMilliseconds -ge $DeadlineSeconds * 1000) { throw 'Download deadline exceeded.' }
            if ($count -eq 0) { break }
            $total += $count
            if ($total -gt $MaximumBytes) { throw 'Download size limit exceeded.' }
            $output.Write($buffer, 0, $count)
        }
        $output.Flush()
        $complete = $true
        if ([string]::IsNullOrEmpty($Destination)) { return ,$output.ToArray() }
    } catch { throw 'GitHub asset download failed (credential, TLS, HTTP, deadline or size); no fallback.' }
    finally {
        $credential = $null
        if ($null -ne $request) { $request.Abort() }
        if ($null -ne $inputStream) { $inputStream.Close() }
        if ($null -ne $response) { $response.Close() }
        if ($null -ne $output) { $output.Close() }
        if ($created -and -not $complete) { [IO.File]::Delete($Destination) }
        $clock.Stop()
    }
}
# END GITHUB BOOTSTRAP HELPERS

function Get-Sha256([string]$Path) {
    $algorithm = New-Object Security.Cryptography.SHA256Managed
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Close(); $algorithm.Clear() }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($null -eq $identity -or $null -eq $identity.User -or @('S-1-5-18','S-1-5-19','S-1-5-20') -contains $identity.User.Value) {
    throw 'Enrollment requires a normal interactive user, not a service account.'
}
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) {
    throw 'Enrollment must run unelevated in the current user session.'
}
if ($HubUrl -notmatch '^https://[^/?#]+$' -or $HubUrl.Contains('@')) { throw 'HubUrl must be an HTTPS origin without credentials or a path.' }
if ($Name -cnotmatch '^[a-z0-9][a-z0-9._-]{0,127}$') { throw 'Name must be canonical lowercase ASCII.' }
if ([string]::IsNullOrEmpty($SshUser) -or $SshUser -match '\s') { throw 'SshUser is invalid.' }
if ($AgentSha256 -cnotmatch '^[0-9a-f]{64}$' -or $ArchiveSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'AgentSha256 must be a lowercase SHA-256 digest.' }
if ($AgentVersion -notmatch '^\d+\.\d+\.\d+([+-][0-9A-Za-z.-]+)?$') { throw 'AgentVersion must be exact semantic version.' }
if (@('x86_64-pc-windows-msvc','x86_64-win7-windows-msvc','i686-win7-windows-msvc') -cnotcontains $Target) { throw 'Unsupported Windows Agent target.' }
$is64BitOS = ([IntPtr]::Size -eq 8) -or ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64')
if (-not $is64BitOS -and $Target.StartsWith('x86_64-')) { throw 'The selected x64 target cannot run on a 32-bit Windows OS.' }
$os = Get-WmiObject -Class Win32_OperatingSystem
$osVersion = [Version]$os.Version
if ($Target -like '*-win7-*' -and ($osVersion.Major -ne 6 -or $osVersion.Minor -ne 1)) { throw 'A Win7 Agent target requires Windows NT 6.1.' }
if ($Target -eq 'x86_64-pc-windows-msvc' -and ([int]$os.BuildNumber -lt 22000)) { throw 'The selected standard Windows target requires a Windows 11 build.' }
if ($Target -eq 'x86_64-win7-windows-msvc' -and -not $is64BitOS) { throw 'The selected Win7 x64 target requires a 64-bit Windows OS.' }
if ($Target -eq 'i686-win7-windows-msvc' -and $is64BitOS) { throw 'The selected Win7 x86 target requires a 32-bit Windows OS, not WOW64.' }

$sid = $identity.User
$localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
if ([string]::IsNullOrEmpty($localAppData) -or -not [IO.Directory]::Exists($localAppData)) { throw 'Current-user LocalAppData is unavailable.' }
if (([IO.Directory]::GetAttributes($localAppData) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'LocalAppData must not be a reparse point.' }
$parent = Join-Path $localAppData 'HostLink'
if ([IO.Directory]::Exists($parent)) { Assert-PrivateDirectory $parent $sid } else { Set-PrivateDirectory $parent $sid }
$root = Join-Path $parent 'Agent'
if ([IO.Directory]::Exists($root) -or [IO.File]::Exists($root)) { throw 'Existing Agent roots are never adopted.' }
$stage = Join-Path ([IO.Path]::GetTempPath()) ('hostlink-agent-enroll-' + [Guid]::NewGuid().ToString('N'))
Set-PrivateDirectory $stage $sid
$agentFile = Join-Path $stage 'hostlink-agent.exe'
$archiveFile = Join-Path $stage 'hostlink-agent.zip'
$verified = Join-Path $stage 'verified-package'
$tokenFile = Join-Path $stage 'invite-token'

try {
    Assert-GitHubAsset $AgentUri
    Assert-GitHubAsset $ArchiveUri
    Get-GitHubAsset $AgentUri $agentFile 268435456 120
    Get-GitHubAsset $ArchiveUri $archiveFile 536870912 180
    if ((Get-Sha256 $agentFile) -cne $AgentSha256) { throw 'Agent executable SHA-256 mismatch.' }
    $versionOutput = & $agentFile --version 2>&1
    if ($LASTEXITCODE -ne 0 -or ($versionOutput -join ' ') -notmatch [regex]::Escape($AgentVersion)) { throw 'Downloaded Agent version does not match the pinned version.' }
    & $agentFile bootstrap-verify --archive $archiveFile --sha256 $ArchiveSha256 --target $Target --version $AgentVersion --output $verified
    if ($LASTEXITCODE -ne 0 -or -not [IO.Directory]::Exists($verified)) { throw 'Exact Agent ZIP package verification failed; invite token was not requested.' }
    $verifiedExecutable = Join-Path $verified 'hostlink-agent.exe'
    if ((Get-Sha256 $verifiedExecutable) -cne $AgentSha256) { throw 'Verified ZIP executable differs from the independently pinned sidecar.' }

    $secureToken = Read-Host 'One-use HostLink invite token' -AsSecureString
    $tokenPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
    $tokenBytes = New-Object byte[] 64
    try {
        if ($secureToken.Length -ne 64) { throw 'Invite token format is invalid.' }
        for ($index = 0; $index -lt 64; $index++) {
            $low = [Runtime.InteropServices.Marshal]::ReadByte($tokenPointer, 2 * $index)
            $high = [Runtime.InteropServices.Marshal]::ReadByte($tokenPointer, (2 * $index) + 1)
            if ($high -ne 0 -or -not (($low -ge 48 -and $low -le 57) -or ($low -ge 97 -and $low -le 102))) { throw 'Invite token format is invalid.' }
            $tokenBytes[$index] = $low
        }
        $tokenStream = [IO.File]::Open($tokenFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $tokenSecurity = New-Object Security.AccessControl.FileSecurity
            $tokenSecurity.SetAccessRuleProtection($true, $false)
            $tokenRule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')
            [void]$tokenSecurity.AddAccessRule($tokenRule)
            $tokenStream.Close()
            [IO.File]::SetAccessControl($tokenFile, $tokenSecurity)
            $tokenStream = [IO.File]::Open($tokenFile, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
            $tokenStream.Write($tokenBytes, 0, $tokenBytes.Length)
            $tokenStream.Flush()
        } finally { if ($null -ne $tokenStream) { $tokenStream.Close() } }
    } finally {
        [Array]::Clear($tokenBytes, 0, $tokenBytes.Length)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPointer)
        $secureToken.Dispose()
    }

    & $agentFile enroll --hub-url $HubUrl --token-file $tokenFile --root $root --name $Name --user $SshUser --retain-pending
    if ($LASTEXITCODE -ne 0) { throw 'Enrollment failed. Inspect the private pending marker and reconcile before requesting another invite.' }
    $bin = Join-Path $root 'bin'
    Set-PrivateDirectory $bin $sid
    $installedAgent = Join-Path $bin 'hostlink-agent.exe'
    if ([IO.File]::Exists($installedAgent)) { throw 'Agent executable already exists; refusing overwrite.' }
    foreach ($member in @('hostlink-agent.exe','Install-HostLink-Agent.ps1','Run-HostLink-Agent.ps1','Update-HostLink-Agent.ps1')) {
        $sourceMember = Join-Path $verified $member
        $destinationMember = Join-Path $bin $member
        if (-not [IO.File]::Exists($sourceMember) -or [IO.File]::Exists($destinationMember)) { throw 'Verified package inventory or fresh install target changed.' }
        [IO.File]::Copy($sourceMember, $destinationMember)
        [IO.File]::SetAccessControl($destinationMember, $tokenSecurity)
        if ((Get-Sha256 $destinationMember) -cne (Get-Sha256 $sourceMember)) { throw 'Published Agent package member digest mismatch.' }
    }
    foreach ($metadata in @('manifest.json','archive.sha256')) {
        $sourceMetadata = Join-Path $verified $metadata
        $installedMetadata = Join-Path $bin $metadata
        [IO.File]::Copy($sourceMetadata, $installedMetadata)
        [IO.File]::SetAccessControl($installedMetadata, $tokenSecurity)
    }
    [IO.File]::Copy((Join-Path $verified 'bootstrap-receipt.json'), (Join-Path $root 'bootstrap-receipt.json'))
    [IO.File]::SetAccessControl((Join-Path $root 'bootstrap-receipt.json'), $tokenSecurity)
    & $agentFile bootstrap-finalize --root $root
    if ($LASTEXITCODE -ne 0) { throw 'Installed package receipt validation failed; pending state retained for reconciliation.' }
    Remove-Item $agentFile -Force
    Remove-Item $archiveFile -Force
    Remove-Item $tokenFile -Force
    $runCommand = '& "' + $installedAgent + '" run --config "' + (Join-Path $root 'state\agent.json') + '"'
    if ($NoRun) {
        Write-Output ('Enrollment complete. Start the Agent in this user session with: ' + $runCommand)
    } else {
        Write-Output 'Enrollment complete. Starting embedded russh Agent in this user session; press Ctrl-C to stop.'
        & $installedAgent run --config (Join-Path $root 'state\agent.json')
        if ($LASTEXITCODE -ne 0) { throw 'Embedded Agent stopped with an error.' }
    }
} finally {
    if ([IO.File]::Exists($tokenFile)) { Remove-Item $tokenFile -Force }
    if ([IO.Directory]::Exists($stage)) { Remove-Item $stage -Recurse -Force }
    if ([IO.Directory]::Exists($parent) -and -not [IO.Directory]::Exists($root)) { Remove-Item $parent -Recurse -Force }
}
