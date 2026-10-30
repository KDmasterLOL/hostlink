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

function Set-PrivateDirectory([string]$Path, [Security.Principal.SecurityIdentifier]$Sid) {
    if ([IO.Directory]::Exists($Path) -or [IO.File]::Exists($Path)) { throw 'Bootstrap staging path already exists.' }
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    # private-fs requires exactly one non-inheritable, protected user ACE.
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($Sid, 'FullControl', 'None', 'None', 'Allow')
    [void]$security.AddAccessRule($rule)
    [void][IO.Directory]::CreateDirectory($Path, $security)
    $directory = New-Object IO.DirectoryInfo($Path)
    if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Private directory is a reparse point.' }
    if (-not $directory.GetAccessControl().GetOwner([Security.Principal.SecurityIdentifier]).Equals($Sid)) { throw 'Private directory owner mismatch.' }
}

function Assert-PrivateDirectory([string]$Path, [Security.Principal.SecurityIdentifier]$Sid) {
    $directory = New-Object IO.DirectoryInfo($Path)
    if (-not $directory.Exists -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Install parent is missing or a reparse point.' }
    $acl = $directory.GetAccessControl()
    if (-not $acl.GetOwner([Security.Principal.SecurityIdentifier]).Equals($Sid) -or -not $acl.AreAccessRulesProtected) { throw 'Install parent owner or ACL is unsafe.' }
    $rules = $acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])
    if ($rules.Count -ne 1) { throw 'Install parent must have exactly one current-user ACL entry; migrate the old parent explicitly.' }
    $rule = $rules[0]
    if (-not $rule.IdentityReference.Equals($Sid) -or
        $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
        $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
        $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
        throw 'Install parent ACL differs from private-fs owner-only policy; migrate the old parent explicitly.'
    }
}

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
    $uri = New-Object Uri($AgentUri)
    $archiveUriObject = New-Object Uri($ArchiveUri)
    if ($uri.Scheme -cne 'https' -or $archiveUriObject.Scheme -cne 'https' -or -not $uri.Authority.Equals($archiveUriObject.Authority, [StringComparison]::OrdinalIgnoreCase) -or -not [string]::IsNullOrEmpty($uri.UserInfo) -or -not [string]::IsNullOrEmpty($uri.Fragment) -or -not [string]::IsNullOrEmpty($archiveUriObject.UserInfo) -or -not [string]::IsNullOrEmpty($archiveUriObject.Fragment)) { throw 'Package URLs must use one HTTPS origin without credentials or fragments.' }
    if ([IO.Path]::GetFileName($archiveUriObject.AbsolutePath) -cne ('hostlink-agent-' + $Target + '.zip')) { throw 'Archive URL must select the exact target-named Agent ZIP.' }
    try {
        $tls12 = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
        [Net.ServicePointManager]::SecurityProtocol = $tls12
    } catch { throw 'TLS 1.2 is unavailable in this Windows/.NET session; bootstrap will not downgrade TLS.' }
    function Download-Pinned([Uri]$DownloadUri, [string]$Destination, [long]$MaximumBytes) {
        $request = [Net.HttpWebRequest]::Create($DownloadUri)
        $request.AllowAutoRedirect = $false
        $request.Method = 'GET'
        $request.Timeout = 30000
        $request.ReadWriteTimeout = 30000
        $response = $request.GetResponse()
        try {
            if ([int]$response.StatusCode -ne 200) { throw 'Pinned download returned an unexpected status.' }
            if ($response.ContentLength -gt $MaximumBytes) { throw 'Pinned download exceeds its size limit.' }
            $input = $response.GetResponseStream()
            $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try {
                $buffer = New-Object byte[] 65536
                $total = 0L
                while (($count = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $total += $count
                    if ($total -gt $MaximumBytes) { throw 'Pinned download exceeds its size limit.' }
                    $output.Write($buffer, 0, $count)
                }
                $output.Flush()
            } finally { $output.Close(); $input.Close() }
        } finally { $response.Close() }
    }
    Download-Pinned $uri $agentFile 268435456
    Download-Pinned $archiveUriObject $archiveFile 536870912
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
    [IO.File]::Copy((Join-Path $verified 'install.json'), (Join-Path $root 'install.json'))
    [IO.File]::SetAccessControl((Join-Path $root 'install.json'), $tokenSecurity)
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
