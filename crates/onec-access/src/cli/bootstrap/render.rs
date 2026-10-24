//! PowerShell invite bootstrap rendering, quoting, encoding, and script identity.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use sha2::{Digest, Sha256};

pub(super) struct RemoteDirectInviteBootstrap<'a> {
    pub(super) installer_url: &'a str,
    pub(super) installer_sha256: &'a str,
    pub(super) hub_url: &'a str,
    pub(super) package_url: &'a str,
    pub(super) package_sha256: &'a str,
    pub(super) package_version: &'a str,
    pub(super) package_target: &'a str,
    pub(super) agent_executable_url: Option<&'a str>,
    pub(super) agent_executable_sha256: Option<&'a str>,
}

/// Render a PowerShell 2 compatible, one-use HostLink Agent bootstrap.
///
/// The enrollment token is read interactively and persisted only into a private,
/// user-owned file. It is never included in this generated source or an argument
/// passed to the Agent installer.
pub(super) fn remote_direct_invite_bootstrap(input: &RemoteDirectInviteBootstrap<'_>) -> String {
    format!(
        r#"
$ErrorActionPreference='Stop'
try {{ [Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor 3072 }} catch {{ throw 'TLS 1.2 is unavailable.' }}
$hubUrl='{}'
$installerUrl='{}'
$installerSha256='{}'
$packageUrl='{}'
$packageSha256='{}'
$packageVersion='{}'
$packageTarget='{}'
$agentExecutableUrl='{}'
$agentExecutableSha256='{}'
if ($hubUrl -notmatch '^https://[^/]+(?:/.*)?$' -or $installerUrl -notmatch '^https://[^/]+/.*$' -or $packageUrl -notmatch '^https://[^/]+/.*$' -or ($agentExecutableUrl -ne '' -and $agentExecutableUrl -notmatch '^https://[^/]+/.*$')) {{ throw 'Hub and artifact URLs must use HTTPS.' }}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if ($identity.User.Value -eq 'S-1-5-18' -or $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{ throw 'Run this bootstrap as a normal, non-elevated user.' }}
$secureToken=Read-Host 'One-use HostLink enrollment token' -AsSecureString
if ($null -eq $secureToken -or $secureToken.Length -eq 0) {{ throw 'Enrollment token is required.' }}
$bstr=[IntPtr]::Zero
$token=$null
$root=$null
$tokenPath=$null
$installerPath=$null
$archivePath=$null
$agentExecutablePath=$null
try {{
    $bstr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
    $token=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    if ([String]::IsNullOrEmpty($token)) {{ throw 'Enrollment token is required.' }}
    $tempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([char]92)
    $root=Join-Path $tempRoot ('hostlink-invite-'+[Guid]::NewGuid().ToString('N'))
    $userSid=$identity.User.Value
    if (Test-Path -LiteralPath $root) {{ throw 'Refusing a pre-existing temporary bootstrap path.' }}
    [IO.Directory]::CreateDirectory($root) | Out-Null
    if (([IO.File]::GetAttributes($root) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{ throw 'Refusing a reparse-point bootstrap directory.' }}
    $aclOutput=& "$env:SystemRoot\System32\icacls.exe" $root '/inheritance:r' '/grant:r' ('*'+$userSid+':(OI)(CI)F') '*S-1-5-18:(OI)(CI)F' 2>&1
    if ($LASTEXITCODE -ne 0) {{ throw 'Could not restrict temporary bootstrap directory permissions.' }}
    $directoryAcl=[IO.Directory]::GetAccessControl($root)
    if ($directoryAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $userSid) {{ throw 'Temporary bootstrap directory owner verification failed.' }}
    $directorySids=@()
    foreach ($entry in $directoryAcl.Access) {{
        $entrySid=$entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($entry.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or -not (@($userSid,'S-1-5-18') -contains $entrySid) -or ($entry.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl) {{ throw 'Temporary bootstrap directory ACL verification failed.' }}
        if (-not ($directorySids -contains $entrySid)) {{ $directorySids+= $entrySid }}
    }}
    if ($directorySids.Count -ne 2) {{ throw 'Temporary bootstrap directory ACL is incomplete.' }}
    $tokenPath=Join-Path $root 'enrollment-token.txt'
    $tokenBytes=(New-Object Text.UTF8Encoding($false)).GetBytes($token)
    $tokenStream=New-Object IO.FileStream($tokenPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {{ $tokenStream.Write($tokenBytes,0,$tokenBytes.Length) }} finally {{ $tokenStream.Dispose() }}
    $aclOutput=& "$env:SystemRoot\System32\icacls.exe" $tokenPath '/inheritance:r' '/grant:r' ('*'+$userSid+':F') '*S-1-5-18:F' 2>&1
    if ($LASTEXITCODE -ne 0) {{ throw 'Could not restrict enrollment token file permissions.' }}
    $tokenAcl=[IO.File]::GetAccessControl($tokenPath)
    if ($tokenAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $userSid) {{ throw 'Enrollment token file owner verification failed.' }}
    $tokenSids=@()
    foreach ($entry in $tokenAcl.Access) {{
        $entrySid=$entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($entry.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or -not (@($userSid,'S-1-5-18') -contains $entrySid) -or ($entry.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl) {{ throw 'Enrollment token file ACL verification failed.' }}
        if (-not ($tokenSids -contains $entrySid)) {{ $tokenSids+= $entrySid }}
    }}
    if ($tokenSids.Count -ne 2) {{ throw 'Enrollment token file ACL is incomplete.' }}
    $installerPath=Join-Path $root 'Install-HostLink-Agent.ps1'
    $installerRequest=[Net.HttpWebRequest]::Create($installerUrl)
    $installerRequest.AllowAutoRedirect=$false
    $installerRequest.Timeout=15000
    $installerRequest.ReadWriteTimeout=15000
    $installerResponse=$installerRequest.GetResponse()
    try {{
        if ($installerResponse.ResponseUri.AbsoluteUri -ne $installerUrl) {{ throw 'Installer URL changed during download.' }}
        if ($installerResponse.ContentLength -lt 0 -or $installerResponse.ContentLength -gt 524288) {{ throw 'Installer script size is invalid.' }}
        $installerStream=$installerResponse.GetResponseStream()
        $installerMemory=New-Object IO.MemoryStream
        try {{
            $buffer=New-Object byte[] 8192
            while (($read=$installerStream.Read($buffer,0,$buffer.Length)) -gt 0) {{
                if (($installerMemory.Length+$read) -gt 524288) {{ throw 'Installer script exceeds its size limit.' }}
                $installerMemory.Write($buffer,0,$read)
            }}
            $installerBytes=$installerMemory.ToArray()
        }} finally {{ $installerStream.Dispose(); $installerMemory.Dispose() }}
    }} finally {{ $installerResponse.Close() }}
    $installerScript=[Text.Encoding]::UTF8.GetString($installerBytes)
    $normalized=$installerScript.Replace(([char]13).ToString()+([char]10).ToString(),([char]10).ToString())
    $hasher=[Security.Cryptography.SHA256]::Create()
    try {{ $actual=([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized)))).Replace('-','').ToLowerInvariant() }} finally {{ $hasher.Clear() }}
    if ($actual -ne $installerSha256) {{ throw 'Install-HostLink-Agent.ps1 SHA-256 mismatch.' }}
    [IO.File]::WriteAllBytes($installerPath,$installerBytes)
    $archivePath=Join-Path $root 'hostlink-agent.zip'
    $packageRequest=[Net.HttpWebRequest]::Create($packageUrl)
    $packageRequest.AllowAutoRedirect=$false
    $packageRequest.Timeout=15000
    $packageRequest.ReadWriteTimeout=15000
    $packageResponse=$packageRequest.GetResponse()
    try {{
        if ($packageResponse.ResponseUri.AbsoluteUri -ne $packageUrl) {{ throw 'Package URL changed during download.' }}
        if ($packageResponse.ContentLength -le 0 -or $packageResponse.ContentLength -gt 536870912) {{ throw 'Agent package size is invalid.' }}
        $packageInput=$packageResponse.GetResponseStream()
        $packageOutput=New-Object IO.FileStream($archivePath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $packageLength=[long]0
        try {{
            $buffer=New-Object byte[] 65536
            while (($read=$packageInput.Read($buffer,0,$buffer.Length)) -gt 0) {{
                $packageLength+=$read
                if ($packageLength -gt 536870912 -or $packageLength -gt $packageResponse.ContentLength) {{ throw 'Agent package exceeds its declared size.' }}
                $packageOutput.Write($buffer,0,$read)
            }}
        }} finally {{ $packageInput.Dispose(); $packageOutput.Dispose() }}
        if ($packageLength -ne $packageResponse.ContentLength) {{ throw 'Agent package size did not match its declared size.' }}
    }} finally {{ $packageResponse.Close() }}
    $archiveStream=New-Object IO.FileStream($archivePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $archiveHasher=[Security.Cryptography.SHA256]::Create()
    try {{ $archiveActual=([BitConverter]::ToString($archiveHasher.ComputeHash($archiveStream))).Replace('-','').ToLowerInvariant() }} finally {{ $archiveHasher.Clear(); $archiveStream.Dispose() }}
    if ($archiveActual -ne $packageSha256) {{ throw 'HostLink Agent package SHA-256 mismatch.' }}
    if ($agentExecutableUrl -ne '') {{
        if ($agentExecutableSha256 -notmatch '^[0-9a-f]{{64}}$') {{ throw 'Agent executable SHA-256 is invalid.' }}
        $agentExecutablePath=Join-Path $root 'hostlink-agent.exe'
        $agentRequest=[Net.HttpWebRequest]::Create($agentExecutableUrl)
        $agentRequest.AllowAutoRedirect=$false
        $agentRequest.Timeout=15000
        $agentRequest.ReadWriteTimeout=15000
        $agentResponse=$agentRequest.GetResponse()
        try {{
            if ([int]$agentResponse.StatusCode -lt 200 -or [int]$agentResponse.StatusCode -ge 300) {{ throw 'Agent executable download returned an unsuccessful HTTP status.' }}
            if ($agentResponse.ResponseUri.AbsoluteUri -ne $agentExecutableUrl) {{ throw 'Agent executable URL changed during download.' }}
            if ($agentResponse.ContentLength -le 0 -or $agentResponse.ContentLength -gt 268435456) {{ throw 'Agent executable size is invalid.' }}
            $agentInput=$agentResponse.GetResponseStream()
            $agentOutput=New-Object IO.FileStream($agentExecutablePath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            $agentLength=[long]0
            try {{
                $buffer=New-Object byte[] 65536
                while (($read=$agentInput.Read($buffer,0,$buffer.Length)) -gt 0) {{
                    $agentLength+=$read
                    if ($agentLength -gt 268435456 -or $agentLength -gt $agentResponse.ContentLength) {{ throw 'Agent executable exceeds its declared size.' }}
                    $agentOutput.Write($buffer,0,$read)
                }}
            }} finally {{ $agentInput.Dispose(); $agentOutput.Dispose() }}
            if ($agentLength -ne $agentResponse.ContentLength) {{ throw 'Agent executable size did not match its declared size.' }}
        }} finally {{ $agentResponse.Close() }}
        $agentStream=New-Object IO.FileStream($agentExecutablePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $agentHasher=[Security.Cryptography.SHA256]::Create()
        try {{ $agentActual=([BitConverter]::ToString($agentHasher.ComputeHash($agentStream))).Replace('-','').ToLowerInvariant() }} finally {{ $agentHasher.Clear(); $agentStream.Dispose() }}
        if ($agentActual -ne $agentExecutableSha256) {{ throw 'HostLink Agent executable SHA-256 mismatch.' }}
    }}
    try {{
        $LASTEXITCODE=$null
        if ($null -ne $agentExecutablePath) {{
            & $installerPath -ArchiveFile ([IO.Path]::GetFullPath($archivePath)) -ArchiveSha256 $packageSha256 -PackageVersion $packageVersion -Target $packageTarget -HubUrl $hubUrl -EnrollmentTokenFile ([IO.Path]::GetFullPath($tokenPath)) -AgentExecutableFile ([IO.Path]::GetFullPath($agentExecutablePath)) -AgentExecutableSha256 $agentExecutableSha256
        }} else {{
            & $installerPath -ArchiveFile ([IO.Path]::GetFullPath($archivePath)) -ArchiveSha256 $packageSha256 -PackageVersion $packageVersion -Target $packageTarget -HubUrl $hubUrl -EnrollmentTokenFile ([IO.Path]::GetFullPath($tokenPath))
        }}
        $installerExitCode=$LASTEXITCODE
        if (($null -eq $installerExitCode) -or ($installerExitCode -ne 0)) {{ throw 'Installer exit status was missing or nonzero.' }}
    }} catch {{ throw 'HostLink Agent enrollment or installation failed. The invite may have been consumed; do not retry this token. Reconcile the target or create a new invite.' }}
}} finally {{
    $cleanupIncomplete=$false
    try {{
        if ($null -ne $root) {{
            if (-not [IO.Directory]::Exists($root)) {{
                $cleanupIncomplete=$true
            }} else {{
                $fullRoot=[IO.Path]::GetFullPath($root).TrimEnd([char]92)
                $tempPrefix=$tempRoot+[IO.Path]::DirectorySeparatorChar
                $rootIsOwned=$fullRoot.StartsWith($tempPrefix,[StringComparison]::OrdinalIgnoreCase) -and [IO.Path]::GetFileName($fullRoot) -match '^hostlink-invite-[0-9a-f]{{32}}$' -and ([IO.File]::GetAttributes($fullRoot) -band [IO.FileAttributes]::ReparsePoint) -eq 0
                if (-not $rootIsOwned) {{
                    $cleanupIncomplete=$true
                }} else {{
                    foreach ($ownedFile in @($tokenPath,$installerPath,$archivePath,$agentExecutablePath)) {{
                        if ($null -ne $ownedFile -and [IO.File]::Exists($ownedFile)) {{
                            try {{
                                $fullFile=[IO.Path]::GetFullPath($ownedFile)
                                if (-not $fullFile.StartsWith($fullRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or ([IO.File]::GetAttributes($fullFile) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{ throw 'Refusing to clean an unowned bootstrap file.' }}
                                [IO.File]::Delete($fullFile)
                            }} catch {{ $cleanupIncomplete=$true }}
                        }}
                    }}
                    try {{ [IO.Directory]::Delete($fullRoot,$false) }} catch {{ $cleanupIncomplete=$true }}
                }}
            }}
        }}
    }} catch {{ $cleanupIncomplete=$true }}
    if ($cleanupIncomplete) {{ try {{ Write-Warning 'HostLink bootstrap cleanup incomplete; private temporary files may remain.' }} catch {{ [Console]::Error.WriteLine('HostLink bootstrap cleanup incomplete; private temporary files may remain.') }} }}
    try {{
        $token=$null
        if ([IntPtr]::Zero -ne $bstr) {{ [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }}
        if ($null -ne $secureToken) {{ $secureToken.Dispose() }}
    }} catch {{ try {{ Write-Warning 'HostLink bootstrap secret cleanup incomplete.' }} catch {{ [Console]::Error.WriteLine('HostLink bootstrap secret cleanup incomplete.') }} }}
}}
"#,
        ps_single_quote(input.hub_url),
        ps_single_quote(input.installer_url),
        input.installer_sha256,
        ps_single_quote(input.package_url),
        input.package_sha256,
        ps_single_quote(input.package_version),
        ps_single_quote(input.package_target),
        input
            .agent_executable_url
            .map(ps_single_quote)
            .unwrap_or_default(),
        input.agent_executable_sha256.unwrap_or_default(),
    )
}

pub(super) fn ps_single_quote(value: &str) -> String {
    value.replace('\'', "''")
}

pub(super) fn powershell_encoded_command(script: &str) -> String {
    let utf16le = script
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    BASE64_STANDARD.encode(utf16le)
}

pub(super) fn powershell_command_line(script: &str) -> String {
    format!(
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {}",
        powershell_encoded_command(script)
    )
}

pub(super) fn normalized_script_sha256(value: &str) -> String {
    let normalized = value.replace("\r\n", "\n");
    format!("{:x}", Sha256::digest(normalized.as_bytes()))
}
