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
    pub(super) persistence: &'a str,
    pub(super) embedded_ssh_candidate: bool,
}

pub(super) struct RemoteRuntimeMigrationBootstrap<'a> {
    pub(super) installer_url: &'a str,
    pub(super) installer_sha256: &'a str,
    pub(super) persistence: &'a str,
    pub(super) direct_package_url: &'a str,
    pub(super) direct_package_sha256: &'a str,
    pub(super) direct_package_version: &'a str,
    pub(super) direct_package_target: &'a str,
}

pub(super) fn remote_runtime_migration_bootstrap(
    input: &RemoteRuntimeMigrationBootstrap<'_>,
) -> String {
    format!(
        r#"
$ErrorActionPreference='Stop'
try {{ [Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor 3072 }} catch {{}}
$u='{}'
$expected='{}'
$persistence='{}'
$packageUrl='{}'
$packageSha256='{}'
$packageVersion='{}'
$packageTarget='{}'
$downloadTimer=[Diagnostics.Stopwatch]::StartNew()
$request=[Net.HttpWebRequest]::Create($u)
$request.AllowAutoRedirect=$false
$request.Timeout=10000
$request.ReadWriteTimeout=5000
$response=$request.GetResponse()
if ($response.ResponseUri.AbsoluteUri -ne $u) {{ throw 'Installer URL changed during download' }}
$stream=$null
$memory=$null
try {{
    if (($response.ContentLength -gt 8388608) -or ($response.ContentLength -lt 0)) {{ throw 'Installer response has an invalid or excessive size' }}
    $stream=$response.GetResponseStream()
    $memory=New-Object IO.MemoryStream
    $buffer=New-Object byte[] 8192
    while (($read=$stream.Read($buffer,0,$buffer.Length)) -gt 0) {{
        if ($downloadTimer.ElapsedMilliseconds -ge 35000) {{ throw 'Installer download exceeded its total time limit' }}
        if (($memory.Length+$read) -gt 8388608) {{ throw 'Installer response exceeds the migration size limit' }}
        $memory.Write($buffer,0,$read)
    }}
    if ($downloadTimer.ElapsedMilliseconds -ge 35000) {{ throw 'Installer download exceeded its total time limit' }}
    $bytes=$memory.ToArray()
}} finally {{
    if ($null -ne $stream) {{ $stream.Dispose() }}
    if ($null -ne $memory) {{ $memory.Dispose() }}
    $response.Close()
}}
$script=[Text.Encoding]::UTF8.GetString($bytes)
$normalized=$script.Replace(([char]13).ToString()+([char]10).ToString(),([char]10).ToString())
$sha=[Security.Cryptography.SHA256]::Create()
$actual=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized)))).Replace('-','').ToLowerInvariant()
if ($actual -ne $expected) {{ throw 'Install-OnecToolkit.ps1 SHA-256 mismatch' }}
$migrationRoot=Join-Path ([IO.Path]::GetTempPath()) 'onec-toolkit-migration'
if (Test-Path -LiteralPath $migrationRoot) {{
    $migrationRootInfo=New-Object IO.DirectoryInfo($migrationRoot)
    if (($migrationRootInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{ throw 'Refusing a reparse-point migration temp root' }}
}} else {{ New-Item -ItemType Directory -Path $migrationRoot -ErrorAction Stop | Out-Null }}
$root=Join-Path $migrationRoot ([Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
$installer=Join-Path $root 'Install-OnecToolkit.ps1'
[IO.File]::WriteAllText($installer,$script,(New-Object Text.UTF8Encoding($false)))
function ConvertTo-PsLiteral([string]$value) {{
    return ([char]39).ToString()+$value.Replace(([char]39).ToString(),(([char]39).ToString()+([char]39).ToString()))+([char]39).ToString()
}}
$child=Join-Path $root 'Install-Detached.ps1'
$childScript='$ErrorActionPreference=''Stop'';$installerPath='+(ConvertTo-PsLiteral $installer)+';$childPath='+(ConvertTo-PsLiteral $child)+';$persistence='+(ConvertTo-PsLiteral $persistence)+';$packageUrl='+(ConvertTo-PsLiteral $packageUrl)+';$packageSha256='+(ConvertTo-PsLiteral $packageSha256)+';$packageVersion='+(ConvertTo-PsLiteral $packageVersion)+';$packageTarget='+(ConvertTo-PsLiteral $packageTarget)+';$ownedParent='+(ConvertTo-PsLiteral $migrationRoot)+';$ownedRoot='+(ConvertTo-PsLiteral $root)+';try {{ & $installerPath {installer_arguments} }} catch {{ $record=$_;$errorType=''Other'';switch -Exact ($record.Exception.GetType().Name) {{ ''WebException'' {{$errorType=''WebException''}};''UnauthorizedAccessException'' {{$errorType=''UnauthorizedAccessException''}};''IOException'' {{$errorType=''IOException''}};''CryptographicException'' {{$errorType=''CryptographicException''}};''InvalidOperationException'' {{$errorType=''InvalidOperationException''}};''ArgumentException'' {{$errorType=''ArgumentException''}} }};$errorLine=0;if ($null -ne $record.InvocationInfo) {{$errorLine=[Math]::Max(0,[int]$record.InvocationInfo.ScriptLineNumber)}};try {{$localRoot=[Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData);if ([String]::IsNullOrWhiteSpace($localRoot)) {{throw ''Local application data path is unavailable''}};$localRoot=[IO.Path]::GetFullPath($localRoot).TrimEnd([char]92);$diagnosticDirectory=Join-Path (Join-Path $localRoot ''onec-toolkit'') ''agent'';$diagnosticPath=Join-Path $diagnosticDirectory ''migration-last-failure.json'';$fullDiagnosticDirectory=[IO.Path]::GetFullPath($diagnosticDirectory);$prefix=$localRoot+[IO.Path]::DirectorySeparatorChar;if (-not $fullDiagnosticDirectory.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {{throw ''Refusing an unowned diagnostic path''}};$cursor=$fullDiagnosticDirectory;while ($cursor.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {{$info=New-Object IO.DirectoryInfo($cursor);if (-not (Test-Path -LiteralPath $cursor)) {{[IO.Directory]::CreateDirectory($cursor) | Out-Null}};$info=New-Object IO.DirectoryInfo($cursor);if (($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{throw ''Refusing a reparse-point diagnostic path''}};$cursor=[IO.Path]::GetDirectoryName($cursor)}};$localInfo=New-Object IO.DirectoryInfo($localRoot);if (($localInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{throw ''Refusing a reparse-point local data path''}};$json=''{{"phase":"installer_execution","error_type":"''+$errorType+''","line":''+[string]$errorLine+''}}'';$bytes=[Text.Encoding]::UTF8.GetBytes($json);$file=New-Object IO.FileStream($diagnosticPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try {{$file.Write($bytes,0,$bytes.Length)}} finally {{$file.Dispose()}} }} catch {{ }} }} finally {{ $fullParent=[IO.Path]::GetFullPath($ownedParent).TrimEnd([char]92);$fullRoot=[IO.Path]::GetFullPath($ownedRoot).TrimEnd([char]92);$prefix=$fullParent+[IO.Path]::DirectorySeparatorChar;if (-not $fullRoot.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($fullParent) -ne ''onec-toolkit-migration'' -or [IO.Path]::GetFileName($fullRoot) -notmatch ''^[0-9a-f]{{32}}$'') {{ throw ''Refusing to clean an unowned migration path'' }};$parentInfo=New-Object IO.DirectoryInfo($fullParent);$rootInfo=New-Object IO.DirectoryInfo($fullRoot);if ((($parentInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or (($rootInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {{ throw ''Refusing to clean a reparse-point migration path'' }};foreach($filePath in @($installerPath,$childPath)) {{ $fileInfo=New-Object IO.FileInfo($filePath);if (-not $fileInfo.FullName.StartsWith($fullRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or (($fileInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {{ throw ''Refusing to clean an unowned migration file'' }};[IO.File]::Delete($fileInfo.FullName) }};[IO.Directory]::Delete($fullRoot,$false) }}'
[IO.File]::WriteAllText($child,$childScript,(New-Object Text.UTF8Encoding($false)))
$powershell=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$commandLine='"'+$powershell+'" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$child+'"'
$detached=$false
try {{
    $result=([WmiClass]'Win32_Process').Create($commandLine)
    if (($null -eq $result) -or ([int]$result.ReturnValue -ne 0) -or ([int]$result.ProcessId -le 0)) {{
        $code=if ($null -eq $result) {{ -1 }} else {{ [int]$result.ReturnValue }}
        throw ('WMI detached installer launch failed; return_value='+[string]$code)
    }}
    $detached=$true
}} finally {{
    if (-not $detached) {{
        $fullParent=[IO.Path]::GetFullPath($migrationRoot).TrimEnd([char]92)
        $fullRoot=[IO.Path]::GetFullPath($root).TrimEnd([char]92)
        $prefix=$fullParent+[IO.Path]::DirectorySeparatorChar
        if (-not $fullRoot.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($fullParent) -ne 'onec-toolkit-migration' -or [IO.Path]::GetFileName($fullRoot) -notmatch '^[0-9a-f]{{32}}$') {{ throw 'Refusing to clean an unowned migration path' }}
        $parentInfo=New-Object IO.DirectoryInfo($fullParent)
        $rootInfo=New-Object IO.DirectoryInfo($fullRoot)
        if ((($parentInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or (($rootInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {{ throw 'Refusing to clean a reparse-point migration path' }}
        foreach ($filePath in @($installer,$child)) {{
            $fileInfo=New-Object IO.FileInfo($filePath)
            if (-not $fileInfo.FullName.StartsWith($fullRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or (($fileInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {{ throw 'Refusing to clean an unowned migration file' }}
            [IO.File]::Delete($fileInfo.FullName)
        }}
        [IO.Directory]::Delete($fullRoot,$false)
    }}
}}
{migration_receipt}
"#,
        ps_single_quote(input.installer_url),
        ps_single_quote(input.installer_sha256),
        ps_single_quote(input.persistence),
        ps_single_quote(input.direct_package_url),
        ps_single_quote(input.direct_package_sha256),
        ps_single_quote(input.direct_package_version),
        ps_single_quote(input.direct_package_target),
        installer_arguments = "-DirectPackageUrl $packageUrl -DirectPackageSha256 $packageSha256 -DirectPackageVersion $packageVersion -DirectPackageTarget $packageTarget -Persistence $persistence",
        migration_receipt = "Write-Output ('ONEC_TOOLKIT_MIGRATION_RECEIPT: detached_pid='+[string]$result.ProcessId+' package_version='+$packageVersion+' package_sha256='+$packageSha256)",
    )
}

pub(super) fn remote_direct_invite_bootstrap(input: &RemoteDirectInviteBootstrap<'_>) -> String {
    let embedded_ssh_candidate = if input.embedded_ssh_candidate {
        " -EmbeddedSshCandidate"
    } else {
        ""
    };
    format!(
        "$ErrorActionPreference='Stop';$q=Read-Host 'Enrollment token' -AsSecureString;$z=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($q);try{{$t=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($z)}}finally{{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($z)}};if([string]::IsNullOrEmpty($t)){{throw 'Enrollment token is required'}};try{{[Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor 3072}}catch{{}};$u='{installer_url}';$expected='{installer_sha256}';$request=[Net.HttpWebRequest]::Create($u);$request.AllowAutoRedirect=$false;$request.Timeout=10000;$request.ReadWriteTimeout=15000;$response=$null;$stream=$null;$memory=$null;try{{$response=$request.GetResponse();if($response.ResponseUri.AbsoluteUri -ne $u){{throw 'Installer URL changed during download'}};if(($response.ContentLength -lt 0) -or ($response.ContentLength -gt 524288)){{throw 'Installer script size is invalid'}};$stream=$response.GetResponseStream();$memory=New-Object IO.MemoryStream;$buffer=New-Object byte[] 8192;while (($read=$stream.Read($buffer,0,$buffer.Length)) -gt 0){{if(($memory.Length+$read) -gt 524288){{throw 'Installer script exceeds the size limit'}};$memory.Write($buffer,0,$read)}};$bytes=$memory.ToArray()}}finally{{if($null -ne $stream){{$stream.Dispose()}};if($null -ne $memory){{$memory.Dispose()}};if($null -ne $response){{$response.Close()}}}};$s=[Text.Encoding]::UTF8.GetString($bytes);$n=$s.Replace(([char]13).ToString()+([char]10).ToString(),([char]10).ToString());$h=[Security.Cryptography.SHA256]::Create();$x=([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($n)))).Replace('-','').ToLowerInvariant();if($x -ne $expected){{throw 'Install-OnecToolkit.ps1 SHA-256 mismatch'}};try{{& ([ScriptBlock]::Create($s)) -HubUrl '{hub_url}' -EnrollToken $t -DirectPackageUrl '{package_url}' -DirectPackageSha256 '{package_sha256}' -DirectPackageVersion '{package_version}' -DirectPackageTarget '{package_target}' -Persistence '{persistence}'{embedded_ssh_candidate}}}finally{{$t=$null;$q=$null}}",
        installer_url = ps_single_quote(input.installer_url),
        installer_sha256 = input.installer_sha256,
        hub_url = ps_single_quote(input.hub_url),
        package_url = ps_single_quote(input.package_url),
        package_sha256 = input.package_sha256,
        package_version = ps_single_quote(input.package_version),
        package_target = ps_single_quote(input.package_target),
        persistence = ps_single_quote(input.persistence),
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
