param(
    [string]$HubUrl = '',
    [string]$EnrollToken = '',
    [string]$Name = $env:COMPUTERNAME,
    [string]$Root = "$env:LOCALAPPDATA\onec-toolkit",
    [string]$DirectPackageUrl = '',
    [string]$DirectPackageSha256 = '',
    [string]$DirectPackageVersion = '',
    [string]$DirectPackageTarget = '',
    [string]$PortableGitPath = '',
    [ValidateSet('user-session', 'windows-service')]
    [string]$Persistence = 'user-session',
    [switch]$NoAgentAutostart,
    [switch]$ForcePortableGit,
    [switch]$EmbeddedSshCandidate,
    [switch]$AllowUnsupportedServer2008
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$directPackageValues = @($DirectPackageUrl, $DirectPackageSha256, $DirectPackageVersion, $DirectPackageTarget)
$directPackageCount = @($directPackageValues | Where-Object { -not [string]::IsNullOrEmpty($_) }).Count
if ($directPackageCount -ne $directPackageValues.Count) {
    throw 'Direct package installation requires DirectPackageUrl, DirectPackageSha256, DirectPackageVersion, and DirectPackageTarget.'
}


function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Enable-Tls12 {
    # Older .NET builds may reject TLS 1.2 in the SecurityProtocol setter even when the
    # numeric enum value is known. This is best-effort only; compatibility download/enrollment
    # falls back to the pinned PortableGit curl path when Schannel/WebClient cannot use HTTPS.
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
    } catch { }
}

function Test-ManagedTargetSshNestedJobSupport {
    # onec-agent owns resident sshd through a Windows Job Object, while Win32-OpenSSH creates
    # a second Job Object for remote commands/subsystems. Nested jobs are available from NT 6.2
    # (Windows 8 / Windows Server 2012); NT 6.1 must use the GatewayControl carrier instead.
    $version = [Environment]::OSVersion.Version
    return (($version.Major -gt 6) -or (($version.Major -eq 6) -and ($version.Minor -ge 2)))
}

function New-Utf8NoBom {
    New-Object System.Text.UTF8Encoding($false)
}

function Write-Utf8NoBom([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, (New-Utf8NoBom))
}

function Get-Serializer {
    Add-Type -AssemblyName System.Web.Extensions
    New-Object System.Web.Script.Serialization.JavaScriptSerializer
}

$script:CompatCurl = $null
$script:SchannelFailed = $false

function Invoke-WebClientDownload([string]$Uri, [string]$Path) {
    $client = New-Object Net.WebClient
    try {
        $client.DownloadFile($Uri, $Path)
    } finally {
        $client.Dispose()
    }
}

function Invoke-NoRedirectDownload([string]$Uri, [string]$Path) {
    $request = [Net.HttpWebRequest]::Create($Uri)
    $request.AllowAutoRedirect = $false
    $request.Timeout = 10000
    $request.ReadWriteTimeout = 15000
    $response = $null
    $inputStream = $null
    $output = $null
    try {
        $response = $request.GetResponse()
        if (($response.StatusCode -lt 200) -or ($response.StatusCode -ge 300)) { throw "Direct artifact returned HTTP $([int]$response.StatusCode)." }
        if ($response.ResponseUri.AbsoluteUri -ne $Uri) { throw 'Direct artifact URL changed during download.' }
        if (($response.ContentLength -gt 0) -and ($response.ContentLength -gt 536870912)) {
            throw 'Direct package exceeds the 512 MiB size limit.'
        }
        $inputStream = $response.GetResponseStream()
        $output = [IO.File]::Open($Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $buffer = New-Object byte[] 65536
        $total = 0L
        $timer = [Diagnostics.Stopwatch]::StartNew()
        while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $total += $read
            if ($total -gt 536870912) { throw 'Direct package exceeds the 512 MiB size limit.' }
            if ($timer.ElapsedMilliseconds -ge 600000) { throw 'Direct package download exceeded its time limit.' }
            $output.Write($buffer, 0, $read)
        }
        if (($response.ContentLength -ge 0) -and ($total -ne $response.ContentLength)) {
            throw 'Direct package response length did not match Content-Length.'
        }
    } finally {
        if ($null -ne $output) { $output.Dispose() }
        if ($null -ne $inputStream) { $inputStream.Dispose() }
        if ($null -ne $response) { $response.Close() }
    }
}

function Download-PinnedDirectFile([string]$Uri, [string]$Path, [string]$ExpectedSha256) {
    if ($Uri -notmatch '^https://[^/?#]+/[^?#]+$') { throw 'Direct artifact URL must be an absolute HTTPS URL without query or fragment.' }
    if ($ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'Direct artifact SHA-256 must contain exactly 64 hexadecimal characters.' }
    try {
        Invoke-NoRedirectDownload $Uri $Path
        Assert-Sha256 $Path $ExpectedSha256
        return
    } catch {
        Remove-Item -Force -ErrorAction SilentlyContinue $Path
        $webClientError = $_.Exception.Message
        $script:SchannelFailed = $true
    }
    try {
        Invoke-CurlDownload $Uri $Path -NoRedirect
        Assert-Sha256 $Path $ExpectedSha256
    } catch {
        Remove-Item -Force -ErrorAction SilentlyContinue $Path
        throw "Direct pinned download failed without redirects. HTTPS: $webClientError; HTTPS curl: $($_.Exception.Message)"
    }
}

function Get-CompatCurl {
    if (($null -ne $script:CompatCurl) -and (Test-Path $script:CompatCurl)) { return $script:CompatCurl }
    $architecture = Get-NativeArchitecture
    $tools = Install-PortableOpenSsh (Join-Path (Join-Path $Root 'agent') 'ssh-tools') $architecture
    $script:CompatCurl = [string]$tools['curl']
    return $script:CompatCurl
}

function Invoke-CurlDownload([string]$Uri, [string]$Path, [switch]$NoRedirect) {
    if (-not $Uri.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {
        throw "curl compatibility transport accepts HTTPS only: $Uri"
    }
    $curl = Get-CompatCurl
    if ([string]::IsNullOrEmpty($curl)) {
        throw 'No compatible HTTPS transport is available.'
    }
    $arguments = @('--fail', '--silent', '--show-error', '--proto', '=https', '--tlsv1.2', '--output', $Path)
    if (-not $NoRedirect) { $arguments += '--location' }
    $arguments += $Uri
    & $curl $arguments
    if ($LASTEXITCODE -ne 0) { throw "curl HTTPS download failed with exit code ${LASTEXITCODE}: $Uri" }
}

function Download-File([string]$Uri, [string]$Path) {
    if (-not $script:SchannelFailed) {
        try {
            Invoke-WebClientDownload $Uri $Path
            return
        } catch {
            $webClientError = $_.Exception.Message
            $script:SchannelFailed = $true
            Remove-Item -Force -ErrorAction SilentlyContinue $Path
        }
    } else {
        $webClientError = 'Windows Schannel/WebClient was already observed failing in this installer run.'
    }
    try {
        Invoke-CurlDownload $Uri $Path
    } catch {
        Remove-Item -Force -ErrorAction SilentlyContinue $Path
        throw "Download failed: $Uri. Windows Schannel/WebClient: $webClientError; PortableGit curl fallback: $($_.Exception.Message)"
    }
}

function Invoke-AgentHubJsonPost([string]$Agent, [string]$Uri, [string]$Token, [object]$Payload) {
    if (-not $Uri.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'onec-hub enrollment URI must use HTTPS.'
    }
    if ([string]::IsNullOrEmpty($Agent) -or (-not (Test-Path $Agent))) {
        throw 'Verified candidate onec-agent is required for enrollment.'
    }

    $serializer = Get-Serializer
    $requestRoot = Join-Path $env:TEMP ('onec-hub-agent-enroll-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $requestRoot | Out-Null
    Protect-SecretDirectory $requestRoot
    $tokenPath = Join-Path $requestRoot 'token.txt'
    $bodyPath = Join-Path $requestRoot 'body.json'
    $responsePath = Join-Path $requestRoot 'response.json'
    try {
        Write-Utf8NoBom $tokenPath ($Token + "`n")
        Protect-SecretFile $tokenPath
        Write-Utf8NoBom $bodyPath ($serializer.Serialize($Payload) + "`n")
        & $Agent '__enroll-http' '--url' $Uri '--token-file' $tokenPath '--body-file' $bodyPath '--output' $responsePath
        if ($LASTEXITCODE -ne 0) { throw "Candidate onec-agent HTTPS enrollment failed with exit code $LASTEXITCODE." }
        $text = [IO.File]::ReadAllText($responsePath)
        return $serializer.DeserializeObject($text)
    } finally {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $requestRoot
    }
}

function Get-Sha256([string]$Path) {
    $sha = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try { $hash = $sha.ComputeHash($stream) }
    finally { $stream.Close() }
    return ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
}

function Assert-Sha256([string]$Path, [string]$Expected) {
    $actual = Get-Sha256 $Path
    if ($actual -ne $Expected.ToLowerInvariant()) {
        throw "SHA-256 mismatch for $Path. Expected $Expected, got $actual."
    }
}

function Expand-DirectPackageZip([string]$Archive, [string]$Destination, [string]$Target, [string]$ExpectedSha256) {
    $archiveInfo = New-Object IO.FileInfo($Archive)
    if ((-not $archiveInfo.Exists) -or ($archiveInfo.Length -le 0) -or ($archiveInfo.Length -gt 536870912)) {
        throw 'Direct package archive is missing, empty, or exceeds the 512 MiB size limit.'
    }
    Assert-Sha256 $Archive $ExpectedSha256

    $archiveStream = $null
    $zip = $null
    try {
        Add-Type -AssemblyName System.IO.Compression
    } catch {
        throw 'Direct package installation requires .NET System.IO.Compression.ZipArchive; this Windows/CLR runtime cannot safely preflight direct ZIP packages.'
    }
    $archiveStream = [IO.File]::Open($Archive, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $archiveSha = [Security.Cryptography.SHA256]::Create()
    $lockedHash = ([BitConverter]::ToString($archiveSha.ComputeHash($archiveStream))).Replace('-', '').ToLowerInvariant()
    if ($lockedHash -ne $ExpectedSha256.ToLowerInvariant()) {
        $archiveStream.Dispose()
        throw 'Direct package archive changed after its pinned SHA-256 check.'
    }
    $archiveStream.Position = 0
    try {
        $zip = New-Object System.IO.Compression.ZipArchive($archiveStream, [System.IO.Compression.ZipArchiveMode]::Read)
    } catch {
        $archiveStream.Dispose()
        throw 'Direct package archive is invalid or this runtime cannot open it as a bounded ZipArchive.'
    }

    $expectedRoot = 'onec-toolkit-' + $Target + '/'
    $expectedNames = @(
        ($expectedRoot + 'onec.exe'),
        ($expectedRoot + 'onec-agent.exe'),
        ($expectedRoot + 'Update-OnecToolkit.ps1'),
        ($expectedRoot + 'Run-OnecAgent.ps1'),
        ($expectedRoot + 'onec-toolkit-update.cmd')
    )
    # Match the Rust Agent's direct ZIP contract. Do not admit a payload in
    # bootstrap that the same host's unattended updater would reject.
    $maxEntryBytes = 268435456L
    $maxExpandedBytes = 536870912L
    $totalExpanded = 0L
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $entries = @()
    $buffer = New-Object byte[] 65536
    try {
        # ZipArchiveEntry does not expose the compression-method field. Inspect the bounded
        # central directory independently so direct packages accept only stored/deflate entries.
        $directoryStream = [IO.File]::Open($Archive, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $directoryReader = New-Object IO.BinaryReader($directoryStream)
        try {
            $tailLength = [int][Math]::Min($directoryStream.Length, 65557)
            $directoryStream.Seek(-$tailLength, [IO.SeekOrigin]::End) | Out-Null
            $tail = $directoryReader.ReadBytes($tailLength)
            $endIndex = -1
            for ($i = $tail.Length - 22; $i -ge 0; $i--) {
                if ([BitConverter]::ToUInt32($tail, $i) -eq 101010256) { $endIndex = $i; break }
            }
            if ($endIndex -lt 0) { throw 'Direct package ZIP has no valid end-of-central-directory record.' }
            $disk = [BitConverter]::ToUInt16($tail, $endIndex + 4)
            $directoryDisk = [BitConverter]::ToUInt16($tail, $endIndex + 6)
            $diskEntries = [BitConverter]::ToUInt16($tail, $endIndex + 8)
            $totalEntries = [BitConverter]::ToUInt16($tail, $endIndex + 10)
            $directorySize = [BitConverter]::ToUInt32($tail, $endIndex + 12)
            $directoryOffset = [BitConverter]::ToUInt32($tail, $endIndex + 16)
            $commentLength = [BitConverter]::ToUInt16($tail, $endIndex + 20)
            if (($disk -ne 0) -or ($directoryDisk -ne 0) -or ($diskEntries -ne 5) -or ($totalEntries -ne 5) -or
                ($directorySize -eq 4294967295) -or ($directoryOffset -eq 4294967295) -or
                ($endIndex + 22 + $commentLength -ne $tail.Length)) {
                throw 'Direct package ZIP uses a multi-disk, ZIP64, or malformed directory layout.'
            }
            $directoryStream.Seek([long]$directoryOffset, [IO.SeekOrigin]::Begin) | Out-Null
            $directoryEnd = [long]$directoryOffset + [long]$directorySize
            for ($i = 0; $i -lt 5; $i++) {
                if (($directoryStream.Position + 46) -gt $directoryEnd) { throw 'Direct package ZIP central directory is truncated.' }
                $record = $directoryReader.ReadBytes(46)
                if (($record.Length -ne 46) -or ([BitConverter]::ToUInt32($record, 0) -ne 33639248)) { throw 'Direct package ZIP central directory record is invalid.' }
                $flags = [BitConverter]::ToUInt16($record, 8)
                $method = [BitConverter]::ToUInt16($record, 10)
                $compressed = [BitConverter]::ToUInt32($record, 20)
                $expanded = [BitConverter]::ToUInt32($record, 24)
                $nameLength = [BitConverter]::ToUInt16($record, 28)
                $extraLength = [BitConverter]::ToUInt16($record, 30)
                $entryCommentLength = [BitConverter]::ToUInt16($record, 32)
                $entryDisk = [BitConverter]::ToUInt16($record, 34)
                if ((($flags -band (-bnot 2062)) -ne 0) -or (($flags -band 1) -ne 0) -or (($method -ne 0) -and ($method -ne 8)) -or
                    ($compressed -eq 4294967295) -or ($expanded -eq 4294967295) -or ($entryDisk -ne 0)) {
                    throw 'Direct package ZIP contains encryption, an unsupported compression method, or ZIP64 entry metadata.'
                }
                $extraStart = $directoryStream.Position + $nameLength
                $directoryStream.Seek($extraStart, [IO.SeekOrigin]::Begin) | Out-Null
                $extraEnd = $extraStart + $extraLength
                while ($directoryStream.Position -lt $extraEnd) {
                    if (($extraEnd - $directoryStream.Position) -lt 4) { throw 'Direct package ZIP has malformed extra metadata.' }
                    $extraId = $directoryReader.ReadUInt16()
                    $extraSize = $directoryReader.ReadUInt16()
                    if (($extraId -eq 1) -or (($directoryStream.Position + $extraSize) -gt $extraEnd)) { throw 'Direct package ZIP has ZIP64 or malformed extra metadata.' }
                    $directoryStream.Seek($extraSize, [IO.SeekOrigin]::Current) | Out-Null
                }
                $directoryStream.Seek([long]$entryCommentLength, [IO.SeekOrigin]::Current) | Out-Null
            }
            if ($directoryStream.Position -ne $directoryEnd) { throw 'Direct package ZIP central directory has unexpected records or trailing data.' }
        } finally {
            $directoryReader.Dispose()
            $directoryStream.Dispose()
        }
        if ($zip.Entries.Count -ne 5) { throw 'Direct package ZIP must contain exactly five entries.' }
        foreach ($entry in $zip.Entries) {
            $name = [string]$entry.FullName
            if (($name.IndexOf('\') -ge 0) -or ($name.StartsWith('/')) -or ($name -match '(^|/)\.($|/)|(^|/)\.\.($|/)') -or ($name -match '^[A-Za-z]:')) {
                throw "Direct package ZIP contains an unsafe entry path: $name"
            }
            if ($expectedNames -notcontains $name) { throw "Direct package ZIP contains an unknown or non-canonical entry: $name" }
            if (-not $seen.Add($name)) { throw "Direct package ZIP contains a duplicate entry: $name" }
            if (($entry.Length -lt 0) -or ($entry.Length -gt $maxEntryBytes) -or ($entry.CompressedLength -lt 0) -or ($entry.CompressedLength -gt 536870912)) {
                throw "Direct package ZIP entry exceeds its compressed or expanded size limit: $name"
            }
            $unixMode = ($entry.ExternalAttributes -shr 16) -band 65535
            $unixType = $unixMode -band 61440
            $unixSpecialMode = $unixMode -band 3584
            $dosAttributes = $entry.ExternalAttributes -band 65535
            if ((($unixType -ne 0) -and ($unixType -ne 32768)) -or ($unixSpecialMode -ne 0) -or (($dosAttributes -band 1046) -ne 0)) {
                throw "Direct package ZIP contains a link, reparse point, or non-regular file: $name"
            }
            $totalExpanded += [long]$entry.Length
            if ($totalExpanded -gt $maxExpandedBytes) { throw 'Direct package ZIP exceeds the 512 MiB expanded size limit.' }
            $entries += $entry
        }
        if ($seen.Count -ne 5) { throw 'Direct package ZIP does not contain the exact required entry set.' }

        # Read every entry to EOF before creating the destination. ZipArchive rejects unsupported
        # compression methods while opening/reading entries; the bounded count must match metadata.
        foreach ($entry in $entries) {
            $entryStream = $entry.Open()
            $actualLength = 0L
            try {
                while (($read = $entryStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $actualLength += $read
                    if (($actualLength -gt $maxEntryBytes) -or ($actualLength -gt [long]$entry.Length)) {
                        throw "Direct package ZIP entry expanded beyond its declared length: $($entry.FullName)"
                    }
                }
            } finally { $entryStream.Dispose() }
            if ($actualLength -ne [long]$entry.Length) { throw "Direct package ZIP entry length did not match its declaration: $($entry.FullName)" }
        }

        New-Item -ItemType Directory -Force -Path $Destination | Out-Null
        foreach ($entry in $entries) {
            $leaf = $entry.FullName.Substring($expectedRoot.Length)
            $outputPath = Join-Path $Destination $leaf
            $entryStream = $entry.Open()
            $output = $null
            $actualLength = 0L
            try {
                $output = [IO.File]::Open($outputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                while (($read = $entryStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $actualLength += $read
                    if (($actualLength -gt [long]$entry.Length) -or ($actualLength -gt $maxEntryBytes)) {
                        throw "Direct package ZIP entry grew beyond its preflight bound: $($entry.FullName)"
                    }
                    $output.Write($buffer, 0, $read)
                }
            } finally {
                if ($null -ne $output) { $output.Dispose() }
                $entryStream.Dispose()
            }
            if ($actualLength -ne [long]$entry.Length) { throw "Direct package ZIP entry changed after preflight: $($entry.FullName)" }
        }
    } catch {
        throw
    } finally {
        $zip.Dispose()
        $archiveStream.Dispose()
    }
}

function Get-NativeArchitecture {
    $arch = $env:PROCESSOR_ARCHITEW6432
    if ([string]::IsNullOrEmpty($arch)) { $arch = $env:PROCESSOR_ARCHITECTURE }
    if ($arch -match 'AMD64|IA64') { return 'x86_64' }
    if ($arch -match 'x86') { return 'x86' }

    try {
        $processor = Get-WmiObject -Class Win32_Processor | Select-Object -First 1
        if ($null -ne $processor) {
            if ([int]$processor.AddressWidth -eq 64) { return 'x86_64' }
            if ([int]$processor.AddressWidth -eq 32) { return 'x86' }
        }
    } catch { }
    throw "Unsupported Windows architecture: $arch"
}

function Get-ToolkitTarget([string]$Architecture, [switch]$Allow2008) {
    $v = [Environment]::OSVersion.Version
    if (($v.Major -lt 6) -or (($v.Major -eq 6) -and ($v.Minor -lt 1))) {
        if (-not $Allow2008) {
            throw "Windows $v is below the guaranteed Win7/Server 2008 R2 compatibility baseline. Re-run with -AllowUnsupportedServer2008 only for an explicit best-effort test."
        }
    }
    if ($Architecture -eq 'x86') { return 'i686-win7-windows-msvc' }
    if ($v.Major -ge 10) { return 'x86_64-pc-windows-msvc' }
    return 'x86_64-win7-windows-msvc'
}

function Get-PortableGitSpec([string]$Architecture) {
    $v = [Environment]::OSVersion.Version
    if ($Architecture -eq 'x86') {
        if (($v.Major -eq 6) -and ($v.Minor -eq 0)) {
            return New-Object PSObject -Property @{
                Version = '2.37.1'
                Tag = 'v2.37.1.windows.1'
                Asset = 'PortableGit-2.37.1-32-bit.7z.exe'
                Sha256 = '1a32f1de26d52ef866f27db395d8ab6bd9dc4c53bfc0161937b20f8749b4d96b'
            }
        }
        return New-Object PSObject -Property @{
            Version = '2.46.2'
            Tag = 'v2.46.2.windows.1'
            Asset = 'PortableGit-2.46.2-32-bit.7z.exe'
            Sha256 = '7351e28f498010f0aa2fd63abbd704698db38cf6f881e2417fb3d73e5a7e6f87'
        }
    }

    if (($v.Major -eq 6) -and ($v.Minor -eq 0)) {
        return New-Object PSObject -Property @{
            Version = '2.37.1'
            Tag = 'v2.37.1.windows.1'
            Asset = 'PortableGit-2.37.1-64-bit.7z.exe'
            Sha256 = 'b0bc403bb03326b835e239b3bf7c0af277f43eba5421132dc8531204c78b6b25'
        }
    }
    if (($v.Major -eq 6) -and ($v.Minor -le 2)) {
        return New-Object PSObject -Property @{
            Version = '2.46.2'
            Tag = 'v2.46.2.windows.1'
            Asset = 'PortableGit-2.46.2-64-bit.7z.exe'
            Sha256 = '58ae5c1a27d3f9ce8518c1a187860973cfa4dd604f518350e84f7baf418fc9fa'
        }
    }
    return New-Object PSObject -Property @{
        Version = '2.55.0.5'
        Tag = 'v2.55.0.windows.5'
        Asset = 'PortableGit-2.55.0.5-64-bit.7z.exe'
        Sha256 = '5aa8a20f6e9abb2c755f0e73c91c687701a46b309ad84a0ca6509380fa4ae290'
    }
}

function Resolve-PortableGitLayout([string]$Root) {
    foreach ($candidateRoot in @($Root, (Join-Path $Root 'PortableGit'))) {
        $candidateSsh = Join-Path $candidateRoot 'usr\bin\ssh.exe'
        $candidateSshKeygen = Join-Path $candidateRoot 'usr\bin\ssh-keygen.exe'
        $candidateGit = Join-Path $candidateRoot 'cmd\git.exe'
        $candidateCurl = Join-Path $candidateRoot 'mingw64\bin\curl.exe'
        if (-not [IO.File]::Exists($candidateCurl)) {
            $candidateCurl = Join-Path $candidateRoot 'mingw32\bin\curl.exe'
        }
        if ([IO.File]::Exists($candidateSsh) -and [IO.File]::Exists($candidateSshKeygen) -and [IO.File]::Exists($candidateGit) -and [IO.File]::Exists($candidateCurl)) {
            return @{ ssh = $candidateSsh; ssh_keygen = $candidateSshKeygen; git = $candidateGit; curl = $candidateCurl }
        }
    }
    return $null
}

function Test-PortableGitRuntime([object]$Layout) {
    if ($null -eq $Layout) { return $false }
    try {
        $git = [string]$Layout['git']
        $versionText = (& $git --version 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { return $false }
        return $versionText.StartsWith('git version ', [StringComparison]::OrdinalIgnoreCase)
    } catch {
        return $false
    }
}

function Install-PortableOpenSsh([string]$Directory, [string]$Architecture) {
    $spec = Get-PortableGitSpec $Architecture
    $root = Join-Path $Directory ('portable-git-' + $spec.Version)
    $existingLayout = Resolve-PortableGitLayout $root
    if (($null -ne $existingLayout) -and (Test-PortableGitRuntime $existingLayout)) {
        return @{ git = [string]$existingLayout['git']; ssh = [string]$existingLayout['ssh']; ssh_keygen = [string]$existingLayout['ssh_keygen']; curl = [string]$existingLayout['curl']; version = $spec.Version }
    }

    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    $archive = Join-Path $Directory $spec.Asset
    if (-not [string]::IsNullOrEmpty($PortableGitPath)) {
        $sourceArchive = [IO.Path]::GetFullPath($PortableGitPath)
        $destinationArchive = [IO.Path]::GetFullPath($archive)
        if (-not [IO.File]::Exists($sourceArchive)) { throw "PortableGit archive not found: $sourceArchive" }
        if (-not $sourceArchive.Equals($destinationArchive, [StringComparison]::OrdinalIgnoreCase)) {
            [IO.File]::Copy($sourceArchive, $destinationArchive, $true)
        }
    } elseif (-not (Test-Path $archive)) {
        $url = 'https://github.com/git-for-windows/git/releases/download/' + $spec.Tag + '/' + $spec.Asset
        try {
            Download-File $url $archive
        } catch {
            throw "PortableGit download failed. On old Windows without working TLS 1.2, download $($spec.Asset) on another machine and rerun with -PortableGitPath. $($_.Exception.Message)"
        }
    }

    try {
        Assert-Sha256 $archive $spec.Sha256
    } catch {
        Remove-Item -Force -ErrorAction SilentlyContinue $archive
        throw
    }

    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $root
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    $extractArgument = '-o"' + $root + '"'
    $process = Start-Process -FilePath $archive -ArgumentList $extractArgument, '-y' -NoNewWindow -Wait -PassThru
    $extractedLayout = Resolve-PortableGitLayout $root
    if (($null -eq $extractedLayout) -or (-not (Test-PortableGitRuntime $extractedLayout))) {
        throw "PortableGit extraction did not produce a runnable supported layout with git.exe, ssh.exe, ssh-keygen.exe, and curl.exe (SFX exit code $($process.ExitCode))."
    }
    if (($process.ExitCode -ne 0) -and ($process.ExitCode -ne 1)) {
        throw "PortableGit extraction returned unsupported exit code $($process.ExitCode) even though the required PortableGit runtime is present."
    }
    if ($process.ExitCode -eq 1) {
        Write-Warning 'PortableGit legacy SFX returned exit code 1 after producing the required PortableGit runtime; continuing with the verified extracted layout.'
    }

    return @{ git = [string]$extractedLayout['git']; ssh = [string]$extractedLayout['ssh']; ssh_keygen = [string]$extractedLayout['ssh_keygen']; curl = [string]$extractedLayout['curl']; version = $spec.Version }
}

function Ensure-AgentKey([string]$Directory, [string]$MachineId, [string]$Architecture, [switch]$UsePortableGit) {
    $ssh = Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'
    $sshKeygen = Join-Path $env:WINDIR 'System32\OpenSSH\ssh-keygen.exe'
    $source = 'windows'
    if ($UsePortableGit -or (-not (Test-Path $ssh)) -or (-not (Test-Path $sshKeygen))) {
        $tools = Install-PortableOpenSsh (Join-Path $Directory 'ssh-tools') $Architecture
        $ssh = [string]$tools['ssh']
        $sshKeygen = [string]$tools['ssh_keygen']
        $source = 'portable-git-' + [string]$tools['version']
    }

    $identity = Join-Path $Directory 'id_ed25519'
    if (-not (Test-Path $identity)) {
        $arguments = '-q -t ed25519 -N "" -C "onec-agent-' + $MachineId + '" -f "' + $identity + '"'
        $process = Start-Process -FilePath $sshKeygen -ArgumentList $arguments -NoNewWindow -Wait -PassThru
        if ($process.ExitCode -ne 0) { throw "ssh-keygen failed with exit code $($process.ExitCode)" }
    }
    $publicPath = $identity + '.pub'
    if (-not (Test-Path $publicPath)) { throw "ssh-keygen did not create $publicPath" }
    $public = [IO.File]::ReadAllText($publicPath).Trim()
    return @{
        program = $ssh
        identity = $identity
        public = $public
        known_hosts = (Join-Path $Directory 'known_hosts')
        source = $source
    }
}

function Get-UserSshServerSpec([string]$Architecture) {
    $v = [Environment]::OSVersion.Version
    if (($v.Major -lt 6) -or (($v.Major -eq 6) -and ($v.Minor -lt 1))) { return $null }
    if ($Architecture -eq 'x86') {
        return New-Object PSObject -Property @{
            Tag = '10.0.0.0p2-Preview'
            Asset = 'OpenSSH-Win32.zip'
            Directory = 'OpenSSH-Win32'
            Sha256 = 'c61d7fea20ddfe0fc50eb56210a66464557721120f7794ff9cc883b5ba526abd'
        }
    }
    return New-Object PSObject -Property @{
        Tag = '10.0.0.0p2-Preview'
        Asset = 'OpenSSH-Win64.zip'
        Directory = 'OpenSSH-Win64'
        Sha256 = '23f50f3458c4c5d0b12217c6a5ddfde0137210a30fa870e98b29827f7b43aba5'
    }
}

function Install-UserSshServer([string]$Directory, [string]$Architecture) {
    $spec = Get-UserSshServerSpec $Architecture
    if ($null -eq $spec) { return $null }
    $installRoot = Join-Path $Directory $spec.Directory
    $sshd = Join-Path $installRoot 'sshd.exe'
    $sshKeygen = Join-Path $installRoot 'ssh-keygen.exe'
    $sftpServer = Join-Path $installRoot 'sftp-server.exe'
    if ((Test-Path $sshd) -and (Test-Path $sshKeygen) -and (Test-Path $sftpServer)) {
        return @{ sshd = $sshd; ssh_keygen = $sshKeygen; sftp_server = $sftpServer; version = $spec.Tag }
    }

    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    $archive = Join-Path $Directory $spec.Asset
    $url = 'https://github.com/PowerShell/Win32-OpenSSH/releases/download/' + $spec.Tag + '/' + $spec.Asset
    Download-File $url $archive
    try {
        Assert-Sha256 $archive $spec.Sha256
    } catch {
        Remove-Item -Force -ErrorAction SilentlyContinue $archive
        throw
    }

    $extractRoot = Join-Path $Directory 'extracting'
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $extractRoot
    New-Item -ItemType Directory -Force -Path $extractRoot | Out-Null
    try {
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [IO.Compression.ZipFile]::ExtractToDirectory($archive, $extractRoot)
        } catch {
            $shell = New-Object -ComObject Shell.Application
            $zip = $shell.NameSpace($archive)
            $dest = $shell.NameSpace($extractRoot)
            if (($null -eq $zip) -or ($null -eq $dest)) { throw "Cannot open OpenSSH ZIP archive $archive" }
            $dest.CopyHere($zip.Items(), 20)
            $deadline = [DateTime]::UtcNow.AddMinutes(3)
            while (([DateTime]::UtcNow -lt $deadline) -and (-not (Test-Path (Join-Path $extractRoot ($spec.Directory + '\sshd.exe'))))) {
                Start-Sleep -Milliseconds 500
            }
        }
        $extracted = Join-Path $extractRoot $spec.Directory
        if ((-not (Test-Path (Join-Path $extracted 'sshd.exe'))) -or (-not (Test-Path (Join-Path $extracted 'ssh-keygen.exe'))) -or (-not (Test-Path (Join-Path $extracted 'sftp-server.exe')))) {
            throw 'Portable OpenSSH archive does not contain sshd.exe, ssh-keygen.exe, and sftp-server.exe.'
        }
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $installRoot
        Move-Item -Force $extracted $installRoot
    } finally {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $extractRoot
    }
    return @{ sshd = $sshd; ssh_keygen = $sshKeygen; sftp_server = $sftpServer; version = $spec.Tag }
}

function Ensure-UserSshHostKey([string]$SshKeygen, [string]$Path, [string]$MachineId) {
    if (-not (Test-Path $Path)) {
        $arguments = '-q -t ed25519 -N "" -C "onec-toolkit-host-' + $MachineId + '" -f "' + $Path + '"'
        $process = Start-Process -FilePath $SshKeygen -ArgumentList $arguments -NoNewWindow -Wait -PassThru
        if ($process.ExitCode -ne 0) { throw "target SSH host-key generation failed with exit code $($process.ExitCode)" }
    }
    if (-not (Test-Path ($Path + '.pub'))) { throw "target SSH host public key was not created: $Path.pub" }
    return [IO.File]::ReadAllText($Path + '.pub').Trim()
}

function Write-UserSshdConfig([string]$Path, [string]$HostKey, [string]$AuthorizedKeys, [string]$SftpServer, [string]$Username, [int]$Port = 27322) {
    $hostKeyConfig = $HostKey.Replace('\', '/')
    $authorizedConfig = $AuthorizedKeys.Replace('\', '/')
    $sftpServerConfig = $SftpServer.Replace('\', '/')
    $text = @(
        ('Port ' + $Port),
        'ListenAddress 127.0.0.1',
        ('HostKey "' + $hostKeyConfig + '"'),
        ('AuthorizedKeysFile "' + $authorizedConfig + '"'),
        'PubkeyAuthentication yes',
        'PasswordAuthentication no',
        'KbdInteractiveAuthentication no',
        'AuthenticationMethods publickey',
        'PermitEmptyPasswords no',
        ('AllowUsers ' + $Username.ToLowerInvariant()),
        'AllowAgentForwarding no',
        'X11Forwarding no',
        'GatewayPorts no',
        'PermitTunnel no',
        ('Subsystem sftp "' + $sftpServerConfig + '"'),
        'LogLevel VERBOSE'
    ) -join "`r`n"
    Write-Utf8NoBom $Path ($text + "`r`n")
}

function Get-FreeLoopbackPort {
    $listener = New-Object System.Net.Sockets.TcpListener -ArgumentList ([Net.IPAddress]::Loopback), 0
    try {
        $listener.Start()
        return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally {
        $listener.Stop()
    }
}

function Wait-LoopbackPort([int]$Port, [Diagnostics.Process]$Process) {
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        if (($null -ne $Process) -and $Process.HasExited) { return $false }
        $client = New-Object Net.Sockets.TcpClient
        try {
            $client.Connect('127.0.0.1', $Port)
            return $true
        } catch {
        } finally {
            $client.Close()
        }
        Start-Sleep -Milliseconds 100
    }
    return $false
}

function Test-UserSshServerPublicKey(
    [System.Collections.IDictionary]$Server,
    [System.Collections.IDictionary]$SshConfig,
    [string]$HostKeyPath,
    [string]$HostPublicKey,
    [string]$Username,
    [string]$AgentDirectory,
    [string]$TempRoot
) {
    $testRoot = Join-Path $TempRoot 'sshd-preflight'
    New-Item -ItemType Directory -Force -Path $testRoot | Out-Null
    $testPort = Get-FreeLoopbackPort
    $authorizedKeys = Join-Path $AgentDirectory ('sshd_authorized_keys.preflight-' + [Guid]::NewGuid().ToString('N'))
    $knownHosts = Join-Path $testRoot 'known_hosts'
    $configPath = Join-Path $testRoot 'sshd_config'
    $logPath = Join-Path $testRoot 'sshd.log'
    $process = $null

    try {
        Write-Utf8NoBom $authorizedKeys ([string]$SshConfig['public'] + "`n")
        Protect-UserAuthorizedKeysFile $authorizedKeys
        Write-Utf8NoBom $knownHosts ('[127.0.0.1]:' + $testPort + ' ' + $HostPublicKey + "`n")
        Write-UserSshdConfig $configPath $HostKeyPath $authorizedKeys ([string]$Server['sftp_server']) $Username $testPort

        $arguments = '-D -E "' + $logPath + '" -f "' + $configPath + '"'
        $process = Start-Process -FilePath ([string]$Server['sshd']) -ArgumentList $arguments -NoNewWindow -PassThru
        if (-not (Wait-LoopbackPort $testPort $process)) { return $false }

        & ([string]$SshConfig['program']) `
            '-T' `
            '-p' ([string]$testPort) `
            '-i' ([string]$SshConfig['identity']) `
            '-o' 'BatchMode=yes' `
            '-o' 'IdentitiesOnly=yes' `
            '-o' 'IdentityAgent=none' `
            '-o' 'ConnectionAttempts=1' `
            '-o' 'ConnectTimeout=5' `
            '-o' 'LogLevel=QUIET' `
            '-o' 'StrictHostKeyChecking=yes' `
            '-o' ('UserKnownHostsFile=' + $knownHosts) `
            '-o' 'GlobalKnownHostsFile=NUL' `
            ($Username + '@127.0.0.1') `
            'whoami' | Out-Null
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    } finally {
        if (($null -ne $process) -and (-not $process.HasExited)) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            try { $process.WaitForExit() } catch { }
        }
        Remove-Item -Force -ErrorAction SilentlyContinue $authorizedKeys
    }
}

function Test-EmbeddedSshServerCandidate(
    [string]$Agent,
    [System.Collections.IDictionary]$SshConfig,
    [string]$HostKeyPath,
    [string]$HostPublicKeyPath,
    [int]$Port,
    [string]$Username,
    [string]$AgentDirectory,
    [string]$TempRoot
) {
    $testRoot = Join-Path $TempRoot 'embedded-ssh-preflight'
    New-Item -ItemType Directory -Force -Path $testRoot | Out-Null
    $authorizedKeys = Join-Path $AgentDirectory ('embedded_ssh_authorized_keys.preflight-' + [Guid]::NewGuid().ToString('N'))
    $configPath = Join-Path $testRoot 'agent.json'

    try {
        Write-Utf8NoBom $authorizedKeys ([string]$SshConfig['public'] + "`n")
        Protect-UserAuthorizedKeysFile $authorizedKeys

        $embeddedSettings = New-Object System.Collections.Specialized.OrderedDictionary
        $embeddedSettings.Add('user', $Username)
        $embeddedSettings.Add('host_key', $HostKeyPath)
        $embeddedSettings.Add('authorized_keys', $authorizedKeys)
        $embeddedSettings.Add('port', $Port)

        $candidateConfig = New-Object System.Collections.Specialized.OrderedDictionary
        $candidateConfig.Add('version', 1)
        $candidateConfig.Add('name', 'embedded-ssh-preflight')
        $candidateConfig.Add('listen', '127.0.0.1:0')
        $candidateConfig.Add('secret_env', 'ONEC_AGENT_SECRET')
        $candidateConfig.Add('embedded_ssh_server', $embeddedSettings)

        Write-Utf8NoBom $configPath ((Get-Serializer).Serialize($candidateConfig) + "`n")
        & $Agent '__embedded-ssh-preflight' '--config' $configPath '--host-public-key' $HostPublicKeyPath '--identity' ([string]$SshConfig['identity']) '--scratch-dir' $testRoot | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "embedded SSH candidate self-preflight failed with exit code $LASTEXITCODE"
        }
        return $true
    } finally {
        Remove-Item -Force -ErrorAction SilentlyContinue $authorizedKeys
    }
}
function Get-CurrentWindowsPrincipal {
    $principal = [string][Security.Principal.WindowsIdentity]::GetCurrent().Name
    if ([string]::IsNullOrEmpty($principal) -or $principal.Contains("`r") -or $principal.Contains("`n")) {
        throw 'Cannot determine a safe canonical Windows principal for managed SSH enrollment.'
    }
    return $principal.Trim()
}

function Get-CanonicalComputerName {
    $name = [string]$env:COMPUTERNAME
    if ([string]::IsNullOrEmpty($name) -or $name.Trim().Length -eq 0) {
        try { $name = [string][Environment]::MachineName } catch { $name = '' }
    }
    $name = $name.Trim()
    if ([string]::IsNullOrEmpty($name) -or $name.Length -gt 255 -or $name.Contains("`r") -or $name.Contains("`n")) {
        throw 'Cannot determine a safe canonical Windows computer name for managed enrollment.'
    }
    return $name
}

function Protect-SecretFile([string]$Path) {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $grant = '*' + $sid + ':F'
    $systemGrant = '*S-1-5-18:F'
    & icacls.exe $Path /inheritance:r /grant:r $grant $systemGrant /C | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed for $Path" }
}

function Protect-SecretDirectory([string]$Path) {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $grant = '*' + $sid + ':(OI)(CI)F'
    $systemGrant = '*S-1-5-18:(OI)(CI)F'
    & icacls.exe $Path /inheritance:r /grant:r $grant $systemGrant /C | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed for private directory $Path" }
}

function Protect-UserAuthorizedKeysFile([string]$Path) {
    Protect-SecretFile $Path
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $owner = '*' + $sid
    & icacls.exe $Path /setowner $owner /C | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls owner normalization failed for $Path" }
}

function Broadcast-EnvironmentChange {
    $source = @'
using System;
using System.Runtime.InteropServices;
public static class EnvironmentBroadcast {
    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint flags, uint timeout, out UIntPtr result);
}
'@
    try {
        Add-Type -TypeDefinition $source -ErrorAction Stop | Out-Null
        $result = [UIntPtr]::Zero
        [EnvironmentBroadcast]::SendMessageTimeout([IntPtr]0xffff, 0x1a, [UIntPtr]::Zero, 'Environment', 0x2, 5000, [ref]$result) | Out-Null
    } catch { }
}

function Add-UserPath([string]$Directory) {
    $current = [Environment]::GetEnvironmentVariable('Path', [EnvironmentVariableTarget]::User)
    if ($null -eq $current) { $current = '' }
    $exists = $false
    foreach ($entry in $current.Split(';')) {
        if ($entry.TrimEnd('\').Equals($Directory.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
            $exists = $true
            break
        }
    }
    if (-not $exists) {
        $newPath = if ([string]::IsNullOrEmpty($current)) { $Directory } else { $current.TrimEnd(';') + ';' + $Directory }
        [Environment]::SetEnvironmentVariable('Path', $newPath, [EnvironmentVariableTarget]::User)
        Broadcast-EnvironmentChange
    }
    $processHasPath = $false
    foreach ($entry in $env:Path.Split(';')) {
        if ($entry.TrimEnd('\').Equals($Directory.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
            $processHasPath = $true
            break
        }
    }
    if (-not $processHasPath) { $env:Path = $Directory + ';' + $env:Path }
}

function Set-AgentAutostart([string]$Runner, [string]$ToolkitRoot) {
    $powershell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $command = '"' + $powershell + '" -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $Runner + '" -Root "' + $ToolkitRoot + '"'
    if ($command.Length -gt 260) { throw 'onec-agent HKCU Run command exceeds the Windows Run-key command-line limit.' }
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Software\Microsoft\Windows\CurrentVersion\Run')
    try { $key.SetValue('onec-agent', $command, [Microsoft.Win32.RegistryValueKind]::String) }
    finally { $key.Close() }
}

function Remove-AgentAutostart {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Run', $true)
    if ($null -eq $key) { return }
    try { $key.DeleteValue('onec-agent', $false) }
    finally { $key.Close() }
}

function Get-AgentAutostartValue {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Run')
    if ($null -eq $key) { return $null }
    try { return $key.GetValue('onec-agent', $null) }
    finally { $key.Close() }
}

function Restore-AgentAutostart([object]$Value) {
    if ($null -eq $Value) {
        Remove-AgentAutostart
        return
    }
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Software\Microsoft\Windows\CurrentVersion\Run')
    try { $key.SetValue('onec-agent', [string]$Value, [Microsoft.Win32.RegistryValueKind]::String) }
    finally { $key.Close() }
}

function Test-SupervisorRunning([string]$AgentDirectory) {
    $lockPath = Join-Path $AgentDirectory 'supervisor.lock'
    $probe = $null
    try {
        $probe = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        return $false
    } catch [IO.IOException] {
        return $true
    } finally {
        if ($null -ne $probe) { $probe.Dispose() }
    }
}

function Start-AgentSupervisor([string]$Runner, [string]$ToolkitRoot) {
    $powershell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $Runner + '" -Root "' + $ToolkitRoot + '"'
    Start-Process -FilePath $powershell -ArgumentList $arguments -WindowStyle Hidden | Out-Null
}

function Get-UnixTimeMilliseconds {
    return [int64](([DateTime]::UtcNow - [DateTime]'1970-01-01').TotalMilliseconds)
}

function Test-AgentTunnelStartedSince([string]$EventLog, [int64]$StartedAfterUnixMs) {
    if (-not (Test-Path $EventLog)) { return $false }
    $serializer = Get-Serializer
    foreach ($line in @(Get-Content -ErrorAction SilentlyContinue $EventLog)) {
        if ([string]::IsNullOrEmpty([string]$line)) { continue }
        try {
            $event = $serializer.DeserializeObject([string]$line)
            if (([string]$event['event_code'] -eq 'tunnel.started') -and ([int64]$event['timestamp_unix_ms'] -ge $StartedAfterUnixMs)) {
                return $true
            }
        } catch { }
    }
    return $false
}

function Wait-AgentServiceReady([string]$AgentProgram, [string]$EventLog, [int64]$StartedAfterUnixMs) {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ([DateTime]::UtcNow -lt $deadline) {
        $statusText = (& $AgentProgram service-status | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { throw 'onec-agent service-status failed during startup verification.' }
        $status = (Get-Serializer).DeserializeObject($statusText)
        if (-not [bool]$status['installed']) { throw 'onec-agent Windows service disappeared during startup verification.' }
        if (Test-AgentTunnelStartedSince $EventLog $StartedAfterUnixMs) { return }
        Start-Sleep -Milliseconds 500
    }
    throw 'onec-agent Windows service started but did not publish a new tunnel.started event within 30 seconds.'
}

function Wait-AgentUserSessionReady([string]$AgentDirectory, [string]$EventLog, [int64]$StartedAfterUnixMs) {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ((Test-SupervisorRunning $AgentDirectory) -and (Test-AgentTunnelStartedSince $EventLog $StartedAfterUnixMs)) {
            return
        }
        Start-Sleep -Milliseconds 500
    }
    throw 'onec-agent user-session supervisor started but did not publish a new tunnel.started event within 30 seconds.'
}

function Acquire-InstallWriterLock([string]$Path) {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            return [IO.File]::Open($Path, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        } catch [IO.IOException] {
            Start-Sleep -Milliseconds 250
        }
    }
    throw "Another onec-toolkit install/update writer owns $Path; timed out after 30 seconds."
}

function Backup-File([string]$Source, [string]$Destination) {
    if (-not (Test-Path $Source)) { return }
    $parent = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    Copy-Item -Force $Source $Destination
}

function Restore-File([string]$Backup, [string]$Destination, [bool]$Existed) {
    if ($Existed) {
        if (-not (Test-Path $Backup)) { throw "Missing rollback file $Backup" }
        Copy-Item -Force $Backup $Destination
    } else {
        Remove-Item -Force -ErrorAction SilentlyContinue $Destination
    }
}

function Stop-ManagedAgentProcesses([string]$ManagedAgentPath) {
    $expected = [IO.Path]::GetFullPath($ManagedAgentPath)
    $processes = @(Get-WmiObject -Class Win32_Process -Filter "Name='onec-agent.exe'" -ErrorAction SilentlyContinue)
    foreach ($candidate in $processes) {
        $candidatePath = [string]$candidate.ExecutablePath
        if ([string]::IsNullOrEmpty($candidatePath)) { continue }
        try { $candidatePath = [IO.Path]::GetFullPath($candidatePath) } catch { continue }
        if ($candidatePath.Equals($expected, [StringComparison]::OrdinalIgnoreCase)) {
            Stop-Process -Id ([int]$candidate.ProcessId) -Force -ErrorAction Stop
        }
    }
}

function Wait-ManagedAgentBinaryReleased([string]$ManagedAgentPath) {
    if (-not [IO.File]::Exists($ManagedAgentPath)) { return }
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ([DateTime]::UtcNow -lt $deadline) {
        $probe = $null
        try {
            $probe = [IO.File]::Open($ManagedAgentPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            return
        } catch [IO.IOException] {
            Start-Sleep -Milliseconds 500
        } finally {
            if ($null -ne $probe) { $probe.Dispose() }
        }
    }
    throw "Managed onec-agent executable is still locked after recovery stop: $ManagedAgentPath"
}

function Get-MaintenanceMarkerState([string]$MaintenancePath) {
    try { [void][IO.File]::GetAttributes($MaintenancePath) }
    catch [IO.FileNotFoundException] { return 'absent' }
    catch [IO.DirectoryNotFoundException] { return 'absent' }
    catch { return 'unknown' }
    try {
        $parts = [IO.File]::ReadAllText($MaintenancePath).Trim().Split('|')
        if (($parts.Length -ne 4) -or ($parts[0] -ne 'v1')) { return 'unknown' }
        $ownerPid = 0
        $ownerStartTicks = [Int64]0
        if ((-not [int]::TryParse($parts[1], [ref]$ownerPid)) -or
            (-not [Int64]::TryParse($parts[2], [ref]$ownerStartTicks)) -or
            ($ownerPid -le 0) -or ($ownerStartTicks -le 0) -or
            (($parts[3] -ne 'update') -and ($parts[3] -ne 'install'))) { return 'unknown' }
        try { $owner = [Diagnostics.Process]::GetProcessById($ownerPid) }
        catch [ArgumentException] { return 'orphan' }
        try {
            if ($owner.HasExited) { return 'orphan' }
            if ($owner.StartTime.ToUniversalTime().Ticks -ne $ownerStartTicks) { return 'orphan' }
            return 'live'
        } catch { return 'unknown' }
        finally { $owner.Dispose() }
    } catch { return 'unknown' }
}

function New-OwnedMaintenanceMarker([string]$AgentDirectory, [string]$Kind) {
    $maintenance = Join-Path $AgentDirectory 'maintenance'
    $gatePath = Join-Path $AgentDirectory 'maintenance.gate'
    $gate = $null
    try { $gate = [IO.File]::Open($gatePath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
    catch [IO.IOException] { throw 'Unable to acquire the maintenance ownership gate.' }
    try {
        $state = Get-MaintenanceMarkerState $maintenance
        if ($state -eq 'live') { throw 'A live update/install process owns the maintenance marker.' }
        if ($state -eq 'unknown') { throw 'The maintenance marker owner cannot be verified; preserving it.' }
        if ($state -eq 'orphan') { [IO.File]::Delete($maintenance) }
        $startTicks = [Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().Ticks
        $text = 'v1|' + [string]$PID + '|' + [string]$startTicks + '|' + $Kind + [Environment]::NewLine
        $temporaryMarker = $maintenance + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
        $stream = [IO.File]::Open($temporaryMarker, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $bytes = (New-Utf8NoBom).GetBytes($text)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
        } finally { $stream.Dispose() }
        [IO.File]::Move($temporaryMarker, $maintenance)
        return $text.Trim()
    } finally { if ($null -ne $gate) { $gate.Dispose() } }
}

function Remove-OwnedMaintenanceMarker([string]$AgentDirectory, [string]$OwnerText) {
    if ([string]::IsNullOrEmpty($OwnerText)) { return }
    $maintenance = Join-Path $AgentDirectory 'maintenance'
    $gate = $null
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while (($null -eq $gate) -and ([DateTime]::UtcNow -lt $deadline)) {
        try { $gate = [IO.File]::Open((Join-Path $AgentDirectory 'maintenance.gate'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
        catch [IO.IOException] { Start-Sleep -Milliseconds 100 }
        catch { break }
    }
    if ($null -eq $gate) { return }
    try {
        if ([IO.File]::Exists($maintenance) -and
            [string]::Equals([IO.File]::ReadAllText($maintenance).Trim(), $OwnerText, [StringComparison]::Ordinal)) {
            [IO.File]::Delete($maintenance)
        }
    } catch { }
    finally { if ($null -ne $gate) { $gate.Dispose() } }
}

function Stop-ExistingUserAgent([string]$AgentDirectory) {
    $maintenance = Join-Path $AgentDirectory 'maintenance'
    $pidFile = Join-Path $AgentDirectory 'agent.pid'
    $supervisorLock = Join-Path $AgentDirectory 'supervisor.lock'
    $maintenanceOwner = New-OwnedMaintenanceMarker $AgentDirectory 'install'
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while ([DateTime]::UtcNow -lt $deadline) {
            if (-not (Test-Path $pidFile)) { break }
            Start-Sleep -Milliseconds 500
        }
        $supervisorStopped = $false
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while ([DateTime]::UtcNow -lt $deadline) {
            $probe = $null
            try {
                $probe = [IO.File]::Open($supervisorLock, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
                $supervisorStopped = $true
                break
            } catch [IO.IOException] {
                Start-Sleep -Milliseconds 500
            } finally {
                if ($null -ne $probe) { $probe.Dispose() }
            }
        }
        if (-not $supervisorStopped) { throw 'Existing user-mode onec-agent supervisor did not stop.' }
    } catch {
        Remove-OwnedMaintenanceMarker $AgentDirectory $maintenanceOwner
        throw
    }
    return $maintenanceOwner
}

if (($Persistence -eq 'windows-service') -and $NoAgentAutostart) {
    throw 'NoAgentAutostart cannot be combined with windows-service persistence.'
}
$initialService = Get-Service -Name 'onec-agent' -ErrorAction SilentlyContinue
$serviceExistedInitially = $null -ne $initialService
if (($Persistence -eq 'windows-service') -and (-not (Test-IsAdministrator))) {
    throw 'windows-service persistence requires an elevated PowerShell session.'
}
if (($Persistence -eq 'user-session') -and $serviceExistedInitially) {
    throw 'An existing onec-agent Windows service was detected. Uninstall it explicitly before switching to user-session persistence.'
}

Enable-Tls12

if ([string]::IsNullOrEmpty($env:LOCALAPPDATA)) { throw 'LOCALAPPDATA is not available for this user.' }
if (($HubUrl -eq '') -xor ($EnrollToken -eq '')) { throw 'HubUrl and EnrollToken must be supplied together.' }
$computerName = Get-CanonicalComputerName
if ([string]::IsNullOrEmpty($Name)) { $Name = $computerName }

$architecture = Get-NativeArchitecture
$target = Get-ToolkitTarget $architecture -Allow2008:$AllowUnsupportedServer2008
$Root = [IO.Path]::GetFullPath($Root)
$tempRoot = [IO.Path]::GetFullPath((Join-Path $env:TEMP ('onec-toolkit-install-' + [Guid]::NewGuid().ToString('N'))))
New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null

$binDir = Join-Path $Root 'bin'
$agentDir = Join-Path $Root 'agent'
$scriptsDir = Join-Path $Root 'scripts'
$sshServerRoot = Join-Path $Root 'ssh-server'
$sshHostKeyPath = Join-Path $agentDir 'ssh_host_ed25519_key'
$sshAuthorizedKeysPath = Join-Path $agentDir 'sshd_authorized_keys'
$sshdConfigPath = Join-Path $agentDir 'sshd_config'
$maintenance = Join-Path $agentDir 'maintenance'
$configPath = Join-Path $agentDir 'agent.json'
$secretPath = Join-Path $agentDir 'control.secret'
$knownHostsPath = Join-Path $agentDir 'known_hosts'
$metadataPath = Join-Path $Root 'install.json'
$updateCommand = Join-Path $binDir 'onec-toolkit-update.cmd'
$hadSupervisor = $false
$stoppedExistingSupervisor = $false
$published = $false
$enrolled = $false
$serviceWasRunning = $false
$managedFiles = @()
$originalUserPath = [Environment]::GetEnvironmentVariable('Path', [EnvironmentVariableTarget]::User)
$originalProcessPath = $env:Path
$originalAutostart = Get-AgentAutostartValue
$installWriterLock = $null
$maintenanceOwned = $null

try {
    New-Item -ItemType Directory -Force -Path $Root | Out-Null
    $installWriterLock = Acquire-InstallWriterLock (Join-Path $Root 'update.lock')

    $archiveName = 'onec-toolkit-' + $target + '.zip'
    $archive = Join-Path $tempRoot $archiveName
    if ($DirectPackageSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'DirectPackageSha256 must contain exactly 64 hexadecimal characters.' }
    if ($DirectPackageVersion -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$') { throw 'DirectPackageVersion must be a semantic package version.' }
    if (@('x86_64-pc-windows-msvc', 'x86_64-win7-windows-msvc', 'i686-win7-windows-msvc') -notcontains $DirectPackageTarget) {
        throw 'DirectPackageTarget is not a supported Windows target triple.'
    }
    if ($DirectPackageTarget -ne $target) { throw "DirectPackageTarget $DirectPackageTarget does not match this host target $target." }
    $directUri = $null
    if (-not [Uri]::TryCreate($DirectPackageUrl, [UriKind]::Absolute, [ref]$directUri) -or
        ($directUri.Scheme -ne 'https') -or (-not [string]::IsNullOrEmpty($directUri.UserInfo)) -or
        (-not [string]::IsNullOrEmpty($directUri.Query)) -or (-not [string]::IsNullOrEmpty($directUri.Fragment))) {
        throw 'DirectPackageUrl must be an absolute credential-free HTTPS URL without query or fragment.'
    }
    if ([IO.Path]::GetFileName($directUri.AbsolutePath) -ne $archiveName) {
        throw "DirectPackageUrl must select the exact target asset $archiveName."
    }
    Download-PinnedDirectFile $DirectPackageUrl $archive $DirectPackageSha256

    $expanded = Join-Path $tempRoot 'expanded'
    Expand-DirectPackageZip $archive $expanded $DirectPackageTarget $DirectPackageSha256
    $candidateOnec = Get-ChildItem -Path $expanded -Filter 'onec.exe' -Recurse | Select-Object -First 1
    if ($null -eq $candidateOnec) { throw 'Release archive does not contain onec.exe.' }
    $candidateOnecPath = [IO.Path]::GetFullPath([string]$candidateOnec.FullName)
    $candidateDir = [IO.Path]::GetFullPath($candidateOnec.Directory.FullName)
    $candidateAgentPath = [IO.Path]::GetFullPath((Join-Path $candidateDir 'onec-agent.exe'))

    $requiredNames = @(
        'onec.exe',
        'onec-agent.exe',
        'Run-OnecAgent.ps1',
        'Update-OnecToolkit.ps1',
        'onec-toolkit-update.cmd'
    )
    foreach ($nameRequired in $requiredNames) {
        if (-not (Test-Path (Join-Path $candidateDir $nameRequired))) {
            throw "Release archive does not contain $nameRequired."
        }
    }

    $onecVersionOutput = & $candidateOnecPath --version
    $onecExitCode = $LASTEXITCODE
    $onecVersion = ($onecVersionOutput | Out-String).Trim()
    if ($onecExitCode -ne 0) { throw "Downloaded onec.exe did not start (exit code $onecExitCode)." }
    if ([string]::IsNullOrEmpty($onecVersion)) { throw 'Downloaded onec.exe returned an empty version.' }
    $version = $onecVersion -replace '^onec\s+', ''
    # onec.exe reports its exact source fingerprint as SemVer build metadata.
    # Keep the requested package version pin and accept only that canonical
    # 16-hex source suffix, never arbitrary extra version text.
    $versionMatches = $version -ceq $DirectPackageVersion
    if ((-not $versionMatches) -and ($DirectPackageVersion -notmatch '\+')) {
        $versionMatches = $version -cmatch ('^' + [Regex]::Escape($DirectPackageVersion) + '\+src[0-9a-f]{16}$')
    }
    if (-not $versionMatches) {
        throw "Direct package version $version did not match requested version $DirectPackageVersion."
    }
    & $candidateOnecPath project --help | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Downloaded onec.exe project command failed to start.' }
    & $candidateOnecPath meta --help | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Downloaded onec.exe meta command failed to start.' }

    New-Item -ItemType Directory -Force -Path $Root, $binDir, $agentDir, $scriptsDir | Out-Null
    $serializer = Get-Serializer
    $preparedConfig = $null
    $preparedSecret = $null
    $preparedKnownHosts = $null

    # Machine tool provisioning belongs to the installer, not to onec. Always install the
    # pinned PortableGit runtime so Git/OpenSSH are available both interactively and to agent
    # children, including user-mode sshd sessions.
    $managedTools = Install-PortableOpenSsh (Join-Path $agentDir 'ssh-tools') $architecture
    $managedPathPrepend = New-Object System.Collections.ArrayList
    foreach ($directory in @(
        $binDir,
        (Split-Path -Parent ([string]$managedTools['git'])),
        (Split-Path -Parent ([string]$managedTools['ssh']))
    )) {
        if (-not [string]::IsNullOrEmpty($directory)) {
            $duplicate = $false
            foreach ($existing in $managedPathPrepend) {
                if ([string]$existing -and ([string]$existing).TrimEnd('\').Equals(([string]$directory).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
                    $duplicate = $true
                    break
                }
            }
            if (-not $duplicate) { [void]$managedPathPrepend.Add([string]$directory) }
        }
    }

    if (($HubUrl -ne '') -and ($EnrollToken -ne '')) {
        $machineIdPath = Join-Path $agentDir 'machine.id'
        if (Test-Path $machineIdPath) {
            $machineId = [IO.File]::ReadAllText($machineIdPath).Trim()
        } else {
            $machineId = [Guid]::NewGuid().ToString()
            Write-Utf8NoBom $machineIdPath ($machineId + "`n")
        }

        $sshConfig = Ensure-AgentKey $agentDir $machineId $architecture -UsePortableGit:$ForcePortableGit
        Protect-SecretFile ([string]$sshConfig['identity'])

        $windowsPrincipal = Get-CurrentWindowsPrincipal
        $targetSshPort = 27322
        $userSshServer = $null
        $embeddedSshServerReady = $false
        $sshHostPublicKey = $null
        if ($EmbeddedSshCandidate) {
            $embeddedHostPublicKey = Ensure-UserSshHostKey ([string]$managedTools['ssh_keygen']) $sshHostKeyPath $machineId
            Protect-SecretFile $sshHostKeyPath
            $embeddedSshServerReady = Test-EmbeddedSshServerCandidate $candidateAgentPath $sshConfig $sshHostKeyPath ($sshHostKeyPath + '.pub') $targetSshPort $windowsPrincipal $agentDir $tempRoot
            if (-not $embeddedSshServerReady) {
                throw 'embedded russh candidate preflight failed; refusing to advertise target SSH'
            }
            $sshHostPublicKey = $embeddedHostPublicKey
        } elseif (Test-ManagedTargetSshNestedJobSupport) {
            try {
                $userSshServer = Install-UserSshServer $sshServerRoot $architecture
                if ($null -ne $userSshServer) {
                    $sshHostPublicKey = Ensure-UserSshHostKey ([string]$userSshServer['ssh_keygen']) $sshHostKeyPath $machineId
                    Protect-SecretFile $sshHostKeyPath
                    $targetSshReady = Test-UserSshServerPublicKey $userSshServer $sshConfig $sshHostKeyPath $sshHostPublicKey $windowsPrincipal $agentDir $tempRoot
                    if (-not $targetSshReady) {
                        throw 'portable OpenSSH public-key preflight failed'
                    }
                }
            } catch {
                Write-Warning ('Target-side portable OpenSSH is unavailable; using the direct onec-agent compatibility carrier instead. ' + $_.Exception.Message)
                $userSshServer = $null
                $sshHostPublicKey = $null
            }
        } else {
            Write-Warning 'Target-side portable OpenSSH is disabled on Windows versions before NT 6.2 because managed sshd and Win32-OpenSSH require nested Job Objects; using the direct onec-agent compatibility carrier instead.'
        }

        # JavaScriptSerializer on legacy Windows PowerShell can walk the
        # PowerShell adapter surface of a Hashtable and encounter
        # PSParameterizedProperty cycles. Keep JSON-bound maps as pure .NET
        # dictionaries instead of PowerShell hashtables.
        $payload = New-Object System.Collections.Specialized.OrderedDictionary
        $payload.Add('machine_id', $machineId)
        $payload.Add('name', $Name)
        $payload.Add('hostname', $computerName)
        $payload.Add('username', $windowsPrincipal)
        $payload.Add('os', 'windows')
        $payload.Add('arch', $architecture)
        $payload.Add('agent_version', $version)
        $payload.Add('transport', 'open_ssh')
        $payload.Add('persistence_mode', $Persistence)
        $payload.Add('ssh_public_key', [string]$sshConfig['public'])
        $payload.Add('ssh_host_public_key', $sshHostPublicKey)
        $enroll = Invoke-AgentHubJsonPost $candidateAgentPath (($HubUrl.TrimEnd('/')) + '/v1/enroll') $EnrollToken $payload

        $preparedSecret = Join-Path $tempRoot 'control.secret'
        Write-Utf8NoBom $preparedSecret ([string]$enroll['control_secret'] + "`n")
        Protect-SecretFile $preparedSecret
        $enrollmentGateways = New-Object System.Collections.ArrayList
        if ($enroll.ContainsKey('gateways') -and $null -ne $enroll['gateways'] -and @($enroll['gateways']).Count -gt 0) {
            foreach ($gateway in @($enroll['gateways'])) {
                [void]$enrollmentGateways.Add($gateway)
            }
        } else {
            $legacyGateway = New-Object System.Collections.Specialized.OrderedDictionary
            $legacyGateway.Add('host', [string]$enroll['gateway_host'])
            $legacyGateway.Add('user', [string]$enroll['agent_ssh_user'])
            $legacyGateway.Add('port', [int]$enroll['gateway_ssh_port'])
            $legacyGateway.Add('host_public_key', [string]$enroll['gateway_host_public_key'])
            [void]$enrollmentGateways.Add($legacyGateway)
        }
        if ($enrollmentGateways.Count -eq 0) { throw 'onec-hub returned no approved SSH gateways.' }
        $gatewayKnownHosts = New-Object System.Text.StringBuilder
        $agentGateways = New-Object System.Collections.ArrayList
        $seenGatewayAddresses = New-Object System.Collections.ArrayList
        foreach ($gateway in $enrollmentGateways) {
            $gatewayHost = [string]$gateway['host']
            $gatewayUser = [string]$gateway['user']
            $gatewayPort = [int]$gateway['port']
            $gatewayHostPublicKey = [string]$gateway['host_public_key']
            if ([string]::IsNullOrEmpty($gatewayHost) -or $gatewayHost.Trim().Length -eq 0 -or $gatewayHost -match '[\s,]' -or
                [string]::IsNullOrEmpty($gatewayUser) -or $gatewayUser.Trim().Length -eq 0 -or
                $gatewayPort -lt 1 -or $gatewayPort -gt 65535 -or
                $gatewayHostPublicKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/=]+(?: .*)?$') {
                throw 'onec-hub returned an invalid approved SSH gateway endpoint.'
            }
            $gatewayAddress = $gatewayHost.ToLowerInvariant() + ':' + $gatewayPort
            if ($seenGatewayAddresses -contains $gatewayAddress) { throw 'onec-hub returned duplicate approved SSH gateway endpoints.' }
            [void]$seenGatewayAddresses.Add($gatewayAddress)
            $hostField = if ($gatewayPort -eq 22) { $gatewayHost } else { '[' + $gatewayHost + ']:' + $gatewayPort }
            [void]$gatewayKnownHosts.Append($hostField).Append(' ').Append($gatewayHostPublicKey).Append("`n")
            $agentGateway = New-Object System.Collections.Specialized.OrderedDictionary
            $agentGateway.Add('host', $gatewayHost)
            $agentGateway.Add('user', $gatewayUser)
            $agentGateway.Add('port', $gatewayPort)
            [void]$agentGateways.Add($agentGateway)
        }
        $preparedKnownHosts = Join-Path $tempRoot 'known_hosts'
        Write-Utf8NoBom $preparedKnownHosts $gatewayKnownHosts.ToString()
        $sshConfig['known_hosts'] = $knownHostsPath

        $sshServerSettings = $null
        $embeddedSshServerSettings = $null
        if ($embeddedSshServerReady -or ($null -ne $userSshServer)) {
            $operatorPublicKeys = New-Object System.Collections.ArrayList
            if ($enroll.ContainsKey('operator_ssh_public_keys') -and $null -ne $enroll['operator_ssh_public_keys']) {
                foreach ($candidate in @($enroll['operator_ssh_public_keys'])) {
                    $operatorPublicKey = ([string]$candidate).Trim()
                    if ($operatorPublicKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/=]+(?: .*)?$') {
                        throw 'onec-hub returned an invalid operator_ssh_public_keys entry.'
                    }
                    if ($operatorPublicKeys -contains $operatorPublicKey) {
                        throw 'onec-hub returned duplicate operator_ssh_public_keys entries.'
                    }
                    [void]$operatorPublicKeys.Add($operatorPublicKey)
                }
            }
            if ($operatorPublicKeys.Count -eq 0) {
                $operatorPublicKey = ([string]$enroll['operator_ssh_public_key']).Trim()
                if ($operatorPublicKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/=]+(?: .*)?$') {
                    throw 'onec-hub returned an invalid operator_ssh_public_key.'
                }
                [void]$operatorPublicKeys.Add($operatorPublicKey)
            }
            $operatorAuthorizedKeys = (($operatorPublicKeys | ForEach-Object { [string]$_ }) -join "`n") + "`n"
            Write-Utf8NoBom $sshAuthorizedKeysPath $operatorAuthorizedKeys
            Protect-UserAuthorizedKeysFile $sshAuthorizedKeysPath
            if ($embeddedSshServerReady) {
                $embeddedSshServerSettings = New-Object System.Collections.Specialized.OrderedDictionary
                $embeddedSshServerSettings.Add('user', $windowsPrincipal)
                $embeddedSshServerSettings.Add('host_key', $sshHostKeyPath)
                $embeddedSshServerSettings.Add('authorized_keys', $sshAuthorizedKeysPath)
                $embeddedSshServerSettings.Add('port', $targetSshPort)
            } else {
                Write-UserSshdConfig $sshdConfigPath $sshHostKeyPath $sshAuthorizedKeysPath ([string]$userSshServer['sftp_server']) $windowsPrincipal $targetSshPort
                & ([string]$userSshServer['sshd']) -t -f $sshdConfigPath
                if ($LASTEXITCODE -ne 0) { throw 'Portable user-mode sshd rejected the generated sshd_config.' }

                $sshServerSettings = New-Object System.Collections.Specialized.OrderedDictionary
                $sshServerSettings.Add('program', [string]$userSshServer['sshd'])
                $sshServerSettings.Add('config', $sshdConfigPath)
                $sshServerSettings.Add('port', $targetSshPort)
            }
        }

        # Use pure .NET dictionaries here. Nested PowerShell hashtables can expose
        # PSParameterizedProperty through JavaScriptSerializer on Windows PowerShell 5.1.
        $sshSettings = New-Object System.Collections.Specialized.OrderedDictionary
        $sshSettings.Add('gateways', $agentGateways.ToArray())
        $sshSettings.Add('remote_port', [int]$enroll['remote_port'])
        $sshSettings.Add('identity', [string]$sshConfig['identity'])
        $sshSettings.Add('known_hosts', $knownHostsPath)
        $sshSettings.Add('reconnect_seconds', 5)

        $agentConfig = New-Object System.Collections.Specialized.OrderedDictionary
        $agentConfig.Add('version', 1)
        $agentConfig.Add('name', [string]$enroll['name'])
        $agentConfig.Add('listen', '127.0.0.1:27391')
        $agentConfig.Add('secret_env', '')
        $agentConfig.Add('secret_file', $secretPath)
        $agentConfig.Add('path_prepend', $managedPathPrepend.ToArray())
        $agentConfig.Add('ssh', $sshSettings)
        if ($null -ne $sshServerSettings) { $agentConfig.Add('ssh_server', $sshServerSettings) }
        if ($null -ne $embeddedSshServerSettings) { $agentConfig.Add('embedded_ssh_server', $embeddedSshServerSettings) }

        $preparedConfig = Join-Path $tempRoot 'agent.json'
        Write-Utf8NoBom $preparedConfig ($serializer.Serialize($agentConfig) + "`n")
        & $candidateAgentPath check --config $preparedConfig | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Candidate onec-agent rejected the prepared enrollment config.' }
        $enrolled = $true
    } elseif (Test-Path $configPath) {
        & $candidateAgentPath check --config $configPath | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'Candidate onec-agent rejected the existing agent.json; install aborted before stopping the current agent.'
        }
    }

    # No running agent is stopped until the archive, enrollment, and candidate config are ready.
    $hadSupervisor = Test-SupervisorRunning $agentDir
    $maintenanceOwned = Stop-ExistingUserAgent $agentDir
    $stoppedExistingSupervisor = $hadSupervisor
    if ($Persistence -eq 'windows-service') {
        $service = Get-Service -Name 'onec-agent' -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            $serviceWasRunning = $service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped
            if ($serviceWasRunning) {
                Stop-Service -Name 'onec-agent' -Force -ErrorAction Stop
                $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
            }
        }
    }
    $managedAgentPath = Join-Path $binDir 'onec-agent.exe'
    Stop-ManagedAgentProcesses $managedAgentPath
    Wait-ManagedAgentBinaryReleased $managedAgentPath

    $backupRoot = Join-Path $tempRoot 'backup'
    $managedFiles = @(
        @{ path = (Join-Path $binDir 'onec-agent.exe'); backup = (Join-Path $backupRoot 'bin\onec-agent.exe') },
        # Retire the installer-owned split controller binary inside this transaction.
        @{ path = (Join-Path $binDir 'onec-ops.exe'); backup = (Join-Path $backupRoot 'bin\onec-ops.exe') },
        @{ path = (Join-Path $binDir 'onec.exe'); backup = (Join-Path $backupRoot 'bin\onec.exe') },
        # Retire the split controller binaries from earlier installs transactionally.
        @{ path = (Join-Path $binDir 'onec-meta.exe'); backup = (Join-Path $backupRoot 'bin\onec-meta.exe') },
        @{ path = (Join-Path $binDir 'onec-project.exe'); backup = (Join-Path $backupRoot 'bin\onec-project.exe') },
        @{ path = (Join-Path $binDir 'Run-OnecAgent.ps1'); backup = (Join-Path $backupRoot 'bin\Run-OnecAgent.ps1') },
        @{ path = (Join-Path $binDir 'Update-OnecToolkit.ps1'); backup = (Join-Path $backupRoot 'bin\Update-OnecToolkit.ps1') },
        @{ path = (Join-Path $scriptsDir 'Run-OnecAgent.ps1'); backup = (Join-Path $backupRoot 'scripts\Run-OnecAgent.ps1') },
        @{ path = (Join-Path $scriptsDir 'Update-OnecToolkit.ps1'); backup = (Join-Path $backupRoot 'scripts\Update-OnecToolkit.ps1') },
        @{ path = $updateCommand; backup = (Join-Path $backupRoot 'bin\onec-toolkit-update.cmd') },
        @{ path = $metadataPath; backup = (Join-Path $backupRoot 'install.json') },
        @{ path = $configPath; backup = (Join-Path $backupRoot 'agent\agent.json') },
        @{ path = $secretPath; backup = (Join-Path $backupRoot 'agent\control.secret') },
        @{ path = $knownHostsPath; backup = (Join-Path $backupRoot 'agent\known_hosts') }
    )
    foreach ($file in $managedFiles) {
        $file['existed'] = Test-Path ([string]$file['path'])
        Backup-File ([string]$file['path']) ([string]$file['backup'])
    }

    try {
        $retiredController = Join-Path $binDir 'onec-ops.exe'
        if (Test-Path -LiteralPath $retiredController) {
            Remove-Item -LiteralPath $retiredController -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $retiredController) { throw 'Retired onec-ops.exe remains after removal.' }
        }
        Copy-Item -LiteralPath $candidateOnecPath -Destination (Join-Path $binDir 'onec.exe') -Force
        Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $binDir 'onec-meta.exe'), (Join-Path $binDir 'onec-project.exe')
        Copy-Item -LiteralPath $candidateAgentPath -Destination (Join-Path $binDir 'onec-agent.exe') -Force
        Copy-Item -LiteralPath (Join-Path $candidateDir 'Run-OnecAgent.ps1') -Destination (Join-Path $binDir 'Run-OnecAgent.ps1') -Force
        Copy-Item -LiteralPath (Join-Path $candidateDir 'Update-OnecToolkit.ps1') -Destination (Join-Path $binDir 'Update-OnecToolkit.ps1') -Force
        Copy-Item -LiteralPath (Join-Path $candidateDir 'onec-toolkit-update.cmd') -Destination $updateCommand -Force
        Copy-Item -LiteralPath (Join-Path $candidateDir 'Run-OnecAgent.ps1') -Destination (Join-Path $scriptsDir 'Run-OnecAgent.ps1') -Force
        Copy-Item -LiteralPath (Join-Path $candidateDir 'Update-OnecToolkit.ps1') -Destination (Join-Path $scriptsDir 'Update-OnecToolkit.ps1') -Force

        if ($null -ne $preparedSecret) {
            Copy-Item -Force $preparedSecret $secretPath
            Protect-SecretFile $secretPath
        }
        if ($null -ne $preparedKnownHosts) { Copy-Item -Force $preparedKnownHosts $knownHostsPath }
        if ($null -ne $preparedConfig) { Copy-Item -Force $preparedConfig $configPath }

        foreach ($directory in $managedPathPrepend) { Add-UserPath ([string]$directory) }

        # Verify the commands through the PATH that a newly opened user shell will inherit.
        $gitVersionOutput = & git --version
        $gitExitCode = $LASTEXITCODE
        if ($gitExitCode -ne 0) { throw "Published Git command was not available through PATH (exit code $gitExitCode)." }
        if ([string]::IsNullOrEmpty(($gitVersionOutput | Out-String).Trim())) { throw 'Published Git command returned an empty version.' }
        $pathOnecOutput = & onec --version
        $pathOnecExitCode = $LASTEXITCODE
        if ($pathOnecExitCode -ne 0) { throw "Published onec command was not available through PATH (exit code $pathOnecExitCode)." }
        if ([string]::IsNullOrEmpty(($pathOnecOutput | Out-String).Trim())) { throw 'Published onec command returned an empty version.' }

        $metadata = New-Object System.Collections.Specialized.OrderedDictionary
        $metadata.Add('version', 2)
        $metadata.Add('target', $target)
        $metadata.Add('installed_version', $version)
        $metadata.Add('installed_at', [DateTime]::UtcNow.ToString('o'))
        $metadata.Add('install_scope', 'user')
        $metadata.Add('persistence_mode', $Persistence)
        $metadata.Add('installed_package_sha256', $DirectPackageSha256.ToLowerInvariant())
        # The Agent's DirectUpToDate decision verifies actual installed bytes
        # against these observations under update.lock. Record the hashes
        # only after the five runtime files were copied into bin.
        $installedRuntimeFiles = New-Object System.Collections.Specialized.OrderedDictionary
        foreach ($runtimeName in $requiredNames) {
            $runtimePath = Join-Path $binDir $runtimeName
            if (-not [IO.File]::Exists($runtimePath)) {
                throw "Direct package installed runtime is missing $runtimeName."
            }
            $identity = New-Object System.Collections.Specialized.OrderedDictionary
            $identity.Add('size', [long](Get-Item -LiteralPath $runtimePath).Length)
            $identity.Add('sha256', (Get-Sha256 $runtimePath))
            $installedRuntimeFiles.Add($runtimeName, $identity)
        }
        $metadata.Add('installed_runtime_files', $installedRuntimeFiles)
        Write-Utf8NoBom $metadataPath ($serializer.Serialize($metadata) + "`n")

        $publishedOnec = Join-Path $binDir 'onec.exe'
        $publishedOnecOutput = & $publishedOnec --version
        $publishedOnecExitCode = $LASTEXITCODE
        if ($publishedOnecExitCode -ne 0) { throw 'Published onec.exe failed to start.' }
        & $publishedOnec project --help | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Published onec.exe project command failed to start.' }
        & $publishedOnec meta --help | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Published onec.exe meta command failed to start.' }
        if (Test-Path $configPath) {
            & (Join-Path $binDir 'onec-agent.exe') check --config $configPath | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Published onec-agent config validation failed.' }
        }

        $runner = Join-Path $scriptsDir 'Run-OnecAgent.ps1'
        if ($Persistence -eq 'windows-service') {
            Remove-AgentAutostart
            Remove-OwnedMaintenanceMarker $agentDir $maintenanceOwned
            $maintenanceOwned = $null
            $serviceEventLog = Join-Path $agentDir 'agent-events.log'
            $serviceStartedAfterUnixMs = Get-UnixTimeMilliseconds
            & (Join-Path $binDir 'onec-agent.exe') install-service --config $configPath --start
            if ($LASTEXITCODE -ne 0) { throw 'onec-agent Windows service installation/start failed.' }
            Wait-AgentServiceReady (Join-Path $binDir 'onec-agent.exe') $serviceEventLog $serviceStartedAfterUnixMs
        } elseif ($NoAgentAutostart) {
            Remove-AgentAutostart
        } elseif (Test-Path $configPath) {
            Set-AgentAutostart $runner $Root
            Remove-OwnedMaintenanceMarker $agentDir $maintenanceOwned
            $maintenanceOwned = $null
            $userEventLog = Join-Path $agentDir 'agent-events.log'
            $userStartedAfterUnixMs = Get-UnixTimeMilliseconds
            Start-AgentSupervisor $runner $Root
            Wait-AgentUserSessionReady $agentDir $userEventLog $userStartedAfterUnixMs
        }
        $published = $true
    } catch {
        $publishError = $_
        if ($Persistence -eq 'windows-service') {
            $rollbackService = Get-Service -Name 'onec-agent' -ErrorAction SilentlyContinue
            if (($null -ne $rollbackService) -and ($rollbackService.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped)) {
                try {
                    Stop-Service -Name 'onec-agent' -Force -ErrorAction Stop
                    $rollbackService.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
                } catch { }
            }
            if (-not $serviceExistedInitially) {
                $rollbackAgent = Join-Path $binDir 'onec-agent.exe'
                if (Test-Path $rollbackAgent) {
                    try { & $rollbackAgent uninstall-service | Out-Null } catch { }
                }
            }
        }
        foreach ($file in $managedFiles) {
            Restore-File ([string]$file['backup']) ([string]$file['path']) ([bool]$file['existed'])
        }
        [Environment]::SetEnvironmentVariable('Path', $originalUserPath, [EnvironmentVariableTarget]::User)
        $env:Path = $originalProcessPath
        Broadcast-EnvironmentChange
        Restore-AgentAutostart $originalAutostart
        throw "onec-toolkit install failed and all managed files, user PATH, and autostart state were rolled back. $($publishError.Exception.Message)"
    }

    Remove-OwnedMaintenanceMarker $agentDir $maintenanceOwned
    $maintenanceOwned = $null

    Write-Host ''
    if ($Persistence -eq 'windows-service') { Write-Host 'onec-toolkit installed with Windows service persistence.' } else { Write-Host 'onec-toolkit installed without administrator rights.' }
    Write-Host ('Version: ' + $version)
    Write-Host ('Target:  ' + $target)
    Write-Host ('Root:    ' + $Root)
    Write-Host ('PATH:    ' + $binDir)
    Write-Host 'Commands: onec, onec-agent, onec-toolkit-update'
    if ($enrolled) {
        Write-Host ('Agent:   ' + [string]$enroll['name'] + ' via OpenSSH')
        if ($Persistence -eq 'windows-service') { Write-Host 'Persistence: Windows SCM auto-start service (LocalSystem)' } elseif (-not $NoAgentAutostart) { Write-Host 'Autostart: HKCU Run after user logon (current user, no elevation)' }
    } elseif (Test-Path $configPath) {
        Write-Host 'Agent:   existing enrollment preserved.'
    } else {
        Write-Host 'Agent:   toolkit installed; enrollment was not requested.'
    }
} catch {
    Remove-OwnedMaintenanceMarker $agentDir $maintenanceOwned
    $maintenanceOwned = $null
    if (($Persistence -eq 'windows-service') -and $serviceExistedInitially -and (-not $published)) {
        try {
            $rollbackService = Get-Service -Name 'onec-agent' -ErrorAction Stop
            if ($serviceWasRunning) {
                if ($rollbackService.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
                    Start-Service -Name 'onec-agent' -ErrorAction Stop
                }
            } elseif ($rollbackService.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
                Stop-Service -Name 'onec-agent' -Force -ErrorAction Stop
                $rollbackService = Get-Service -Name 'onec-agent' -ErrorAction Stop
                $rollbackService.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
            }
        } catch { }
    }
    if ($stoppedExistingSupervisor -and (-not $published)) {
        $oldRunner = Join-Path $scriptsDir 'Run-OnecAgent.ps1'
        if ((Test-Path $oldRunner) -and (Test-Path $configPath)) {
            try { Start-AgentSupervisor $oldRunner $Root } catch { }
        }
    }
    if ($enrolled -and (-not $published)) {
        Write-Warning 'Enrollment succeeded but local publication failed. Re-run `onec-access invite` before retrying if this machine remains offline.'
    }
    throw
} finally {
    Remove-OwnedMaintenanceMarker $agentDir $maintenanceOwned
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $tempRoot
    if ($null -ne $installWriterLock) { $installWriterLock.Dispose() }
}
