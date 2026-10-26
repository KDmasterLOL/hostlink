param(
    [Parameter(Mandatory=$true)][string]$SourceSha,
    [Parameter(Mandatory=$true)][string]$Version,
    [Parameter(Mandatory=$true)][string]$BuildRoot,
    [Parameter(Mandatory=$true)][string]$X64PackageRoot,
    [Parameter(Mandatory=$true)][string]$X86PackageRoot,
    [Parameter(Mandatory=$true)][string]$DisposableRoot
)

# Windows PowerShell 2 / .NET 3.5 compatible. This harness never installs or starts a service.
$ErrorActionPreference = 'Stop'

function Stop-Harness([string]$Message) {
    throw ('verify-win7-bootstrap-native: ' + $Message)
}

function Get-JsonValue($Object, [string]$Name) {
    if ($null -eq $Object -or -not $Object.ContainsKey($Name)) { Stop-Harness ('missing JSON field: ' + $Name) }
    return $Object[$Name]
}

function Convert-JsonObject($Value) {
    if ($Value -is [System.Collections.IDictionary]) {
        $result = @{}
        foreach ($key in $Value.Keys) { $result[[string]$key] = Convert-JsonObject $Value[$key] }
        return ,$result
    }
    if ($Value -is [System.Collections.IList]) {
        $result = @()
        foreach ($item in $Value) { $result += ,(Convert-JsonObject $item) }
        return ,$result
    }
    return $Value
}

function Read-JsonFile([string]$Path) {
    try {
        $text = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
        $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $serializer.MaxJsonLength = 4194304
        return Convert-JsonObject ($serializer.DeserializeObject($text))
    } catch { Stop-Harness ('malformed JSON input: ' + [IO.Path]::GetFileName($Path)) }
}

function Get-Sha256([string]$Path) {
    $algorithm = New-Object Security.Cryptography.SHA256Managed
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Close(); $algorithm.Clear() }
}

function Assert-NoReparsePath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    $current = $root
    $relative = $full.Substring($root.Length)
    foreach ($part in $relative.Split([char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar), [StringSplitOptions]::RemoveEmptyEntries)) {
        $current = [IO.Path]::Combine($current, $part)
        if ([IO.Directory]::Exists($current) -or [IO.File]::Exists($current)) {
            $attributes = [IO.File]::GetAttributes($current)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Stop-Harness 'a path component is a reparse point' }
        }
    }
    return $full
}

function Assert-Owner([string]$Path, [Security.Principal.SecurityIdentifier]$Sid) {
    try {
        if ([IO.Directory]::Exists($Path)) { $acl = (New-Object IO.DirectoryInfo($Path)).GetAccessControl() }
        elseif ([IO.File]::Exists($Path)) { $acl = (New-Object IO.FileInfo($Path)).GetAccessControl() }
        else { Stop-Harness 'required input does not exist' }
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier])
        if (-not $owner.Equals($Sid)) { Stop-Harness 'input is owned by a different user' }
    } catch { Stop-Harness 'cannot verify input owner' }
}

function Assert-PrivateDirectory([string]$Path, [Security.Principal.SecurityIdentifier]$Sid) {
    if (-not [IO.Directory]::Exists($Path)) { Stop-Harness 'private directory is missing' }
    Assert-NoReparsePath $Path | Out-Null
    $directory = New-Object IO.DirectoryInfo($Path)
    $acl = $directory.GetAccessControl()
    if (-not $acl.GetOwner([Security.Principal.SecurityIdentifier]).Equals($Sid) -or -not $acl.AreAccessRulesProtected) {
        Stop-Harness 'private directory owner or protected ACL is unsafe'
    }
    foreach ($rule in $acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and -not $rule.IdentityReference.Equals($Sid)) {
            Stop-Harness 'private directory grants access to another identity'
        }
    }
}

function Set-PrivateDirectory([string]$Path, [Security.Principal.SecurityIdentifier]$Sid) {
    if ([IO.Directory]::Exists($Path) -or [IO.File]::Exists($Path)) { Stop-Harness 'refusing to overwrite an existing staging path' }
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($Sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    [void]$security.AddAccessRule($rule)
    [void][IO.Directory]::CreateDirectory($Path, $security)
    Assert-PrivateDirectory $Path $Sid
}

function Assert-RegularOwnedFile([string]$Path, [Security.Principal.SecurityIdentifier]$Sid) {
    $full = Assert-NoReparsePath $Path
    if (-not [IO.File]::Exists($full)) { Stop-Harness 'required artifact file is missing' }
    $info = New-Object IO.FileInfo($full)
    if (($info.Attributes -band [IO.FileAttributes]::Directory) -ne 0 -or $info.Length -le 0) { Stop-Harness 'artifact must be a nonempty regular file' }
    Assert-Owner $full $Sid
    return $full
}

function Assert-NoSensitiveJsonFields($Object) {
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in $Object.Keys) {
            if ([string]$key -match '(?i)token|secret|credential|public.?key|invite|auth') { Stop-Harness 'receipt contains a prohibited sensitive field' }
            Assert-NoSensitiveJsonFields $Object[$key]
        }
    } elseif ($Object -is [System.Collections.IList]) {
        foreach ($item in $Object) { Assert-NoSensitiveJsonFields $item }
    }
}

function Assert-ReceiptKeys($Object, [string[]]$Allowed) {
    Assert-NoSensitiveJsonFields $Object
    foreach ($key in $Object.Keys) {
        if ($Allowed -cnotcontains [string]$key) { Stop-Harness 'receipt contains an unexpected field' }
    }
}

function Assert-BuildArtifact([string]$BuildRoot, [string]$Target, [string]$PackageRoot, [Security.Principal.SecurityIdentifier]$Sid) {
    $build = Assert-NoReparsePath $BuildRoot
    Assert-Owner $build $Sid
    $receiptPath = Assert-RegularOwnedFile ([IO.Path]::Combine($build, 'receipt.json')) $Sid
    $receipt = Read-JsonFile $receiptPath
    Assert-ReceiptKeys $receipt @('schema_version','status','source','built_at_utc','build_environment','targets','native_acceptance')
    if ((Get-JsonValue $receipt 'status') -cne 'PE_BUILD_AND_INSPECTION_PASS') { Stop-Harness 'build receipt is not a passing inspected candidate' }
    if ((Get-JsonValue (Get-JsonValue $receipt 'source') 'git_sha') -cne $SourceSha) { Stop-Harness 'build receipt source SHA mismatch' }
    if ((Get-JsonValue $receipt 'native_acceptance').status -cne 'NOT_RUN') { Stop-Harness 'build receipt native acceptance state is malformed' }
    $targetRows = @((Get-JsonValue $receipt 'targets') | Where-Object { $_.target -ceq $Target })
    if ($targetRows.Count -ne 1) { Stop-Harness 'build receipt must contain exactly one selected target' }
    $binaryRows = @($targetRows[0].binaries | Where-Object { $_.file -ceq 'hostlink-agent.exe' })
    if ($binaryRows.Count -ne 1 -or $binaryRows[0].static_crt_import_check -cne 'passed') { Stop-Harness 'build receipt lacks the exact Agent PE inspection' }
    $expectedMachine = '0x8664'
    if ($Target -ceq 'i686-win7-windows-msvc') { $expectedMachine = '0x14c' }
    if ([string]$binaryRows[0].pe_machine -cne $expectedMachine -or [int]$binaryRows[0].subsystem.major -ne 6 -or [int]$binaryRows[0].subsystem.minor -ne 0) {
        Stop-Harness 'build receipt PE machine or subsystem does not match the Win7 target'
    }
    $package = Assert-NoReparsePath $PackageRoot
    Assert-Owner $package $Sid
    $artifactReceiptPath = Assert-RegularOwnedFile ([IO.Path]::Combine($package, 'artifact-receipt.json')) $Sid
    $artifact = Read-JsonFile $artifactReceiptPath
    Assert-ReceiptKeys $artifact @('format','source_sha','target','version','archive','archive_sha256','sidecar','sidecar_sha256','installer','installer_sha256','files','build_receipt')
    if ([int](Get-JsonValue $artifact 'format') -ne 1 -or (Get-JsonValue $artifact 'source_sha') -cne $SourceSha -or (Get-JsonValue $artifact 'target') -cne $Target -or (Get-JsonValue $artifact 'version') -cne $Version) {
        Stop-Harness 'package receipt source, target, or version does not match the request'
    }
    if ((Get-JsonValue (Get-JsonValue $artifact 'build_receipt') 'sha256') -cne (Get-Sha256 $receiptPath)) { Stop-Harness 'package receipt does not bind to this exact build receipt' }
    $archiveName = 'hostlink-agent-' + $Target + '.zip'
    if ((Get-JsonValue $artifact 'archive') -cne $archiveName) { Stop-Harness 'package archive name does not match the exact target' }
    $archivePath = Assert-RegularOwnedFile ([IO.Path]::Combine([IO.Path]::Combine($package, $Version), $archiveName)) $Sid
    $archiveHash = Get-Sha256 $archivePath
    if ($archiveHash -cnotmatch '^[0-9a-f]{64}$' -or $archiveHash -cne (Get-JsonValue $artifact 'archive_sha256')) { Stop-Harness 'archive digest does not match its package receipt' }
    $archiveSidecar = Assert-RegularOwnedFile ($archivePath + '.sha256') $Sid
    $sidecarLine = [IO.File]::ReadAllText($archiveSidecar, [Text.Encoding]::ASCII)
    if ($sidecarLine -cne ($archiveHash + '  ' + $archiveName + "`n") -and $sidecarLine -cne ($archiveHash + '  ' + $archiveName + "`r`n")) { Stop-Harness 'ZIP SHA-256 sidecar is malformed or mismatched' }
    $agentPath = Assert-RegularOwnedFile ([IO.Path]::Combine([IO.Path]::Combine([IO.Path]::Combine($package, $Version), $Target), 'hostlink-agent.exe')) $Sid
    $agentHash = Get-Sha256 $agentPath
    if ($agentHash -cne (Get-JsonValue $artifact 'sidecar_sha256') -or $agentHash -cne $binaryRows[0].sha256) { Stop-Harness 'target verifier sidecar does not match build/package receipts' }
    $agentSidecar = Assert-RegularOwnedFile ($agentPath + '.sha256') $Sid
    $agentSidecarLine = [IO.File]::ReadAllText($agentSidecar, [Text.Encoding]::ASCII)
    if ($agentSidecarLine -cne ($agentHash + '  hostlink-agent.exe' + "`n") -and $agentSidecarLine -cne ($agentHash + '  hostlink-agent.exe' + "`r`n")) { Stop-Harness 'Agent executable sidecar manifest is malformed or mismatched' }
    return @{ Target=$Target; BuildReceipt=$receiptPath; PackageReceipt=$artifactReceiptPath; Archive=$archivePath; ArchiveSha256=$archiveHash; Agent=$agentPath; AgentSha256=$agentHash; Files=(Get-JsonValue $artifact 'files') }
}

function Quote-ProcessArgument([string]$Value) {
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Copy-ByteRange([IO.FileStream]$InputStream, [IO.FileStream]$OutputStream, [long]$Offset, [long]$Length) {
    $InputStream.Seek($Offset, [IO.SeekOrigin]::Begin) | Out-Null
    $buffer = New-Object byte[] 1048576
    $remaining = $Length
    while ($remaining -gt 0) {
        $wanted = [int][Math]::Min([long]$buffer.Length, $remaining)
        $read = $InputStream.Read($buffer, 0, $wanted)
        if ($read -le 0) { Stop-Harness 'truncated ZIP while building duplicate-entry negative fixture' }
        $OutputStream.Write($buffer, 0, $read)
        $remaining -= $read
    }
}

function New-DuplicateZipFixture([string]$Source, [string]$Destination) {
    $input = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $output = $null
    try {
        if ($input.Length -lt 22) { Stop-Harness 'ZIP is too short for duplicate-entry negative fixture' }
        $tailLength = [int][Math]::Min([long]65557, $input.Length)
        $tail = New-Object byte[] $tailLength
        $input.Seek(-$tailLength, [IO.SeekOrigin]::End) | Out-Null
        if ($input.Read($tail, 0, $tailLength) -ne $tailLength) { Stop-Harness 'could not read ZIP directory trailer' }
        $eocdIndex = -1
        for ($index = $tail.Length - 22; $index -ge 0; $index--) {
            if ($tail[$index] -eq 80 -and $tail[$index + 1] -eq 75 -and $tail[$index + 2] -eq 5 -and $tail[$index + 3] -eq 6) {
                $commentLength = [BitConverter]::ToUInt16($tail, $index + 20)
                if ($index + 22 + $commentLength -eq $tail.Length) { $eocdIndex = $index; break }
            }
        }
        if ($eocdIndex -lt 0) { Stop-Harness 'ZIP end-of-directory record is missing or malformed' }
        $eocdOffset = $input.Length - $tailLength + $eocdIndex
        $entriesOnDisk = [BitConverter]::ToUInt16($tail, $eocdIndex + 8)
        $entriesTotal = [BitConverter]::ToUInt16($tail, $eocdIndex + 10)
        $centralSize = [BitConverter]::ToUInt32($tail, $eocdIndex + 12)
        $centralOffset = [BitConverter]::ToUInt32($tail, $eocdIndex + 16)
        if ($entriesTotal -eq 0 -or $entriesTotal -eq 65535 -or $centralSize -eq [uint32]::MaxValue -or $centralOffset -eq [uint32]::MaxValue -or $entriesOnDisk -ne $entriesTotal) {
            Stop-Harness 'ZIP uses unsupported split or ZIP64 directory metadata'
        }
        if ([long]$centralOffset + [long]$centralSize -gt $eocdOffset) { Stop-Harness 'ZIP central directory bounds are malformed' }
        $centralHeader = New-Object byte[] 46
        $input.Seek([long]$centralOffset, [IO.SeekOrigin]::Begin) | Out-Null
        if ($input.Read($centralHeader, 0, 46) -ne 46 -or $centralHeader[0] -ne 80 -or $centralHeader[1] -ne 75 -or $centralHeader[2] -ne 1 -or $centralHeader[3] -ne 2) {
            Stop-Harness 'ZIP central directory first entry is malformed'
        }
        $recordLength = 46 + [BitConverter]::ToUInt16($centralHeader, 28) + [BitConverter]::ToUInt16($centralHeader, 30) + [BitConverter]::ToUInt16($centralHeader, 32)
        if ($recordLength -gt $centralSize) { Stop-Harness 'ZIP central directory entry bounds are malformed' }
        $duplicateEntry = New-Object byte[] $recordLength
        $input.Seek([long]$centralOffset, [IO.SeekOrigin]::Begin) | Out-Null
        if ($input.Read($duplicateEntry, 0, $recordLength) -ne $recordLength) { Stop-Harness 'ZIP central directory entry is truncated' }
        $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        Copy-ByteRange $input $output 0 ([long]$centralOffset)
        Copy-ByteRange $input $output ([long]$centralOffset) ([long]$centralSize)
        $output.Write($duplicateEntry, 0, $duplicateEntry.Length)
        Copy-ByteRange $input $output ([long]$centralOffset + [long]$centralSize) ($input.Length - ([long]$centralOffset + [long]$centralSize))
        $output.Seek([long]$eocdOffset + $duplicateEntry.Length + 8, [IO.SeekOrigin]::Begin) | Out-Null
        $writer = New-Object IO.BinaryWriter($output)
        $writer.Write([UInt16]($entriesOnDisk + 1))
        $writer.Write([UInt16]($entriesTotal + 1))
        $writer.Write([UInt32]($centralSize + $duplicateEntry.Length))
        $writer.Flush()
        # BinaryWriter.Dispose is not exposed as a public callable member on
        # the .NET 3.5 runtime that ships with this PowerShell 2 host.
        $writer.Close()
    } finally {
        if ($null -ne $output) { $output.Close() }
        $input.Close()
    }
}

function Invoke-Agent([string]$Agent, [string[]]$Arguments, [string]$LogPrefix, [string]$WorkingDirectory) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Agent
    $info.Arguments = [string]::Join(' ', @($Arguments | ForEach-Object { Quote-ProcessArgument $_ }))
    $info.WorkingDirectory = $WorkingDirectory
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $false
    $info.RedirectStandardError = $false
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { Stop-Harness 'could not start the target Agent verifier' }
        if (-not $process.WaitForExit(600000)) {
            $process.Kill()
            Stop-Harness 'target Agent verifier exceeded the ten-minute execution limit'
        }
        return @{ ExitCode=$process.ExitCode }
    } finally {
        $process.Close()
    }
}

function Assert-OutputReceipt([string]$Output, $Artifact, [Security.Principal.SecurityIdentifier]$Sid) {
    Assert-PrivateDirectory $Output $Sid
    $receiptPath = Assert-RegularOwnedFile ([IO.Path]::Combine($Output, 'bootstrap-receipt.json')) $Sid
    $receipt = Read-JsonFile $receiptPath
    Assert-ReceiptKeys $receipt @('format','component','target','version','archive_sha256','sidecar_sha256','files')
    if ([int](Get-JsonValue $receipt 'format') -ne 1 -or (Get-JsonValue $receipt 'component') -cne 'agent' -or (Get-JsonValue $receipt 'target') -cne $Artifact.Target -or (Get-JsonValue $receipt 'version') -cne $Version -or (Get-JsonValue $receipt 'archive_sha256') -cne $Artifact.ArchiveSha256 -or (Get-JsonValue $receipt 'sidecar_sha256') -cne $Artifact.AgentSha256) {
        Stop-Harness 'native bootstrap receipt does not match the source-bound package'
    }
    $receiptFiles = Get-JsonValue $receipt 'files'
    if ($receiptFiles.Count -ne $Artifact.Files.Count) { Stop-Harness 'native receipt package inventory count mismatch' }
    foreach ($name in $Artifact.Files.Keys) {
        if (-not $receiptFiles.ContainsKey($name) -or $receiptFiles[$name].sha256 -cne $Artifact.Files[$name].sha256 -or [long]$receiptFiles[$name].size -ne [long]$Artifact.Files[$name].size) {
            Stop-Harness 'native receipt package member identity mismatch'
        }
        $outputFile = Assert-RegularOwnedFile ([IO.Path]::Combine($Output, $name)) $Sid
        $outputInfo = New-Object IO.FileInfo($outputFile)
        if ((Get-Sha256 $outputFile) -cne $receiptFiles[$name].sha256 -or [long]$outputInfo.Length -ne [long]$receiptFiles[$name].size) {
            Stop-Harness 'extracted package member does not match the verified receipt'
        }
    }
    $metadataPath = Assert-RegularOwnedFile ([IO.Path]::Combine($Output, 'install.json')) $Sid
    $metadata = Read-JsonFile $metadataPath
    Assert-ReceiptKeys $metadata @('format','target','installed_version','installed_package_sha256','installed_files')
    if ([int](Get-JsonValue $metadata 'format') -ne 1 -or (Get-JsonValue $metadata 'target') -cne $Artifact.Target -or (Get-JsonValue $metadata 'installed_version') -cne $Version -or (Get-JsonValue $metadata 'installed_package_sha256') -cne $Artifact.ArchiveSha256) { Stop-Harness 'installed metadata does not bind exact package version and digest' }
    $installed = Get-JsonValue $metadata 'installed_files'
    if ($installed.Count -ne $Artifact.Files.Count) { Stop-Harness 'installed metadata inventory count mismatch' }
    foreach ($name in $Artifact.Files.Keys) {
        if (-not $installed.ContainsKey($name) -or $installed[$name].sha256 -cne $Artifact.Files[$name].sha256 -or [long]$installed[$name].size -ne [long]$Artifact.Files[$name].size) { Stop-Harness 'installed metadata member inventory mismatch' }
    }
    # validate_and_stage_archive intentionally preserves the exact package.zip
    # and manifest.json alongside extracted files and the two receipts. Both
    # must be verified; simply increasing the allowed file count would hide
    # an unauthorized or modified output member.
    $archivePath = Assert-RegularOwnedFile ([IO.Path]::Combine($Output, 'package.zip')) $Sid
    if ((Get-Sha256 $archivePath) -cne $Artifact.ArchiveSha256) { Stop-Harness 'preserved package ZIP digest mismatch' }
    $manifestPath = Assert-RegularOwnedFile ([IO.Path]::Combine($Output, 'manifest.json')) $Sid
    $manifest = Read-JsonFile $manifestPath
    Assert-ReceiptKeys $manifest @('format','component','target','version','files')
    if ([int](Get-JsonValue $manifest 'format') -ne 1 -or (Get-JsonValue $manifest 'component') -cne 'agent' -or (Get-JsonValue $manifest 'target') -cne $Artifact.Target -or (Get-JsonValue $manifest 'version') -cne $Version) { Stop-Harness 'preserved manifest identity mismatch' }
    $manifestFiles = Get-JsonValue $manifest 'files'
    if ($manifestFiles.Count -ne $Artifact.Files.Count) { Stop-Harness 'preserved manifest member count mismatch' }
    foreach ($name in $Artifact.Files.Keys) {
        if (-not $manifestFiles.ContainsKey($name) -or $manifestFiles[$name].sha256 -cne $Artifact.Files[$name].sha256 -or [long]$manifestFiles[$name].size -ne [long]$Artifact.Files[$name].size) { Stop-Harness 'preserved manifest member digest or size mismatch' }
    }
    $expectedCount = $Artifact.Files.Count + 4
    $actualFiles = @(Get-ChildItem -LiteralPath $Output -Force | Where-Object { -not $_.PSIsContainer })
    if ($actualFiles.Count -ne $expectedCount) { Stop-Harness 'native output contains unexpected files' }
    # Windows PowerShell 2 does not provide modern scalar/null .Count semantics.
    # Force an array so an empty directory result is exactly zero.
    if (@(Get-ChildItem -LiteralPath $Output -Force | Where-Object { $_.PSIsContainer }).Count -ne 0) { Stop-Harness 'native output contains unexpected directories' }
}

function Invoke-TargetHarness($Artifact, [string]$OtherTarget, [string]$Stage, [Security.Principal.SecurityIdentifier]$Sid) {
    $positiveOutput = [IO.Path]::Combine($Stage, ($Artifact.Target + '-verified'))
    $positive = Invoke-Agent $Artifact.Agent @('bootstrap-verify','--archive',$Artifact.Archive,'--sha256',$Artifact.ArchiveSha256,'--target',$Artifact.Target,'--version',$Version,'--output',$positiveOutput) ($Artifact.Target + '-positive') $Stage
    if ($positive.ExitCode -ne 0) {
        Stop-Harness ('native positive bootstrap verification failed for ' + $Artifact.Target)
    }
    Assert-OutputReceipt $positiveOutput $Artifact $Sid

    $badSha = '0'
    if ($Artifact.ArchiveSha256.Substring(0,1) -ceq '0') { $badSha = '1' }
    $wrongDigestOutput = [IO.Path]::Combine($Stage, ($Artifact.Target + '-wrong-digest'))
    $wrongDigest = Invoke-Agent $Artifact.Agent @('bootstrap-verify','--archive',$Artifact.Archive,'--sha256',($badSha + $Artifact.ArchiveSha256.Substring(1)),'--target',$Artifact.Target,'--version',$Version,'--output',$wrongDigestOutput) ($Artifact.Target + '-wrong-digest') $Stage
    if ($wrongDigest.ExitCode -eq 0 -or [IO.Directory]::Exists($wrongDigestOutput) -or [IO.File]::Exists($wrongDigestOutput)) { Stop-Harness 'native verifier accepted an incorrect archive digest or published output' }

    $wrongTargetOutput = [IO.Path]::Combine($Stage, ($Artifact.Target + '-wrong-target'))
    $wrongTarget = Invoke-Agent $Artifact.Agent @('bootstrap-verify','--archive',$Artifact.Archive,'--sha256',$Artifact.ArchiveSha256,'--target',$OtherTarget,'--version',$Version,'--output',$wrongTargetOutput) ($Artifact.Target + '-wrong-target') $Stage
    if ($wrongTarget.ExitCode -eq 0 -or [IO.Directory]::Exists($wrongTargetOutput) -or [IO.File]::Exists($wrongTargetOutput)) { Stop-Harness 'native verifier accepted a different target or published output' }

    $duplicateArchive = [IO.Path]::Combine($Stage, ($Artifact.Target + '-duplicate-entry.zip'))
    New-DuplicateZipFixture $Artifact.Archive $duplicateArchive
    $duplicateHash = Get-Sha256 $duplicateArchive
    $duplicateOutput = [IO.Path]::Combine($Stage, ($Artifact.Target + '-duplicate-zip'))
    $duplicate = Invoke-Agent $Artifact.Agent @('bootstrap-verify','--archive',$duplicateArchive,'--sha256',$duplicateHash,'--target',$Artifact.Target,'--version',$Version,'--output',$duplicateOutput) ($Artifact.Target + '-duplicate-zip') $Stage
    if ($duplicate.ExitCode -eq 0 -or [IO.Directory]::Exists($duplicateOutput) -or [IO.File]::Exists($duplicateOutput)) { Stop-Harness 'native verifier accepted a ZIP with a duplicated central-directory entry' }

    $existingOutput = [IO.Path]::Combine($Stage, ($Artifact.Target + '-existing-output'))
    Set-PrivateDirectory $existingOutput $Sid
    $sentinel = [IO.Path]::Combine($existingOutput, 'preserve.txt')
    [IO.File]::WriteAllText($sentinel, 'keep', [Text.Encoding]::ASCII)
    $overwrite = Invoke-Agent $Artifact.Agent @('bootstrap-verify','--archive',$Artifact.Archive,'--sha256',$Artifact.ArchiveSha256,'--target',$Artifact.Target,'--version',$Version,'--output',$existingOutput) ($Artifact.Target + '-existing-output') $Stage
    if ($overwrite.ExitCode -eq 0 -or -not [IO.File]::Exists($sentinel) -or [IO.File]::ReadAllText($sentinel) -cne 'keep') { Stop-Harness 'native verifier accepted or modified an existing output path' }
}

if ($SourceSha -cnotmatch '^[0-9a-f]{40}$') { Stop-Harness 'SourceSha must be a full lowercase Git SHA' }
if ($Version -cnotmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)([-+][0-9A-Za-z.-]+)?$') { Stop-Harness 'Version must be exact semantic version' }
Add-Type -AssemblyName System.Web.Extensions
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($null -eq $identity -or $null -eq $identity.User -or @('S-1-5-18','S-1-5-19','S-1-5-20') -contains $identity.User.Value) { Stop-Harness 'a normal interactive user identity is required' }
$sid = $identity.User
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) { Stop-Harness 'run unelevated in an interactive user session' }
$is64BitOs = ([IntPtr]::Size -eq 8) -or ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64')
if (-not $is64BitOs) { Stop-Harness 'both x64 and x86 target binaries require a 64-bit Windows test OS' }

$disposable = Assert-NoReparsePath $DisposableRoot
if ((New-Object IO.DriveInfo([IO.Path]::GetPathRoot($disposable))).DriveType -ne [IO.DriveType]::Fixed) { Stop-Harness 'disposable root must be on a fixed local drive' }
Assert-PrivateDirectory $disposable $sid
if (@(Get-ChildItem -LiteralPath $disposable -Force).Count -ne 0) { Stop-Harness 'disposable root must be empty before the run' }
$x64 = Assert-BuildArtifact $BuildRoot 'x86_64-win7-windows-msvc' $X64PackageRoot $sid
$x86 = Assert-BuildArtifact $BuildRoot 'i686-win7-windows-msvc' $X86PackageRoot $sid
if ((Read-JsonFile $x64.BuildReceipt).source.git_sha -cne (Read-JsonFile $x86.BuildReceipt).source.git_sha -or (Read-JsonFile $x64.PackageReceipt).source_sha -cne (Read-JsonFile $x86.PackageReceipt).source_sha) { Stop-Harness 'x64 and x86 artifacts are not from the same source SHA' }

$stage = [IO.Path]::Combine($disposable, ('hostlink-bootstrap-' + [Guid]::NewGuid().ToString('N')))
Set-PrivateDirectory $stage $sid
Invoke-TargetHarness $x64 'i686-win7-windows-msvc' $stage $sid
Invoke-TargetHarness $x86 'x86_64-win7-windows-msvc' $stage $sid
$os = Get-WmiObject -Class Win32_OperatingSystem
$osVersion = [string]$os.Version
Write-Output ('PASS: x64 and x86 Win7-targeted bootstrap-verify ran on ' + [string]$os.Caption + ' ' + $osVersion + ' x64; source_sha=' + $SourceSha)
Write-Output ('ENVIRONMENT: Windows PowerShell ' + $PSVersionTable.PSVersion.ToString())
Write-Output 'SCOPE: x86 execution occurred under WoW64 on the reported 64-bit OS.'
Write-Output 'PASS: exact ZIP digest/target, ZIP manifest, output receipts, wrong-digest, wrong-target, and overwrite rejection'
Write-Output ('EVIDENCE: private output receipts and extracted files retained at ' + $stage)
if ([string]$os.Caption -notmatch 'Windows 7') { Write-Output 'LIMIT: this host is not desktop Windows 7; NT6.1 server or newer OS execution does not fulfill Win7 desktop acceptance.' }
