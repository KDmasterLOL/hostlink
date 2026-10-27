param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{40}$')][string]$SourceShaA,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{40}$')][string]$SourceShaB,
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter(Mandatory=$true)][string]$ExpectedDisposableSid,
    [Parameter(Mandatory=$true)][string]$ExpectedDisposableProfile,
    [Parameter(Mandatory=$true)][string]$ProtectedWorkSid,
    [Parameter(Mandatory=$true)][string]$ProtectedWorkProfile,
    [Parameter(Mandatory=$true)][string]$SentinelPath,
    [Parameter(Mandatory=$true)][string]$BuildRootA,
    [Parameter(Mandatory=$true)][string]$BuildRootB,
    [Parameter(Mandatory=$true)][string]$PackageARoot,
    [Parameter(Mandatory=$true)][string]$PackageBRoot
)

# Windows 11 live registered-Agent acceptance. This intentionally requires Windows
# PowerShell 5+ and an operator-created, owner-only disposable interactive profile.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Fail([string]$Message) { throw "Updater acceptance refused: $Message" }
function Full([string]$Path) { [IO.Path]::GetFullPath($Path).TrimEnd('\') }
function SamePath([string]$A, [string]$B) {
    [string]::Equals((Full $A), (Full $B), [StringComparison]::OrdinalIgnoreCase)
}
function PathsOverlap([string]$A, [string]$B) {
    $aFull = Full $A; $bFull = Full $B
    if (SamePath $aFull $bFull) { return $true }
    return ($aFull.StartsWith($bFull + '\', [StringComparison]::OrdinalIgnoreCase) -or $bFull.StartsWith($aFull + '\', [StringComparison]::OrdinalIgnoreCase))
}
function Sha256([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Write-PrivateBytes([string]$Path, [byte[]]$Bytes, [string]$Sid) {
    [IO.File]::WriteAllBytes($Path, $Bytes)
    Set-PrivateAcl $Path $Sid $false
}
function Set-PrivateAcl([string]$Path, [string]$Sid, [bool]$Directory) {
    $acl = if ($Directory) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true, $false)
    $principal = New-Object Security.Principal.SecurityIdentifier($Sid)
    $rights = [Security.AccessControl.FileSystemRights]::FullControl
    $inherit = if ($Directory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($principal, $rights, $inherit, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
    $acl.SetOwner($principal)
    $acl.SetAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
    Assert-PrivateAcl $Path $Sid $Directory
}
function Assert-PrivateAcl([string]$Path, [string]$Sid, [bool]$RequireProtected) {
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail "reparse point in owned path: $Path" }
    $acl = Get-Acl -LiteralPath $Path
    $ownerSid = $acl.Owner
    try { $ownerSid = ([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value } catch { }
    if ($ownerSid -ne $Sid) { Fail "path owner differs from disposable SID: $Path" }
    if ($RequireProtected -and -not $acl.AreAccessRulesProtected) { Fail "ACL inheritance is not protected: $Path" }
    $allowed = @($Sid, 'S-1-5-18', 'S-1-5-32-544')
    foreach ($ace in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $ace.IdentityReference.Value -notin $allowed) {
            Fail "foreign allow ACE on $Path ($($ace.IdentityReference.Value))"
        }
    }
}
function Assert-NoReparseChain([string]$Path) {
    $full = Full $Path
    $cursor = $full
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $i = Get-Item -LiteralPath $cursor -Force
            if (($i.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail "reparse point in path chain: $cursor" }
        }
        $parent = [IO.Directory]::GetParent($cursor)
        if ($null -eq $parent) { break }
        $cursor = $parent.FullName
    }
}
function Get-RunValues {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Run', $false)
    if ($null -eq $key) { return @{} }
    try {
        $result = @{}
        foreach ($name in $key.GetValueNames()) { $result[$name] = [string]$key.GetValue($name, $null, 'DoNotExpandEnvironmentNames') }
        return $result
    } finally { $key.Dispose() }
}
function Assert-RunUnchangedExcept([hashtable]$Before, [hashtable]$After, [string]$TestValue, [bool]$ExpectPresent) {
    foreach ($name in $Before.Keys) {
        if ($name -eq $TestValue) { continue }
        if (-not $After.ContainsKey($name) -or $Before[$name] -cne $After[$name]) { Fail "pre-existing HKCU Run value changed: $name" }
    }
    foreach ($name in $After.Keys) { if ($name -ne $TestValue -and -not $Before.ContainsKey($name)) { Fail "unexpected HKCU Run value appeared: $name" } }
    if ($ExpectPresent -ne $After.ContainsKey($TestValue)) { Fail "test registration presence is unexpected: $TestValue" }
}
function Get-OldOneCRegistrySnapshot {
    $result = @()
    foreach ($path in @('Software\OneC', 'Software\1C', 'Software\1C-Bitrix')) {
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($path, $false)
        if ($null -eq $key) { continue }
        try {
            $stack = New-Object 'System.Collections.Generic.Stack[Microsoft.Win32.RegistryKey]'
            $stack.Push($key)
            while ($stack.Count -gt 0) {
                $node = $stack.Pop()
                $result += $path + '|' + $node.Name
                foreach ($name in $node.GetValueNames()) { $result += $node.Name + '|' + $name + '|' + [string]$node.GetValue($name, $null, 'DoNotExpandEnvironmentNames') }
                foreach ($childName in $node.GetSubKeyNames()) { $child = $node.OpenSubKey($childName, $false); if ($null -eq $child) { Fail "cannot read old OneC key $($node.Name)\$childName" }; $stack.Push($child) }
            }
        } catch { throw } finally { $key.Dispose() }
    }
    @($result | Sort-Object)
}
function Get-OldOneCServiceSnapshot {
    $items = Get-WmiObject Win32_Service | Where-Object { $_.Name -match '(?i)(^|[^a-z])(?:1c|onec)(?:[^a-z]|$)' -or $_.DisplayName -match '(?i)(^|[^a-z])(?:1c|onec)(?:[^a-z]|$)' } | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Name,$_.State,$_.ProcessId,$_.StartName }
    @($items | Sort-Object)
}
function Get-ServiceSnapshot {
    @((Get-WmiObject Win32_Service | ForEach-Object { '{0}|{1}|{2}|{3}|{4}' -f $_.Name,$_.DisplayName,$_.State,$_.ProcessId,$_.StartName }) | Sort-Object)
}
function Invoke-Agent([string]$Exe, [string[]]$Arguments) {
    $output = @(& $Exe @Arguments 2>&1)
    $code = $LASTEXITCODE
    [pscustomobject]@{ ExitCode=$code; Text=($output | Out-String) }
}
function Require-CommandSuccess($Result, [string]$Label) {
    if ($Result.ExitCode -ne 0) { Fail "$Label failed ($($Result.ExitCode)): $($Result.Text)" }
}
function Require-CommandFailure($Result, [string]$Label) {
    if ($Result.ExitCode -eq 0) { Fail "$Label unexpectedly succeeded" }
}
function Require-CommandFailureContains($Result, [string]$Label, [string]$Diagnostic) {
    Require-CommandFailure $Result $Label
    if ($Result.Text -notmatch [regex]::Escape($Diagnostic)) { Fail "$Label failed for an unexpected reason; expected '$Diagnostic', got: $($Result.Text)" }
}
function Assert-FileSnapshot([hashtable]$Snapshot, [string]$Label) {
    $after = Snapshot-Install
    if ($after.Count -ne $Snapshot.Count) { Fail "$Label changed installed tree inventory" }
    foreach ($path in $Snapshot.Keys) { if (-not $after.ContainsKey($path) -or $after[$path] -cne $Snapshot[$path]) { Fail "$Label changed protected file identity: $path" } }
}
function Snapshot-Install {
    $files = @{}
    foreach ($item in Get-ChildItem -LiteralPath $script:Root -Force -Recurse) {
        Assert-NoReparseChain $item.FullName
        if ($item.PSIsContainer) { $files[$item.FullName] = '<directory>' }
        else { $files[$item.FullName] = Sha256 $item.FullName }
    }
    $files
}
function Invoke-Update([string]$Archive, [string]$Digest, [string]$Version) {
    Invoke-Agent $script:Updater @('update','--root',$script:Root,'--archive',$Archive,'--sha256',$Digest,'--target',$script:Target,'--version',$Version)
}
function Assert-Status([string]$Exe, [string]$ExpectedHash, [bool]$Active) {
    $status = Invoke-Agent $Exe @('service','status','--root',$script:Root)
    if ($Active) { Require-CommandSuccess $status 'service status' } elseif ($status.ExitCode -eq 0) { Fail 'inactive service unexpectedly reported healthy' }
    if ($status.Text -notmatch ('owner_sid=' + [regex]::Escape($script:Sid)) -or $status.Text -notmatch ('executable_sha256=' + $ExpectedHash)) { Fail "status identity readback mismatch: $($status.Text)" }
    if ($Active -and $status.Text -notmatch 'ssh_banner=true') { Fail "authenticated health banner is absent: $($status.Text)" }
    if ($Active -and $status.Text -notmatch 'pid=([1-9][0-9]*)') { Fail 'active status omitted an owned process ID' }
    $status
}
function Assert-AgentPidExited([int]$ProcessId) {
    $process = Get-WmiObject Win32_Process -Filter ("ProcessId = {0}" -f $ProcessId)
    if ($null -ne $process) {
        if (-not $process.ExecutablePath) { Fail "cannot prove prior Agent PID $ProcessId has exited" }
        if (SamePath $process.ExecutablePath $script:AgentExe) { Fail "prior registered Agent PID $ProcessId is still running from the owned image" }
    }
}
function Read-Json([string]$Path) { Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
function Validate-Package([string]$PackageRoot, [string]$ExpectedVersion, [string]$Label, [string]$ExpectedSourceSha, $BuildEvidence) {
    Assert-PrivateAcl $PackageRoot $script:Sid $false
    $receiptPath = Join-Path $PackageRoot 'artifact-receipt.json'
    if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) { Fail "$Label artifact receipt missing" }
    Assert-NoReparseChain $receiptPath; Assert-PrivateAcl $receiptPath $script:Sid $false
    $receipt = Read-Json $receiptPath
    if ($ExpectedVersion -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$') { Fail "$Label version is not exact semantic version" }
    if ($receipt.source_sha -cne $ExpectedSourceSha -or $receipt.target -cne $script:Target -or $receipt.version -cne $ExpectedVersion) { Fail "$Label artifact receipt source/target/version mismatch" }
    if ($receipt.archive_sha256 -notmatch '^[0-9a-f]{64}$' -or $receipt.sidecar_sha256 -notmatch '^[0-9a-f]{64}$') { Fail "$Label receipt has malformed hashes" }
    if ($null -eq $receipt.build_receipt -or $receipt.build_receipt.sha256 -cne $BuildEvidence.ReceiptHash) { Fail "$Label does not bind its exact source build receipt" }
    if ($receipt.files.'hostlink-agent.exe'.sha256 -cne $BuildEvidence.AgentHash -or $receipt.sidecar_sha256 -cne $BuildEvidence.AgentHash) { Fail "$Label Agent binary differs from its exact source build" }
    $sidecar = Join-Path $PackageRoot ([string]$receipt.sidecar)
    $archive = Join-Path (Join-Path $PackageRoot ([string]$receipt.version)) ([string]$receipt.archive)
    foreach ($file in @($sidecar,$archive)) {
        $fileFull = Full $file
        $packageFull = Full $PackageRoot
        if (-not ($fileFull.StartsWith($packageFull + '\', [StringComparison]::OrdinalIgnoreCase))) { Fail "$Label receipt file escapes its package root" }
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { Fail "$Label package input missing: $file" }
        Assert-NoReparseChain $file
        Assert-PrivateAcl $file $script:Sid $false
    }
    if ((Sha256 $sidecar) -cne $receipt.sidecar_sha256 -or (Sha256 $archive) -cne $receipt.archive_sha256) { Fail "$Label package bytes differ from artifact receipt" }
    $archiveSidecar = $archive + '.sha256'
    $binarySidecar = $sidecar + '.sha256'
    foreach ($sidecarPath in @($archiveSidecar,$binarySidecar)) {
        if (-not (Test-Path -LiteralPath $sidecarPath -PathType Leaf)) { Fail "$Label SHA-256 sidecar is missing: $sidecarPath" }
        Assert-NoReparseChain $sidecarPath; Assert-PrivateAcl $sidecarPath $script:Sid $false
    }
    if ([IO.File]::ReadAllText($archiveSidecar, [Text.Encoding]::ASCII).Trim() -cne ($receipt.archive_sha256 + '  ' + [IO.Path]::GetFileName($archive)) -or [IO.File]::ReadAllText($binarySidecar, [Text.Encoding]::ASCII).Trim() -cne ($receipt.sidecar_sha256 + '  ' + [IO.Path]::GetFileName($sidecar))) { Fail "$Label SHA-256 sidecar readback mismatch" }
    $zip = [IO.Compression.ZipFile]::OpenRead($archive)
    try {
        $entries = @($zip.Entries | ForEach-Object { $_.FullName } | Sort-Object)
        $prefix = 'hostlink-agent-' + $script:Target + '/'
        $expected = @($receipt.files.PSObject.Properties | ForEach-Object { $prefix + $_.Name }) + @($prefix + 'manifest.json')
        if (($entries -join "`n") -cne (@($expected | Sort-Object) -join "`n")) { Fail "$Label ZIP inventory differs from exact package manifest" }
        $manifestEntry = $zip.GetEntry($prefix + 'manifest.json')
        $reader = New-Object IO.StreamReader($manifestEntry.Open(), [Text.Encoding]::UTF8)
        try { $manifest = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
        if ($manifest.component -cne 'agent' -or $manifest.target -cne $script:Target -or $manifest.version -cne $ExpectedVersion) { Fail "$Label embedded manifest identity mismatch" }
        foreach ($property in $receipt.files.PSObject.Properties) {
            $expectedFile = $manifest.files.PSObject.Properties[$property.Name].Value
            if ($null -eq $expectedFile -or $expectedFile.sha256 -cne $property.Value.sha256 -or [long]$expectedFile.size -ne [long]$property.Value.size) { Fail "$Label embedded file identity mismatch: $($property.Name)" }
            $entry = $zip.GetEntry($prefix + $property.Name)
            if ($null -eq $entry -or [long]$entry.Length -ne [long]$property.Value.size) { Fail "$Label ZIP member size mismatch: $($property.Name)" }
            $stream = $entry.Open(); $hasher = [Security.Cryptography.SHA256]::Create()
            try { $memberHash = [BitConverter]::ToString($hasher.ComputeHash($stream)).Replace('-','').ToLowerInvariant() } finally { $stream.Dispose(); $hasher.Dispose() }
            if ($memberHash -cne $property.Value.sha256) { Fail "$Label ZIP member digest mismatch: $($property.Name)" }
        }
    } finally { $zip.Dispose() }
    [pscustomobject]@{ Receipt=$receipt; Archive=$archive; Sidecar=$sidecar }
}
function Extract-PackageToBin($Package) {
    $zip = [IO.Compression.ZipFile]::OpenRead($Package.Archive)
    try {
        $prefix = 'hostlink-agent-' + $script:Target + '/'
        foreach ($entry in $zip.Entries) {
            if ($entry.FullName -eq ($prefix + 'manifest.json')) { continue }
            $name = $entry.FullName.Substring($prefix.Length)
            if ($name -match '[/\\]' -or $name -notin @('hostlink-agent.exe','Install-HostLink-Agent.ps1','Run-HostLink-Agent.ps1','Update-HostLink-Agent.ps1')) { Fail "unexpected package member: $name" }
            $destination = Join-Path (Join-Path $script:Root 'bin') $name
            $source = $entry.Open(); $target = [IO.File]::Open($destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $source.CopyTo($target); $target.Flush($true) } finally { $target.Dispose(); $source.Dispose() }
            Set-PrivateAcl $destination $script:Sid $false
        }
    } finally { $zip.Dispose() }
    $metadata = [ordered]@{ format=1; target=$script:Target; installed_version=$Package.Receipt.version; installed_package_sha256=$Package.Receipt.archive_sha256; installed_files=$Package.Receipt.files }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($metadata | ConvertTo-Json -Depth 8))
    Write-PrivateBytes (Join-Path $script:Root 'install.json') $bytes $script:Sid
}
function New-Job([string]$State, [bool]$Corrupt) {
    $id = ([guid]::NewGuid()).ToString('D').ToLowerInvariant()
    $dir = Join-Path (Join-Path $script:Root 'jobs') $id
    [IO.Directory]::CreateDirectory($dir) | Out-Null; Set-PrivateAcl $dir $script:Sid $true
    if ($Corrupt) {
        $recordPath = Join-Path $dir 'record.json'
        Write-PrivateBytes $recordPath ([Text.Encoding]::UTF8.GetBytes('{broken')) $script:Sid
        $script:HarnessJobHashes[$dir] = Sha256 $recordPath
        return $dir
    }
    $spec = [ordered]@{ program='native-updater-fixture'; args=@(); cwd=$null; source_sha256=('b' * 64) }
    $specBytes = [Text.Encoding]::UTF8.GetBytes(($spec | ConvertTo-Json -Compress -Depth 5))
    $jobHasher = [Security.Cryptography.SHA256]::Create()
    try { $requestHash = [BitConverter]::ToString($jobHasher.ComputeHash($specBytes)).Replace('-','').ToLowerInvariant() } finally { $jobHasher.Dispose() }
    $record = [ordered]@{ version=1; id=$id; controller_key_sha256=('a' * 64); request_sha256=$requestHash; spec=$spec; state=[ordered]@{ state=$State } }
    $recordPath = Join-Path $dir 'record.json'
    Write-PrivateBytes $recordPath ([Text.Encoding]::UTF8.GetBytes(($record | ConvertTo-Json -Compress -Depth 7))) $script:Sid
    $script:HarnessJobHashes[$dir] = Sha256 $recordPath
    $dir
}
function Remove-HarnessJob([string]$Directory) {
    if ((Full ([IO.Path]::GetDirectoryName((Full $Directory)))) -ne (Full $script:Jobs) -or [IO.Path]::GetFileName($Directory) -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { Fail 'job cleanup path is not an exact harness-owned UUID entry' }
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) { return }
    Assert-NoReparseChain $Directory; Assert-PrivateAcl $Directory $script:Sid $true
    $children = @(Get-ChildItem -LiteralPath $Directory -Force)
    if ($children.Count -ne 1 -or $children[0].Name -cne 'record.json' -or $children[0].PSIsContainer) { Fail "ambiguous content in harness job fixture; preserving it: $Directory" }
    Assert-NoReparseChain $children[0].FullName; Assert-PrivateAcl $children[0].FullName $script:Sid $false
    if (-not $script:HarnessJobHashes.ContainsKey($Directory) -or (Sha256 $children[0].FullName) -cne $script:HarnessJobHashes[$Directory]) { Fail "harness job fixture changed; preserving it: $Directory" }
    Remove-Item -LiteralPath $children[0].FullName -Force
    [IO.Directory]::Delete($Directory, $false)
}
function Assert-CleanupInventory {
    $expected = @(
        '.', 'bin', 'tools', 'state', 'jobs', '.updates', '.native-evidence',
        '.native-test-owner.json', 'install.json', 'bin\hostlink-agent.exe',
        'tools\hostlink-agent-updater.exe', 'state\agent.json', 'state\machine.json',
        'state\manifest.json', 'state\authorized_keys', 'state\gateway_host_key',
        'state\gateway_identity', 'state\host_key', '.native-evidence\package-a.zip',
        '.native-evidence\package-b.zip', '.native-evidence\package-a-receipt.json',
        '.native-evidence\package-b-receipt.json'
    )
    foreach ($property in $script:AgentA.Receipt.files.PSObject.Properties) { $expected += 'bin\' + $property.Name }
    $actual = @('.')
    foreach ($item in Get-ChildItem -LiteralPath $script:Root -Force -Recurse) {
        Assert-NoReparseChain $item.FullName
        Assert-PrivateAcl $item.FullName $script:Sid $false
        $relative = $item.FullName.Substring((Full $script:Root).Length).TrimStart('\') -replace '/', '\'
        $actual += $relative
    }
    $expected = @($expected | Sort-Object -Unique)
    $actual = @($actual | Sort-Object -Unique)
    if (($actual -join "`n") -cne ($expected -join "`n")) {
        $extra = @($actual | Where-Object { $_ -notin $expected }) -join ', '
        $missing = @($expected | Where-Object { $_ -notin $actual }) -join ', '
        Fail "owned root inventory is ambiguous; preserving whole tree (extra: $extra; missing: $missing)"
    }
}
function Remove-VerifiedTree {
    Assert-CleanupInventory
    $items = @(Get-ChildItem -LiteralPath $script:Root -Force -Recurse | Sort-Object { $_.FullName.Length } -Descending)
    foreach ($item in $items) {
        if ($item.PSIsContainer) { [IO.Directory]::Delete($item.FullName, $false) }
        else { [IO.File]::Delete($item.FullName) }
    }
    [IO.Directory]::Delete($script:Root, $false)
    [IO.Directory]::Delete($hostLinkParent, $false)
}

if ($PSVersionTable.PSVersion.Major -lt 5) { Fail 'Windows PowerShell 5 or newer is required' }
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { Fail 'this harness only runs on Windows' }

Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class HostLinkLocalAppDataNative {
  [DllImport("shell32.dll", EntryPoint="SHGetFolderPathW", CharSet=CharSet.Unicode, ExactSpelling=true)]
  public static extern int SHGetFolderPathW(IntPtr hwnd, int csidl, IntPtr token, uint flags, StringBuilder path);
}
'@
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$script:Sid = $identity.User.Value
$script:SourceShaA = $SourceShaA
$script:SourceShaB = $SourceShaB
$script:Target = $Target
foreach ($value in @($ExpectedDisposableSid,$ExpectedDisposableProfile,$ProtectedWorkSid,$ProtectedWorkProfile,$SentinelPath,$BuildRootA,$BuildRootB,$PackageARoot,$PackageBRoot)) {
    if ([string]::IsNullOrWhiteSpace($value)) { Fail 'all explicit disposable identity, sentinel and artifact paths are required' }
}
if ($script:Sid -ne $ExpectedDisposableSid -or $script:Sid -eq $ProtectedWorkSid -or $script:Sid -eq 'S-1-5-18') { Fail 'current SID is not the explicitly verified separate disposable SID' }
if ($SourceShaA -ceq $SourceShaB) { Fail 'package A and B must bind two distinct source commits' }
if ($ExpectedDisposableSid -notmatch '^S-1-5-21-(\d+-){2,}\d+$') { Fail 'expected SID must identify a normal user account' }
if ($ProtectedWorkSid -notmatch '^S-1-5-21-(\d+-){2,}\d+$' -or $ProtectedWorkSid -eq $ExpectedDisposableSid) { Fail 'protected WORK SID must be a distinct explicitly verified normal-user SID' }
if ((New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail 'elevated or Administrators execution is forbidden' }
foreach ($group in $identity.Groups) { if ($group.Value -eq 'S-1-5-32-544') { Fail 'disposable account belongs to local Administrators' } }
if (SamePath $ExpectedDisposableProfile $ProtectedWorkProfile) { Fail 'disposable and protected WORK profiles are identical' }
$profile = Full ([Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile))
if (-not (SamePath $profile $ExpectedDisposableProfile) -or (SamePath $profile $ProtectedWorkProfile)) { Fail 'OS-resolved user profile is not the expected disposable profile' }
if (-not (Test-Path -LiteralPath (Join-Path $profile 'NTUSER.DAT') -PathType Leaf)) { Fail 'disposable user profile is not loaded' }
if ($env:USERPROFILE -and -not (SamePath $env:USERPROFILE $profile)) { Fail 'USERPROFILE differs from OS-resolved profile' }
$os = Get-WmiObject Win32_OperatingSystem
if ($os.Version -notlike '10.0.*' -or [int]$os.BuildNumber -lt 22000 -or [IntPtr]::Size -ne 8 -or $env:PROCESSOR_ARCHITECTURE -cne 'AMD64') { Fail 'harness requires native x64 Windows 11; Windows 7 and WOW64 are separate gates' }
if ($Target -cne 'x86_64-win7-windows-msvc') { Fail 'target must be the exact source-built x86_64-win7-windows-msvc Agent artifact' }
$localBuffer = New-Object Text.StringBuilder 260
$hr = [HostLinkLocalAppDataNative]::SHGetFolderPathW([IntPtr]::Zero, 0x001c, [IntPtr]::Zero, 0, $localBuffer)
if ($hr -ne 0 -or $localBuffer.Length -eq 0) { Fail 'SHGetFolderPathW could not resolve OS LocalAppData' }
$script:LocalAppData = Full $localBuffer.ToString()
if (-not $script:LocalAppData.StartsWith($profile + '\', [StringComparison]::OrdinalIgnoreCase)) { Fail 'OS LocalAppData is outside the expected disposable profile' }
if ($env:LOCALAPPDATA -and -not (SamePath $env:LOCALAPPDATA $script:LocalAppData)) { Fail 'LOCALAPPDATA differs from SHGetFolderPathW; environment override is not accepted' }
Assert-NoReparseChain $script:LocalAppData
Assert-PrivateAcl $script:LocalAppData $script:Sid $false

$sentinel = Full $SentinelPath
if (-not (SamePath ([IO.Path]::GetDirectoryName($sentinel)) $profile) -or [IO.Path]::GetFileName($sentinel) -cne '.hostlink-disposable-profile') { Fail 'sentinel must be .hostlink-disposable-profile directly inside the disposable profile' }
Assert-NoReparseChain $sentinel
if (-not (Test-Path -LiteralPath $sentinel -PathType Leaf)) { Fail 'operator disposable-profile sentinel is missing' }
Assert-PrivateAcl $sentinel $script:Sid $true
$expectedSentinel = 'HOSTLINK-NATIVE-UPDATER-DISPOSABLE|SID=' + $script:Sid + '|SOURCE_A=' + $SourceShaA + '|SOURCE_B=' + $SourceShaB
if ([IO.File]::ReadAllText($sentinel, [Text.Encoding]::ASCII).Trim() -cne $expectedSentinel) { Fail 'sentinel contents do not bind this profile SID and both exact source SHAs' }

$script:Root = Join-Path $script:LocalAppData 'HostLink\Agent'
$hostLinkParent = Join-Path $script:LocalAppData 'HostLink'
if (Test-Path -LiteralPath $script:Root) { Fail 'authorized HostLink Agent root already exists; prior install or marker is present' }
if (Test-Path -LiteralPath $hostLinkParent) { Fail 'HostLink parent already exists; harness will not adopt or inspect an existing install tree' }
Assert-NoReparseChain $hostLinkParent
$script:RunValue = $null
$script:RunBefore = Get-RunValues
if (@($script:RunBefore.Keys | Where-Object { $_ -like 'HostLinkAgent-*' }).Count -gt 0) { Fail 'pre-existing HostLink Agent HKCU Run value found; refusing to adopt any prior registration' }
$script:OneCRegistryBefore = Get-OldOneCRegistrySnapshot
$script:OneCServicesBefore = Get-OldOneCServiceSnapshot
$script:ServicesBefore = Get-ServiceSnapshot

$inputRoots = @($BuildRootA,$BuildRootB,$PackageARoot,$PackageBRoot)
for ($i=0; $i -lt $inputRoots.Count; $i++) {
    for ($j=$i+1; $j -lt $inputRoots.Count; $j++) {
        if (PathsOverlap $inputRoots[$i] $inputRoots[$j]) { Fail 'build and package evidence roots must be distinct and non-overlapping' }
    }
}
foreach ($p in $inputRoots) {
    Assert-NoReparseChain $p
    if (-not (Test-Path -LiteralPath $p -PathType Container)) { Fail "source-bound build/package directory is missing: $p" }
    if ((PathsOverlap $p $script:Root) -or (PathsOverlap $p $hostLinkParent)) { Fail 'build/package inputs may not overlap the authorized HostLink install path' }
}
function Validate-Build([string]$Root, [string]$ExpectedSourceSha, [string]$Label) {
    $receiptPath = Join-Path $Root 'receipt.json'
    if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) { Fail "$Label source-exact build receipt missing" }
    Assert-PrivateAcl $Root $script:Sid $false
    Assert-NoReparseChain $receiptPath; Assert-PrivateAcl $receiptPath $script:Sid $false
    $receipt = Read-Json $receiptPath
    if ($receipt.source.git_sha -cne $ExpectedSourceSha -or $receipt.status -cne 'PE_BUILD_AND_INSPECTION_PASS') { Fail "$Label build receipt source/status mismatch" }
    $targetEntry = @($receipt.targets | Where-Object { $_.target -ceq $script:Target })
    if ($targetEntry.Count -ne 1) { Fail "$Label build receipt must contain exactly one selected target" }
    $binaryEntries = @($targetEntry[0].binaries + $targetEntry[0].artifacts | Where-Object { ($_.file -or $_.name) -ceq 'hostlink-agent.exe' })
    if ($binaryEntries.Count -ne 1 -or $binaryEntries[0].sha256 -notmatch '^[0-9a-f]{64}$') { Fail "$Label build receipt lacks one exact Agent binary identity" }
    if ([string]$binaryEntries[0].pe_machine -cne '0x8664' -or [int]$binaryEntries[0].subsystem.major -ne 6 -or [int]$binaryEntries[0].subsystem.minor -ne 0 -or $binaryEntries[0].static_crt_import_check -cne 'passed') { Fail "$Label x64 Win7 build receipt lacks the exact PE/subsystem/static CRT inspection" }
    $binaryPath = Join-Path (Join-Path $Root $script:Target) 'hostlink-agent.exe'
    if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) { Fail "$Label source-exact build output executable is missing" }
    Assert-NoReparseChain $binaryPath; Assert-PrivateAcl $binaryPath $script:Sid $false
    if ((Sha256 $binaryPath) -cne $binaryEntries[0].sha256) { Fail "$Label build output executable differs from its exact build receipt SHA" }
    if ($receipt.native_acceptance.status -cne 'NOT_RUN') { Fail "$Label build receipt native status is not the expected unrun source-bound receipt" }
    [pscustomobject]@{ ReceiptHash=(Sha256 $receiptPath); AgentHash=$binaryEntries[0].sha256; BinaryPath=$binaryPath }
}
$script:BuildA = Validate-Build $BuildRootA $SourceShaA 'build A'
$script:BuildB = Validate-Build $BuildRootB $SourceShaB 'build B'
if ($script:BuildA.AgentHash -ceq $script:BuildB.AgentHash) { Fail 'source-verified package A and B executable SHA values are identical' }
$receiptA = Read-Json (Join-Path $PackageARoot 'artifact-receipt.json')
$receiptB = Read-Json (Join-Path $PackageBRoot 'artifact-receipt.json')
$script:AgentA = Validate-Package $PackageARoot ([string]$receiptA.version) 'package A' $SourceShaA $script:BuildA
$script:AgentB = Validate-Package $PackageBRoot ([string]$receiptB.version) 'package B' $SourceShaB $script:BuildB
if ($script:AgentA.Receipt.version -ceq $script:AgentB.Receipt.version -or $script:AgentA.Receipt.archive_sha256 -ceq $script:AgentB.Receipt.archive_sha256) { Fail 'package A and B must represent distinct versions and archive bytes' }
if ($script:AgentA.Receipt.sidecar_sha256 -ceq $script:AgentB.Receipt.sidecar_sha256) { Fail 'package A and B do not contain two distinct source-verified executable SHA values' }
foreach ($property in $script:AgentA.Receipt.files.PSObject.Properties) {
    if ($property.Name -ceq 'hostlink-agent.exe') { continue }
    $other = $script:AgentB.Receipt.files.PSObject.Properties[$property.Name]
    if ($null -eq $other -or $property.Value.sha256 -cne $other.Value.sha256 -or [long]$property.Value.size -ne [long]$other.Value.size) { Fail "package A/B support file differs and cannot be safely updated: $($property.Name)" }
}
if (@($script:AgentB.Receipt.files.PSObject.Properties | Where-Object { $_.Name -ne 'hostlink-agent.exe' }).Count -ne @($script:AgentA.Receipt.files.PSObject.Properties | Where-Object { $_.Name -ne 'hostlink-agent.exe' }).Count) { Fail 'package A/B support-file inventories differ' }
if ($script:AgentA.Receipt.version -notmatch '^\d+\.\d+\.\d+' -or $script:AgentB.Receipt.version -notmatch '^\d+\.\d+\.\d+') { Fail 'package versions are not semantic versions' }

# Preflight is complete. From this point the only permitted writable target is the
# previously absent OS-resolved LocalAppData\HostLink\Agent tree in this profile.
$script:CreatedRoot = $false
$script:RegistrationCreated = $false
$script:Updater = Join-Path $script:Root 'tools\hostlink-agent-updater.exe'
$script:AgentExe = Join-Path $script:Root 'bin\hostlink-agent.exe'
$script:State = Join-Path $script:Root 'state'
$script:Jobs = Join-Path $script:Root 'jobs'
$script:Evidence = Join-Path $script:Root '.native-evidence'
$script:AgentAInstalled = $false
$script:TestPort = $null
$script:HarnessJobDirs = @()
$script:HarnessJobHashes = @{}
$script:TemporaryKeyHashes = @{}
$script:AcceptanceError = $null
try {
    [IO.Directory]::CreateDirectory($hostLinkParent) | Out-Null; Set-PrivateAcl $hostLinkParent $script:Sid $true
    [IO.Directory]::CreateDirectory($script:Root) | Out-Null; Set-PrivateAcl $script:Root $script:Sid $true
    $script:CreatedRoot = $true
    Write-PrivateBytes (Join-Path $script:Root '.native-test-owner.json') ([Text.Encoding]::UTF8.GetBytes('{"format":2,"source_sha_a":"' + $SourceShaA + '","source_sha_b":"' + $SourceShaB + '","candidate_sha256":"' + $script:AgentB.Receipt.sidecar_sha256 + '","owner_sid":"' + $script:Sid + '"}')) $script:Sid
    foreach ($directory in @('bin','tools','state','jobs','.updates','.native-evidence')) { $path=Join-Path $script:Root $directory; [IO.Directory]::CreateDirectory($path) | Out-Null; Set-PrivateAcl $path $script:Sid $true }
    $script:Evidence = Join-Path $script:Root '.native-evidence'
    $script:ArchiveA = Join-Path $script:Evidence 'package-a.zip'
    $script:ArchiveB = Join-Path $script:Evidence 'package-b.zip'
    Copy-Item -LiteralPath $script:AgentA.Archive -Destination $script:ArchiveA
    Copy-Item -LiteralPath $script:AgentB.Archive -Destination $script:ArchiveB
    Set-PrivateAcl $script:ArchiveA $script:Sid $false
    Set-PrivateAcl $script:ArchiveB $script:Sid $false
    if ((Sha256 $script:ArchiveA) -cne $script:AgentA.Receipt.archive_sha256 -or (Sha256 $script:ArchiveB) -cne $script:AgentB.Receipt.archive_sha256) { Fail 'private in-root archive copies differ from source package receipts' }
    $script:TestPort = (New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0)); $script:TestPort.Start(); $port=$script:TestPort.LocalEndpoint.Port; $script:TestPort.Stop(); $script:TestPort=$null
    $script:AgentA.Receipt | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $script:Evidence 'package-a-receipt.json') -Encoding UTF8
    $script:AgentB.Receipt | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $script:Evidence 'package-b-receipt.json') -Encoding UTF8
    Extract-PackageToBin $script:AgentA
    Copy-Item -LiteralPath $script:AgentB.Sidecar -Destination $script:Updater
    Set-PrivateAcl $script:Updater $script:Sid $false
    if ((Sha256 $script:AgentExe) -cne $script:AgentA.Receipt.sidecar_sha256 -or (Sha256 $script:Updater) -cne $script:AgentB.Receipt.sidecar_sha256 -or (SamePath $script:Updater $script:AgentExe)) { Fail 'installed A or separate updater B does not match its source-verified package SHA' }
    $machineId = ([guid]::NewGuid()).ToString('D').ToLowerInvariant()
    $hostKey = Join-Path $script:State 'host_key'
    $controllerKey = Join-Path $script:Evidence 'controller'
    $gatewayKey = Join-Path $script:Evidence 'gateway'
    $sshKeygen = Get-Command ssh-keygen.exe -ErrorAction SilentlyContinue
    if ($null -eq $sshKeygen) { Fail 'OpenSSH ssh-keygen.exe is required to create disposable local enrollment fixture keys' }
    & $sshKeygen.Source -q -t ed25519 -N '' -C 'hostlink-native-fixture-host' -f $hostKey
    if ($LASTEXITCODE -ne 0) { Fail 'ssh-keygen could not create disposable Agent host key' }
    & $sshKeygen.Source -q -t ed25519 -N '' -C 'hostlink-native-fixture-controller' -f $controllerKey
    if ($LASTEXITCODE -ne 0) { Fail 'ssh-keygen could not create disposable controller key' }
    & $sshKeygen.Source -q -t ed25519 -N '' -C 'hostlink-native-fixture-gateway' -f $gatewayKey
    if ($LASTEXITCODE -ne 0) { Fail 'ssh-keygen could not create disposable gateway key' }
    foreach ($temporaryKey in @($controllerKey,$controllerKey+'.pub',$gatewayKey,$gatewayKey+'.pub')) {
        Assert-NoReparseChain $temporaryKey
        Assert-PrivateAcl $temporaryKey $script:Sid $false
        $script:TemporaryKeyHashes[$temporaryKey] = Sha256 $temporaryKey
    }
    $controllerPublic = [IO.File]::ReadAllText($controllerKey + '.pub').Trim()
    $hostPublic = [IO.File]::ReadAllText($hostKey + '.pub').Trim()
    $gatewayPublic = [IO.File]::ReadAllText($gatewayKey + '.pub').Trim()
    Copy-Item ($gatewayKey + '.pub') (Join-Path $script:State 'gateway_host_key')
    Copy-Item $gatewayKey (Join-Path $script:State 'gateway_identity')
    Write-PrivateBytes (Join-Path $script:State 'authorized_keys') ([Text.Encoding]::UTF8.GetBytes($controllerPublic + "`n")) $script:Sid
    $machine = [ordered]@{ format=1; machine_id=$machineId; name='native-updater-fixture'; ssh_public_key=$controllerPublic; ssh_host_public_key=$hostPublic }
    Write-PrivateBytes (Join-Path $script:State 'machine.json') ([Text.Encoding]::UTF8.GetBytes(($machine | ConvertTo-Json -Compress))) $script:Sid
    $config = [ordered]@{ listen=('127.0.0.1:' + $port); user='native-fixture'; host_key=$hostKey; authorized_keys=(Join-Path $script:State 'authorized_keys'); jobs_root=$script:Jobs; gateway=$null }
    Write-PrivateBytes (Join-Path $script:State 'agent.json') ([Text.Encoding]::UTF8.GetBytes(($config | ConvertTo-Json -Compress))) $script:Sid
    $enrollmentFiles = [ordered]@{}
    foreach ($name in @('agent.json','machine.json','authorized_keys','gateway_host_key','gateway_identity','host_key')) {
        $path=Join-Path $script:State $name; Set-PrivateAcl $path $script:Sid $false
        $enrollmentFiles[$name]=[ordered]@{ size=(Get-Item $path).Length; sha256=(Sha256 $path) }
    }
    $manifest = [ordered]@{ format=1; machine_id=$machineId; files=$enrollmentFiles }
    Write-PrivateBytes (Join-Path $script:State 'manifest.json') ([Text.Encoding]::UTF8.GetBytes(($manifest | ConvertTo-Json -Compress -Depth 6))) $script:Sid
    foreach ($path in @($controllerKey,$controllerKey+'.pub',$gatewayKey,$gatewayKey+'.pub',$hostKey+'.pub')) { if (Test-Path $path) { Remove-Item -LiteralPath $path -Force } }
    $script:AgentAInstalled = $true
    $beforeServiceInstall = Get-RunValues
    Require-CommandSuccess (Invoke-Agent $script:AgentExe @('service','install','--root',$script:Root,'--config',(Join-Path $script:State 'agent.json'))) 'service install'
    $script:RegistrationCreated = $true
    $afterInstall = Get-RunValues
    $serviceMarker = Read-Json (Join-Path $script:Root '.hostlink-user-service.json')
    $script:RunValue = [string]$serviceMarker.run_value
    if ($script:RunValue -notmatch '^HostLinkAgent-[0-9a-f]{24}$' -or $beforeServiceInstall.ContainsKey($script:RunValue)) { Fail 'service marker Run value is malformed or existed before test install' }
    Assert-RunUnchangedExcept $beforeServiceInstall $afterInstall $script:RunValue $true
    if (-not $afterInstall.ContainsKey($script:RunValue)) { Fail 'service install did not create exact derived HKCU Run registration' }
    $runCommand = $afterInstall[$script:RunValue]
    Require-CommandSuccess (Invoke-Agent $script:AgentExe @('service','start','--root',$script:Root)) 'service start A'
    $statusA = Assert-Status $script:AgentExe $script:AgentA.Receipt.sidecar_sha256 $true
    $oldPid = [int]([regex]::Match($statusA.Text, 'pid=([1-9][0-9]*)').Groups[1].Value)
    $terminalJobDir = New-Job 'failed' $false
    $script:HarnessJobDirs += $terminalJobDir
    $jobsBefore = @(Get-ChildItem -LiteralPath $script:Jobs -Force | ForEach-Object { $_.Name + ':' + $(if ($_.PSIsContainer) { (Sha256 (Join-Path $_.FullName 'record.json')) } else { Sha256 $_.FullName }) } | Sort-Object)
    $positive = Invoke-Update $script:ArchiveB $script:AgentB.Receipt.archive_sha256 $script:AgentB.Receipt.version
    Require-CommandSuccess $positive 'registered live Agent update A to B'
    if ((Sha256 $script:AgentExe) -cne $script:AgentB.Receipt.sidecar_sha256) { Fail 'published Agent executable SHA differs from package B' }
    $metadataB = Read-Json (Join-Path $script:Root 'install.json')
    if ($metadataB.installed_version -cne $script:AgentB.Receipt.version -or $metadataB.installed_package_sha256 -cne $script:AgentB.Receipt.archive_sha256) { Fail 'package B install metadata readback mismatch' }
    foreach ($property in $script:AgentB.Receipt.files.PSObject.Properties) {
        $path = Join-Path (Join-Path $script:Root 'bin') $property.Name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Sha256 $path) -cne $property.Value.sha256) { Fail "package B installed file readback mismatch: $($property.Name)" }
        if ($metadataB.installed_files.PSObject.Properties[$property.Name].Value.sha256 -cne $property.Value.sha256) { Fail "package B installed metadata inventory mismatch: $($property.Name)" }
    }
    $statusB = Assert-Status $script:AgentExe $script:AgentB.Receipt.sidecar_sha256 $true
    $newPid = [int]([regex]::Match($statusB.Text, 'pid=([1-9][0-9]*)').Groups[1].Value)
    if ($newPid -eq $oldPid) { Fail 'update status reused the old Agent PID instead of proving a replacement process' }
    Assert-AgentPidExited $oldPid
    $afterRun = Get-RunValues
    if (-not $afterRun.ContainsKey($script:RunValue) -or $afterRun[$script:RunValue] -cne $runCommand) { Fail 'authenticated B health did not restore exact original test Run value' }
    if ((Get-ChildItem -LiteralPath $script:Jobs -Force | ForEach-Object { $_.Name + ':' + $(if ($_.PSIsContainer) { (Sha256 (Join-Path $_.FullName 'record.json')) } else { Sha256 $_.FullName }) } | Sort-Object | Out-String) -cne ($jobsBefore | Out-String)) { Fail 'durable jobs store changed during the successful update' }

    $baseSnapshot = Snapshot-Install
    $badHash = if ($script:AgentB.Receipt.archive_sha256[0] -eq '0') { '1' + $script:AgentB.Receipt.archive_sha256.Substring(1) } else { '0' + $script:AgentB.Receipt.archive_sha256.Substring(1) }
    Require-CommandFailure (Invoke-Update $script:ArchiveB $badHash $script:AgentB.Receipt.version) 'bad archive digest negative case'
    Assert-FileSnapshot $baseSnapshot 'bad digest rejection'
    Assert-Status $script:AgentExe $script:AgentB.Receipt.sidecar_sha256 $true | Out-Null

    foreach ($state in @('prepared','running','interrupted')) {
        $jobDir = New-Job $state $false
        $script:HarnessJobDirs += $jobDir
        $snapshot = Snapshot-Install
        Require-CommandFailureContains (Invoke-Update $script:ArchiveA $script:AgentA.Receipt.archive_sha256 $script:AgentA.Receipt.version) "$state durable job deferral" 'jobs not terminal'
        Assert-FileSnapshot $snapshot "$state job deferral"
        if (-not (Test-Path (Join-Path $jobDir 'record.json'))) { Fail "$state job record disappeared" }
        Assert-Status $script:AgentExe $script:AgentB.Receipt.sidecar_sha256 $true | Out-Null
        Remove-HarnessJob $jobDir
    }
    $unknownDir = New-Job 'prepared' $true
    $script:HarnessJobDirs += $unknownDir
    $unknownSnapshot = Snapshot-Install
    Require-CommandFailureContains (Invoke-Update $script:ArchiveA $script:AgentA.Receipt.archive_sha256 $script:AgentA.Receipt.version) 'corrupt durable job record rejection' 'job record is invalid or incomplete'
    Assert-FileSnapshot $unknownSnapshot 'unknown job rejection'
    Assert-Status $script:AgentExe $script:AgentB.Receipt.sidecar_sha256 $true | Out-Null
    Remove-HarnessJob $unknownDir
    $script:HarnessJobDirs = @($script:HarnessJobDirs | Where-Object { $_ -ne $unknownDir })

    # A deterministic candidate-health fault injection is not implemented here.
    # Do not stop the old Agent or claim that its subsequent start proves rollback.
    Remove-HarnessJob $terminalJobDir
    $script:HarnessJobDirs = @($script:HarnessJobDirs | Where-Object { $_ -ne $terminalJobDir })
    Write-Output ("PASS: live registered updater Win11; source_sha_a={0}; source_sha_b={1}; SID={2}; target={3}; A={4}/{5}/{6}; B={7}/{8}/{9}; health_failure_rollback=NOT_TESTED" -f $SourceShaA,$SourceShaB,$script:Sid,$Target,$script:AgentA.Receipt.version,$script:AgentA.Receipt.archive_sha256,$script:AgentA.Receipt.sidecar_sha256,$script:AgentB.Receipt.version,$script:AgentB.Receipt.archive_sha256,$script:AgentB.Receipt.sidecar_sha256)
}
catch {
    $script:AcceptanceError = $_
}
finally {
    if ($script:CreatedRoot -and (Test-Path -LiteralPath $script:Root)) {
        try {
            $ownerFile = Join-Path $script:Root '.native-test-owner.json'
            if (Test-Path -LiteralPath $ownerFile -PathType Leaf) {
                Assert-PrivateAcl $ownerFile $script:Sid $true
                $owner = Read-Json $ownerFile
            } else { Fail 'cleanup owner marker is missing; preserving root' }
            if ($owner.format -eq 2 -and $owner.source_sha_a -ceq $SourceShaA -and $owner.source_sha_b -ceq $SourceShaB -and $owner.candidate_sha256 -ceq $script:AgentB.Receipt.sidecar_sha256 -and $owner.owner_sid -ceq $script:Sid) {
                foreach ($temporaryKey in $script:TemporaryKeyHashes.Keys) {
                    if (Test-Path -LiteralPath $temporaryKey -PathType Leaf) {
                        Assert-NoReparseChain $temporaryKey; Assert-PrivateAcl $temporaryKey $script:Sid $false
                        if ((Sha256 $temporaryKey) -cne $script:TemporaryKeyHashes[$temporaryKey]) { Fail "fixture key changed; preserving owned tree: $temporaryKey" }
                        Remove-Item -LiteralPath $temporaryKey -Force
                    }
                }
                foreach ($jobDir in $script:HarnessJobDirs) {
                    if (Test-Path -LiteralPath $jobDir) { Remove-HarnessJob $jobDir }
                }
                $marker = Join-Path $script:Root '.hostlink-user-service.json'
                if (Test-Path -LiteralPath $marker -PathType Leaf) {
                    $state = Invoke-Agent $script:AgentExe @('service','remove','--root',$script:Root)
                    if ($state.ExitCode -ne 0) { Fail "source-bound cleanup could not remove test registration: $($state.Text)" }
                    $script:RegistrationCreated = $false
                }
                $remainingRun = Get-RunValues
                if ($remainingRun.ContainsKey($script:RunValue)) { Fail 'test-created HKCU Run value remains after cleanup' }
                Remove-VerifiedTree
            } else { Fail 'cleanup owner marker does not bind the created root to this exact source/SID; preserving it' }
        } catch {
            if ($null -eq $script:AcceptanceError) { $script:AcceptanceError = $_ }
        }
    }
    $runAfterFinally = Get-RunValues
    if ($null -ne $script:RunBefore) {
        foreach ($name in $script:RunBefore.Keys) { if (-not $runAfterFinally.ContainsKey($name) -or $runAfterFinally[$name] -cne $script:RunBefore[$name]) { $script:AcceptanceError = "pre-existing HKCU Run value changed: $name" } }
        foreach ($name in $runAfterFinally.Keys) { if ($name -ne $script:RunValue -and -not $script:RunBefore.ContainsKey($name)) { $script:AcceptanceError = "unexpected HKCU Run value appeared: $name" } }
        if ($null -ne $script:RunValue -and $runAfterFinally.ContainsKey($script:RunValue)) { $script:AcceptanceError = 'test-created Run value remains after cleanup' }
    }
    if ($null -ne $script:OneCRegistryBefore -and (($script:OneCRegistryBefore -join "`n") -cne ((Get-OldOneCRegistrySnapshot) -join "`n"))) { $script:AcceptanceError = 'existing HKCU OneC registry state changed' }
    if ($null -ne $script:OneCServicesBefore -and (($script:OneCServicesBefore -join "`n") -cne ((Get-OldOneCServiceSnapshot) -join "`n"))) { $script:AcceptanceError = 'existing OneC Windows service inventory changed' }
    if ($null -ne $script:ServicesBefore -and (($script:ServicesBefore -join "`n") -cne ((Get-ServiceSnapshot) -join "`n"))) { $script:AcceptanceError = 'Windows service inventory changed; harness must not touch SCM services' }
}
if ($null -ne $script:AcceptanceError) { throw $script:AcceptanceError }
