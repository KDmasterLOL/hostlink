[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SourceSha,
    [Parameter(Mandatory = $true)][string]$AgentArchive,
    [Parameter(Mandatory = $true)][string]$ArchiveSha256,
    [Parameter(Mandatory = $true)][string]$Installer,
    [string]$ReceiptFile
)

$ErrorActionPreference = 'Stop'
$script:Results = New-Object System.Collections.Generic.List[object]
$script:Workspace = $null
$script:WorkspaceSentinel = $null
$script:Root = $null
$script:RootCreatedByThisRun = $false
$script:RootAbsentAtStart = $false
$script:RootSentinel = $null
$script:RootInventory = $null
$script:Success = $false
$script:ReceiptWritten = $false
$script:Stage = 'preflight'
$script:CleanupState = 'not-started'
$target = 'x86_64-pc-windows-msvc'

function Add-Result([string]$Name, [string]$Status, [string]$Detail) {
    $script:Results.Add([pscustomobject]@{ name = $Name; status = $Status; detail = $Detail })
}

function Assert-Condition([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Test-PathEntry([string]$Path) {
    if (Test-Path -LiteralPath $Path) { return $true }
    try { [void][IO.File]::GetAttributes($Path); return $true } catch { return $false }
}

function Assert-NotReparse([string]$Path, [string]$Label) {
    if (-not (Test-PathEntry $Path)) { return }
    $attributes = [IO.File]::GetAttributes($Path)
    if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw ($Label + ' is a reparse point.')
    }
}

function Assert-PathChainNotReparse([string]$Path, [string]$Label) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($true) {
        Assert-NotReparse $current $Label
        $parent = [IO.Directory]::GetParent($current)
        if ($null -eq $parent) { break }
        $current = $parent.FullName
    }
}

function Set-PrivateDirectory([string]$Path) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity.User, [Security.AccessControl.FileSystemRights]::FullControl, $inherit, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
    [void]$security.AddAccessRule($rule)
    [void][IO.Directory]::CreateDirectory($Path, $security)
}

function Set-PrivateFile([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    Assert-Condition ([IO.File]::Exists($full)) 'Private file must exist before ACL restriction.'
    Assert-NotReparse $full 'Private file ACL target'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $owner = (New-Object IO.FileInfo($full)).GetAccessControl().GetOwner([Security.Principal.SecurityIdentifier])
    Assert-Condition ($owner.Equals($identity.User)) 'Private file must be owned by this test user.'
    $icacls = Join-Path $env:WINDIR 'System32\icacls.exe'
    Assert-Condition ([IO.File]::Exists($icacls)) 'Windows icacls.exe is required.'
    # The non-admin test user can change the DACL of its own file. Suppress paths
    # in icacls output; check its exit status and the resulting protected DACL.
    $null = @(& $icacls $full '/inheritance:r' '/grant:r' ('*' + $identity.User.Value + ':F') '*S-1-5-18:F' 2>&1)
    Assert-Condition ($LASTEXITCODE -eq 0) 'Could not restrict the private test file DACL.'
    $acl = (New-Object IO.FileInfo($full)).GetAccessControl()
    Assert-Condition ($acl.AreAccessRulesProtected) 'Private file DACL remains inherited.'
    foreach ($access in $acl.Access) {
        $sid = $access.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        Assert-Condition (($sid -eq $identity.User.Value -or $sid -eq 'S-1-5-18') -and -not $access.IsInherited -and $access.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) 'Private file has an unapproved ACL entry.'
    }
}

function Get-Sha256([string]$Path) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose(); $stream.Dispose() }
}

function Invoke-PowerShellFile([string]$Path, [string[]]$Arguments) {
    # Capture child output in memory only. It may contain absolute user paths or local details.
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $captured = @(& (Join-Path $PSHOME 'powershell.exe') -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Path @Arguments 2>&1)
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    return [pscustomobject]@{ exit_code = $code; output_count = $captured.Count }
}

function Assert-ExpectedFailure([string]$Name, [string]$Path, [string[]]$Arguments) {
    $result = Invoke-PowerShellFile $Path $Arguments
    Assert-Condition ($result.exit_code -ne 0) ($Name + ' unexpectedly succeeded.')
    Assert-Condition (-not (Test-PathEntry $script:Root)) ($Name + ' created the HostLink install root.')
    Add-Result $Name 'PASS' 'rejected-before-install;root-absent'
}

function Get-RootInventory([string]$Path) {
    Assert-NotReparse $Path 'Install root during inventory'
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($item in @(Get-ChildItem -LiteralPath $Path -Force -Recurse)) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'The install root contains a reparse point.'
        }
        if ($item.FullName -eq $script:RootSentinel) { continue }
        $relative = $item.FullName.Substring($Path.Length).TrimStart('\')
        if ($item.PSIsContainer) {
            $items.Add([pscustomobject]@{ path = $relative; kind = 'directory'; length = 0; sha256 = '' })
        } else {
            $items.Add([pscustomobject]@{ path = $relative; kind = 'file'; length = $item.Length; sha256 = (Get-Sha256 $item.FullName) })
        }
    }
    return ,@($items | Sort-Object path)
}

function Test-ReceiptPath([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path)) { throw 'ReceiptFile must be an absolute path.' }
    $full = [IO.Path]::GetFullPath($Path)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $full.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'ReceiptFile must be inside the current user temporary directory.'
    }
    Assert-PathChainNotReparse $full 'ReceiptFile path'
    if (Test-PathEntry $full) { throw 'ReceiptFile already exists.' }
    return $full
}

function Write-Receipt([string]$Status, [string]$Failure) {
    if ([string]::IsNullOrEmpty($script:ReceiptPath)) { return }
    $receipt = [ordered]@{
        schema = 1
        status = $Status
        source_sha = $SourceSha.ToLowerInvariant()
        target = $target
        archive_sha256 = $ArchiveSha256.ToLowerInvariant()
        windows_build = [Environment]::OSVersion.Version.Build
        windows_edition = $script:WindowsEdition
        powershell = $PSVersionTable.PSVersion.ToString()
        clr = [Environment]::Version.ToString()
        checks = @($script:Results.ToArray())
        cleanup = $script:CleanupState
        failure = $Failure
    }
    $json = ConvertTo-Json -InputObject $receipt -Depth 8
    $stream = $null
    $complete = $false
    $created = $false
    try {
        $stream = [IO.File]::Open($script:ReceiptPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $created = $true
        $stream.Dispose()
        $stream = $null

        # Restrict the closed, empty file before reopening it for receipt content.
        Set-PrivateFile $script:ReceiptPath
        Assert-NotReparse $script:ReceiptPath 'ReceiptFile before write'
        $attributes = [IO.File]::GetAttributes($script:ReceiptPath)
        Assert-Condition (($attributes -band [IO.FileAttributes]::Directory) -eq 0) 'ReceiptFile must be a regular file.'
        $receiptInfo = New-Object IO.FileInfo($script:ReceiptPath)
        $receiptAcl = $receiptInfo.GetAccessControl()
        $receiptOwner = $receiptAcl.GetOwner([Security.Principal.SecurityIdentifier])
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().User
        Assert-Condition ($receiptOwner.Equals($currentUser)) 'ReceiptFile owner changed before write.'
        Assert-Condition ($receiptAcl.AreAccessRulesProtected) 'ReceiptFile DACL is not private.'
        Assert-Condition ($receiptInfo.Length -eq 0) 'ReceiptFile is not empty before write.'

        $stream = [IO.File]::Open($script:ReceiptPath, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
        Assert-Condition ($stream.Length -eq 0) 'ReceiptFile changed before write.'
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($json + "`n")
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        $stream.Dispose()
        $stream = $null
        $complete = $true
    } finally {
        if ($null -ne $stream) { try { $stream.Dispose() } catch { } }
        if ($created -and -not $complete -and (Test-PathEntry $script:ReceiptPath)) {
            try {
                Assert-NotReparse $script:ReceiptPath 'ReceiptFile during failed-write cleanup'
                $cleanupInfo = New-Object IO.FileInfo($script:ReceiptPath)
                $cleanupOwner = $cleanupInfo.GetAccessControl().GetOwner([Security.Principal.SecurityIdentifier])
                $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().User
                Assert-Condition ($cleanupOwner.Equals($currentUser)) 'ReceiptFile owner changed during failed-write cleanup.'
                if ($cleanupInfo.Length -eq 0) { [IO.File]::Delete($script:ReceiptPath) }
            } catch { }
        }
    }
    $script:ReceiptWritten = $true
}

$failure = ''
$script:ReceiptPath = ''
try {
    Assert-Condition ($SourceSha -match '^[0-9a-fA-F]{40}$') 'SourceSha must contain exactly 40 hexadecimal characters.'
    Assert-Condition ($ArchiveSha256 -match '^[0-9a-fA-F]{64}$') 'ArchiveSha256 must contain exactly 64 hexadecimal characters.'
    Assert-Condition ($PSVersionTable.PSEdition -eq 'Desktop' -and $PSVersionTable.PSVersion.Major -eq 5) 'Run this harness with Windows PowerShell 5.1 (powershell.exe), not PowerShell Core.'
    Assert-Condition ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) 'This harness runs only on Windows.'
    Assert-Condition ([Environment]::Is64BitOperatingSystem) 'The x64 MSVC package requires 64-bit Windows.'
    Assert-Condition ([Environment]::OSVersion.Version.Build -ge 22000) 'This harness is scoped to Windows 11 builds (22000 or newer).'
    Assert-Condition ([IO.File]::Exists((Join-Path $PSHOME 'powershell.exe'))) 'Windows PowerShell executable could not be resolved.'
    # Get-ExecutionPolicy -List returns rows, not MachinePolicy/UserPolicy fields.
    $machinePolicy = Get-ExecutionPolicy -Scope MachinePolicy
    $userPolicy = Get-ExecutionPolicy -Scope UserPolicy
    Assert-Condition ($machinePolicy -eq 'Undefined' -and $userPolicy -eq 'Undefined') 'A Group Policy controls PowerShell execution; the harness will not override it.'
    Assert-Condition ((Get-ExecutionPolicy) -ne 'Restricted') 'PowerShell is Restricted; start this disposable test run with -ExecutionPolicy Bypass (process scope only).'
    Add-Type -AssemblyName System.IO.Compression
    Assert-Condition ($null -ne [IO.Compression.ZipArchive]) 'The .NET ZipArchive API is unavailable.'
    Assert-Condition ([Environment]::UserInteractive -and [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0) 'An interactive user session is required.'

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    Assert-Condition ($null -ne $identity.User -and @('S-1-5-18', 'S-1-5-19', 'S-1-5-20') -notcontains $identity.User.Value) 'Built-in service accounts are not allowed.'
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    Assert-Condition (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Run unelevated as a normal user.'

    $script:Stage = 'input-validation'
    $archivePath = [IO.Path]::GetFullPath($AgentArchive)
    $installerPath = [IO.Path]::GetFullPath($Installer)
    Assert-Condition ([IO.Path]::IsPathRooted($AgentArchive) -and [IO.Path]::IsPathRooted($Installer)) 'AgentArchive and Installer must be absolute paths.'
    Assert-Condition ([IO.File]::Exists($archivePath) -and [IO.File]::Exists($installerPath)) 'AgentArchive or Installer does not exist.'
    Assert-PathChainNotReparse $archivePath 'AgentArchive path'
    Assert-PathChainNotReparse $installerPath 'Installer path'
    Assert-Condition ((Get-Sha256 $archivePath) -eq $ArchiveSha256.ToLowerInvariant()) 'AgentArchive digest does not match ArchiveSha256.'
    Add-Result 'trusted-archive-digest' 'PASS' 'sha256-matches-supplied-trusted-digest'

    $script:Stage = 'fresh-root-check'
    $localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    Assert-Condition (-not [string]::IsNullOrEmpty($localAppData)) 'LocalAppData is unavailable.'
    $script:Root = [IO.Path]::GetFullPath((Join-Path $localAppData 'HostLink\Agent'))
    $rootParent = [IO.Path]::GetDirectoryName($script:Root)
    Assert-PathChainNotReparse $rootParent 'HostLink root parent'
    Assert-Condition (-not (Test-PathEntry $script:Root)) 'The HostLink Agent root already exists; refusing to inspect, adopt, or modify it.'
    $script:RootAbsentAtStart = $true
    Add-Result 'fresh-install-root' 'PASS' 'root-absent-at-start'

    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    Assert-PathChainNotReparse $tempRoot 'Temporary directory'
    $workspaceName = 'hostlink-native-acceptance-' + [Guid]::NewGuid().ToString('N')
    $script:Workspace = Join-Path $tempRoot $workspaceName
    Set-PrivateDirectory $script:Workspace
    Assert-NotReparse $script:Workspace 'Harness workspace'
    $script:WorkspaceSentinel = Join-Path $script:Workspace '.native-acceptance-owner'
    [IO.File]::WriteAllText($script:WorkspaceSentinel, $workspaceName, (New-Object Text.UTF8Encoding($false)))
    Set-PrivateFile $script:WorkspaceSentinel
    Add-Result 'owned-private-temp' 'PASS' 'unique-current-user-only-temporary-directory'
    if (-not [string]::IsNullOrEmpty($ReceiptFile)) { $script:ReceiptPath = Test-ReceiptPath $ReceiptFile }

    $script:Stage = 'archive-contract'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        $stem = 'hostlink-agent-' + $target
        $expectedNames = @(
            ($stem + '/hostlink-agent.exe'),
            ($stem + '/Install-HostLink-Agent.ps1'),
            ($stem + '/Run-HostLink-Agent.ps1'),
            ($stem + '/Update-HostLink-Agent.ps1')
        )
        $names = @($zip.Entries | ForEach-Object { $_.FullName })
        Assert-Condition ($names.Count -eq 4) 'Agent ZIP must have exactly four members.'
        foreach ($name in $expectedNames) { Assert-Condition ($names -ccontains $name) 'Agent ZIP member whitelist mismatch.' }
        foreach ($entry in $zip.Entries) {
            Assert-Condition ($entry.Length -gt 0 -and $entry.Length -le 268435456) 'Agent ZIP contains an empty or oversized member.'
            Assert-Condition (-not $entry.FullName.EndsWith('/')) 'Agent ZIP directory entries are forbidden.'
        }
        $embeddedInstaller = $zip.GetEntry($stem + '/Install-HostLink-Agent.ps1')
        $embeddedStream = $embeddedInstaller.Open()
        $embeddedBuffer = New-Object IO.MemoryStream
        try { $embeddedStream.CopyTo($embeddedBuffer); $embeddedBytes = $embeddedBuffer.ToArray() }
        finally { $embeddedBuffer.Dispose(); $embeddedStream.Dispose() }
        $suppliedBytes = [IO.File]::ReadAllBytes($installerPath)
        Assert-Condition ([Convert]::ToBase64String($embeddedBytes) -ceq [Convert]::ToBase64String($suppliedBytes)) 'Supplied installer does not byte-match the source-exact installer in AgentArchive.'
        $agentEntry = $zip.GetEntry($stem + '/hostlink-agent.exe')
        $agentStream = $agentEntry.Open()
        $agentHash = [Security.Cryptography.SHA256]::Create()
        try { $script:ArchiveAgentSha = ([BitConverter]::ToString($agentHash.ComputeHash($agentStream))).Replace('-', '').ToLowerInvariant() }
        finally { $agentHash.Dispose(); $agentStream.Dispose() }
    } finally { $zip.Dispose() }
    Add-Result 'exact-archive-inventory-and-installer-identity' 'PASS' 'four-member-msvc-whitelist;installer-bytes-match-archive'

    $script:WindowsEdition = 'unknown'
    try { $script:WindowsEdition = [string](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID } catch { }
    $edition = $script:WindowsEdition
    $script:WindowsEdition = $edition -replace '[^A-Za-z0-9_.-]', ''

    $script:Stage = 'fixture-creation'
    $configPath = Join-Path $script:Workspace 'agent.json'
    $secretPath = Join-Path $script:Workspace 'control.secret'
    $identityPath = Join-Path $script:Workspace 'ssh-identity'
    $hostKeyPath = Join-Path $script:Workspace 'ssh-host-key'
    $knownHostsPath = Join-Path $script:Workspace 'known_hosts'
    $authorizedKeysPath = Join-Path $script:Workspace 'authorized_keys'
    $sshKeygen = Join-Path $env:WINDIR 'System32\OpenSSH\ssh-keygen.exe'
    if (-not [IO.File]::Exists($sshKeygen)) {
        $candidate = Get-Command ssh-keygen.exe -ErrorAction SilentlyContinue
        if ($null -ne $candidate) { $sshKeygen = $candidate.Source }
    }
    Assert-Condition ([IO.File]::Exists($sshKeygen)) 'Windows OpenSSH ssh-keygen.exe is required to create native Ed25519 test keys.'
    $keySpecifications = @(
        [pscustomobject]@{ path = $identityPath; comment = 'hostlink-native-acceptance-identity' },
        [pscustomobject]@{ path = $hostKeyPath; comment = 'hostlink-native-acceptance-host' }
    )
    foreach ($key in $keySpecifications) {
        $script:Stage = 'fixture-ed25519-keygen'
        # Windows PowerShell 5.1 drops an unquoted empty native argument.
        # This literal reaches ssh-keygen as an empty passphrase on Windows.
        & $sshKeygen -q -t ed25519 -N '""' -C $key.comment -f $key.path 2>$null
        Assert-Condition ($LASTEXITCODE -eq 0 -and [IO.File]::Exists($key.path) -and [IO.File]::Exists($key.path + '.pub')) 'OpenSSH Ed25519 key generation failed.'
        $script:Stage = 'fixture-ed25519-private-acl'
        Set-PrivateFile $key.path
    }
    $script:Stage = 'fixture-public-key-material'
    $identityPublic = [IO.File]::ReadAllText($identityPath + '.pub').Trim()
    $hostPublic = [IO.File]::ReadAllText($hostKeyPath + '.pub').Trim()
    $hostParts = $hostPublic -split '\s+'
    Assert-Condition ($hostParts.Count -ge 2) 'OpenSSH returned an invalid host public key.'
    [IO.File]::WriteAllText($knownHostsPath, ('gateway.example.test ' + $hostParts[0] + ' ' + $hostParts[1] + "`n"), (New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText($authorizedKeysPath, ($identityPublic + "`n"), (New-Object Text.UTF8Encoding($false)))
    $script:Stage = 'fixture-random-secret'
    $secret = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($secret) } finally { $rng.Dispose() }
    [IO.File]::WriteAllText($secretPath, [Convert]::ToBase64String($secret), (New-Object Text.UTF8Encoding($false)))
    [Array]::Clear($secret, 0, $secret.Length)
    $script:Stage = 'fixture-secret-private-acl'
    Set-PrivateFile $secretPath
    $script:Stage = 'fixture-config-serialization'
    $config = [ordered]@{
        version = 1
        name = 'native-acceptance'
        listen = '127.0.0.1:27391'
        secret_env = 'HOSTLINK_NATIVE_ACCEPTANCE_SECRET'
        secret_file = $secretPath
        jobs_dir = (Join-Path $script:Root 'jobs')
        ssh = [ordered]@{
            gateways = @(@{ host = 'gateway.example.test'; user = 'hostlink-test'; port = 22 })
            remote_port = 41000
            identity = $identityPath
            known_hosts = $knownHostsPath
            reconnect_seconds = 5
        }
        embedded_ssh_server = [ordered]@{
            user = 'hostlink'
            host_key = $hostKeyPath
            authorized_keys = $authorizedKeysPath
            port = 27392
        }
    }
    [IO.File]::WriteAllText($configPath, (ConvertTo-Json -InputObject $config -Depth 8), (New-Object Text.UTF8Encoding($false)))
    Add-Result 'private-manual-config-and-ssh-fixtures' 'PASS' 'config-v1;root-jobs;private-secret;ed25519-keys;reserved-hostname;no-network'

    $script:Stage = 'source-exact-version'
    # Query the executable from the archive only after extracting it to the owned workspace.
    $zip = [IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        $entry = $zip.GetEntry('hostlink-agent-' + $target + '/hostlink-agent.exe')
        $out = [IO.File]::Open((Join-Path $script:Workspace 'hostlink-agent.exe'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $input = $entry.Open()
        try { $input.CopyTo($out) } finally { $input.Dispose(); $out.Dispose() }
    } finally { $zip.Dispose() }
    $agentPath = Join-Path $script:Workspace 'hostlink-agent.exe'
    Assert-Condition ((Get-Sha256 $agentPath) -eq $script:ArchiveAgentSha) 'Extracted Agent executable does not match the archive member digest.'
    $versionOutput = @(& $agentPath --version 2>$null)
    Assert-Condition ($LASTEXITCODE -eq 0 -and $versionOutput.Count -gt 0) 'Source-exact Agent executable did not return its version.'
    $versionText = ($versionOutput -join ' ').Trim()
    Assert-Condition ($versionText -match '(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)') 'Agent --version output did not include a supported package version.'
    $packageVersion = $Matches[1]
    Add-Result 'source-exact-agent-version' 'PASS' 'version-parsed-from-archive-executable'

    $badDigest = ('0' * 64)
    if ($badDigest -eq $ArchiveSha256.ToLowerInvariant()) { $badDigest = ('1' * 64) }
    Assert-ExpectedFailure 'negative-wrong-sha256' $installerPath @('-ArchiveFile', $archivePath, '-ArchiveSha256', $badDigest, '-PackageVersion', $packageVersion, '-Target', $target, '-ConfigFile', $configPath)
    Assert-ExpectedFailure 'negative-missing-config' $installerPath @('-ArchiveFile', $archivePath, '-ArchiveSha256', $ArchiveSha256, '-PackageVersion', $packageVersion, '-Target', $target, '-ConfigFile', (Join-Path $script:Workspace 'missing.json'))
    Assert-ExpectedFailure 'negative-foreign-target' $installerPath @('-ArchiveFile', $archivePath, '-ArchiveSha256', $ArchiveSha256, '-PackageVersion', $packageVersion, '-Target', 'x86_64-pc-windows-gnu', '-ConfigFile', $configPath)

    $reparsePath = Join-Path $script:Workspace 'reparse-config.json'
    $reparseAvailable = $true
    try { New-Item -ItemType SymbolicLink -Path $reparsePath -Target $configPath -ErrorAction Stop | Out-Null }
    catch {
        if (@(-2147024891, -2147023578) -contains [int]$_.Exception.HResult) {
            $reparseAvailable = $false
        } else {
            throw 'Could not create the reparse fixture for a reason other than missing symlink capability.'
        }
    }
    if ($reparseAvailable) {
        Assert-ExpectedFailure 'negative-reparse-config' $installerPath @('-ArchiveFile', $archivePath, '-ArchiveSha256', $ArchiveSha256, '-PackageVersion', $packageVersion, '-Target', $target, '-ConfigFile', $reparsePath)
        Remove-Item -LiteralPath $reparsePath -Force
    } else {
        Add-Result 'negative-reparse-config' 'SKIP' 'Windows did not grant symbolic-link creation capability'
    }

    $script:Stage = 'manual-install'
    $installResult = Invoke-PowerShellFile $installerPath @('-ArchiveFile', $archivePath, '-ArchiveSha256', $ArchiveSha256, '-PackageVersion', $packageVersion, '-Target', $target, '-ConfigFile', $configPath)
    Assert-Condition ($installResult.exit_code -eq 0) 'Source-exact manual-mode installer failed; any partial root is retained for investigation.'
    Assert-Condition ((Test-Path -LiteralPath $script:Root -PathType Container)) 'Installer returned success without creating the expected root.'
    Assert-NotReparse $script:Root 'Installed Agent root'
    $script:RootCreatedByThisRun = $true
    $script:RootSentinel = Join-Path $script:Root '.native-windows-acceptance-owner'
    [IO.File]::WriteAllText($script:RootSentinel, $workspaceName, (New-Object Text.UTF8Encoding($false)))
    Set-PrivateFile $script:RootSentinel
    Add-Result 'native-manual-install' 'PASS' 'source-exact-msvc-installer-completed-unelevated'

    $script:Stage = 'installed-check'
    $installedAgent = Join-Path $script:Root 'hostlink-agent\bin\hostlink-agent.exe'
    $checkOutput = @(& $installedAgent check --config $configPath 2>$null)
    Assert-Condition ($LASTEXITCODE -eq 0) 'Installed Agent check --config failed.'
    Add-Result 'installed-agent-check' 'PASS' 'check-command-exit-0'

    $script:Stage = 'idempotent-update'
    $script:RootInventory = Get-RootInventory $script:Root
    $stagedArchive = Join-Path $script:Root '.native-acceptance-package.zip'
    [IO.File]::Copy($archivePath, $stagedArchive, $false)
    $updater = Join-Path $script:Root 'hostlink-agent\bin\Update-HostLink-Agent.ps1'
    Assert-Condition ([IO.File]::Exists($updater)) 'Installed Agent updater script is missing.'
    $updateResult = Invoke-PowerShellFile $updater @('-ArchiveFile', $stagedArchive, '-ArchiveSha256', $ArchiveSha256, '-PackageVersion', $packageVersion, '-Target', $target)
    Assert-Condition ($updateResult.exit_code -eq 0) 'Identical-digest Agent-only update did not complete successfully.'
    [IO.File]::Delete($stagedArchive)
    $afterUpdate = Get-RootInventory $script:Root
    Assert-Condition ((ConvertTo-Json -InputObject $afterUpdate -Depth 5 -Compress) -ceq (ConvertTo-Json -InputObject $script:RootInventory -Depth 5 -Compress)) 'Idempotent update changed installed files.'
    Add-Result 'self-update-idempotence' 'PASS' 'same-archive-digest-preserved-installed-inventory'

    $finalCheck = @(& $installedAgent check --config $configPath 2>$null)
    Assert-Condition ($LASTEXITCODE -eq 0) 'Installed Agent check failed after idempotent update.'
    Add-Result 'post-update-agent-check' 'PASS' 'check-command-exit-0'
    $script:Success = $true
    Add-Result 'native-windows-context' 'PASS' ('windows-build-' + [Environment]::OSVersion.Version.Build + ';edition-' + $script:WindowsEdition + ';powershell-' + $PSVersionTable.PSVersion.ToString() + ';clr-' + [Environment]::Version.ToString())
} catch {
    # Exception text can contain usernames, local paths, config values, or key material.
    # Keep the receipt and console output limited to a stable stage identifier.
    $failure = 'harness-failure-at-' + $script:Stage
    Add-Result 'harness' 'FAIL' $failure
    Write-Output ('FAIL ' + $failure)
} finally {
    if ($script:Success -and $script:RootAbsentAtStart -and $script:RootCreatedByThisRun -and $null -ne $script:RootInventory) {
        try {
            Assert-PathChainNotReparse ([IO.Path]::GetDirectoryName($script:Root)) 'HostLink root parent during cleanup'
            Assert-NotReparse $script:Root 'Install root during cleanup'
            Assert-Condition ((Test-Path -LiteralPath $script:RootSentinel -PathType Leaf)) 'Ownership sentinel is missing; install root retained.'
            Assert-NotReparse $script:RootSentinel 'Ownership sentinel'
            Assert-Condition ([IO.File]::ReadAllText($script:RootSentinel) -eq ([IO.Path]::GetFileName($script:Workspace))) 'Ownership sentinel does not match this run; install root retained.'
            Assert-Condition ((ConvertTo-Json -InputObject (Get-RootInventory $script:Root) -Depth 5 -Compress) -ceq (ConvertTo-Json -InputObject $script:RootInventory -Depth 5 -Compress)) 'Install root changed after verification; root retained.'
            [IO.File]::Delete($script:RootSentinel)
            [IO.Directory]::Delete($script:Root, $true)
            Assert-Condition (-not (Test-PathEntry $script:Root)) 'Install root remains after cleanup.'
            $script:CleanupState = 'success-root-removed-and-absence-confirmed'
            Add-Result 'install-root-cleanup' 'PASS' 'root-removed-and-absence-confirmed'
        } catch {
            $script:CleanupState = 'warning-root-retained-cleanup-guard-failed'
            $script:Success = $false
            Add-Result 'install-root-cleanup' 'FAIL' 'root-retained-cleanup-guard-failed'
            Write-Warning 'Cleanup guard failed. The HostLink root was retained; inspect it manually. No recursive deletion was attempted after the guard failure.'
        }
    } elseif (Test-PathEntry $script:Root) {
        $script:CleanupState = 'warning-root-retained-after-failure-or-uncertain-ownership'
        if ($script:Success) {
            $script:Success = $false
            Add-Result 'install-root-cleanup' 'FAIL' 'root-retained-after-ownership-check'
        }
        Write-Warning 'The HostLink root exists after a failed or uncertain run and was retained for investigation. Do not retry until you inspect it.'
    } else {
        $script:CleanupState = 'root-absent'
    }

    if (-not [string]::IsNullOrEmpty($script:Workspace) -and (Test-PathEntry $script:Workspace)) {
        try {
            Assert-NotReparse $script:Workspace 'Harness workspace during cleanup'
            Assert-Condition ((Test-Path -LiteralPath $script:WorkspaceSentinel -PathType Leaf)) 'Temporary workspace ownership sentinel is missing.'
            Assert-Condition ([IO.File]::ReadAllText($script:WorkspaceSentinel) -eq ([IO.Path]::GetFileName($script:Workspace))) 'Temporary workspace ownership sentinel mismatch.'
            foreach ($item in @(Get-ChildItem -LiteralPath $script:Workspace -Force -Recurse)) {
                Assert-NotReparse $item.FullName 'Harness workspace entry during cleanup'
            }
            Remove-Item -LiteralPath $script:Workspace -Recurse -Force
        } catch {
            Write-Warning 'Owned temporary workspace cleanup failed; inspect the current user temporary directory.'
            $script:Success = $false
            if ($script:CleanupState -eq 'success-root-removed-and-absence-confirmed') {
                $script:CleanupState = 'success-root-removed;warning-workspace-retained-after-cleanup-failure'
            } else {
                $script:CleanupState = 'warning-workspace-retained-after-cleanup-failure'
            }
        }
    }
    try { Write-Receipt $(if ($script:Success) { 'PASS' } else { 'FAIL' }) $failure } catch {
        Write-Warning 'Receipt could not be written to the requested temporary path.'
        $script:Success = $false
    }
}

if ($script:Success) {
    Write-Output ('PASS source_sha=' + $SourceSha.ToLowerInvariant())
    Write-Output ('PASS archive_sha256=' + $ArchiveSha256.ToLowerInvariant())
    Write-Output ('PASS agent_exe_sha256=' + $script:ArchiveAgentSha)
    foreach ($result in $script:Results) { Write-Output ($result.status + ' ' + $result.name + ' ' + $result.detail) }
    Write-Output ('PASS cleanup=' + $script:CleanupState)
    if ($script:ReceiptWritten) { Write-Output 'PASS receipt=written-private' }
} else {
    foreach ($result in $script:Results | Where-Object { $_.status -eq 'FAIL' }) {
        Write-Output ('FAIL ' + $result.name + ' ' + $result.detail)
    }
    Write-Output ('FAIL cleanup=' + $script:CleanupState)
}
if (-not $script:Success) { exit 1 }
exit 0
