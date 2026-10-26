param(
    [Parameter(Mandatory=$true)][string]$SourceSha,
    [Parameter(Mandatory=$true)][string]$BuildRoot,
    [Parameter(Mandatory=$true)][string]$X64PackageRoot,
    [Parameter(Mandatory=$true)][string]$X86PackageRoot,
    [Parameter(Mandatory=$true)][string]$DisposableRoot
)

# Windows PowerShell 2 / .NET 3.5 compatible. Runs only side-by-side test CLIs.
$ErrorActionPreference = 'Stop'

function Stop-Harness([string]$Message) {
    throw ('verify-win7-side-by-side: ' + $Message)
}

function Get-Sha256([string]$Path) {
    $algorithm = New-Object Security.Cryptography.SHA256Managed
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Close(); $algorithm.Clear() }
}

function Set-PrivateDirectory([string]$Path, [Security.Principal.SecurityIdentifier]$Sid) {
    if ([IO.Directory]::Exists($Path) -or [IO.File]::Exists($Path)) { Stop-Harness 'refusing to overwrite an existing run path' }
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($Sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    [void]$security.AddAccessRule($rule)
    [void][IO.Directory]::CreateDirectory($Path, $security)
}

function Quote-ProcessArgument([string]$Value) {
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Invoke-Captured([string]$Executable, [string[]]$Arguments, [string]$WorkingDirectory, [string]$StdoutPath, [string]$StderrPath, [int]$TimeoutMilliseconds) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Executable
    $info.Arguments = [string]::Join(' ', @($Arguments | ForEach-Object { Quote-ProcessArgument $_ }))
    $info.WorkingDirectory = $WorkingDirectory
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { Stop-Harness 'could not start a test executable' }
        # These commands have bounded, small output. Both streams are saved verbatim.
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            $process.Kill()
            Stop-Harness 'test executable exceeded its execution limit'
        }
        [IO.File]::WriteAllText($StdoutPath, $stdout, (New-Object Text.UTF8Encoding($false)))
        [IO.File]::WriteAllText($StderrPath, $stderr, (New-Object Text.UTF8Encoding($false)))
        return $process.ExitCode
    } finally { $process.Dispose() }
}

function Read-PackageVersion([string]$PackageRoot) {
    $receiptPath = [IO.Path]::Combine($PackageRoot, 'artifact-receipt.json')
    if (-not [IO.File]::Exists($receiptPath)) { Stop-Harness 'package receipt is missing' }
    try {
        $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $serializer.MaxJsonLength = 4194304
        $receipt = $serializer.DeserializeObject([IO.File]::ReadAllText($receiptPath, [Text.Encoding]::UTF8))
    } catch { Stop-Harness 'package receipt is malformed' }
    if (-not $receipt.ContainsKey('version') -or -not $receipt.ContainsKey('source_sha') -or -not $receipt.ContainsKey('target')) { Stop-Harness 'package receipt lacks required identity fields' }
    if ($receipt['source_sha'] -cne $SourceSha) { Stop-Harness 'package receipt source SHA mismatch' }
    return [string]$receipt['version']
}

if ($SourceSha -cnotmatch '^[0-9a-f]{40}$') { Stop-Harness 'SourceSha must be a full lowercase Git SHA' }
if ($PSVersionTable.PSVersion.Major -ne 2) { Stop-Harness 'run this acceptance harness under Windows PowerShell 2' }
$os = Get-WmiObject -Class Win32_OperatingSystem
$osVersion = [string]$os.Version
$osCaption = [string]$os.Caption
if ($osVersion -notmatch '^6\.1\.7601(\.|$)' -or $osCaption -notmatch 'Windows 7' -or [int]$os.ServicePackMajorVersion -lt 1) {
    Stop-Harness ('native acceptance requires Windows 7 SP1 NT6.1.7601; found ' + $osCaption + ' ' + $osVersion)
}
$is64BitOs = ([IntPtr]::Size -eq 8) -or ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64')
if (-not $is64BitOs) { Stop-Harness 'this harness requires a 64-bit Windows 7 OS; x86-on-x64 is recorded as WoW64 evidence' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($null -eq $identity -or $null -eq $identity.User -or @('S-1-5-18','S-1-5-19','S-1-5-20') -contains $identity.User.Value) { Stop-Harness 'a normal interactive user identity is required' }
$sid = $identity.User
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) { Stop-Harness 'run unelevated in an interactive user session' }

$disposable = [IO.Path]::GetFullPath($DisposableRoot)
if (-not [IO.Directory]::Exists($disposable)) { Stop-Harness 'DisposableRoot must be a pre-created, private empty directory' }
$rootInfo = New-Object IO.DirectoryInfo($disposable)
$rootAcl = $rootInfo.GetAccessControl()
if (-not $rootAcl.GetOwner([Security.Principal.SecurityIdentifier]).Equals($sid) -or -not $rootAcl.AreAccessRulesProtected) { Stop-Harness 'DisposableRoot owner or protected ACL is unsafe' }
foreach ($rule in $rootAcl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and -not $rule.IdentityReference.Equals($sid)) { Stop-Harness 'DisposableRoot grants access to another identity' }
}
$pathRoot = [IO.Path]::GetPathRoot($disposable)
$pathCurrent = $pathRoot
$pathRelative = $disposable.Substring($pathRoot.Length)
foreach ($pathPart in $pathRelative.Split([char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar), [StringSplitOptions]::RemoveEmptyEntries)) {
    $pathCurrent = [IO.Path]::Combine($pathCurrent, $pathPart)
    $pathAttributes = [IO.File]::GetAttributes($pathCurrent)
    if (($pathAttributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Stop-Harness 'DisposableRoot or an ancestor is a reparse point' }
}
foreach ($entry in Get-ChildItem -LiteralPath $disposable -Force) { Stop-Harness 'DisposableRoot must be empty; refusing overwrite' }
$drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($disposable))
if ($drive.DriveType -ne [IO.DriveType]::Fixed) { Stop-Harness 'DisposableRoot must be on a fixed local drive' }

$run = [IO.Path]::Combine($disposable, ('hostlink-win7-' + $SourceSha + '-' + [Guid]::NewGuid().ToString('N')))
Set-PrivateDirectory $run $sid
$verifierRoot = [IO.Path]::Combine($run, 'bootstrap-evidence')
Set-PrivateDirectory $verifierRoot $sid
$result = 'FAILED'
$exitCode = 1
$cleanupOutcome = 'retained-private-evidence'
$failure = $null
$artifactHashes = @{}
try {
    Add-Type -AssemblyName System.Web.Extensions
    $x64Version = Read-PackageVersion $X64PackageRoot
    $x86Version = Read-PackageVersion $X86PackageRoot
    if ($x64Version -cne $x86Version) { Stop-Harness 'x64 and x86 package versions differ' }
    $x64Agent = [IO.Path]::Combine([IO.Path]::Combine([IO.Path]::Combine($X64PackageRoot, $x64Version), 'x86_64-win7-windows-msvc'), 'hostlink-agent.exe')
    $x86Agent = [IO.Path]::Combine([IO.Path]::Combine([IO.Path]::Combine($X86PackageRoot, $x86Version), 'i686-win7-windows-msvc'), 'hostlink-agent.exe')
    if (-not [IO.File]::Exists($x64Agent) -or -not [IO.File]::Exists($x86Agent)) { Stop-Harness 'target-specific Agent sidecar is missing' }
    $harnessPath = [IO.Path]::Combine([IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path), 'verify-win7-bootstrap-native.ps1')
    if (-not [IO.File]::Exists($harnessPath)) { Stop-Harness 'bootstrap verification helper is missing' }
    $powershell = [IO.Path]::Combine($PSHOME, 'powershell.exe')
    $stdoutPath = [IO.Path]::Combine($run, 'bootstrap.stdout.txt')
    $stderrPath = [IO.Path]::Combine($run, 'bootstrap.stderr.txt')
    $arguments = @('-NoProfile','-ExecutionPolicy','RemoteSigned','-File',$harnessPath,'-SourceSha',$SourceSha,'-Version',$x64Version,'-BuildRoot',$BuildRoot,'-X64PackageRoot',$X64PackageRoot,'-X86PackageRoot',$X86PackageRoot,'-DisposableRoot',$verifierRoot)
    $exitCode = Invoke-Captured $powershell $arguments $run $stdoutPath $stderrPath 1800000
    if ($exitCode -ne 0) { Stop-Harness ('bootstrap verifier exited ' + $exitCode) }
    foreach ($entry in @(
        @{Name='build-receipt';Path=[IO.Path]::Combine($BuildRoot, 'receipt.json')},
        @{Name='x64-package-receipt';Path=[IO.Path]::Combine($X64PackageRoot, 'artifact-receipt.json')},
        @{Name='x86-package-receipt';Path=[IO.Path]::Combine($X86PackageRoot, 'artifact-receipt.json')},
        @{Name='x64-archive';Path=[IO.Path]::Combine([IO.Path]::Combine($X64PackageRoot, $x64Version), 'hostlink-agent-x86_64-win7-windows-msvc.zip')},
        @{Name='x86-archive';Path=[IO.Path]::Combine([IO.Path]::Combine($X86PackageRoot, $x86Version), 'hostlink-agent-i686-win7-windows-msvc.zip')},
        @{Name='x64-agent';Path=$x64Agent},
        @{Name='x86-agent';Path=$x86Agent}
    )) {
        if ([IO.File]::Exists($entry.Path)) { $artifactHashes[$entry.Name] = Get-Sha256 $entry.Path }
    }
    # The existing verifier has now checked owner, ACL, exact receipts and PE identities
    # before either sidecar is executed by this wrapper.
    foreach ($entry in @(@{Name='x64-version';Path=$x64Agent},@{Name='x86-wow64-version';Path=$x86Agent})) {
        $versionStdout = [IO.Path]::Combine($run, ($entry.Name + '.stdout.txt'))
        $versionStderr = [IO.Path]::Combine($run, ($entry.Name + '.stderr.txt'))
        $versionExit = Invoke-Captured $entry.Path @('--version') $run $versionStdout $versionStderr 30000
        if ($versionExit -ne 0) { Stop-Harness ($entry.Name + ' target Agent --version failed') }
        $versionText = [IO.File]::ReadAllText($versionStdout, [Text.Encoding]::UTF8).Trim()
        if ($versionText -notmatch ('(^|\s)' + [regex]::Escape($x64Version) + '(\s|$)')) { Stop-Harness ($entry.Name + ' target Agent --version does not match package receipt') }
    }
    $malformedPath = [IO.Path]::Combine($run, 'malformed-archive.bin')
    [IO.File]::WriteAllBytes($malformedPath, [byte[]]@(0,1,2,3,4,5))
    $malformedHash = Get-Sha256 $malformedPath
    $malformedOutput = [IO.Path]::Combine($run, 'malformed-output')
    $malformedStdout = [IO.Path]::Combine($run, 'malformed.stdout.txt')
    $malformedStderr = [IO.Path]::Combine($run, 'malformed.stderr.txt')
    $malformedExit = Invoke-Captured $x64Agent @('bootstrap-verify','--archive',$malformedPath,'--sha256',$malformedHash,'--target','x86_64-win7-windows-msvc','--version',$x64Version,'--output',$malformedOutput) $run $malformedStdout $malformedStderr 600000
    if ($malformedExit -eq 0 -or [IO.Directory]::Exists($malformedOutput) -or [IO.File]::Exists($malformedOutput)) { Stop-Harness 'target verifier accepted malformed ZIP input or published output' }
    $result = 'PASS_NT61_WIN7_SP1_X64_AND_X86_WOW64_BOOTSTRAP'
} catch {
    $failure = $_.Exception.Message
    if ($exitCode -eq 0) { $exitCode = 1 }
} finally {
    $fileHashes = @{}
    foreach ($evidenceFile in Get-ChildItem -LiteralPath $run -Recurse -Force | Where-Object { -not $_.PSIsContainer }) {
        $relativeName = $evidenceFile.FullName.Substring($run.Length + 1)
        $fileHashes[$relativeName] = Get-Sha256 $evidenceFile.FullName
    }
    $receipt = @{
        schema_version = 1
        status = $result
        source_sha = $SourceSha
        os = @{ caption = $osCaption; version = $osVersion; service_pack_major = [int]$os.ServicePackMajorVersion; architecture = 'x64'; x86_execution = 'WOW64' }
        identity = @{ sid = $sid.Value; elevated = $false; session_id = [Diagnostics.Process]::GetCurrentProcess().SessionId }
        powershell = [string]$PSVersionTable.PSVersion
        exit_code = $exitCode
        failure = $failure
        stdout_sha256 = @{}
        stderr_sha256 = @{}
        artifact_sha256 = $artifactHashes
        file_sha256 = $fileHashes
        cleanup_outcome = $cleanupOutcome
        evidence_root = $run
    }
    foreach ($name in @('x64-version','x86-wow64-version','bootstrap','malformed')) {
        foreach ($stream in @('stdout','stderr')) {
            $path = [IO.Path]::Combine($run, ($name + '.' + $stream + '.txt'))
            if ([IO.File]::Exists($path)) {
                if ($stream -eq 'stdout') { $receipt.stdout_sha256[$name] = Get-Sha256 $path }
                else { $receipt.stderr_sha256[$name] = Get-Sha256 $path }
            }
        }
    }
    $json = (New-Object System.Web.Script.Serialization.JavaScriptSerializer).Serialize($receipt)
    [IO.File]::WriteAllText([IO.Path]::Combine($run, 'native-acceptance-receipt.json'), $json, (New-Object Text.UTF8Encoding($false)))
}
if ($null -ne $failure) { Stop-Harness $failure }
Write-Output ('PASS: ' + $result + '; source_sha=' + $SourceSha)
Write-Output ('OS: ' + $osCaption + ' ' + $osVersion + '; x64 with x86 under WoW64; PowerShell ' + [string]$PSVersionTable.PSVersion)
Write-Output ('EVIDENCE: ' + [IO.Path]::Combine($run, 'native-acceptance-receipt.json'))
