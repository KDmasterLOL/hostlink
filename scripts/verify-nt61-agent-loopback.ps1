param(
    [Parameter(Mandatory=$true)][string]$SourceSha,
    [Parameter(Mandatory=$true)][string]$BuildReceipt,
    [Parameter(Mandatory=$true)][string]$DisposableRoot,
    [Parameter(Mandatory=$true)][string]$X64Agent,
    [Parameter(Mandatory=$true)][string]$X64Client,
    [Parameter(Mandatory=$true)][string]$X86Agent,
    [Parameter(Mandatory=$true)][string]$X86Client,
    [Parameter(Mandatory=$true)][string]$HostPrivateKey,
    [Parameter(Mandatory=$true)][string]$HostPublicKey,
    [Parameter(Mandatory=$true)][string]$ControllerPrivateKey,
    [Parameter(Mandatory=$true)][string]$ControllerPublicKey
)

# Windows PowerShell 2 / .NET 3.5 only. No service, registry, installation,
# remote access, or process discovery is performed by this harness.
$ErrorActionPreference = 'Stop'
$script:MaxCapturedBytes = 1048576

function Stop-Harness([string]$Message) {
    throw ('verify-nt61-agent-loopback: ' + $Message)
}

function Get-Sha256([string]$Path) {
    $algorithm = New-Object Security.Cryptography.SHA256Managed
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Close(); $algorithm.Clear() }
}

function Combine-Path([string]$First, [string]$Second) {
    return [IO.Path]::Combine($First, $Second)
}

function Assert-NoReparseAncestors([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    $current = $root
    $relative = $full.Substring($root.Length)
    foreach ($part in $relative.Split([char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar), [StringSplitOptions]::RemoveEmptyEntries)) {
        $current = Combine-Path $current $part
        if (-not [IO.File]::Exists($current) -and -not [IO.Directory]::Exists($current)) { Stop-Harness ('path component is missing: ' + $current) }
        if (([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Stop-Harness ('reparse path is forbidden: ' + $current) }
    }
}

function Assert-OwnedRegularFile([string]$Path, [Security.Principal.SecurityIdentifier]$Sid, [string]$Label) {
    $full = [IO.Path]::GetFullPath($Path)
    Assert-NoReparseAncestors $full
    if (-not [IO.File]::Exists($full) -or [IO.Directory]::Exists($full)) { Stop-Harness ($Label + ' must be a regular file') }
    $info = New-Object IO.FileInfo($full)
    if ($info.Length -le 0) { Stop-Harness ($Label + ' is empty') }
    $acl = $info.GetAccessControl()
    if (-not $acl.GetOwner([Security.Principal.SecurityIdentifier]).Equals($Sid)) { Stop-Harness ($Label + ' is not owned by the current user') }
    return $full
}

function Assert-PrivateOwnedFile([string]$Path, [Security.Principal.SecurityIdentifier]$Sid, [string]$Label) {
    $full = Assert-OwnedRegularFile $Path $Sid $Label
    $acl = (New-Object IO.FileInfo($full)).GetAccessControl()
    if (-not $acl.AreAccessRulesProtected) { Stop-Harness ($Label + ' DACL must be protected') }
    foreach ($rule in $acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and -not $rule.IdentityReference.Equals($Sid)) { Stop-Harness ($Label + ' grants access to another identity') }
    }
    return $full
}

function Set-PrivateDirectory([string]$Path, [Security.Principal.SecurityIdentifier]$Sid) {
    if ([IO.Directory]::Exists($Path) -or [IO.File]::Exists($Path)) { Stop-Harness 'refusing to overwrite an existing private path' }
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($Sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    [void]$security.AddAccessRule($rule)
    [void][IO.Directory]::CreateDirectory($Path, $security)
}

function Quote-ProcessArgument([string]$Value) {
    # CommandLineToArgvW-compatible quoting; these arguments are paths or fixed literals.
    $builder = New-Object Text.StringBuilder
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]92) { $slashes++; continue }
        if ($character -eq [char]34) {
            [void]$builder.Append((Repeat-Backslash ((2 * $slashes) + 1)))
            [void]$builder.Append([char]34)
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) { [void]$builder.Append((Repeat-Backslash $slashes)); $slashes = 0 }
        [void]$builder.Append($character)
    }
    if ($slashes -gt 0) { [void]$builder.Append((Repeat-Backslash (2 * $slashes))) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Repeat-Backslash([int]$Count) {
    $builder = New-Object Text.StringBuilder
    for ($index = 0; $index -lt $Count; $index++) { [void]$builder.Append([char]92) }
    return $builder.ToString()
}

function Invoke-Captured([string]$Executable, [string[]]$Arguments, [string]$WorkingDirectory, [string]$StdoutPath, [string]$StderrPath, [int]$TimeoutMilliseconds) {
    $quoted = @()
    foreach ($argument in $Arguments) { $quoted += (Quote-ProcessArgument ([string]$argument)) }
    $captured = [HostLinkNativeCapture]::Run($Executable, [string]::Join(' ', $quoted), $WorkingDirectory, $TimeoutMilliseconds, $script:MaxCapturedBytes, $StdoutPath, $StderrPath)
    if ($captured.TimedOut) { Stop-Harness 'acceptance child exceeded its time limit; exact child handle was killed and waited' }
    if ($captured.OutputExceeded) { Stop-Harness 'child output exceeded the bounded capture limit' }
    return [int]$captured.ExitCode
}

function Find-LoopbackPort {
    for ($port = 20000; $port -le 29999; $port++) {
        $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $port)
        try { $listener.Start(); return $port }
        catch { }
        finally { $listener.Stop() }
    }
    Stop-Harness 'no unused loopback port in 20000..29999'
}

function Write-PrivateText([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($false)))
}

function Assert-BuildReceipt([string]$ReceiptPath, [string]$ExpectedSha, [hashtable]$Binaries) {
    try {
        $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $serializer.MaxJsonLength = 4194304
        $receipt = $serializer.DeserializeObject([IO.File]::ReadAllText($ReceiptPath, [Text.Encoding]::UTF8))
    } catch { Stop-Harness 'build receipt is malformed' }
    $receiptSha = $null
    if ($receipt.ContainsKey('source_sha')) { $receiptSha = [string]$receipt['source_sha'] }
    elseif ($receipt.ContainsKey('source') -and $receipt['source'].ContainsKey('git_sha')) { $receiptSha = [string]$receipt['source']['git_sha'] }
    if ($receiptSha -cne $ExpectedSha) { Stop-Harness 'build receipt source SHA mismatch' }
    if (($receipt['status'] -cne 'PE_BUILD_AND_INSPECTION_PASS') -or -not $receipt.ContainsKey('targets')) { Stop-Harness 'build receipt does not attest a passing exact Win7 build' }
    foreach ($identity in $Binaries.GetEnumerator()) {
        $expectedTarget = [string]$identity.Value.Target
        $expectedName = [string]$identity.Value.Name
        $expectedHash = [string]$identity.Value.Sha
        $found = 0
        foreach ($target in $receipt['targets']) {
            if ($target['target'] -cne $expectedTarget) { continue }
            foreach ($binary in $target['binaries']) {
                if ($binary['file'] -ceq $expectedName -and $binary['sha256'] -ceq $expectedHash) { $found++ }
            }
        }
        if ($found -ne 1) { Stop-Harness ($expectedTarget + '/' + $expectedName + ' is missing or mismatched in build receipt') }
    }
}

if ($SourceSha -cnotmatch '^[0-9a-f]{40}$') { Stop-Harness 'SourceSha must be the full lowercase 40-character source SHA' }
if ($PSVersionTable.PSVersion.Major -ne 2) { Stop-Harness 'run under Windows PowerShell 2' }
$os = Get-WmiObject -Class Win32_OperatingSystem
$osVersion = [string]$os.Version
$osCaption = [string]$os.Caption
if ($osVersion -notmatch '^6\.1\.7601(\.|$)' -or $osCaption -notmatch 'Windows Server 2008 R2 Standard' -or [int]$os.ServicePackMajorVersion -lt 1) {
    Stop-Harness ('requires Windows Server 2008 R2 Standard SP1 NT6.1.7601; found ' + $osCaption + ' ' + $osVersion)
}
$osArchitecture = [string]$os.OSArchitecture
$is64BitOs = ($osArchitecture -match '64') -or ([IntPtr]::Size -eq 8) -or ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64')
if (-not $is64BitOs) { Stop-Harness 'this assignment requires the x64 NT6.1 host; x86 runs under WOW64' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($null -eq $identity -or $null -eq $identity.User -or @('S-1-5-18','S-1-5-19','S-1-5-20') -contains $identity.User.Value) { Stop-Harness 'a normal interactive user identity is required' }
$sid = $identity.User
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or $sessionId -eq 0) { Stop-Harness 'run unelevated in an interactive non-service session' }

$root = [IO.Path]::GetFullPath($DisposableRoot)
if (-not [IO.Directory]::Exists($root)) { Stop-Harness 'DisposableRoot must be pre-created, private and empty' }
Assert-NoReparseAncestors $root
$rootInfo = New-Object IO.DirectoryInfo($root)
$rootAcl = $rootInfo.GetAccessControl()
if (-not $rootAcl.GetOwner([Security.Principal.SecurityIdentifier]).Equals($sid) -or -not $rootAcl.AreAccessRulesProtected) { Stop-Harness 'DisposableRoot owner or protected DACL is unsafe' }
foreach ($rule in $rootAcl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and -not $rule.IdentityReference.Equals($sid)) { Stop-Harness 'DisposableRoot grants access to another identity' }
}
foreach ($entry in Get-ChildItem -LiteralPath $root -Force) { Stop-Harness 'DisposableRoot must be empty' }

Add-Type -AssemblyName System.Web.Extensions
Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

public sealed class HostLinkNativeCaptureResult {
    public int ExitCode;
    public bool TimedOut;
    public bool OutputExceeded;
}

public sealed class HostLinkNativeChild {
    public Process Process;
    private HostLinkNativeCapture.CopyState Stdout;
    private HostLinkNativeCapture.CopyState Stderr;
    private bool Finished;
    public bool OutputExceeded;
    internal HostLinkNativeChild(Process process, HostLinkNativeCapture.CopyState stdout, HostLinkNativeCapture.CopyState stderr) {
        Process = process;
        Stdout = stdout;
        Stderr = stderr;
    }
    public void Finish() {
        if (Finished) return;
        if (!Stdout.Done.WaitOne(10000) || !Stderr.Done.WaitOne(10000)) throw new TimeoutException("owned Agent output streams did not close");
        if (Stdout.Error != null) throw Stdout.Error;
        if (Stderr.Error != null) throw Stderr.Error;
        OutputExceeded = Stdout.Exceeded || Stderr.Exceeded;
        Stdout.Done.Close();
        Stderr.Done.Close();
        Finished = true;
    }
}

public static class HostLinkNativeCapture {
    public sealed class CopyState {
        public Stream Input;
        public string OutputPath;
        public int Maximum;
        public bool Exceeded;
        public Exception Error;
        public ManualResetEvent Done = new ManualResetEvent(false);
    }

    private static void CopyStream(object value) {
        CopyState state = (CopyState)value;
        try {
            byte[] buffer = new byte[8192];
            using (FileStream output = new FileStream(state.OutputPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) {
                int total = 0;
                int count;
                while ((count = state.Input.Read(buffer, 0, buffer.Length)) > 0) {
                    int keep = Math.Min(count, Math.Max(0, state.Maximum - total));
                    if (keep > 0) output.Write(buffer, 0, keep);
                    total += keep;
                    if (keep != count) state.Exceeded = true;
                }
                output.Flush();
            }
        } catch (Exception error) { state.Error = error; }
        finally { state.Done.Set(); }
    }

    public static HostLinkNativeChild StartChild(string executable, string arguments, string workingDirectory, int maximumBytes, string stdoutPath, string stderrPath) {
        ProcessStartInfo info = new ProcessStartInfo();
        info.FileName = executable;
        info.Arguments = arguments;
        info.WorkingDirectory = workingDirectory;
        info.UseShellExecute = false;
        info.CreateNoWindow = true;
        info.RedirectStandardOutput = true;
        info.RedirectStandardError = true;
        Process process = new Process();
        process.StartInfo = info;
        if (!process.Start()) { process.Close(); throw new InvalidOperationException("could not start owned Agent child"); }
        CopyState stdout = new CopyState();
        stdout.Input = process.StandardOutput.BaseStream;
        stdout.OutputPath = stdoutPath;
        stdout.Maximum = maximumBytes;
        CopyState stderr = new CopyState();
        stderr.Input = process.StandardError.BaseStream;
        stderr.OutputPath = stderrPath;
        stderr.Maximum = maximumBytes;
        ThreadPool.QueueUserWorkItem(CopyStream, stdout);
        ThreadPool.QueueUserWorkItem(CopyStream, stderr);
        return new HostLinkNativeChild(process, stdout, stderr);
    }

    public static HostLinkNativeCaptureResult Run(string executable, string arguments, string workingDirectory, int timeoutMilliseconds, int maximumBytes, string stdoutPath, string stderrPath) {
        ProcessStartInfo info = new ProcessStartInfo();
        info.FileName = executable;
        info.Arguments = arguments;
        info.WorkingDirectory = workingDirectory;
        info.UseShellExecute = false;
        info.CreateNoWindow = true;
        info.RedirectStandardOutput = true;
        info.RedirectStandardError = true;
        Process process = new Process();
        process.StartInfo = info;
        CopyState stdout = new CopyState();
        CopyState stderr = new CopyState();
        try {
            if (!process.Start()) throw new InvalidOperationException("could not start child process");
            stdout.Input = process.StandardOutput.BaseStream;
            stdout.OutputPath = stdoutPath;
            stdout.Maximum = maximumBytes;
            stderr.Input = process.StandardError.BaseStream;
            stderr.OutputPath = stderrPath;
            stderr.Maximum = maximumBytes;
            ThreadPool.QueueUserWorkItem(CopyStream, stdout);
            ThreadPool.QueueUserWorkItem(CopyStream, stderr);
            HostLinkNativeCaptureResult result = new HostLinkNativeCaptureResult();
            if (!process.WaitForExit(timeoutMilliseconds)) {
                result.TimedOut = true;
                process.Kill();
                if (!process.WaitForExit(10000)) throw new TimeoutException("owned child did not exit after Kill");
            }
            if (!stdout.Done.WaitOne(10000) || !stderr.Done.WaitOne(10000)) throw new TimeoutException("owned child output streams did not close");
            if (stdout.Error != null) throw stdout.Error;
            if (stderr.Error != null) throw stderr.Error;
            result.OutputExceeded = stdout.Exceeded || stderr.Exceeded;
            result.ExitCode = process.ExitCode;
            return result;
        } finally { process.Close(); }
    }
}
'@
$receiptPath = Assert-OwnedRegularFile $BuildReceipt $sid 'BuildReceipt'
$binaryPaths = @{}
$binaryPaths['x64-agent'] = Assert-OwnedRegularFile $X64Agent $sid 'X64Agent'
$binaryPaths['x64-client'] = Assert-OwnedRegularFile $X64Client $sid 'X64Client'
$binaryPaths['x86-agent'] = Assert-OwnedRegularFile $X86Agent $sid 'X86Agent'
$binaryPaths['x86-client'] = Assert-OwnedRegularFile $X86Client $sid 'X86Client'
$hostPrivate = Assert-PrivateOwnedFile $HostPrivateKey $sid 'HostPrivateKey'
$hostPublic = Assert-OwnedRegularFile $HostPublicKey $sid 'HostPublicKey'
$controllerPrivate = Assert-PrivateOwnedFile $ControllerPrivateKey $sid 'ControllerPrivateKey'
$controllerPublic = Assert-OwnedRegularFile $ControllerPublicKey $sid 'ControllerPublicKey'
$buildEntries = @{
    'x64-agent' = @{Target='x86_64-win7-windows-msvc';Name='hostlink-agent.exe';Sha=(Get-Sha256 $binaryPaths['x64-agent'])}
    'x64-client' = @{Target='x86_64-win7-windows-msvc';Name='hostlink.exe';Sha=(Get-Sha256 $binaryPaths['x64-client'])}
    'x86-agent' = @{Target='i686-win7-windows-msvc';Name='hostlink-agent.exe';Sha=(Get-Sha256 $binaryPaths['x86-agent'])}
    'x86-client' = @{Target='i686-win7-windows-msvc';Name='hostlink.exe';Sha=(Get-Sha256 $binaryPaths['x86-client'])}
}
$artifactHashes = @{}
foreach ($entry in $buildEntries.GetEnumerator()) { $artifactHashes[$entry.Key] = [string]$entry.Value.Sha }
Assert-BuildReceipt $receiptPath $SourceSha $buildEntries

$hostPublicText = [IO.File]::ReadAllText($hostPublic, [Text.Encoding]::ASCII).Trim()
$controllerPublicText = [IO.File]::ReadAllText($controllerPublic, [Text.Encoding]::ASCII).Trim()
if ($hostPublicText -notmatch '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}( .*)?$' -or $controllerPublicText -notmatch '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}( .*)?$') { Stop-Harness 'host and controller public keys must be OpenSSH Ed25519 public-key lines' }
$hostPin = (($hostPublicText -split '\s+')[0..1] -join ' ')
$controllerPin = (($controllerPublicText -split '\s+')[0..1] -join ' ')
if ($hostPin -ceq $controllerPin) { Stop-Harness 'host and controller key pairs must be distinct for wrong-pin rejection' }
$run = Combine-Path $root ('hostlink-nt61-' + $SourceSha.Substring(0,12) + '-' + [Guid]::NewGuid().ToString('N'))
Set-PrivateDirectory $run $sid
$result = 'FAILED'
$exitCode = 1
$failure = $null
$cleanupOutcome = 'private-evidence-retained'
$hostCaptionLabel = 'NT6.1 Windows Server 2008 R2 Standard x64'
$modeResults = @()
$children = New-Object System.Collections.ArrayList
$serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$serializer.MaxJsonLength = 4194304

try {
    foreach ($mode in @(
        @{Name='x64-native';Agent=$binaryPaths['x64-agent'];Client=$binaryPaths['x64-client'];Architecture='x64'},
        @{Name='x86-wow64';Agent=$binaryPaths['x86-agent'];Client=$binaryPaths['x86-client'];Architecture='x86-on-x64-WOW64'}
    )) {
        $modeRoot = Combine-Path $run $mode.Name
        Set-PrivateDirectory $modeRoot $sid
        $jobs = Combine-Path $modeRoot 'jobs'
        Set-PrivateDirectory $jobs $sid
        $port = Find-LoopbackPort
        $agentConfigPath = Combine-Path $modeRoot 'agent.json'
        $clientConfigPath = Combine-Path $modeRoot 'host.json'
        $authorizedPath = Combine-Path $modeRoot 'authorized_keys'
        Write-PrivateText $authorizedPath ($controllerPublicText + "`n")
        $agentConfig = @{listen=('127.0.0.1:' + $port);user='hostlink-native';host_key=$hostPrivate;jobs_root=$jobs;authorized_keys=$authorizedPath;gateway=$null;gateway_alternates=@()}
        $clientConfig = @{endpoint=('127.0.0.1:' + $port);user='hostlink-native';identity=$controllerPrivate;host_public_key=$hostPin;gateway=$null}
        Write-PrivateText $agentConfigPath ($serializer.Serialize($agentConfig))
        Write-PrivateText $clientConfigPath ($serializer.Serialize($clientConfig))

        $checkOut = Combine-Path $modeRoot 'agent-check.stdout.txt'
        $checkErr = Combine-Path $modeRoot 'agent-check.stderr.txt'
        $checkExit = Invoke-Captured $mode.Agent @('check','--config',$agentConfigPath) $modeRoot $checkOut $checkErr 30000
        if ($checkExit -ne 0) { Stop-Harness ($mode.Name + ' Agent check failed') }

        $agentStdout = Combine-Path $modeRoot 'agent-run.stdout.txt'
        $agentStderr = Combine-Path $modeRoot 'agent-run.stderr.txt'
        $agentChild = [HostLinkNativeCapture]::StartChild($mode.Agent, ((Quote-ProcessArgument 'run') + ' ' + (Quote-ProcessArgument '--config') + ' ' + (Quote-ProcessArgument $agentConfigPath)), $modeRoot, $script:MaxCapturedBytes, $agentStdout, $agentStderr)
        $agentProcess = $agentChild.Process
        [void]$children.Add(@{Process=$agentProcess;Capture=$agentChild;Mode=$mode.Name;Id=$agentProcess.Id;Path=$mode.Agent})
        $ready = $false
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        $probeAttempt = 0
        while ([DateTime]::UtcNow -lt $deadline) {
            if ($agentProcess.HasExited) { Stop-Harness ($mode.Name + ' Agent exited before SSH readiness') }
            $probeAttempt++
            $clientOut = Combine-Path $modeRoot ('client-check-' + $probeAttempt + '.stdout.txt')
            $clientErr = Combine-Path $modeRoot ('client-check-' + $probeAttempt + '.stderr.txt')
            $clientExit = Invoke-Captured $mode.Client @('check','--config',$clientConfigPath) $modeRoot $clientOut $clientErr 10000
            if ($clientExit -eq 0) { $ready = $true; break }
            Start-Sleep -Milliseconds 500
        }
        if (-not $ready) { Stop-Harness ($mode.Name + ' SSH readiness deadline expired') }

        $execOut = Combine-Path $modeRoot 'exec.stdout.txt'
        $execErr = Combine-Path $modeRoot 'exec.stderr.txt'
        $execExit = Invoke-Captured $mode.Client @('exec','--config',$clientConfigPath,'--command','exit 7') $modeRoot $execOut $execErr 30000
        if ($execExit -ne 7) { Stop-Harness ($mode.Name + ' SSH exec did not preserve remote exit 7') }

        $payloadPath = Combine-Path $modeRoot 'sftp-source.bin'
        $payload = [byte[]](0,1,2,127,128,254,255,10,13)
        [IO.File]::WriteAllBytes($payloadPath, $payload)
        $payloadSha = Get-Sha256 $payloadPath
        $remoteName = $payloadSha + '.upload'
        $uploadOut = Combine-Path $modeRoot 'upload.stdout.txt'
        $uploadErr = Combine-Path $modeRoot 'upload.stderr.txt'
        $uploadExit = Invoke-Captured $mode.Client @('upload','--config',$clientConfigPath,'--local',$payloadPath,'--remote',$remoteName) $modeRoot $uploadOut $uploadErr 30000
        if ($uploadExit -ne 0) { Stop-Harness ($mode.Name + ' SFTP upload failed') }
        $downloadPath = Combine-Path $modeRoot 'sftp-downloaded.bin'
        $downloadOut = Combine-Path $modeRoot 'download.stdout.txt'
        $downloadErr = Combine-Path $modeRoot 'download.stderr.txt'
        $downloadExit = Invoke-Captured $mode.Client @('download','--config',$clientConfigPath,'--remote',$remoteName,'--local',$downloadPath) $modeRoot $downloadOut $downloadErr 30000
        if ($downloadExit -ne 0 -or (Get-Sha256 $downloadPath) -cne $payloadSha) { Stop-Harness ($mode.Name + ' SFTP download digest mismatch') }

        $wrongPinConfig = Combine-Path $modeRoot 'wrong-pin.json'
        $wrongPin = $clientConfig.Clone()
        $wrongPin['host_public_key'] = $controllerPin
        Write-PrivateText $wrongPinConfig ($serializer.Serialize($wrongPin))
        $negativePinExit = Invoke-Captured $mode.Client @('check','--config',$wrongPinConfig) $modeRoot (Combine-Path $modeRoot 'wrong-pin.stdout.txt') (Combine-Path $modeRoot 'wrong-pin.stderr.txt') 15000
        if ($negativePinExit -eq 0) { Stop-Harness ($mode.Name + ' accepted an incorrect host key pin') }
        $wrongUserConfig = Combine-Path $modeRoot 'wrong-user.json'
        $wrongUser = $clientConfig.Clone()
        $wrongUser['user'] = 'hostlink-unknown'
        Write-PrivateText $wrongUserConfig ($serializer.Serialize($wrongUser))
        $negativeUserExit = Invoke-Captured $mode.Client @('check','--config',$wrongUserConfig) $modeRoot (Combine-Path $modeRoot 'wrong-user.stdout.txt') (Combine-Path $modeRoot 'wrong-user.stderr.txt') 15000
        if ($negativeUserExit -eq 0) { Stop-Harness ($mode.Name + ' accepted an unknown SSH user') }

        $modeResults += @{name=$mode.Name;architecture=$mode.Architecture;port=$port;agent_check_exit=$checkExit;client_check_exit=$clientExit;exec_exit=$execExit;upload_exit=$uploadExit;download_exit=$downloadExit;negative_wrong_pin_exit=$negativePinExit;negative_unknown_user_exit=$negativeUserExit;payload_sha256=$payloadSha}
        $agentProcess.Kill()
        if (-not $agentProcess.WaitForExit(10000)) { Stop-Harness ($mode.Name + ' owned Agent child did not stop') }
        $agentChild.Finish()
        $agentProcess.Close()
        $children.RemoveAt($children.Count - 1)
        if ($agentChild.OutputExceeded) { Stop-Harness ($mode.Name + ' Agent output exceeded bounded capture') }
    }
    $result = 'PASS_NT61_SERVER_2008_R2_X64_SSH_SFTP_X64_AND_X86_WOW64'
    $exitCode = 0
} catch {
    $failure = $_.Exception.Message
    $exitCode = 1
} finally {
    foreach ($child in @($children)) {
        try {
            $process = $child.Process
            if (-not $process.HasExited) {
                # Kill only the Process object started above, never a PID lookup or discovered process.
                $process.Kill()
                if (-not $process.WaitForExit(10000)) { $cleanupOutcome = 'FAILED-owned-child-did-not-exit'; $result = 'FAILED_CLEANUP'; $exitCode = 1 }
            }
            $child.Capture.Finish()
            if ($child.Capture.OutputExceeded) { $cleanupOutcome = 'FAILED-owned-child-output-limit'; $result = 'FAILED_CLEANUP'; $exitCode = 1 }
            $process.Close()
        } catch { $cleanupOutcome = 'FAILED-owned-child-cleanup'; $result = 'FAILED_CLEANUP'; $exitCode = 1 }
    }
    $streamHashes = @{stdout=@{};stderr=@{}}
    if ([IO.Directory]::Exists($run)) {
        foreach ($file in Get-ChildItem -LiteralPath $run -Recurse -Force | Where-Object { -not $_.PSIsContainer }) {
            if ($file.Name -like '*.stdout.txt') { $streamHashes.stdout[$file.FullName.Substring($run.Length + 1)] = Get-Sha256 $file.FullName }
            elseif ($file.Name -like '*.stderr.txt') { $streamHashes.stderr[$file.FullName.Substring($run.Length + 1)] = Get-Sha256 $file.FullName }
        }
    }
    $receipt = @{
        schema_version=1;status=$result;source_sha=$SourceSha
        os=@{caption=$osCaption;version=$osVersion;architecture='x64';label=$hostCaptionLabel}
        identity=@{sid=$sid.Value;elevated=$false;session_id=$sessionId}
        powershell=[string]$PSVersionTable.PSVersion;exit_code=$exitCode;failure=$failure
        build_receipt_sha256=(Get-Sha256 $receiptPath);artifact_sha256=$artifactHashes
        key_input_paths=@{host_private=$hostPrivate;host_public=$hostPublic;controller_private=$controllerPrivate;controller_public=$controllerPublic}
        modes=$modeResults;stdout_sha256=$streamHashes.stdout;stderr_sha256=$streamHashes.stderr
        cleanup_outcome=$cleanupOutcome;evidence_root=$run
    }
    Write-PrivateText (Combine-Path $run 'native-acceptance-receipt.json') ($serializer.Serialize($receipt))
}
if ($null -ne $failure) { Stop-Harness $failure }
if ($exitCode -ne 0 -or $result -notmatch '^PASS_') { Stop-Harness ('acceptance did not pass; status=' + $result + '; exit_code=' + $exitCode) }
Write-Output ('PASS: ' + $result + '; source_sha=' + $SourceSha)
Write-Output ('OS: ' + $hostCaptionLabel + ' (' + $osCaption + ' ' + $osVersion + '); PowerShell ' + [string]$PSVersionTable.PSVersion)
Write-Output ('EVIDENCE: ' + (Combine-Path $run 'native-acceptance-receipt.json'))
