$identity = Get-BootstrapIdentity
$arch = $env:PROCESSOR_ARCHITECTURE
if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }
$os = Get-WmiObject -Class Win32_OperatingSystem
$version = [Version]$os.Version
if ($version.Major -eq 6 -and $version.Minor -eq 1) {
    if ($arch -eq 'AMD64') { $Target = 'x86_64-win7-windows-msvc'; $AgentSha256 = $ShaWin7X64 }
    elseif ($arch -eq 'x86') { $Target = 'i686-win7-windows-msvc'; $AgentSha256 = $ShaWin7X86 }
    else { throw 'Unsupported Windows architecture.' }
} elseif ($version.Major -eq 10 -and [int]$os.BuildNumber -ge 10240 -and $arch -eq 'AMD64') {
    $Target = 'x86_64-pc-windows-msvc'; $AgentSha256 = $ShaWin11X64
} else { throw 'Unsupported Windows version or architecture.' }
if ($RequestedTarget -and $RequestedTarget -ne $Target) { throw 'Selected target does not match this Windows system.' }
if ($AgentSha256 -cnotmatch '\A[0-9a-f]{64}\z') { throw 'No matching release digest.' }
$AgentUri = 'https://github.com/KDmasterLOL/hostlink/releases/download/' + $ReleaseTag + '/hostlink-agent-' + $Target + '.exe'
$localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
if ([string]::IsNullOrEmpty($localAppData) -or -not [IO.Path]::IsPathRooted($localAppData)) { throw 'Current-user LocalAppData is unavailable.' }
$root = Join-Path $localAppData 'HostLink\Agent'
$stage = Join-Path ([IO.Path]::GetTempPath()) ('hostlink-bootstrap-' + [Guid]::NewGuid().ToString('N'))
Set-PrivateDirectory $stage $identity.User
$agentFile = Join-Path $stage 'hostlink-agent.exe'
$tokenFile = Join-Path $stage 'invite-token'
try {
    if ($version.Major -eq 6) { Get-Win7Asset $AgentUri $agentFile 268435456 120 }
    else { Get-GitHubAsset $AgentUri $agentFile 268435456 120 }
    $algorithm = New-Object Security.Cryptography.SHA256Managed
    $stream = [IO.File]::OpenRead($agentFile)
    try { $actual = ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Close(); $algorithm.Clear() }
    if ($actual -cne $AgentSha256) { throw 'Agent executable SHA-256 mismatch.' }
    # No executable code or one-use token prompt before the digest matches.
    [void](Write-PrivateSecret $tokenFile $identity.User 'One-use HostLink invite token' '[0-9a-f]' 64 64 $Invite)
    $installArgs = @('install', '--hub-url', $HubUrl, '--token-file', $tokenFile, '--name', $Name, '--user', $SshUser)
    if (-not [string]::IsNullOrEmpty($HubCaCert)) { $installArgs += @('--hub-ca-cert', $HubCaCert) }
    if (-not [string]::IsNullOrEmpty($GatewayIndex)) { $installArgs += @('--gateway-index', $GatewayIndex) }
    if ($MachineId) { $installArgs += @('--machine-id', $MachineId) }
    if ($ReplaceIdentity) { $installArgs += '--replace-identity' }
    & $agentFile @installArgs
    if ($LASTEXITCODE -ne 0) { throw 'Agent install failed.' }
    Remove-Item -LiteralPath $stage -Recurse -Force
    $installedAgent = Join-Path $root 'bin\hostlink-agent.exe'
    $config = Join-Path $root 'state\agent.json'
    & $installedAgent service install --root $root --config $config
    if ($LASTEXITCODE -ne 0) { throw 'Service install failed.' }
    & $installedAgent service start --root $root
    if ($LASTEXITCODE -ne 0) { throw 'Service start failed.' }
} finally {
    if ([IO.Directory]::Exists($stage)) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
