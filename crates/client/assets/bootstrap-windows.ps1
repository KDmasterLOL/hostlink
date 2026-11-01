$identity = Get-BootstrapIdentity
$is64BitOS = ([IntPtr]::Size -eq 8) -or ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64')
if (-not $is64BitOS -and $Target.StartsWith('x86_64-')) { throw 'The selected x64 target cannot run on a 32-bit Windows OS.' }
$os = Get-WmiObject -Class Win32_OperatingSystem
$osVersion = [Version]$os.Version
if ($Target -like '*-win7-*' -and ($osVersion.Major -ne 6 -or $osVersion.Minor -ne 1)) { throw 'A Win7 Agent target requires Windows NT 6.1.' }
if ($Target -eq 'x86_64-pc-windows-msvc' -and ([int]$os.BuildNumber -lt 22000)) { throw 'The selected standard Windows target requires a Windows 11 build.' }
if ($Target -eq 'i686-win7-windows-msvc' -and $is64BitOS) { throw 'The selected Win7 x86 target requires a 32-bit Windows OS, not WOW64.' }
$localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
if ([string]::IsNullOrEmpty($localAppData) -or -not [IO.Path]::IsPathRooted($localAppData)) { throw 'Current-user LocalAppData is unavailable.' }
$root = Join-Path $localAppData 'HostLink\Agent'
$stage = Join-Path ([IO.Path]::GetTempPath()) ('hostlink-bootstrap-' + [Guid]::NewGuid().ToString('N'))
Set-PrivateDirectory $stage $identity.User
$agentFile = Join-Path $stage 'hostlink-agent.exe'
$tokenFile = Join-Path $stage 'invite-token'
try {
    Get-GitHubAsset $AgentUri $agentFile 268435456 120
    $algorithm = New-Object Security.Cryptography.SHA256Managed
    $stream = [IO.File]::OpenRead($agentFile)
    try { $actual = ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Close(); $algorithm.Clear() }
    if ($actual -cne $AgentSha256) { throw 'Agent executable SHA-256 mismatch.' }
    # No executable code or one-use token prompt before the digest matches.
    [void](Write-PrivateSecret $tokenFile $identity.User 'One-use HostLink invite token' '[0-9a-f]' 64 64)
    if ([string]::IsNullOrEmpty($HubCaCert)) {
        & $agentFile install --hub-url $HubUrl --token-file $tokenFile --name $Name --user $SshUser
    } else {
        & $agentFile install --hub-url $HubUrl --token-file $tokenFile --name $Name --user $SshUser --hub-ca-cert $HubCaCert
    }
    if ($LASTEXITCODE -ne 0) { throw 'Agent install failed.' }
    Remove-Item -LiteralPath $stage -Recurse -Force
    $installedAgent = Join-Path $root 'bin\hostlink-agent.exe'
    $config = Join-Path $root 'state\agent.json'
    if ($NoRun) {
        Write-Output ('Installation complete. Start the Agent with: & "' + $installedAgent + '" run --config "' + $config + '"')
    } else {
        & $installedAgent run --config $config
        if ($LASTEXITCODE -ne 0) { throw 'Agent stopped with an error.' }
    }
} finally {
    if ([IO.Directory]::Exists($stage)) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
