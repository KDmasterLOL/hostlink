$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    throw 'LOCALAPPDATA is not available for this user.'
}

$sourcePath = Join-Path $PSScriptRoot 'onec-access.exe'
if (-not [IO.File]::Exists($sourcePath)) {
    throw "Expected onec-access.exe beside this installer: $sourcePath"
}

$destinationDirectory = Join-Path $env:LOCALAPPDATA 'Programs\onec-toolkit\controller'
$destinationPath = Join-Path $destinationDirectory 'onec-access.exe'
$shellDirectory = Join-Path $env:LOCALAPPDATA 'onec-toolkit\shell-bin'
$shellWrapper = Join-Path $shellDirectory 'onec-access.cmd'
New-Item -ItemType Directory -Force -Path $destinationDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $shellDirectory | Out-Null

$stagedPath = Join-Path $destinationDirectory ('onec-access.' + [Guid]::NewGuid().ToString('N') + '.exe')
$backupPath = Join-Path $destinationDirectory ('onec-access.' + [Guid]::NewGuid().ToString('N') + '.bak')
try {
    Copy-Item -LiteralPath $sourcePath -Destination $stagedPath
    & $stagedPath --version | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'The staged onec-access.exe failed its version check.'
    }

    if ([IO.File]::Exists($destinationPath)) {
        [IO.File]::Replace($stagedPath, $destinationPath, $backupPath, $true)
        [IO.File]::Delete($backupPath)
    } else {
        [IO.File]::Move($stagedPath, $destinationPath)
    }
} finally {
    if ([IO.File]::Exists($stagedPath)) { [IO.File]::Delete($stagedPath) }
    if ([IO.File]::Exists($backupPath)) { [IO.File]::Delete($backupPath) }
}

$wrapperContent = "@echo off`r`n`"%LOCALAPPDATA%\Programs\onec-toolkit\controller\onec-access.exe`" %*`r`n"
Set-Content -LiteralPath $shellWrapper -Value $wrapperContent -Encoding Ascii -NoNewline

$userPath = [Environment]::GetEnvironmentVariable('Path', [EnvironmentVariableTarget]::User)
$pathEntries = @($userPath -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$alreadyPresent = $false
foreach ($entry in $pathEntries) {
    if ($entry.TrimEnd('\').Equals($shellDirectory.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
        $alreadyPresent = $true
        break
    }
}
if (-not $alreadyPresent) {
    $updatedUserPath = (@($pathEntries) + $shellDirectory) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $updatedUserPath, [EnvironmentVariableTarget]::User)
}

$processEntries = @($env:Path -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$processHasInstall = $false
foreach ($entry in $processEntries) {
    if ($entry.TrimEnd('\').Equals($shellDirectory.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
        $processHasInstall = $true
        break
    }
}
if (-not $processHasInstall) { $env:Path = (@($processEntries) + $shellDirectory) -join ';' }

Write-Host 'onec-access installed for the current user.'
Write-Host ('Executable: ' + $destinationPath)
Write-Host ('Shell wrapper: ' + $shellWrapper)
Write-Host 'If shell-bin was not already in the parent terminal PATH, open a new terminal before using onec-access.'
