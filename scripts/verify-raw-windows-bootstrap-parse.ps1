param([Parameter(Mandatory=$true)][string[]]$Path)
$ErrorActionPreference = 'Stop'
if ($Path.Count -eq 0) { throw 'Explicit fixture paths required' }

# Self-test the parser without evaluating either string.
$errors = $null
[void][System.Management.Automation.PSParser]::Tokenize('function broken {', [ref]$errors)
if ($null -eq $errors -or $errors.Count -eq 0) { throw 'Parser negative self-test failed' }
Write-Output 'MALFORMED_REJECTED'

$failed = $false
foreach ($item in $Path) {
    try {
        $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $item).ProviderPath)
        if ($bytes.Length -eq 0 -or $bytes.Length -gt 1048576) { throw 'Invalid fixture size' }
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $hash = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
        $text = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($bytes)
        $provision = [regex]::Matches($text, '(?m)^\[void\]\(Get-GitHubCredential \$true(?: ''github_pat_synthetic_fixture_123'')?\)\r?$')
        if ($provision.Count -ne 1) { throw 'Invalid synthetic fixture credential provision' }
        # The exporter uses this one literal synthetic token; refuse other PAT-looking text.
        $sanitized = $text.Replace('github_pat_synthetic_fixture_123', '')
        if ($sanitized -match 'github_pat_|gh[pousr]_[A-Za-z0-9_]') { throw 'Non-fixture credential marker' }
        $errors = $null
        [void][System.Management.Automation.PSParser]::Tokenize($text, [ref]$errors)
        if ($null -ne $errors -and $errors.Count -gt 0) { $failed = $true; $result = 'PARSE_FAIL' }
        else { $result = 'PARSE_PASS' }
        Write-Output ("{0} {1} sha256={2}" -f $result, [System.IO.Path]::GetFileName($item), $hash)
    } catch {
        $failed = $true
        Write-Output ("PARSE_ERROR {0}" -f [System.IO.Path]::GetFileName($item))
    }
}
if ($failed) { exit 1 }
exit 0
