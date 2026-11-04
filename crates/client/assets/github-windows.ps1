# Target-local bootstrap helpers, never installed; compatible with PowerShell 2/.NET 3.5.
function Assert-GitHubAsset([string]$Url) {
    if ($Url -cnotmatch '\Ahttps://github\.com/KDmasterLOL/hostlink/releases/download/v[^/]+/hostlink-agent-[^/]+\z') { throw 'Expected a public HostLink release asset URL.' }
}
function Assert-NoReparse([string]$Path) {
    $part = New-Object IO.DirectoryInfo($Path)
    while ($null -ne $part) {
        if (([IO.File]::GetAttributes($part.FullName) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Credential ancestor must not be a reparse point.' }
        $part = $part.Parent
    }
}
function Set-PrivateDirectory([string]$Path, [Security.Principal.SecurityIdentifier]$Sid) {
    if ([IO.Directory]::Exists($Path) -or [IO.File]::Exists($Path)) { throw 'Bootstrap staging path already exists.' }
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetOwner($Sid)
    $security.SetAccessRuleProtection($true, $false)
    # Child files inherit only the current user SID.
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($Sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    [void]$security.AddAccessRule($rule)
    [void][IO.Directory]::CreateDirectory($Path, $security)
    Assert-PrivateDirectory $Path $Sid
}
function Assert-PrivateDirectory([string]$Path, [Security.Principal.SecurityIdentifier]$Sid) {
    $directory = New-Object IO.DirectoryInfo($Path)
    if (-not $directory.Exists -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Private directory is missing or a reparse point.' }
    $acl = $directory.GetAccessControl()
    if (-not $acl.GetOwner([Security.Principal.SecurityIdentifier]).Equals($Sid) -or -not $acl.AreAccessRulesProtected) { throw 'Private directory owner or ACL is unsafe.' }
    $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    if ($rules.Count -ne 1) { throw 'Private directory must have exactly one current-user ACL entry.' }
    $rule = $rules[0]
    if (-not $rule.IdentityReference.Equals($Sid) -or
        $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
        $rule.InheritanceFlags -ne ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit) -or
        $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { throw 'Private directory ACL differs from owner-only policy.' }
}
function Get-BootstrapIdentity {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity -or $null -eq $identity.User -or @('S-1-5-18','S-1-5-19','S-1-5-20') -contains $identity.User.Value) { throw 'Bootstrap requires a normal interactive user.' }
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) { throw 'Bootstrap must run unelevated in the current user session.' }
    return $identity
}
function Write-PrivateSecret([string]$Path, [Security.Principal.SecurityIdentifier]$Sid, [string]$Prompt, [string]$Characters, [int]$Minimum, [int]$Maximum, [string]$EmbeddedToken) {
    $secure = $null; $pointer = [IntPtr]::Zero; $bytes = $null; $stream = $null
    try {
        if ([string]::IsNullOrEmpty($EmbeddedToken)) {
            $secure = Read-Host $Prompt -AsSecureString
            $length = $secure.Length
            $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        } else { $length = $EmbeddedToken.Length }
        if ($length -lt $Minimum -or $length -gt $Maximum) { throw 'Invalid secret size.' }
        $bytes = New-Object byte[] $length
        for ($i = 0; $i -lt $length; $i++) {
            if ($null -ne $secure) { $character = [char][Runtime.InteropServices.Marshal]::ReadInt16($pointer, 2 * $i) }
            else { $character = $EmbeddedToken[$i] }
            if ($character -cnotmatch ('\A' + $Characters + '\z')) { throw 'Invalid secret format.' }
            $bytes[$i] = [byte]$character
        }
        $security = New-Object Security.AccessControl.FileSecurity
        $security.SetOwner($Sid)
        $security.SetAccessRuleProtection($true, $false)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($Sid, 'FullControl', 'Allow')
        [void]$security.AddAccessRule($rule)
        # Atomic CreateNew with a protected DACL; never expose bytes before fixing ACLs.
        $stream = New-Object IO.FileStream($Path, [IO.FileMode]::CreateNew, [Security.AccessControl.FileSystemRights]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::None, $security)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        return $security
    } finally {
        if ($null -ne $stream) { $stream.Close() }
        if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
        if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
        if ($null -ne $secure) { $secure.Dispose() }
    }
}
function Get-GitHubAsset([string]$Url, [string]$Destination, [long]$MaximumBytes, [int]$DeadlineSeconds) {
    Assert-GitHubAsset $Url
    $response = $null; $output = $null; $inputStream = $null; $request = $null; $created = $false; $complete = $false
    $clock = [Diagnostics.Stopwatch]::StartNew()
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
        for ($hop = 0; $hop -le 1; $hop++) {
            $remaining = [int]($DeadlineSeconds * 1000 - $clock.ElapsedMilliseconds)
            if ($remaining -le 0) { throw 'Download deadline exceeded.' }
            $request = [Net.HttpWebRequest]::Create((New-Object Uri($Url)))
            $request.AllowAutoRedirect = $false
            $request.UseDefaultCredentials = $false
            $request.Method = 'GET'
            $request.UserAgent = 'HostLink-bootstrap'
            $request.Accept = 'application/octet-stream'
            $request.Timeout = [Math]::Min(30000, $remaining)
            $request.ReadWriteTimeout = [Math]::Min(30000, $remaining)
            $response = $request.GetResponse()
            if ([int]$response.StatusCode -eq 200) { break }
            if ([int]$response.StatusCode -ne 302 -or $hop -ne 0) { throw 'Download response rejected.' }
            $Url = $response.Headers['Location']
            if ($Url -cnotmatch '\Ahttps://(release-assets|objects)\.githubusercontent\.com/[^\s\\#]+\z') { throw 'Download redirect destination rejected.' }
            $response.Close(); $response = $null
        }
        if ($response.ContentLength -gt $MaximumBytes) { throw 'Download size limit exceeded.' }
        $inputStream = $response.GetResponseStream()
        $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None); $created = $true
        $buffer = New-Object byte[] 65536
        $total = 0L
        while ($true) {
            $remaining = [int]($DeadlineSeconds * 1000 - $clock.ElapsedMilliseconds)
            if ($remaining -le 0) { throw 'Download deadline exceeded.' }
            $inputStream.ReadTimeout = [Math]::Min(30000, $remaining)
            $count = $inputStream.Read($buffer, 0, $buffer.Length)
            if ($clock.ElapsedMilliseconds -ge $DeadlineSeconds * 1000) { throw 'Download deadline exceeded.' }
            if ($count -eq 0) { break }
            $total += $count
            if ($total -gt $MaximumBytes) { throw 'Download size limit exceeded.' }
            $output.Write($buffer, 0, $count)
        }
        $output.Flush()
        $complete = $true
    } catch { throw 'GitHub asset download failed (TLS, HTTP, deadline or size); no fallback.' }
    finally {
        if ($null -ne $request) { $request.Abort() }
        if ($null -ne $inputStream) { $inputStream.Close() }
        if ($null -ne $response) { $response.Close() }
        if ($null -ne $output) { $output.Close() }
        if ($created -and -not $complete) { [IO.File]::Delete($Destination) }
        $clock.Stop()
    }
}
