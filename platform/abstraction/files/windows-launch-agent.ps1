<#
OpenInfra launch agent for Windows instances: the Windows counterpart of the Linux instance metadata
agent. It behaves as EC2Launch v2 does for what a workload observes.

Windows PowerShell 5.1 (.NET Framework 4.7.2+) on Windows Server 2019, 2022 and 2025. Nothing beyond what
ships with Windows, and no internet access at runtime.

The instance's launch CD carries this script (as openinfra-launch.ps1), launch-config.json, user-data (the
instance's user data exactly as instance metadata serves it, when it has any), platform-root-ca.pem and
aws-endpoints-ca.pem. Its identity CD carries the instance's identity token (files token and namespace).
Drives are found by what they carry, never by letter.

Modes:
  -Install  Run once by Windows Setup (specialize pass, as LocalSystem; the network may be down). Installs
            C:\ProgramData\openinfra\launch\launch-stub.ps1 and registers the "OpenInfra Launch" scheduled
            task, which runs the stub at every startup. The stub finds the launch CD and runs this script's
            -Run from it, so the agent an instance runs is always the one its launch CD carries. Idempotent.
  -Run      Each boot. Trusts the platform's CAs (and publishes AWS_CA_BUNDLE); brings up instance metadata
            (IMDSv1 and IMDSv2) on 169.254.169.254:80 in a separate -Serve process (a TCP listener on that
            address alone, so port 80 stays free for the workload; the address is on the agent's own
            loopback adapter, "OpenInfra Metadata", and the instance's NICs are never changed), checks
            from the instance that it answers; on the first boot of
            this instance id extends C: to the end of its disk; writes "Message: Windows is Ready to use" to
            the serial console; then runs the user data as EC2Launch v2 does (XML <script> and <powershell>
            blocks, once per instance unless <persist>true</persist>; not at all when instance metadata is
            disabled, as EC2Launch v2 reads it from there). It then stays running to keep the metadata
            service up.
  -Serve    Internal: the instance metadata service process.

Logs: C:\ProgramData\openinfra\launch\log\agent.log and userdata.log, and the serial console (COM1), which
EC2's GetConsoleOutput shows. User data, credentials and the identity token are never written to a log.

Loading the file with dot-sourcing (". .\windows-launch-agent.ps1") only defines its functions: the pure
ones (user data parsing, the metadata router, IMDSv2 tokens, credential refresh) are tested that way.
#>
[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Run,
    [switch]$Serve
)

# ---------------------------------------------------------------------------------------------------------
# Constants.
# ---------------------------------------------------------------------------------------------------------

$script:OIBase = 'C:\ProgramData\openinfra'
$script:OIRoot = 'C:\ProgramData\openinfra\launch'
$script:OILogDir = 'C:\ProgramData\openinfra\launch\log'
$script:OIWorkDir = 'C:\ProgramData\openinfra\launch\userdata'
$script:OIAgentLog = 'C:\ProgramData\openinfra\launch\log\agent.log'
$script:OIUserDataLog = 'C:\ProgramData\openinfra\launch\log\userdata.log'
$script:OIStatePath = 'C:\ProgramData\openinfra\launch\state.json'
$script:OIStubPath = 'C:\ProgramData\openinfra\launch\launch-stub.ps1'
$script:OICaBundlePath = 'C:\ProgramData\openinfra\launch\ca-bundle.pem'
$script:OITaskName = 'OpenInfra Launch'
$script:OIAgentFileName = 'openinfra-launch.ps1'
$script:OILaunchConfigName = 'launch-config.json'
$script:OIUserDataName = 'user-data'
$script:OIPlatformCaName = 'platform-root-ca.pem'
$script:OIAwsEndpointsCaName = 'aws-endpoints-ca.pem'
$script:OIImdsAddress = '169.254.169.254'
$script:OIImdsPrefix = 'http://169.254.169.254:80/'
$script:OIFirewallRuleName = 'OpenInfra-InstanceMetadata-In'
$script:OIMetadataAdapterName = 'OpenInfra Metadata'
$script:OILoopbackHardwareId = '*MSLOOP'
$script:OIAdapterDevicePath = 'C:\ProgramData\openinfra\launch\metadata-adapter.txt'
$script:OILoopbackBefore = $null
$script:OITokenHeader = 'X-aws-ec2-metadata-token'
$script:OITokenTtlHeader = 'X-aws-ec2-metadata-token-ttl-seconds'
$script:OIMaxTokenTtl = 21600
$script:OIDefaultPowerShellArgs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass'
$script:OILogCapBytes = 10485760

$script:OIVersions = @(
    '1.0', '2007-01-19', '2007-03-01', '2007-08-29', '2007-10-10', '2007-12-15', '2008-02-01',
    '2008-09-01', '2009-04-04', '2011-01-01', '2011-05-01', '2012-01-12', '2014-02-25',
    '2014-11-05', '2015-10-20', '2016-04-19', '2016-06-30', '2016-09-02', '2018-03-28',
    '2018-08-17', '2018-09-24', '2019-10-01', '2020-10-27', '2021-01-03', '2021-03-23',
    '2021-07-15', '2022-09-24', 'latest'
)

$script:OINotFoundBody = (@(
    '<?xml version="1.0" encoding="iso-8859-1"?>',
    '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"',
    ("`t" + '"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">'),
    '<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">',
    ' <head>',
    '  <title>404 - Not Found</title>',
    ' </head>',
    ' <body>',
    '  <h1>404 - Not Found</h1>',
    ' </body>',
    '</html>'
) -join "`n") + "`n"

# What the platform's refusals mean, appended to the error a caller of iam/security-credentials sees.
$script:OICredsHints = @{
    401 = " - the instance's identity was not accepted by the platform"
    403 = " - the instance profile's role does not trust ec2.amazonaws.com"
}
$script:OIIdentityHints = @{
    401 = " - the instance's identity was not accepted by the platform"
}

$script:OITimestampPattern = '^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.\d+)?(Z|[+-]\d\d:?\d\d)?$'
$script:OIInvariant = [System.Globalization.CultureInfo]::InvariantCulture

# ---------------------------------------------------------------------------------------------------------
# Small pure helpers.
# ---------------------------------------------------------------------------------------------------------

function Format-OILogLine {
    # One log line as EC2Launch v2 writes them to the console: "yyyy/MM/dd HH:mm:ssZ: <message>" (UTC).
    param([datetime]$Time, [string]$Message)
    $text = ([string]$Message) -replace "[`r`n]+", ' '
    return $Time.ToUniversalTime().ToString("yyyy'/'MM'/'dd HH':'mm':'ss'Z: '", $script:OIInvariant) + $text
}

function Get-OIField {
    # A field of a parsed JSON object (PSCustomObject) or a dictionary; $null when absent.
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function ConvertTo-OIText {
    # A JSON value as the text it was sent as. PowerShell 7's ConvertFrom-Json turns ISO 8601 strings into
    # DateTime values; Windows PowerShell 5.1 leaves them strings. Either way the RFC 3339 text comes back.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        return $Value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH':'mm':'ss'Z'", $script:OIInvariant)
    }
    if ($Value -is [System.DateTimeOffset]) {
        return $Value.UtcDateTime.ToString("yyyy-MM-dd'T'HH':'mm':'ss'Z'", $script:OIInvariant)
    }
    return [string]$Value
}

function ConvertTo-OINull {
    # "" -> $null: a metadata entry with no value is not served (404), as on EC2.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ([string]$Value -eq '') { return $null }
    return $Value
}

function ConvertTo-OIJsonString {
    # A JSON string literal, escaped as Python's json.dumps does by default (non-ASCII as \uXXXX).
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return 'null' }
    $s = [string]$Value
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    foreach ($ch in $s.ToCharArray()) {
        $c = [int]$ch
        if ($c -eq 34) { [void]$sb.Append('\"') }
        elseif ($c -eq 92) { [void]$sb.Append('\\') }
        elseif ($c -eq 10) { [void]$sb.Append('\n') }
        elseif ($c -eq 13) { [void]$sb.Append('\r') }
        elseif ($c -eq 9) { [void]$sb.Append('\t') }
        elseif ($c -eq 8) { [void]$sb.Append('\b') }
        elseif ($c -eq 12) { [void]$sb.Append('\f') }
        elseif ($c -lt 32 -or $c -gt 126) { [void]$sb.Append('\u' + $c.ToString('x4')) }
        else { [void]$sb.Append($ch) }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function ConvertTo-OIAwsJson {
    # A flat document in EC2 instance metadata's JSON layout: two-space indent, "key" : value, in the
    # order given, and a trailing newline.
    param([System.Collections.IDictionary]$Document)
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($k in $Document.Keys) {
        $lines.Add('  ' + (ConvertTo-OIJsonString $k) + ' : ' + (ConvertTo-OIJsonString $Document[$k]))
    }
    if ($lines.Count -eq 0) { return "{}`n" }
    return "{`n" + ($lines -join ",`n") + "`n" + '}' + "`n"
}

function ConvertFrom-OITimestamp {
    # RFC 3339 timestamp -> epoch seconds (UTC when it carries no offset). Throws when it is malformed.
    param([AllowNull()][string]$Text)
    $m = [regex]::Match(([string]$Text).Trim(), $script:OITimestampPattern)
    if (-not $m.Success) { throw ("unparseable timestamp '{0}'" -f $Text) }
    $g = $m.Groups
    $dt = New-Object System.DateTime ([int]$g[1].Value), ([int]$g[2].Value), ([int]$g[3].Value), ([int]$g[4].Value), ([int]$g[5].Value), ([int]$g[6].Value), ([System.DateTimeKind]::Utc)
    $ts = [double](New-Object System.DateTimeOffset $dt).ToUnixTimeSeconds()
    $tz = $g[7].Value
    if ($tz -and $tz -ne 'Z') {
        $sign = 1
        if ($tz[0] -eq '+') { $sign = -1 }
        $hh = [int]$tz.Substring(1, 2)
        $mm = [int]$tz.Substring($tz.Length - 2, 2)
        $ts += $sign * ($hh * 3600 + $mm * 60)
    }
    return $ts
}

function Format-OIIso8601 {
    # Epoch seconds -> "yyyy-MM-ddTHH:mm:ssZ".
    param([double]$Epoch)
    $d = [System.DateTimeOffset]::FromUnixTimeSeconds([long][Math]::Floor($Epoch)).UtcDateTime
    return $d.ToString("yyyy-MM-dd'T'HH':'mm':'ss'Z'", $script:OIInvariant)
}

function Get-OISha256Hex {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text)) } finally { $sha.Dispose() }
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $h) { [void]$sb.Append($b.ToString('x2')) }
    return $sb.ToString()
}

function Get-OIInstanceProfileId {
    # The instance profile's id, stable for the account and role (AIPA + 17 hex digits, upper case).
    param([string]$AccountId, [string]$Role)
    return ('AIPA' + (Get-OISha256Hex ($AccountId + '/' + $Role)).Substring(0, 17)).ToUpperInvariant()
}

function ConvertTo-OIArchitecture {
    # PROCESSOR_ARCHITECTURE -> the identity document's architecture.
    param([string]$ProcessorArchitecture)
    $m = ([string]$ProcessorArchitecture).ToLowerInvariant()
    if ($m -eq 'amd64' -or $m -eq 'x86_64' -or $m -eq '') { return 'x86_64' }
    if ($m -eq 'arm64' -or $m -eq 'aarch64') { return 'arm64' }
    return $m
}

function New-OIRandomBytes {
    param([int]$Count)
    $b = New-Object byte[] $Count
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($b) } finally { $rng.Dispose() }
    return , $b
}

# ---------------------------------------------------------------------------------------------------------
# The launch configuration.
# ---------------------------------------------------------------------------------------------------------

function ConvertTo-OILaunchConfig {
    # launch-config.json (parsed) -> the agent's configuration, with the Linux agent's defaults and checks.
    # Problems found are listed in .warnings for the caller to log.
    param($Raw)
    $cfg = @{
        instanceId = ''; imageId = ''; instanceType = ''; region = 'us-east-1'; availabilityZone = ''
        accountId = ''; launchTime = ''; role = ''; credentialsUrl = ''; identityUrl = ''
        securityGroups = @(); imds = @{ enabled = $true; httpTokens = 'optional'; hopLimit = 1; outside = $false }
        warnings = (New-Object System.Collections.Generic.List[string])
    }
    foreach ($k in @('instanceId', 'imageId', 'instanceType', 'region', 'availabilityZone', 'accountId', 'launchTime', 'role', 'credentialsUrl', 'identityUrl')) {
        $v = Get-OIField $Raw $k
        if ($null -ne $v) { $cfg[$k] = ConvertTo-OIText $v }
    }
    if (-not $cfg.region) { $cfg.region = 'us-east-1' }
    $groups = New-Object System.Collections.Generic.List[string]
    foreach ($g in @(Get-OIField $Raw 'securityGroups')) {
        if ($null -ne $g -and [string]$g -ne '') { $groups.Add([string]$g) }
    }
    $cfg.securityGroups = $groups.ToArray()
    $imds = Get-OIField $Raw 'imds'
    if ($null -ne $imds) {
        $en = Get-OIField $imds 'enabled'
        if ($null -ne $en) { $cfg.imds.enabled = [bool]$en }
        $out = Get-OIField $imds 'outside'
        if ($null -ne $out) { $cfg.imds.outside = [bool]$out }
        $tok = Get-OIField $imds 'httpTokens'
        if ($null -ne $tok) { $cfg.imds.httpTokens = [string]$tok }
        $hop = Get-OIField $imds 'hopLimit'
        if ($null -ne $hop) {
            $n = 0
            if (-not [int]::TryParse([string]$hop, [ref]$n)) { $n = 0 }
            $cfg.imds.hopLimit = $n
        }
    }
    if ($cfg.imds.hopLimit -lt 1 -or $cfg.imds.hopLimit -gt 64) {
        $cfg.warnings.Add(('imds.hopLimit {0} is outside 1..64; using 1' -f $cfg.imds.hopLimit))
        $cfg.imds.hopLimit = 1
    }
    if ($cfg.imds.httpTokens -cne 'optional' -and $cfg.imds.httpTokens -cne 'required') {
        $cfg.warnings.Add(("imds.httpTokens '{0}' is not optional|required; using required" -f $cfg.imds.httpTokens))
        $cfg.imds.httpTokens = 'required'
    }
    if (-not $cfg.availabilityZone) { $cfg.availabilityZone = $cfg.region + 'a' }
    return $cfg
}

# ---------------------------------------------------------------------------------------------------------
# Certificates: the platform root CA and the AWS endpoints CA, from the launch CD.
# ---------------------------------------------------------------------------------------------------------

function ConvertFrom-OIPemCertificates {
    # PEM text -> the DER bytes of its certificates (duplicates dropped). Throws unless the text is PEM
    # CERTIFICATE blocks only: nothing else is ever installed.
    param([string]$Text)
    $pattern = '-----BEGIN ([A-Z0-9 ]+)-----[ \t]*\r?\n(.*?)\r?\n-----END \1-----'
    $opts = [System.Text.RegularExpressions.RegexOptions]::Singleline
    $ms = [regex]::Matches([string]$Text, $pattern, $opts)
    if ($ms.Count -eq 0) { throw 'no PEM block' }
    if ([regex]::Replace([string]$Text, $pattern, '', $opts).Trim().Length -gt 0) { throw 'content outside the PEM blocks' }
    $ders = New-Object 'System.Collections.Generic.List[byte[]]'
    $seen = @{}
    foreach ($m in $ms) {
        $kind = $m.Groups[1].Value
        if ($kind -cne 'CERTIFICATE') { throw ('refusing a {0} block' -f $kind) }
        try { $der = [Convert]::FromBase64String(($m.Groups[2].Value -replace '\s', '')) }
        catch { throw 'a CERTIFICATE block is not valid base64' }
        $key = [Convert]::ToBase64String($der)
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $ders.Add($der)
        }
    }
    return , $ders.ToArray()
}

function Test-OICaCertificate {
    # $true when the certificate is a CA certificate (basicConstraints CA:TRUE).
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    foreach ($ext in $Certificate.Extensions) {
        if ($ext -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
            return [bool]$ext.CertificateAuthority
        }
    }
    return $false
}

function ConvertFrom-OICaPem {
    # PEM text -> @{ Ok; Certificates (X509Certificate2[]); Message }. Every certificate must be a CA.
    param([string]$Text)
    try { $ders = ConvertFrom-OIPemCertificates $Text }
    catch { return @{ Ok = $false; Certificates = @(); Message = $_.Exception.Message } }
    $certs = New-Object 'System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]'
    foreach ($der in $ders) {
        try { $c = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$der) }
        catch { return @{ Ok = $false; Certificates = @(); Message = 'not a parseable X.509 certificate' } }
        if (-not (Test-OICaCertificate $c)) {
            return @{ Ok = $false; Certificates = @(); Message = 'not a CA certificate (basicConstraints CA:TRUE is required)' }
        }
        $certs.Add($c)
    }
    return @{ Ok = $true; Certificates = $certs.ToArray(); Message = '' }
}

function ConvertTo-OIPem {
    # DER bytes -> one PEM CERTIFICATE block, base64 wrapped at 64 columns.
    param([byte[]]$Der)
    $b64 = [Convert]::ToBase64String($Der)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("-----BEGIN CERTIFICATE-----`n")
    for ($i = 0; $i -lt $b64.Length; $i += 64) {
        [void]$sb.Append($b64.Substring($i, [Math]::Min(64, $b64.Length - $i))).Append("`n")
    }
    [void]$sb.Append("-----END CERTIFICATE-----`n")
    return $sb.ToString()
}

function New-OICaBundle {
    # The CA bundle AWS_CA_BUNDLE names: every certificate of the machine's trusted root store, then any of
    # the required ones (the platform's CAs) the store did not carry; each certificate once.
    param([object[]]$StoreCertificates, [object[]]$Required)
    $sb = New-Object System.Text.StringBuilder
    $seen = @{}
    foreach ($der in @(@($StoreCertificates) + @($Required))) {
        if ($null -eq $der) { continue }
        $key = [Convert]::ToBase64String([byte[]]$der)
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        [void]$sb.Append((ConvertTo-OIPem ([byte[]]$der)))
    }
    return $sb.ToString()
}

# ---------------------------------------------------------------------------------------------------------
# Who may use the metadata service: this instance and its own containers, never another host.
# ---------------------------------------------------------------------------------------------------------

function ConvertTo-OIIPv4Number {
    # "a.b.c.d" (or its IPv4-mapped IPv6 form) -> a number; $null for anything else.
    param([string]$Address)
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse([string]$Address, [ref]$ip)) { return $null }
    if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        if (-not $ip.IsIPv4MappedToIPv6) { return $null }
        $ip = $ip.MapToIPv4()
    }
    $b = $ip.GetAddressBytes()
    return ([long]$b[0] -shl 24) -bor ([long]$b[1] -shl 16) -bor ([long]$b[2] -shl 8) -bor [long]$b[3]
}

function ConvertTo-OIIPv4Mask {
    param([int]$PrefixLength)
    if ($PrefixLength -le 0) { return [long]0 }
    if ($PrefixLength -ge 32) { return [long]4294967295 }
    return ([long]4294967295 -shl (32 - $PrefixLength)) -band [long]4294967295
}

function Get-OIImdsAdmission {
    # What the metadata service does with a connection: 'serve', or 'refuse' (another host: it gets no
    # answer, as when EC2's metadata service is out of its reach), or 'drop' (a token request from one of
    # this instance's containers when the PUT response hop limit is 1: on EC2 the response would not reach
    # it). This instance is no hops away; a container behind the instance's NAT is one.
    param(
        [string]$Remote,
        [string[]]$LocalAddresses,
        [object[]]$ContainerNetworks,
        [string]$Method,
        [int]$HopLimit
    )
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse([string]$Remote, [ref]$ip)) { return 'refuse' }
    if ([System.Net.IPAddress]::IsLoopback($ip)) { return 'serve' }
    $n = ConvertTo-OIIPv4Number $Remote
    if ($null -eq $n) { return 'refuse' }
    if ($n -eq (ConvertTo-OIIPv4Number $script:OIImdsAddress)) { return 'serve' }
    foreach ($a in @($LocalAddresses)) {
        if ($null -ne $a -and (ConvertTo-OIIPv4Number $a) -eq $n) { return 'serve' }
    }
    foreach ($net in @($ContainerNetworks)) {
        if ($null -eq $net) { continue }
        if (($n -band [long]$net.Mask) -eq [long]$net.Network) {
            if (([string]$Method).ToUpperInvariant() -eq 'PUT' -and $HopLimit -lt 2) { return 'drop' }
            return 'serve'
        }
    }
    return 'refuse'
}

# ---------------------------------------------------------------------------------------------------------
# IMDSv2 session tokens: stateless HMAC tokens bound to the metadata service process (its key is random per
# process), carrying their expiry on the process's monotonic clock.
# ---------------------------------------------------------------------------------------------------------

function Get-OITokenMac {
    param([byte[]]$Key, [byte[]]$Body)
    $h = [System.Security.Cryptography.HMACSHA256]::new($Key)
    try { $full = $h.ComputeHash($Body) } finally { $h.Dispose() }
    $mac = New-Object byte[] 24
    [Array]::Copy($full, $mac, 24)
    return , $mac
}

function New-OIImdsToken {
    # A token valid for TtlSeconds from Now (seconds on the monotonic clock).
    param([byte[]]$Key, [double]$Now, [int]$TtlSeconds)
    $ms = [long][Math]::Floor(($Now + $TtlSeconds) * 1000)
    $body = New-Object byte[] 8
    for ($i = 7; $i -ge 0; $i--) {
        $body[$i] = [byte]($ms -band [long]255)
        $ms = $ms -shr 8
    }
    $mac = Get-OITokenMac $Key $body
    $raw = New-Object byte[] 32
    [Array]::Copy($body, 0, $raw, 0, 8)
    [Array]::Copy($mac, 0, $raw, 8, 24)
    return [Convert]::ToBase64String($raw).Replace('+', '-').Replace('/', '_')
}

function Test-OIImdsToken {
    # $true when the token was issued by this key and has not expired at Now.
    param([byte[]]$Key, [double]$Now, [AllowNull()][string]$Token)
    if ($null -eq $Token) { return $false }
    try { $raw = [Convert]::FromBase64String($Token.Trim().Replace('-', '+').Replace('_', '/')) }
    catch { return $false }
    if ($raw.Length -ne 32) { return $false }
    $body = New-Object byte[] 8
    [Array]::Copy($raw, 0, $body, 0, 8)
    $want = Get-OITokenMac $Key $body
    $diff = 0
    for ($i = 0; $i -lt 24; $i++) { $diff = $diff -bor ($want[$i] -bxor $raw[8 + $i]) }
    if ($diff -ne 0) { return $false }
    $ms = [long]0
    for ($i = 0; $i -lt 8; $i++) { $ms = ($ms -shl 8) -bor [long]$body[$i] }
    return (($ms / 1000.0) -gt $Now)
}

# ---------------------------------------------------------------------------------------------------------
# Role credentials, fetched from the aws-shim with the instance's identity token and cached. They are
# refreshed when a third of their lifetime remains (at least 5 and at most 20 minutes before Expiration), so
# a caller always receives credentials with ample time left; a failed refresh keeps serving the cached ones
# until they actually expire. Times are epoch seconds (Expiration is wall-clock).
#
# A fetch is a scriptblock taking the cache and returning @{ Ok = $true; Creds = @{ AccessKeyId;
# SecretAccessKey; Token; Expiration } } or @{ Ok = $false; Message; Status } (Status: the shim's HTTP status,
# or $null for a transport or local failure).
# ---------------------------------------------------------------------------------------------------------

function New-OICredentialCache {
    param([scriptblock]$Fetch)
    return @{
        Fetch = $Fetch; Creds = $null; Expires = 0.0; RefreshAt = 0.0; LastUpdated = 0.0
        LastError = $null; NextAttempt = 0.0; Backoff = 5.0
    }
}

function Get-OICredentialRefreshAt {
    param([double]$Expiration, [double]$Now)
    $margin = [Math]::Min([Math]::Max(($Expiration - $Now) / 3.0, 300.0), 1200.0)
    return $Expiration - $margin
}

function Test-OICredentialsValid {
    param([hashtable]$Cache, [double]$Now)
    return (($null -ne $Cache.Creds) -and ($Now -lt ($Cache.Expires - 60)))
}

function Update-OICredentialCache {
    # Fetch now; on success store the credentials and their refresh time.
    param([hashtable]$Cache, [double]$Now)
    $r = & $Cache.Fetch $Cache
    if ($null -eq $r -or -not $r.Ok) {
        if ($null -eq $r) { $r = @{ Ok = $false; Message = 'no answer from the credentials fetch'; Status = $null } }
        $Cache.LastError = $r
        return $r
    }
    $exp = ConvertFrom-OITimestamp $r.Creds.Expiration
    $Cache.Creds = $r.Creds
    $Cache.Expires = $exp
    $Cache.RefreshAt = Get-OICredentialRefreshAt $exp $Now
    $Cache.LastUpdated = $Now
    $Cache.LastError = $null
    return $r
}

function Get-OICachedCredentials {
    # The credentials to serve: the cached ones while they are valid (a due refresh happens in the
    # background), else a fetch now.
    param([hashtable]$Cache, [double]$Now)
    if (Test-OICredentialsValid $Cache $Now) { return @{ Ok = $true; Creds = $Cache.Creds } }
    return (Update-OICredentialCache $Cache $Now)
}

function Test-OICredentialRefreshDue {
    param([hashtable]$Cache, [double]$Now)
    if ($Now -lt $Cache.NextAttempt) { return $false }
    return (($null -eq $Cache.Creds) -or ($Now -ge $Cache.RefreshAt))
}

function Invoke-OICredentialRefresh {
    # The background refresh: on failure, retry after a backoff of 5 s doubling to 60 s. .Stale is set when
    # the credentials just received have already expired by this instance's clock.
    param([hashtable]$Cache, [double]$Now)
    $r = Update-OICredentialCache $Cache $Now
    if ($r.Ok -and (Test-OICredentialsValid $Cache $Now)) {
        $Cache.Backoff = 5.0
        $Cache.NextAttempt = 0.0
        return $r
    }
    if ($r.Ok) { $r.Stale = $true }
    $Cache.NextAttempt = $Now + $Cache.Backoff
    $Cache.Backoff = [Math]::Min($Cache.Backoff * 2, 60.0)
    return $r
}

# The platform-signed instance identity document, refreshed at half its lifetime (the shim issues documents
# valid for an hour). Its lifetime is counted on the monotonic clock from the fetch, so a skewed clock changes
# nothing. Until a document arrives, or once it has expired, the agent's own unsigned document is served.
# A fetch returns @{ Ok = $true; Signed = @{ document; signature; pkcs7; rsa2048; expiresInSeconds } } or a
# failure as above.

function New-OIIdentityCache {
    param([scriptblock]$Fetch)
    return @{ Fetch = $Fetch; Signed = $null; Expires = 0.0; RefreshAt = 0.0; LastError = $null; NextAttempt = 0.0; Backoff = 5.0 }
}

function Get-OICurrentIdentity {
    param([hashtable]$Cache, [double]$Mono)
    if ($null -ne $Cache.Signed -and $Mono -lt $Cache.Expires) { return $Cache.Signed }
    return $null
}

function Test-OIIdentityRefreshDue {
    param([hashtable]$Cache, [double]$Mono)
    if ($Mono -lt $Cache.NextAttempt) { return $false }
    return (($null -eq $Cache.Signed) -or ($Mono -ge $Cache.RefreshAt))
}

function Invoke-OIIdentityRefresh {
    # Fetch now. On failure retry after the backoff, or after 15 minutes when the shim has no such
    # endpoint (404).
    param([hashtable]$Cache, [double]$Mono)
    $r = & $Cache.Fetch $Cache
    if ($null -ne $r -and $r.Ok) {
        $ttl = [Math]::Max(60.0, [double]$r.Signed.expiresInSeconds)
        $Cache.Signed = $r.Signed
        $Cache.Expires = $Mono + $ttl - 30.0
        $Cache.RefreshAt = $Mono + $ttl / 2.0
        $Cache.LastError = $null
        $Cache.Backoff = 5.0
        $Cache.NextAttempt = 0.0
        return $r
    }
    if ($null -eq $r) { $r = @{ Ok = $false; Message = 'no answer from the identity fetch'; Status = $null } }
    $Cache.LastError = $r
    if ($r.Status -eq 404) { $Cache.NextAttempt = $Mono + 900.0 } else { $Cache.NextAttempt = $Mono + $Cache.Backoff }
    $Cache.Backoff = [Math]::Min($Cache.Backoff * 2, 60.0)
    return $r
}

# ---------------------------------------------------------------------------------------------------------
# The platform's answers (the aws-shim's /v1/vm-credentials and /v1/vm-identity).
# ---------------------------------------------------------------------------------------------------------

function Format-OIShimHttpError {
    # The error for a refusal from the platform's instance credentials or identity service: its status, the
    # start of its answer, and what the status means. The service's host is never named.
    param([string]$Service, [int]$Status, [string]$Detail, [hashtable]$Hints)
    $hint = ''
    if ($null -ne $Hints -and $Hints.ContainsKey($Status)) { $hint = $Hints[$Status] }
    $d = ([string]$Detail).Trim()
    if ($d.Length -gt 300) { $d = $d.Substring(0, 300) }
    return ("the platform's instance {0} service answered HTTP {1}: {2}{3}" -f $Service, $Status, $d, $hint)
}

function ConvertFrom-OICredentialsDocument {
    # The body of /v1/vm-credentials -> a fetch result. A failure never quotes the body: it holds secrets.
    param([string]$Body)
    $bad = "the platform's instance credentials service returned an unusable credentials document: "
    try { $d = ConvertFrom-Json -InputObject $Body -ErrorAction Stop }
    catch { return @{ Ok = $false; Message = ($bad + 'not JSON'); Status = $null } }
    $creds = @{}
    foreach ($k in @('AccessKeyId', 'SecretAccessKey', 'Token', 'Expiration')) {
        $v = Get-OIField $d $k
        if ($null -eq $v -or [string]$v -eq '') { return @{ Ok = $false; Message = ($bad + 'no ' + $k); Status = $null } }
        $creds[$k] = ConvertTo-OIText $v
    }
    try { [void](ConvertFrom-OITimestamp $creds.Expiration) }
    catch { return @{ Ok = $false; Message = ($bad + 'its Expiration is not an RFC 3339 timestamp'); Status = $null } }
    return @{ Ok = $true; Creds = $creds }
}

function ConvertFrom-OIIdentityDocument {
    # The body of /v1/vm-identity -> a fetch result: the document and its signatures, served as received.
    param([string]$Body)
    $bad = "the platform's instance identity service returned an unusable identity document: "
    try { $d = ConvertFrom-Json -InputObject $Body -ErrorAction Stop }
    catch { return @{ Ok = $false; Message = ($bad + 'not JSON'); Status = $null } }
    $signed = @{}
    foreach ($k in @('document', 'signature', 'pkcs7', 'rsa2048')) {
        $v = Get-OIField $d $k
        if ($null -eq $v) { return @{ Ok = $false; Message = ($bad + 'no ' + $k); Status = $null } }
        $signed[$k] = [string]$v
    }
    $ttl = 0
    if (-not [int]::TryParse([string](Get-OIField $d 'expiresInSeconds'), [ref]$ttl)) {
        return @{ Ok = $false; Message = ($bad + 'no expiresInSeconds'); Status = $null }
    }
    $signed['expiresInSeconds'] = $ttl
    try { $inner = ConvertFrom-Json -InputObject $signed.document -ErrorAction Stop }
    catch { return @{ Ok = $false; Message = ($bad + 'its document is not JSON'); Status = $null } }
    if (-not [string](Get-OIField $inner 'instanceId')) { return @{ Ok = $false; Message = ($bad + 'the document names no instance'); Status = $null } }
    return @{ Ok = $true; Signed = $signed }
}

# ---------------------------------------------------------------------------------------------------------
# The metadata tree and the request router.
#
# The router's State: Config (ConvertTo-OILaunchConfig), TokenKey (byte[]), UtcNow (epoch seconds), MonoNow
# (monotonic seconds), Facts (Hostname, LocalIPv4, Mac, Architecture, BootTime), Creds (a credential cache, or
# $null without a role), Identity (an identity cache, or $null), UserData (byte[], or $null when the instance
# has none).
# ---------------------------------------------------------------------------------------------------------

function New-OIMap {
    # A case-sensitive map: metadata paths are case-sensitive, as on EC2.
    return , (New-Object System.Collections.Hashtable ([System.StringComparer]::Ordinal))
}

function Get-OILastUpdated {
    param([hashtable]$State)
    if ($null -ne $State.Creds -and $State.Creds.LastUpdated -gt 0) { return $State.Creds.LastUpdated }
    return $State.UtcNow
}

function Get-OIIamInfoBody {
    param([hashtable]$State)
    $cfg = $State.Config
    $account = [string]$cfg.accountId
    $role = [string]$cfg.role
    $doc = [ordered]@{}
    $doc['Code'] = 'Success'
    $doc['LastUpdated'] = Format-OIIso8601 (Get-OILastUpdated $State)
    $doc['InstanceProfileArn'] = 'arn:aws:iam::' + $account + ':instance-profile/' + $role
    $doc['InstanceProfileId'] = Get-OIInstanceProfileId $account $role
    return (ConvertTo-OIAwsJson $doc)
}

function Get-OICredentialsBody {
    param([hashtable]$State)
    $r = Get-OICachedCredentials $State.Creds $State.UtcNow
    $doc = [ordered]@{}
    if (-not $r.Ok) {
        $code = 'InternalError'
        if ($r.Status -eq 401 -or $r.Status -eq 403) { $code = 'AssumeRoleUnauthorizedAccess' }
        $doc['Code'] = $code
        $doc['Message'] = [string]$r.Message
        $doc['LastUpdated'] = Format-OIIso8601 $State.UtcNow
        return (ConvertTo-OIAwsJson $doc)
    }
    $c = $r.Creds
    $doc['Code'] = 'Success'
    $doc['LastUpdated'] = Format-OIIso8601 (Get-OILastUpdated $State)
    $doc['Type'] = 'AWS-HMAC'
    $doc['AccessKeyId'] = $c.AccessKeyId
    $doc['SecretAccessKey'] = $c.SecretAccessKey
    $doc['Token'] = $c.Token
    $doc['Expiration'] = $c.Expiration
    return (ConvertTo-OIAwsJson $doc)
}

function Get-OIIdentityDocumentBody {
    # The agent's own (unsigned) instance identity document.
    param([hashtable]$State)
    $cfg = $State.Config
    $f = $State.Facts
    try { $pending = Format-OIIso8601 (ConvertFrom-OITimestamp $cfg.launchTime) }
    catch { $pending = Format-OIIso8601 ([double]$f.BootTime) }
    $doc = [ordered]@{}
    $doc['accountId'] = [string]$cfg.accountId
    $doc['architecture'] = [string]$f.Architecture
    $doc['availabilityZone'] = [string]$cfg.availabilityZone
    $doc['billingProducts'] = $null
    $doc['devpayProductCodes'] = $null
    $doc['marketplaceProductCodes'] = $null
    $doc['imageId'] = [string]$cfg.imageId
    $doc['instanceId'] = [string]$cfg.instanceId
    $doc['instanceType'] = ConvertTo-OINull $cfg.instanceType
    $doc['kernelId'] = $null
    $doc['pendingTime'] = $pending
    $doc['privateIp'] = ConvertTo-OINull $f.LocalIPv4
    $doc['ramdiskId'] = $null
    $doc['region'] = [string]$cfg.region
    $doc['version'] = '2017-09-30'
    return (ConvertTo-OIAwsJson $doc)
}

function Get-OIMetadataTree {
    # /latest as nested maps. A leaf is a string, the user data's bytes, or a scriptblock taking the State
    # that renders it on request; $null leaves are not served.
    param([hashtable]$State)
    $cfg = $State.Config
    $f = $State.Facts
    $hostName = [string]$f.Hostname
    $ip = ConvertTo-OINull $f.LocalIPv4
    $mac = ConvertTo-OINull $f.Mac
    $md = New-OIMap
    $md['ami-id'] = ConvertTo-OINull $cfg.imageId
    $md['ami-launch-index'] = '0'
    $md['hostname'] = $hostName
    $md['instance-action'] = 'none'
    $md['instance-id'] = ConvertTo-OINull $cfg.instanceId
    $md['instance-life-cycle'] = 'on-demand'
    $md['instance-type'] = ConvertTo-OINull $cfg.instanceType
    $md['local-hostname'] = $hostName
    $md['local-ipv4'] = $ip
    $md['mac'] = $mac
    $placement = New-OIMap
    $placement['availability-zone'] = [string]$cfg.availabilityZone
    $placement['region'] = [string]$cfg.region
    $md['placement'] = $placement
    $md['security-groups'] = ConvertTo-OINull (@($cfg.securityGroups) -join "`n")
    $services = New-OIMap
    $services['domain'] = 'amazonaws.com'
    $services['partition'] = 'aws'
    $md['services'] = $services
    if ($mac) {
        $nic = New-OIMap
        $nic['device-number'] = '0'
        $nic['local-hostname'] = $hostName
        $nic['local-ipv4s'] = $ip
        $nic['mac'] = $mac
        $macs = New-OIMap
        $macs[$mac] = $nic
        $interfaces = New-OIMap
        $interfaces['macs'] = $macs
        $network = New-OIMap
        $network['interfaces'] = $interfaces
        $md['network'] = $network
    }
    if ($cfg.role -and $null -ne $State.Creds) {
        $iam = New-OIMap
        $iam['info'] = { param($s) Get-OIIamInfoBody $s }
        $sc = New-OIMap
        $sc[[string]$cfg.role] = { param($s) Get-OICredentialsBody $s }
        $iam['security-credentials'] = $sc
        $md['iam'] = $iam
    }
    $signed = $null
    if ($null -ne $State.Identity) { $signed = Get-OICurrentIdentity $State.Identity $State.MonoNow }
    $ii = New-OIMap
    if ($null -ne $signed) {
        foreach ($k in @('document', 'signature', 'pkcs7', 'rsa2048')) { $ii[$k] = [string]$signed[$k] }
    } else {
        $ii['document'] = { param($s) Get-OIIdentityDocumentBody $s }
    }
    $dynamic = New-OIMap
    $dynamic['instance-identity'] = $ii
    $latest = New-OIMap
    $latest['dynamic'] = $dynamic
    $latest['meta-data'] = $md
    if ($null -ne $State.UserData) { $latest['user-data'] = $State.UserData }
    return , $latest
}

function New-OIResponse {
    param([int]$Status, [string]$ContentType, $Body, [hashtable]$Headers)
    if ($null -eq $Body) { $Body = New-Object byte[] 0 }
    elseif ($Body -is [string]) { $Body = [System.Text.Encoding]::UTF8.GetBytes($Body) }
    if ($null -eq $Headers) { $Headers = @{} }
    return @{ Status = $Status; ContentType = $ContentType; Body = $Body; Headers = $Headers }
}

function Get-OISortedKeys {
    param([System.Collections.IDictionary]$Map)
    $keys = New-Object System.Collections.Generic.List[string]
    foreach ($k in $Map.Keys) { $keys.Add([string]$k) }
    $arr = $keys.ToArray()
    [Array]::Sort($arr, [System.StringComparer]::Ordinal)
    return , $arr
}

function Find-OIMetadata {
    # A GET path -> @{ Status; ContentType; Body } as EC2's metadata service answers it.
    param([string]$Path, [hashtable]$State)
    $notFound = New-OIResponse 404 'text/html' $script:OINotFoundBody
    $parts = @(([string]$Path) -split '/' | Where-Object { $_ -ne '' })
    if ($parts.Count -eq 0) { return (New-OIResponse 200 'text/plain' ($script:OIVersions -join "`n")) }
    if ($script:OIVersions -cnotcontains $parts[0]) { return $notFound }
    $node = Get-OIMetadataTree $State
    if ($parts.Count -eq 1) {
        # The version root lists its categories without trailing slashes.
        return (New-OIResponse 200 'text/plain' ((Get-OISortedKeys $node) -join "`n"))
    }
    for ($i = 1; $i -lt $parts.Count; $i++) {
        $p = $parts[$i]
        if (-not ($node -is [System.Collections.IDictionary])) { return $notFound }
        if (-not $node.ContainsKey($p) -or $null -eq $node[$p]) { return $notFound }
        $node = $node[$p]
    }
    if ($node -is [System.Collections.IDictionary]) {
        $names = New-Object System.Collections.Generic.List[string]
        foreach ($k in (Get-OISortedKeys $node)) {
            $v = $node[$k]
            if ($null -eq $v) { continue }
            if ($v -is [System.Collections.IDictionary]) { $names.Add($k + '/') } else { $names.Add($k) }
        }
        return (New-OIResponse 200 'text/plain' ($names -join "`n"))
    }
    if ($node -is [scriptblock]) { $node = & $node $State }
    if ($null -eq $node) { return $notFound }
    if ($node -is [byte[]]) { return (New-OIResponse 200 'text/plain' $node) }
    return (New-OIResponse 200 'text/plain' ([string]$node))
}

function Get-OIHeader {
    # A request header's value (names are case-insensitive), or $null when the request has none.
    param([System.Collections.IDictionary]$Headers, [string]$Name)
    if ($null -eq $Headers) { return $null }
    foreach ($k in $Headers.Keys) {
        if ([string]::Equals([string]$k, $Name, [System.StringComparison]::OrdinalIgnoreCase)) { return [string]$Headers[$k] }
    }
    return $null
}

function Get-OIRequestPath {
    # The request target's path: no scheme and authority, no query or fragment.
    param([string]$RawUrl)
    $u = [string]$RawUrl
    $m = [regex]::Match($u, '^[A-Za-z][A-Za-z0-9+.-]*://[^/]*(.*)$')
    if ($m.Success) { $u = $m.Groups[1].Value }
    $q = $u.IndexOfAny([char[]]@('?', '#'))
    if ($q -ge 0) { $u = $u.Substring(0, $q) }
    return $u
}

function Invoke-OIImdsRequest {
    # One metadata request -> @{ Status; ContentType; Body (byte[]); Headers }, IMDSv1 and IMDSv2 as
    # metadataOptions.httpTokens allows.
    param([string]$Method, [string]$Path, [System.Collections.IDictionary]$Headers, [hashtable]$State)
    $m = ([string]$Method).ToUpperInvariant()
    $imds = $State.Config.imds
    if ($m -eq 'PUT') {
        if ($Path -cne '/latest/api/token') {
            return (New-OIResponse 405 'text/plain' "Method Not Allowed`n" @{ Allow = 'GET, PUT' })
        }
        # EC2 refuses a token request that went through a proxy (the SSRF guard).
        if ($null -ne (Get-OIHeader $Headers 'X-Forwarded-For')) { return (New-OIResponse 403 'text/plain' "Forbidden`n") }
        $ttl = ([string](Get-OIHeader $Headers $script:OITokenTtlHeader)).Trim()
        if ($ttl -notmatch '^[0-9]{1,9}$' -or [int]$ttl -lt 1 -or [int]$ttl -gt $script:OIMaxTokenTtl) {
            return (New-OIResponse 400 'text/plain' "Bad Request`n")
        }
        $token = New-OIImdsToken $State.TokenKey $State.MonoNow ([int]$ttl)
        $h = @{}
        $h[$script:OITokenTtlHeader] = $ttl
        return (New-OIResponse 200 'text/plain' $token $h)
    }
    if ($m -eq 'GET' -or $m -eq 'HEAD') {
        $token = Get-OIHeader $Headers $script:OITokenHeader
        if ($null -ne $token) {
            if (-not (Test-OIImdsToken $State.TokenKey $State.MonoNow $token)) { return (New-OIResponse 401 'text/plain' "Unauthorized`n") }
        } elseif ($imds.httpTokens -ceq 'required') {
            return (New-OIResponse 401 'text/plain' "Unauthorized`n")
        }
        return (Find-OIMetadata $Path $State)
    }
    return (New-OIResponse 405 'text/plain' "Method Not Allowed`n" @{ Allow = 'GET, PUT' })
}

# ---------------------------------------------------------------------------------------------------------
# HTTP/1.1 on the metadata socket: requests parsed, responses written. Every response closes its connection.
# ---------------------------------------------------------------------------------------------------------

$script:OIMaxHeaderBytes = 32768
$script:OIMaxBodyBytes = 65536
$script:OILatin1 = [System.Text.Encoding]::GetEncoding(28591)
$script:OIReasons = @{
    200 = 'OK'; 400 = 'Bad Request'; 401 = 'Unauthorized'; 403 = 'Forbidden'; 404 = 'Not Found'
    405 = 'Method Not Allowed'; 500 = 'Internal Server Error'; 503 = 'Service Unavailable'
}

function ConvertFrom-OIHttpRequest {
    # The bytes a connection has sent so far -> @{ State = 'incomplete' | 'complete' | 'bad'; Method; Target;
    # Headers }. A request is complete once its header block, and any body it announces of up to 64 KiB (read
    # and discarded), have arrived; a larger body is not waited for.
    param([byte[]]$Bytes)
    $result = @{ State = 'incomplete'; Method = ''; Target = ''; Headers = @{} }
    if ($null -eq $Bytes) { return $result }
    $text = $script:OILatin1.GetString($Bytes)
    $m = [regex]::Match($text, '\r?\n\r?\n')
    if (-not $m.Success -or $m.Index -gt $script:OIMaxHeaderBytes) {
        if ($Bytes.Length -gt $script:OIMaxHeaderBytes) { $result.State = 'bad' }
        return $result
    }
    $lines = $text.Substring(0, $m.Index) -split '\r?\n'
    $parts = $lines[0] -split ' '
    if ($parts.Count -ne 3 -or $parts[0] -cnotmatch '^[A-Za-z]+$' -or $parts[1] -eq '' -or $parts[2] -cnotmatch '^HTTP/[0-9]+\.[0-9]+$') {
        $result.State = 'bad'
        return $result
    }
    $headers = @{}
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        $c = $line.IndexOf(':')
        if ($c -le 0 -or $line.Substring(0, $c) -cnotmatch '^[!#$%&''*+.^_`|~0-9A-Za-z-]+$') {
            $result.State = 'bad'
            return $result
        }
        $name = $line.Substring(0, $c)
        $value = $line.Substring($c + 1).Trim()
        if ($headers.ContainsKey($name)) { $headers[$name] = $headers[$name] + ', ' + $value } else { $headers[$name] = $value }
    }
    $body = 0
    $cl = Get-OIHeader $headers 'Content-Length'
    if ($null -ne $cl) {
        if ($cl -notmatch '^[0-9]{1,10}$') {
            $result.State = 'bad'
            return $result
        }
        $body = [long]$cl
        if ($body -gt $script:OIMaxBodyBytes) { $body = 0 }
    }
    if ($Bytes.Length -lt ($m.Index + $m.Length + $body)) { return $result }
    $result.State = 'complete'
    $result.Method = $parts[0]
    $result.Target = $parts[1]
    $result.Headers = $headers
    return $result
}

function ConvertTo-OIHttpResponse {
    # A router result -> the response's bytes: the status line, EC2's Server header, Date, Content-Type,
    # Content-Length, the result's own headers and Connection: close. A HEAD response carries no body.
    param([hashtable]$Result, [string]$Method, [datetime]$Date)
    $reason = $script:OIReasons[[int]$Result.Status]
    if (-not $reason) { $reason = 'Unknown' }
    $body = [byte[]]$Result.Body
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('HTTP/1.1 ' + $Result.Status + ' ' + $reason + "`r`n")
    [void]$sb.Append("Server: EC2ws`r`n")
    [void]$sb.Append('Date: ' + $Date.ToUniversalTime().ToString('r', $script:OIInvariant) + "`r`n")
    [void]$sb.Append('Content-Type: ' + $Result.ContentType + "`r`n")
    [void]$sb.Append('Content-Length: ' + $body.Length + "`r`n")
    foreach ($k in (Get-OISortedKeys $Result.Headers)) { [void]$sb.Append($k + ': ' + [string]$Result.Headers[$k] + "`r`n") }
    [void]$sb.Append("Connection: close`r`n`r`n")
    $head = $script:OILatin1.GetBytes($sb.ToString())
    if (([string]$Method).ToUpperInvariant() -eq 'HEAD' -or $body.Length -eq 0) { return , $head }
    $out = New-Object byte[] ($head.Length + $body.Length)
    [Array]::Copy($head, 0, $out, 0, $head.Length)
    [Array]::Copy($body, 0, $out, $head.Length, $body.Length)
    return , $out
}

function Get-OIWebFailureText {
    # Why a request to the platform got no answer, without naming its host.
    param([string]$Status)
    switch ($Status) {
        'NameResolutionFailure' { return 'its name does not resolve' }
        'ConnectFailure' { return 'the connection was refused or did not complete' }
        'Timeout' { return 'it did not answer in time' }
        'ConnectionClosed' { return 'the connection closed before it answered' }
        'ReceiveFailure' { return 'the connection failed while it answered' }
        'SendFailure' { return 'the connection failed while the request was sent' }
        'KeepAliveFailure' { return 'the connection closed before it answered' }
    }
    if (-not $Status) { return 'the request failed' }
    return ('the request failed ({0})' -f $Status)
}

# ---------------------------------------------------------------------------------------------------------
# User data, as EC2Launch v2 reads it.
# ---------------------------------------------------------------------------------------------------------

function Read-OIUserData {
    # User data text -> @{ Format; Persist; Tasks }. Format is 'none' (no user data), 'empty', 'yaml' (the
    # EC2Launch v2 YAML format, "version: 1.0"), 'untagged' (neither YAML nor XML-tagged), or 'xml'. Only
    # 'xml' has tasks: the <script> block (run with cmd.exe) and then the <powershell> block (run with
    # powershell.exe and the <powershellArguments>, if given), each @{ Type; Content; Args; Persist }.
    # <persist>true</persist> runs them at every boot; otherwise once per instance.
    param($Text)
    $result = @{ Format = 'none'; Persist = $false; Tasks = @() }
    if ($null -eq $Text) { return $result }
    $t = [string]$Text
    if ($t.Length -gt 0 -and [int]$t[0] -eq 0xFEFF) { $t = $t.Substring(1) }
    if ($t.Trim().Length -eq 0) {
        $result.Format = 'empty'
        return $result
    }
    foreach ($line in ($t -split "`r?`n")) {
        $l = $line.Trim()
        if ($l -eq '' -or $l.StartsWith('#')) { continue }
        if ($l -match '^version\s*:') {
            $result.Format = 'yaml'
            return $result
        }
        break
    }
    $opts = [System.Text.RegularExpressions.RegexOptions]'IgnoreCase, Singleline'
    $script = [regex]::Match($t, '<script>(.*?)</script>', $opts)
    $ps = [regex]::Match($t, '<powershell>(.*?)</powershell>', $opts)
    if (-not $script.Success -and -not $ps.Success) {
        $result.Format = 'untagged'
        return $result
    }
    $persist = [regex]::IsMatch($t, '<persist>\s*true\s*</persist>', $opts)
    $psArgs = $script:OIDefaultPowerShellArgs
    $argMatch = [regex]::Match($t, '<powershellArguments>(.*?)</powershellArguments>', $opts)
    if ($argMatch.Success -and $argMatch.Groups[1].Value.Trim()) { $psArgs = $argMatch.Groups[1].Value.Trim() }
    $tasks = New-Object System.Collections.Generic.List[hashtable]
    if ($script.Success) { $tasks.Add(@{ Type = 'script'; Content = $script.Groups[1].Value; Args = ''; Persist = $persist }) }
    if ($ps.Success) { $tasks.Add(@{ Type = 'powershell'; Content = $ps.Groups[1].Value; Args = $psArgs; Persist = $persist }) }
    $result.Format = 'xml'
    $result.Persist = $persist
    $result.Tasks = $tasks.ToArray()
    return $result
}

function Get-OIUserDataCommandLine {
    # The cmd.exe arguments that run one user data task, its output and errors appended to LogPath.
    param([hashtable]$Task, [string]$ScriptPath, [string]$LogPath, [string]$PowerShellExe)
    if ($Task.Type -eq 'script') {
        $inner = '"' + $ScriptPath + '"'
    } else {
        $inner = '"' + $PowerShellExe + '" ' + $Task.Args + ' -File "' + $ScriptPath + '"'
    }
    return '/d /s /c "' + $inner + ' >> "' + $LogPath + '" 2>&1"'
}

function Resolve-OIInstanceState {
    # The saved state (state.json) -> this instance's state. State saved by another instance id (an image
    # made from another instance carries its state) counts as none: this is that instance's first boot.
    param($Saved, [string]$InstanceId)
    $s = @{ instanceId = $InstanceId; rootExtended = $false; userDataRan = $false }
    if ($null -ne $Saved -and [string](Get-OIField $Saved 'instanceId') -ceq $InstanceId) {
        $s.rootExtended = ((Get-OIField $Saved 'rootExtended') -eq $true)
        $s.userDataRan = ((Get-OIField $Saved 'userDataRan') -eq $true)
    }
    return $s
}

function Test-OIUserDataShouldRun {
    param([hashtable]$InstanceState, [hashtable]$UserData)
    if ($UserData.Format -ne 'xml') { return $false }
    return ([bool]$UserData.Persist -or -not $InstanceState.userDataRan)
}

# ---------------------------------------------------------------------------------------------------------
# What -Install writes: the boot stub and the scheduled task that runs it.
# ---------------------------------------------------------------------------------------------------------

function Get-OIStubSource {
    return @'
# OpenInfra launch stub, installed by the launch agent (openinfra-launch.ps1 -Install) and run at every
# startup by the "OpenInfra Launch" scheduled task. It finds the launch CD - the CD-ROM carrying
# openinfra-launch.ps1 and launch-config.json - and runs the agent from it, so the agent an instance runs is
# always the one its launch CD carries. It retries while the CD is not yet visible.
$ErrorActionPreference = 'Continue'
$logDir = 'C:\ProgramData\openinfra\launch\log'
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
for ($i = 0; $i -lt 300; $i++) {
    foreach ($d in [System.IO.DriveInfo]::GetDrives()) {
        try {
            if ($d.DriveType -ne [System.IO.DriveType]::CDRom -or -not $d.IsReady) { continue }
            $root = $d.RootDirectory.FullName
            $agent = Join-Path $root 'openinfra-launch.ps1'
            if ((Test-Path -LiteralPath $agent) -and (Test-Path -LiteralPath (Join-Path $root 'launch-config.json'))) {
                & $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $agent -Run
                exit $LASTEXITCODE
            }
        } catch { }
    }
    Start-Sleep -Seconds 2
}
try {
    if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    $stamp = [DateTime]::UtcNow.ToString("yyyy'/'MM'/'dd HH':'mm':'ss'Z'", [Globalization.CultureInfo]::InvariantCulture)
    Add-Content -LiteralPath (Join-Path $logDir 'agent.log') -Value ($stamp + ': no launch CD (openinfra-launch.ps1 and launch-config.json) appeared within 10 minutes')
} catch { }
exit 1
'@
}

function Get-OITaskXml {
    # The "OpenInfra Launch" task: at startup, as LocalSystem with the highest privileges, no execution
    # time limit, restarted on failure.
    param([string]$StubPath, [string]$PowerShellExe)
    $esc = [System.Security.SecurityElement]
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $StubPath + '"'
    return @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>OpenInfra launch agent: instance metadata (169.254.169.254), the platform CAs and user data, as EC2Launch v2 does.</Description>
    <URI>\$($script:OITaskName)</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>4</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>$($esc::Escape($PowerShellExe))</Command>
      <Arguments>$($esc::Escape($arguments))</Arguments>
    </Exec>
  </Actions>
</Task>
"@
}

# ---------------------------------------------------------------------------------------------------------
# Native helpers, compiled on first use: TLS to the aws-shim pinned to the platform root CA, and the
# metadata adapter's creation.
#
# TLS to the aws-shim, pinned to the platform root CA: the server must chain to a certificate of
# platform-root-ca.pem (no other root is accepted, whatever the machine trusts) and its certificate must name
# the host. The identity token is written only after that handshake verifies.
# ---------------------------------------------------------------------------------------------------------

$script:OINativeSource = @'
using System;
using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace OpenInfraLaunch
{
    public sealed class RootPin
    {
        private readonly X509Certificate2Collection roots;
        public string LastFailure;

        public RootPin(X509Certificate2Collection roots)
        {
            this.roots = roots;
        }

        public RemoteCertificateValidationCallback Callback()
        {
            return new RemoteCertificateValidationCallback(this.Validate);
        }

        public bool Validate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
        {
            X509Certificate2Collection presented = new X509Certificate2Collection();
            if (chain != null)
            {
                foreach (X509ChainElement element in chain.ChainElements)
                {
                    presented.Add(element.Certificate);
                }
            }
            string failure;
            bool ok = Check(this.roots, certificate, presented, errors, out failure);
            this.LastFailure = failure;
            return ok;
        }

        public static bool Check(X509Certificate2Collection roots, X509Certificate certificate, X509Certificate2Collection intermediates, SslPolicyErrors errors, out string failure)
        {
            failure = null;
            if (roots == null || roots.Count == 0)
            {
                failure = "no platform root CA to verify the server with";
                return false;
            }
            if (certificate == null || (errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0)
            {
                failure = "the server presented no certificate";
                return false;
            }
            if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
            {
                failure = "the server's certificate does not name the host";
                return false;
            }
            X509Certificate2 leaf = new X509Certificate2(certificate);
            X509Chain own = new X509Chain();
            try
            {
                own.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                own.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                own.ChainPolicy.ExtraStore.AddRange(roots);
                if (intermediates != null)
                {
                    own.ChainPolicy.ExtraStore.AddRange(intermediates);
                }
                own.Build(leaf);
                int n = own.ChainElements.Count;
                if (n == 0)
                {
                    failure = "no certificate chain could be built";
                    return false;
                }
                X509Certificate2 top = own.ChainElements[n - 1].Certificate;
                bool pinned = false;
                foreach (X509Certificate2 root in roots)
                {
                    if (string.Equals(root.Thumbprint, top.Thumbprint, StringComparison.OrdinalIgnoreCase))
                    {
                        pinned = true;
                    }
                }
                if (!pinned)
                {
                    failure = "the server's certificate does not chain to the platform root CA";
                    return false;
                }
                foreach (X509ChainStatus status in own.ChainStatus)
                {
                    if (status.Status == X509ChainStatusFlags.NoError || status.Status == X509ChainStatusFlags.UntrustedRoot)
                    {
                        continue;
                    }
                    failure = "certificate chain error: " + status.Status.ToString();
                    return false;
                }
                return true;
            }
            finally
            {
                own.Reset();
            }
        }
    }

    public static class LoopbackAdapter
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct SP_DEVINFO_DATA
        {
            public int cbSize;
            public Guid ClassGuid;
            public int DevInst;
            public IntPtr Reserved;
        }

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern IntPtr SetupDiCreateDeviceInfoList(ref Guid classGuid, IntPtr hwndParent);

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "SetupDiCreateDeviceInfoW")]
        private static extern bool SetupDiCreateDeviceInfo(IntPtr deviceInfoSet, string deviceName, ref Guid classGuid, string deviceDescription, IntPtr hwndParent, int creationFlags, ref SP_DEVINFO_DATA deviceInfoData);

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "SetupDiSetDeviceRegistryPropertyW")]
        private static extern bool SetupDiSetDeviceRegistryProperty(IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData, int property, byte[] propertyBuffer, int propertyBufferSize);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiCallClassInstaller(int installFunction, IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "SetupDiOpenDeviceInfoW")]
        private static extern bool SetupDiOpenDeviceInfo(IntPtr deviceInfoSet, string deviceInstanceId, IntPtr hwndParent, int openFlags, ref SP_DEVINFO_DATA deviceInfoData);

        [DllImport("newdev.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "UpdateDriverForPlugAndPlayDevicesW")]
        private static extern bool UpdateDriverForPlugAndPlayDevices(IntPtr hwndParent, string hardwareId, string fullInfPath, int installFlags, out bool rebootRequired);

        private const int DICD_GENERATE_ID = 1;
        private const int SPDRP_HARDWAREID = 1;
        private const int DIF_REMOVE = 5;
        private const int DIF_REGISTERDEVICE = 0x19;
        private const int INSTALLFLAG_FORCE = 1;

        // Creates a root-enumerated network device with the hardware id and installs the inf's driver on it,
        // as "devcon install <inf> <hardware id>" does. Returns null on success, else why it failed (the
        // half-made device is removed).
        public static string Install(string infPath, string hardwareId)
        {
            Guid netClass = new Guid("4d36e972-e325-11ce-bfc1-08002be10318");
            IntPtr set = SetupDiCreateDeviceInfoList(ref netClass, IntPtr.Zero);
            if (set == new IntPtr(-1))
            {
                return "SetupDiCreateDeviceInfoList failed (error " + Marshal.GetLastWin32Error() + ")";
            }
            try
            {
                SP_DEVINFO_DATA data = new SP_DEVINFO_DATA();
                data.cbSize = Marshal.SizeOf(typeof(SP_DEVINFO_DATA));
                if (!SetupDiCreateDeviceInfo(set, "Net", ref netClass, null, IntPtr.Zero, DICD_GENERATE_ID, ref data))
                {
                    return "SetupDiCreateDeviceInfo failed (error " + Marshal.GetLastWin32Error() + ")";
                }
                byte[] ids = System.Text.Encoding.Unicode.GetBytes(hardwareId + "\0\0");
                if (!SetupDiSetDeviceRegistryProperty(set, ref data, SPDRP_HARDWAREID, ids, ids.Length))
                {
                    return "SetupDiSetDeviceRegistryProperty failed (error " + Marshal.GetLastWin32Error() + ")";
                }
                if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, set, ref data))
                {
                    return "SetupDiCallClassInstaller(DIF_REGISTERDEVICE) failed (error " + Marshal.GetLastWin32Error() + ")";
                }
                bool reboot;
                if (!UpdateDriverForPlugAndPlayDevices(IntPtr.Zero, hardwareId, infPath, INSTALLFLAG_FORCE, out reboot))
                {
                    int error = Marshal.GetLastWin32Error();
                    SetupDiCallClassInstaller(DIF_REMOVE, set, ref data);
                    return "UpdateDriverForPlugAndPlayDevices failed (error " + error + ")";
                }
                return null;
            }
            finally
            {
                SetupDiDestroyDeviceInfoList(set);
            }
        }

        // Removes the device with the instance id, as "devcon remove @<instance id>" does. Returns null on
        // success, else why it failed.
        public static string Remove(string instanceId)
        {
            Guid netClass = new Guid("4d36e972-e325-11ce-bfc1-08002be10318");
            IntPtr set = SetupDiCreateDeviceInfoList(ref netClass, IntPtr.Zero);
            if (set == new IntPtr(-1))
            {
                return "SetupDiCreateDeviceInfoList failed (error " + Marshal.GetLastWin32Error() + ")";
            }
            try
            {
                SP_DEVINFO_DATA data = new SP_DEVINFO_DATA();
                data.cbSize = Marshal.SizeOf(typeof(SP_DEVINFO_DATA));
                if (!SetupDiOpenDeviceInfo(set, instanceId, IntPtr.Zero, 0, ref data))
                {
                    return "SetupDiOpenDeviceInfo failed (error " + Marshal.GetLastWin32Error() + ")";
                }
                if (!SetupDiCallClassInstaller(DIF_REMOVE, set, ref data))
                {
                    return "SetupDiCallClassInstaller(DIF_REMOVE) failed (error " + Marshal.GetLastWin32Error() + ")";
                }
                return null;
            }
            finally
            {
                SetupDiDestroyDeviceInfoList(set);
            }
        }
    }
}
'@

function Initialize-OINative {
    if (-not ('OpenInfraLaunch.RootPin' -as [type])) {
        Add-Type -TypeDefinition $script:OINativeSource -Language CSharp
    }
}

function New-OICertificateCollection {
    param([object[]]$Certificates)
    $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    foreach ($c in @($Certificates)) { if ($null -ne $c) { [void]$col.Add($c) } }
    return , $col
}

# ---------------------------------------------------------------------------------------------------------
# Logging: agent.log, and the serial console (COM1, 115200 8N1), which EC2's GetConsoleOutput shows.
# ---------------------------------------------------------------------------------------------------------

$script:OIConsolePresent = $null

function Add-OIFileLine {
    param([string]$Path, [string]$Line)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Line + "`r`n")
    for ($i = 0; $i -lt 5; $i++) {
        try {
            $fs = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
            try { $fs.Write($bytes, 0, $bytes.Length) } finally { $fs.Dispose() }
            return
        } catch {
            Start-Sleep -Milliseconds 50
        }
    }
}

function Write-OIConsole {
    # The port is opened per line, so the -Run and -Serve processes can share it.
    param([string]$Line)
    if ($null -eq $script:OIConsolePresent) {
        try { $script:OIConsolePresent = ([System.IO.Ports.SerialPort]::GetPortNames() -contains 'COM1') }
        catch { $script:OIConsolePresent = $false }
    }
    if (-not $script:OIConsolePresent) { return }
    for ($i = 0; $i -lt 5; $i++) {
        $port = $null
        try {
            $port = New-Object System.IO.Ports.SerialPort 'COM1', 115200, ([System.IO.Ports.Parity]::None), 8, ([System.IO.Ports.StopBits]::One)
            $port.WriteTimeout = 2000
            $port.Open()
            $port.Write($Line + "`r`n")
            return
        } catch {
            Start-Sleep -Milliseconds 100
        } finally {
            if ($null -ne $port) { try { $port.Close() } catch { } }
        }
    }
}

function Write-OILog {
    param([string]$Message, [switch]$Console)
    $line = Format-OILogLine (Get-Date) $Message
    Add-OIFileLine $script:OIAgentLog $line
    if ($Console) { Write-OIConsole $line }
}

function Step-OILogRotation {
    foreach ($p in @($script:OIAgentLog, $script:OIUserDataLog)) {
        try {
            if ([System.IO.File]::Exists($p) -and (New-Object System.IO.FileInfo $p).Length -gt $script:OILogCapBytes) {
                Move-Item -LiteralPath $p -Destination ($p + '.1') -Force
            }
        } catch { }
    }
}

function Initialize-OIDirectories {
    foreach ($d in @($script:OIBase, $script:OIRoot, $script:OILogDir, $script:OIWorkDir)) {
        if (-not [System.IO.Directory]::Exists($d)) { [void][System.IO.Directory]::CreateDirectory($d) }
    }
    # LocalSystem and Administrators only: the stub runs as LocalSystem, and the logs carry user data output.
    try {
        & (Join-Path $env:SystemRoot 'System32\icacls.exe') $script:OIBase /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q 2>&1 | Out-Null
    } catch { }
}

function Get-OIPowerShellExe {
    return (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')
}

function Get-OIUtcNow {
    return ([System.DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0)
}

function Get-OIMonoNow {
    return ([System.Diagnostics.Stopwatch]::GetTimestamp() / [double][System.Diagnostics.Stopwatch]::Frequency)
}

# ---------------------------------------------------------------------------------------------------------
# The launch and identity CDs.
# ---------------------------------------------------------------------------------------------------------

function Find-OIDrive {
    # The root of the CD-ROM carrying all of Files, or $null.
    param([string[]]$Files)
    foreach ($d in [System.IO.DriveInfo]::GetDrives()) {
        try {
            if ($d.DriveType -ne [System.IO.DriveType]::CDRom -or -not $d.IsReady) { continue }
            $root = $d.RootDirectory.FullName
            $all = $true
            foreach ($f in $Files) { if (-not [System.IO.File]::Exists((Join-Path $root $f))) { $all = $false } }
            if ($all) { return $root }
        } catch { }
    }
    return $null
}

$script:OIIdentityRoot = $null

function Get-OIIdentityTokenPath {
    if ($script:OIIdentityRoot -and [System.IO.File]::Exists((Join-Path $script:OIIdentityRoot 'token'))) {
        return (Join-Path $script:OIIdentityRoot 'token')
    }
    $script:OIIdentityRoot = Find-OIDrive @('token', 'namespace')
    if ($script:OIIdentityRoot) { return (Join-Path $script:OIIdentityRoot 'token') }
    return $null
}

function Read-OILaunchConfig {
    param([string]$LaunchDir)
    $text = [System.IO.File]::ReadAllText((Join-Path $LaunchDir $script:OILaunchConfigName))
    return (ConvertTo-OILaunchConfig (ConvertFrom-Json -InputObject $text -ErrorAction Stop))
}

function Read-OICaFile {
    param([string]$Path)
    if (-not [System.IO.File]::Exists($Path)) { return @{ Ok = $false; Certificates = @(); Message = 'it is not on the launch CD' } }
    try { $text = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::ASCII) }
    catch { return @{ Ok = $false; Certificates = @(); Message = 'it cannot be read' } }
    return (ConvertFrom-OICaPem $text)
}

# ---------------------------------------------------------------------------------------------------------
# Trust: the platform's CAs in LocalMachine\Root, and the bundle AWS_CA_BUNDLE names (the AWS CLI v2 and other
# SDKs that ship their own CA bundle read only that one, so it is the machine's whole trusted root store).
# ---------------------------------------------------------------------------------------------------------

function Set-OIPlatformTrust {
    param([string]$LaunchDir)
    $required = New-Object 'System.Collections.Generic.List[byte[]]'
    $all = New-Object 'System.Collections.Generic.List[byte[]]'
    $x509 = 'System.Security.Cryptography.X509Certificates'
    $store = New-Object "$x509.X509Store" ([System.Security.Cryptography.X509Certificates.StoreName]::Root), ([System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    try {
        $items = @(
            @{ File = $script:OIPlatformCaName; What = 'the platform root CA' },
            @{ File = $script:OIAwsEndpointsCaName; What = 'the AWS endpoints CA' }
        )
        foreach ($item in $items) {
            $r = Read-OICaFile (Join-Path $LaunchDir $item.File)
            if (-not $r.Ok) {
                Write-OILog -Console ('{0} ({1}) is not trusted: {2}' -f $item.What, $item.File, $r.Message)
                continue
            }
            foreach ($c in $r.Certificates) {
                $required.Add($c.RawData)
                $found = $store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $c.Thumbprint, $false)
                if ($found.Count -gt 0) {
                    Write-OILog ('{0} is trusted (thumbprint {1})' -f $item.What, $c.Thumbprint)
                } else {
                    $store.Add($c)
                    Write-OILog -Console ('Trusted {0} (thumbprint {1})' -f $item.What, $c.Thumbprint)
                }
            }
        }
        foreach ($c in $store.Certificates) { $all.Add($c.RawData) }
    } finally {
        $store.Close()
    }
    $bundle = New-OICaBundle $all.ToArray() $required.ToArray()
    [System.IO.File]::WriteAllText($script:OICaBundlePath, $bundle, [System.Text.Encoding]::ASCII)
    [System.Environment]::SetEnvironmentVariable('AWS_CA_BUNDLE', $script:OICaBundlePath, [System.EnvironmentVariableTarget]::Machine)
    $env:AWS_CA_BUNDLE = $script:OICaBundlePath
    $count = ([regex]::Matches($bundle, '-----BEGIN CERTIFICATE-----')).Count
    Write-OILog ('Wrote {0} ({1} certificates: the trusted root store and the platform CAs); AWS_CA_BUNDLE names it' -f $script:OICaBundlePath, $count)
}

# ---------------------------------------------------------------------------------------------------------
# The platform's instance credentials and identity service (the aws-shim): TLS only, pinned to the platform
# root CA, no proxy, no redirects.
# ---------------------------------------------------------------------------------------------------------

function Read-OIResponseBody {
    param($Response)
    $reader = New-Object System.IO.StreamReader ($Response.GetResponseStream()), ([System.Text.Encoding]::UTF8)
    try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
}

function Invoke-OIShimGet {
    # GET Url on the platform's instance credentials or identity service (Service) with this instance's
    # identity -> @{ Ok; Body; Status } or a failure. No message names the service's host.
    param([string]$Url, [AllowNull()][string]$TokenPath, [object]$Roots, [hashtable]$Hints, [string]$Service = 'credentials', [int]$TimeoutMs = 5000)
    $what = "the platform's instance " + $Service + ' service'
    if (-not ([string]$Url).StartsWith('https://', [System.StringComparison]::OrdinalIgnoreCase)) {
        return @{ Ok = $false; Status = $null; Message = ("refusing to send the instance's identity to {0} without TLS" -f $what) }
    }
    if ($null -eq $Roots -or $Roots.Count -eq 0) {
        return @{ Ok = $false; Status = $null; Message = ('no platform root CA to verify {0} with ({1} on the launch CD is missing or not a CA certificate), so nothing is fetched' -f $what, $script:OIPlatformCaName) }
    }
    if (-not $TokenPath) {
        return @{ Ok = $false; Status = $null; Message = ("the instance's identity disk is not attached, so {0} cannot be asked" -f $what) }
    }
    try { $token = ([System.IO.File]::ReadAllText($TokenPath)) -replace '\s', '' }
    catch { return @{ Ok = $false; Status = $null; Message = "the instance's identity cannot be read from its identity disk" } }
    if (-not $token) { return @{ Ok = $false; Status = $null; Message = "the instance's identity on its identity disk is empty" } }
    Initialize-OINative
    $pin = [OpenInfraLaunch.RootPin]::new($Roots)
    try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12 } catch { }
    $req = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($Url)
    $req.Method = 'GET'
    $req.Accept = 'application/json'
    $req.Proxy = $null
    $req.AllowAutoRedirect = $false
    $req.KeepAlive = $false
    $req.Timeout = $TimeoutMs
    $req.ReadWriteTimeout = $TimeoutMs
    $req.ServerCertificateValidationCallback = $pin.Callback()
    $req.Headers.Add('Authorization', $token)
    $resp = $null
    try {
        $resp = [System.Net.HttpWebResponse]$req.GetResponse()
        $status = [int]$resp.StatusCode
        $body = Read-OIResponseBody $resp
        if ($status -lt 200 -or $status -gt 299) {
            return @{ Ok = $false; Status = $status; Message = (Format-OIShimHttpError $Service $status $body $Hints) }
        }
        return @{ Ok = $true; Status = $status; Body = $body }
    } catch {
        $e = $_.Exception
        while ($null -ne $e -and -not ($e -is [System.Net.WebException]) -and $null -ne $e.InnerException) { $e = $e.InnerException }
        if ($e -is [System.Net.WebException] -and $null -ne $e.Response) {
            $er = [System.Net.HttpWebResponse]$e.Response
            $status = [int]$er.StatusCode
            $detail = ''
            try { $detail = Read-OIResponseBody $er } catch { }
            try { $er.Close() } catch { }
            return @{ Ok = $false; Status = $status; Message = (Format-OIShimHttpError $Service $status $detail $Hints) }
        }
        if ($pin.LastFailure) {
            return @{ Ok = $false; Status = $null; Message = ("the server answering as {0} is not the platform (TLS verification against the platform root CA failed: {1}); the instance's identity was not sent" -f $what, $pin.LastFailure) }
        }
        $webStatus = ''
        if ($e -is [System.Net.WebException]) { $webStatus = [string]$e.Status }
        if ($webStatus -eq 'TrustFailure' -or $webStatus -eq 'SecureChannelFailure') {
            return @{ Ok = $false; Status = $null; Message = ("the TLS handshake with {0} failed; the instance's identity was not sent" -f $what) }
        }
        return @{ Ok = $false; Status = $null; Message = ('cannot reach {0}: {1}' -f $what, (Get-OIWebFailureText $webStatus)) }
    } finally {
        if ($null -ne $resp) { try { $resp.Close() } catch { } }
    }
}

function Get-OIShimCredentials {
    param([hashtable]$Cache)
    $r = Invoke-OIShimGet -Url $Cache.Url -TokenPath (Get-OIIdentityTokenPath) -Roots $Cache.Roots -Hints $script:OICredsHints -Service 'credentials'
    if (-not $r.Ok) { return $r }
    return (ConvertFrom-OICredentialsDocument $r.Body)
}

function Get-OIShimIdentity {
    param([hashtable]$Cache)
    $r = Invoke-OIShimGet -Url $Cache.Url -TokenPath (Get-OIIdentityTokenPath) -Roots $Cache.Roots -Hints $script:OIIdentityHints -Service 'identity'
    if (-not $r.Ok) { return $r }
    return (ConvertFrom-OIIdentityDocument $r.Body)
}

# ---------------------------------------------------------------------------------------------------------
# What the instance metadata service observes about the instance at request time.
# ---------------------------------------------------------------------------------------------------------

function Format-OIMac {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return $null }
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($b in $Bytes) { $parts.Add($b.ToString('x2')) }
    return ($parts -join ':')
}

function Get-OIHostFacts {
    $mono = Get-OIMonoNow
    $arch = $env:PROCESSOR_ARCHITEW6432
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    $facts = @{
        Hostname = [System.Net.Dns]::GetHostName(); LocalIPv4 = $null; Mac = $null
        LocalAddresses = @(); ContainerNetworks = @(); Architecture = (ConvertTo-OIArchitecture $arch)
        BootTime = ((Get-OIUtcNow) - $mono); Taken = $mono
    }
    $sock = $null
    try {
        # The default route's source address (TEST-NET-1: nothing is sent).
        $sock = New-Object System.Net.Sockets.Socket ([System.Net.Sockets.AddressFamily]::InterNetwork), ([System.Net.Sockets.SocketType]::Dgram), ([System.Net.Sockets.ProtocolType]::Udp)
        $sock.Connect('192.0.2.1', 9)
        $facts.LocalIPv4 = $sock.LocalEndPoint.Address.ToString()
    } catch {
    } finally {
        if ($null -ne $sock) { $sock.Close() }
    }
    $local = New-Object System.Collections.Generic.List[string]
    $local.Add('127.0.0.1')
    $local.Add($script:OIImdsAddress)
    $nets = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            $props = $nic.GetIPProperties()
            $hasGateway = $false
            foreach ($gw in $props.GatewayAddresses) {
                if ($gw.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and $gw.Address.ToString() -ne '0.0.0.0') { $hasGateway = $true }
            }
            # A Hyper-V virtual adapter with no gateway is the host side of a container network (NAT).
            $containerNic = (-not $hasGateway) -and ([string]$nic.Description).StartsWith('Hyper-V Virtual Ethernet Adapter', [System.StringComparison]::OrdinalIgnoreCase)
            foreach ($ua in $props.UnicastAddresses) {
                if ($ua.Address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { continue }
                $a = $ua.Address.ToString()
                $local.Add($a)
                if ($a -eq $facts.LocalIPv4 -and -not $facts.Mac) { $facts.Mac = Format-OIMac $nic.GetPhysicalAddress().GetAddressBytes() }
                if ($containerNic) {
                    $mask = ConvertTo-OIIPv4Mask ([int]$ua.PrefixLength)
                    $nets.Add(@{ Network = ((ConvertTo-OIIPv4Number $a) -band $mask); Mask = $mask })
                }
            }
        }
    } catch { }
    $facts.LocalAddresses = $local.ToArray()
    $facts.ContainerNetworks = $nets.ToArray()
    return $facts
}

# ---------------------------------------------------------------------------------------------------------
# The metadata address and the -Serve process.
# ---------------------------------------------------------------------------------------------------------

function Test-OIImdsAddressPresent {
    return ($null -ne (Get-NetIPAddress -AddressFamily IPv4 -IPAddress $script:OIImdsAddress -ErrorAction SilentlyContinue))
}

function Set-OIImdsFirewallRule {
    # Lets the instance's containers reach the metadata service: their connections arrive on a virtual
    # adapter, which the firewall filters (the instance's own are loopback, which it does not). Other hosts
    # are refused by the service itself.
    try {
        if (-not (Get-NetFirewallRule -Name $script:OIFirewallRuleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -Name $script:OIFirewallRuleName -DisplayName 'OpenInfra instance metadata (169.254.169.254:80)' -Direction Inbound -Protocol TCP -LocalAddress $script:OIImdsAddress -LocalPort 80 -Action Allow -Profile Any -ErrorAction Stop | Out-Null
        }
    } catch {
        Write-OILog ('The firewall rule for instance metadata was not added: {0}' -f $_.Exception.Message)
    }
}

function Select-OIMetadataAdapter {
    # The instance metadata adapter among the network adapters (@{ Name; InterfaceIndex; Loopback; Device }):
    # the loopback adapter named "OpenInfra Metadata"; else the loopback device this agent recorded as its own
    # (KnownDevice); else, given the loopback devices there were before this agent created one (BeforeDevices;
    # $null: it created none), the loopback adapter that is new. A customer's own loopback adapter is never
    # taken.
    param([object[]]$Adapters, $BeforeDevices = $null, [string]$KnownDevice = '')
    foreach ($a in @($Adapters)) {
        if ($null -ne $a -and $a.Loopback -and [string]$a.Name -eq $script:OIMetadataAdapterName) { return $a }
    }
    if ($KnownDevice) {
        foreach ($a in @($Adapters)) {
            if ($null -ne $a -and $a.Loopback -and [string]$a.Device -eq $KnownDevice) { return $a }
        }
    }
    if ($null -eq $BeforeDevices) { return $null }
    $before = @{}
    foreach ($d in @($BeforeDevices)) { if ($d) { $before[[string]$d] = $true } }
    foreach ($a in @($Adapters)) {
        if ($null -ne $a -and $a.Loopback -and -not $before.ContainsKey([string]$a.Device)) { return $a }
    }
    return $null
}

function Get-OIKnownAdapterDevice {
    try {
        if ([System.IO.File]::Exists($script:OIAdapterDevicePath)) { return ([System.IO.File]::ReadAllText($script:OIAdapterDevicePath)).Trim() }
    } catch { }
    return ''
}

function Get-OINetworkAdapters {
    # The network adapters, each marked when it is a Microsoft KM-TEST Loopback Adapter (hardware id *MSLOOP).
    $loop = @{}
    foreach ($d in @(Get-CimInstance -ClassName Win32_PnPEntity -Filter "PNPClass = 'Net'" -ErrorAction SilentlyContinue)) {
        if (@($d.HardwareID) -contains $script:OILoopbackHardwareId) { $loop[[string]$d.PNPDeviceID] = $true }
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($a in @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue)) {
        $out.Add(@{ Name = [string]$a.Name; InterfaceIndex = [int]$a.InterfaceIndex; Loopback = $loop.ContainsKey([string]$a.PnPDeviceID); Device = [string]$a.PnPDeviceID; Status = [string]$a.Status })
    }
    return , $out.ToArray()
}

function Get-OILoopbackDevices {
    $ids = New-Object System.Collections.Generic.List[string]
    foreach ($a in (Get-OINetworkAdapters)) { if ($a.Loopback) { $ids.Add($a.Device) } }
    return , $ids.ToArray()
}

function New-OIMetadataAdapter {
    # Create a Microsoft KM-TEST Loopback Adapter (the inbox netloop.inf), as "devcon install netloop.inf
    # *MSLOOP" does, and wait for it to appear. -> the adapter, or throws.
    $inf = Join-Path $env:SystemRoot 'INF\netloop.inf'
    if (-not [System.IO.File]::Exists($inf)) { throw ('{0} is missing, so no loopback adapter can be created' -f $inf) }
    $before = Get-OILoopbackDevices
    $script:OILoopbackBefore = $before  # one creation per process: later calls look for this one
    Initialize-OINative
    Write-OILog -Console ('Creating the instance metadata adapter "{0}" (Microsoft KM-TEST Loopback Adapter)' -f $script:OIMetadataAdapterName)
    $failure = [OpenInfraLaunch.LoopbackAdapter]::Install($inf, $script:OILoopbackHardwareId)
    if ($failure) { throw ('the loopback adapter was not created: ' + $failure) }
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        $a = Select-OIMetadataAdapter (Get-OINetworkAdapters) $before (Get-OIKnownAdapterDevice)
        if ($null -ne $a) { return $a }
        Start-Sleep -Seconds 2
    }
    throw 'the loopback adapter was created but did not appear as a network adapter within a minute'
}

function Remove-OIStrayImdsAddress {
    # 169.254.169.254 belongs on the metadata adapter alone. An earlier agent put it on the instance's NIC,
    # which turned that NIC's DHCP off: remove it there, and when the NIC is left with no IPv4 address and DHCP
    # off, turn DHCP back on.
    param([int]$KeepIndex = -1, [string]$Why = 'it belongs on the instance metadata adapter')
    foreach ($e in @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $script:OIImdsAddress -ErrorAction SilentlyContinue)) {
        $idx = [int]$e.InterfaceIndex
        if ($idx -eq $KeepIndex) { continue }
        Remove-NetIPAddress -InputObject $e -Confirm:$false -ErrorAction SilentlyContinue
        Write-OILog -Console ('Removed 169.254.169.254 from interface {0} ({1}): {2}' -f $idx, $e.InterfaceAlias, $Why)
        $left = @(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $idx -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne $script:OIImdsAddress })
        $ipif = Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $idx -ErrorAction SilentlyContinue
        if ($left.Count -eq 0 -and $null -ne $ipif -and [string]$ipif.Dhcp -eq 'Disabled') {
            Set-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4 -Dhcp Enabled -ErrorAction SilentlyContinue
            Write-OILog -Console ('Interface {0} ({1}) had no address left: DHCP is on again' -f $idx, $e.InterfaceAlias)
        }
    }
}

function Format-OIInterfaceState {
    # One line per IPv4 interface: alias, index, connection state, DHCP, metric, addresses with their state,
    # and its default routes. Takes what Get-NetIPInterface, Get-NetIPAddress and Get-NetRoute report.
    param([object[]]$Interfaces, [object[]]$Addresses, [object[]]$Routes)
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($i in @($Interfaces)) {
        if ($null -eq $i) { continue }
        $idx = [int]$i.InterfaceIndex
        $addrs = New-Object System.Collections.Generic.List[string]
        foreach ($a in @($Addresses)) {
            if ($null -ne $a -and [int]$a.InterfaceIndex -eq $idx) { $addrs.Add(('{0}/{1} {2}' -f $a.IPAddress, $a.PrefixLength, $a.AddressState)) }
        }
        $gws = New-Object System.Collections.Generic.List[string]
        foreach ($r in @($Routes)) {
            if ($null -ne $r -and [int]$r.InterfaceIndex -eq $idx -and [string]$r.DestinationPrefix -eq '0.0.0.0/0') { $gws.Add([string]$r.NextHop) }
        }
        $list = 'none'
        if ($addrs.Count -gt 0) { $list = $addrs -join ', ' }
        $line = 'Interface {0} (index {1}): {2}, DHCP {3}, metric {4}, addresses {5}' -f $i.InterfaceAlias, $idx, $i.ConnectionState, $i.Dhcp, $i.InterfaceMetric, $list
        if ($gws.Count -gt 0) { $line += '; default route via ' + ($gws -join ', ') }
        $lines.Add($line)
    }
    return , $lines.ToArray()
}

function Write-OIInterfaceState {
    # The interfaces' state, to the console: what to look at when instance metadata is not reachable.
    try {
        $ifs = @(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop)
        $addrs = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)
        $routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
        foreach ($line in (Format-OIInterfaceState $ifs $addrs $routes)) { Write-OILog -Console $line }
    } catch {
        Write-OILog -Console ('The interfaces could not be listed: {0}' -f $_.Exception.Message)
    }
}

function Set-OIImdsAddress {
    # 169.254.169.254/32 on the instance's own metadata adapter: a Microsoft KM-TEST Loopback Adapter named
    # "OpenInfra Metadata", created once (it stays, also in an image made from the instance; its device id is
    # recorded so it is found again), with that static address alone, no DHCP, no gateway, a high metric and
    # no DNS registration. The instance's NICs are never changed. On any failure the reason and the
    # interfaces' state go to the console. -> $true when the address is in place.
    $step = 'finding the metadata adapter'
    try {
        $known = Get-OIKnownAdapterDevice
        $adapter = Select-OIMetadataAdapter (Get-OINetworkAdapters) $script:OILoopbackBefore $known
        $keep = -1
        if ($null -ne $adapter) { $keep = [int]$adapter.InterfaceIndex }
        $step = 'removing 169.254.169.254 from other interfaces'
        Remove-OIStrayImdsAddress $keep
        if ($null -eq $adapter) {
            if ($null -ne $script:OILoopbackBefore) { throw 'the loopback adapter created earlier has not appeared' }
            $step = 'creating the metadata adapter'
            $adapter = New-OIMetadataAdapter
        }
        if ($adapter.Device -and $adapter.Device -ne $known) {
            [System.IO.File]::WriteAllText($script:OIAdapterDevicePath, $adapter.Device, [System.Text.Encoding]::ASCII)
        }
        $idx = [int]$adapter.InterfaceIndex
        if ($adapter.Name -ne $script:OIMetadataAdapterName) {
            $step = 'naming the metadata adapter'
            for ($i = 1; $true; $i++) {
                try {
                    Rename-NetAdapter -Name $adapter.Name -NewName $script:OIMetadataAdapterName -ErrorAction Stop
                    break
                } catch {
                    if ($i -ge 5) { throw }
                    Start-Sleep -Seconds 2
                }
            }
        }
        if ($adapter.Status -eq 'Disabled') {
            $step = 'enabling the metadata adapter'
            Enable-NetAdapter -Name $script:OIMetadataAdapterName -Confirm:$false -ErrorAction Stop
        }
        $step = 'waiting for the metadata adapter''s IPv4 interface'
        $deadline = (Get-Date).AddSeconds(30)
        while ($null -eq (Get-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
            if ((Get-Date) -gt $deadline) { throw 'the metadata adapter has no IPv4 interface' }
            Start-Sleep -Seconds 1
        }
        $step = 'configuring the metadata adapter'
        Set-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4 -Dhcp Disabled -InterfaceMetric 9999 -ErrorAction Stop
        Set-DnsClient -InterfaceIndex $idx -RegisterThisConnectionsAddress $false -ErrorAction SilentlyContinue
        foreach ($r in @(Get-NetRoute -AddressFamily IPv4 -InterfaceIndex $idx -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)) {
            Remove-NetRoute -InputObject $r -Confirm:$false -ErrorAction SilentlyContinue
        }
        $have = $false
        foreach ($a in @(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $idx -ErrorAction SilentlyContinue)) {
            if ($a.IPAddress -eq $script:OIImdsAddress -and [int]$a.PrefixLength -eq 32) {
                $have = $true
                if ($a.SkipAsSource) { Set-NetIPAddress -InputObject $a -SkipAsSource $false -ErrorAction SilentlyContinue }
            } else {
                Remove-NetIPAddress -InputObject $a -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
        if (-not $have) {
            $step = 'adding 169.254.169.254/32 to the metadata adapter'
            # Not SkipAsSource: the instance's own requests to 169.254.169.254 are sourced from it, so they
            # work before DHCP has given the NIC an address; strong-host sending keeps it off the NICs' traffic.
            New-NetIPAddress -InterfaceIndex $idx -IPAddress $script:OIImdsAddress -PrefixLength 32 -ErrorAction Stop | Out-Null
            Write-OILog ('Added 169.254.169.254/32 to the instance metadata adapter (interface {0})' -f $idx)
        }
        $step = 'waiting for 169.254.169.254 to be usable'
        $deadline = (Get-Date).AddSeconds(15)
        while ($true) {
            $a = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $idx -IPAddress $script:OIImdsAddress -ErrorAction SilentlyContinue
            if ($null -ne $a -and [string]$a.AddressState -eq 'Preferred') { break }
            if ((Get-Date) -gt $deadline) { throw ('169.254.169.254 is {0} on the metadata adapter' -f $(if ($null -eq $a) { 'missing' } else { [string]$a.AddressState })) }
            Start-Sleep -Milliseconds 500
        }
        Set-OIImdsFirewallRule
        return $true
    } catch {
        Write-OILog -Console ('Instance metadata address: {0} failed: {1}' -f $step, $_.Exception.Message)
        Write-OIInterfaceState
        return $false
    }
}

# ---------------------------------------------------------------------------------------------------------
# Instance metadata outside the instance (launch-config imds.outside): the platform serves it from the
# instance's pod, reached through the instance's network adapter. The agent routes 169.254.169.254 through
# the adapter's default gateway, as EC2Launch routes it on EC2, and removes the metadata adapter an earlier
# agent made (an instance from before, or an image of one), so no request for it stays inside the instance.
# ---------------------------------------------------------------------------------------------------------

function Select-OIDefaultRoute {
    # The default route instance metadata goes through: among the IPv4 default routes (@{ InterfaceIndex;
    # NextHop; Metric }), the one with a gateway and the lowest metric. -> that route, or $null.
    param([object[]]$Routes)
    $best = $null
    foreach ($r in @($Routes)) {
        if ($null -eq $r -or -not $r.NextHop -or [string]$r.NextHop -eq '0.0.0.0') { continue }
        if ($null -eq $best -or [int]$r.Metric -lt [int]$best.Metric) { $best = $r }
    }
    return $best
}

function Get-OIMetadataRouteChanges {
    # The changes that leave 169.254.169.254/32 routed through Gateway (@{ InterfaceIndex; NextHop }) alone,
    # given the routes to it there are (@{ InterfaceIndex; NextHop; Route }). -> @{ Remove = routes; Add = bool }.
    param([object[]]$Existing, $Gateway)
    $remove = New-Object System.Collections.Generic.List[object]
    $have = $false
    foreach ($r in @($Existing)) {
        if ($null -eq $r) { continue }
        if (-not $have -and [int]$r.InterfaceIndex -eq [int]$Gateway.InterfaceIndex -and [string]$r.NextHop -eq [string]$Gateway.NextHop) {
            $have = $true
        } else {
            $remove.Add($r)
        }
    }
    return @{ Remove = $remove.ToArray(); Add = (-not $have) }
}

function Set-OIMetadataRoute {
    # 169.254.169.254/32 through the instance's default gateway. -> $true when the route is in place; $false
    # (logged unless -Quiet) when the instance has no default gateway yet, or the route could not be added.
    param([switch]$Quiet)
    try {
        $defaults = New-Object System.Collections.Generic.List[object]
        foreach ($d in @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)) {
            $ifm = Get-NetIPInterface -InterfaceIndex $d.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            $m = [int]$d.RouteMetric
            if ($null -ne $ifm) { $m += [int]$ifm.InterfaceMetric }
            $defaults.Add(@{ InterfaceIndex = [int]$d.InterfaceIndex; NextHop = [string]$d.NextHop; Metric = $m })
        }
        $gw = Select-OIDefaultRoute $defaults.ToArray()
        if ($null -eq $gw) { throw 'the instance has no default gateway yet' }
        $existing = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix ($script:OIImdsAddress + '/32') -ErrorAction SilentlyContinue |
            ForEach-Object { @{ InterfaceIndex = [int]$_.InterfaceIndex; NextHop = [string]$_.NextHop; Route = $_ } })
        $plan = Get-OIMetadataRouteChanges $existing $gw
        foreach ($r in $plan.Remove) { Remove-NetRoute -InputObject $r.Route -Confirm:$false -ErrorAction SilentlyContinue }
        if ($plan.Add) {
            New-NetRoute -AddressFamily IPv4 -DestinationPrefix ($script:OIImdsAddress + '/32') -InterfaceIndex $gw.InterfaceIndex -NextHop $gw.NextHop -RouteMetric 15 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
            Write-OILog -Console ('Instance metadata (169.254.169.254) is routed through the gateway {0} (interface {1})' -f $gw.NextHop, $gw.InterfaceIndex)
        }
        return $true
    } catch {
        if (-not $Quiet) {
            Write-OILog -Console ('Routing instance metadata through the gateway failed: {0}' -f $_.Exception.Message)
            Write-OIInterfaceState
        }
        return $false
    }
}

function Wait-OIMetadataRoute {
    # Set-OIMetadataRoute, retried until the instance has its default gateway (DHCP), for up to TimeoutSeconds.
    param([int]$TimeoutSeconds)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Set-OIMetadataRoute -Quiet) { return $true }
        Start-Sleep -Seconds 2
    }
    return (Set-OIMetadataRoute)
}

function Remove-OIMetadataAdapter {
    # The metadata adapter an earlier agent made (an instance from before instance metadata moved outside it,
    # or one launched from an image of such an instance): its address, the adapter itself and its firewall
    # rule are removed, and 169.254.169.254 is taken off every interface, so a request for it leaves the
    # instance. A customer's own loopback adapter is never touched (Select-OIMetadataAdapter).
    try {
        Remove-OIStrayImdsAddress -1 'instance metadata is served outside the instance'
        $known = Get-OIKnownAdapterDevice
        $adapter = Select-OIMetadataAdapter (Get-OINetworkAdapters) $null $known
        if ($null -ne $adapter -and $adapter.Device) {
            Initialize-OINative
            $failure = [OpenInfraLaunch.LoopbackAdapter]::Remove($adapter.Device)
            if ($failure) {
                Write-OILog -Console ('The instance metadata adapter "{0}" was not removed ({1}); disabling it' -f $adapter.Name, $failure)
                Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
            } else {
                Write-OILog -Console ('Removed the instance metadata adapter "{0}": instance metadata is served outside the instance' -f $adapter.Name)
            }
        }
        if ([System.IO.File]::Exists($script:OIAdapterDevicePath)) { Remove-Item -LiteralPath $script:OIAdapterDevicePath -Force -ErrorAction SilentlyContinue }
        Remove-NetFirewallRule -Name $script:OIFirewallRuleName -ErrorAction SilentlyContinue
    } catch {
        Write-OILog -Console ('Removing the instance metadata adapter failed: {0}' -f $_.Exception.Message)
    }
}

function Start-OITcpListener {
    # A TCP listener on Address:Port -> @{ Listener; InUse; Message }. It does not take the port exclusively,
    # so a workload can still bind 0.0.0.0:80 while 169.254.169.254:80, the more specific address, keeps the
    # metadata traffic, as on EC2. InUse: the port is already held exclusively, by the HTTP Server API when
    # IIS runs.
    param([string]$Address = $script:OIImdsAddress, [int]$Port = 80, [int]$Attempts = 15)
    $message = ''
    $inUse = 0
    for ($i = 0; $i -lt $Attempts; $i++) {
        $l = New-Object System.Net.Sockets.TcpListener ([System.Net.IPAddress]::Parse($Address)), $Port
        try {
            try { $l.ExclusiveAddressUse = $false } catch { }
            $l.Start(128)
            return @{ Listener = $l; InUse = $false; Message = '' }
        } catch {
            $e = $_.Exception
            while ($null -ne $e -and -not ($e -is [System.Net.Sockets.SocketException]) -and $null -ne $e.InnerException) { $e = $e.InnerException }
            $message = $e.Message
            try { $l.Stop() } catch { }
            if ($e -is [System.Net.Sockets.SocketException] -and ($e.SocketErrorCode -eq [System.Net.Sockets.SocketError]::AddressAlreadyInUse -or $e.SocketErrorCode -eq [System.Net.Sockets.SocketError]::AccessDenied)) {
                $inUse++
                if ($inUse -ge 3) { return @{ Listener = $null; InUse = $true; Message = $message } }
            }
            if ($i -lt $Attempts - 1) { Start-Sleep -Seconds 2 }
        }
    }
    return @{ Listener = $null; InUse = $false; Message = $message }
}

function Close-OIConnection {
    param([hashtable]$Conn)
    $Conn.Closed = $true
    try { $Conn.Socket.Close() } catch { }
    try { $Conn.Data.Dispose() } catch { }
}

function Send-OITcpResponse {
    param([hashtable]$Conn, [hashtable]$Result, [string]$Method, [int]$Ttl)
    try {
        # The IMDSv2 token response leaves with the PUT response hop limit as its IP TTL, so each router on its
        # way (a container's NAT, a bridge the instance routes for) takes one off, as on EC2.
        if ($Ttl -gt 0) { $Conn.Socket.Ttl = [int16]$Ttl }
        $bytes = ConvertTo-OIHttpResponse $Result $Method (Get-Date)
        $off = 0
        while ($off -lt $bytes.Length) { $off += $Conn.Socket.Send($bytes, $off, $bytes.Length - $off, [System.Net.Sockets.SocketFlags]::None) }
        $Conn.Socket.Shutdown([System.Net.Sockets.SocketShutdown]::Send)
    } catch { }
    Close-OIConnection $Conn
}

function Add-OIConnection {
    # Accept one connection. Another host gets no answer: its connection is closed unread.
    param($Listener, [System.Collections.Generic.List[hashtable]]$Connections, [hashtable]$State)
    $sock = $Listener.AcceptSocket()
    if ($Connections.Count -ge 64) {
        try { $sock.Close() } catch { }
        return
    }
    $remote = ''
    try { $remote = [string]$sock.RemoteEndPoint.Address } catch { }
    $f = $State.Facts
    $verdict = Get-OIImdsAdmission $remote $f.LocalAddresses $f.ContainerNetworks 'GET' 64
    if ($verdict -eq 'refuse' -and ((Get-OIMonoNow) - $f.Taken) -gt 2) {
        $State.Facts = Get-OIHostFacts  # perhaps an address this instance has just gained
        $f = $State.Facts
        $verdict = Get-OIImdsAdmission $remote $f.LocalAddresses $f.ContainerNetworks 'GET' 64
    }
    if ($verdict -ne 'serve') {
        try { $sock.Close() } catch { }
        return
    }
    $sock.NoDelay = $true
    $sock.SendTimeout = 2000
    $Connections.Add(@{ Socket = $sock; Remote = $remote; Data = (New-Object System.IO.MemoryStream); Deadline = ((Get-OIMonoNow) + 10); Closed = $false })
}

function Receive-OIConnection {
    # Read what a connection sent; once its request is complete, answer it and close the connection.
    param([hashtable]$Conn, [hashtable]$State)
    $buf = New-Object byte[] 8192
    $n = 0
    try { $n = $Conn.Socket.Receive($buf) } catch { $n = 0 }
    if ($n -le 0) {
        Close-OIConnection $Conn
        return
    }
    $Conn.Data.Write($buf, 0, $n)
    $req = ConvertFrom-OIHttpRequest $Conn.Data.ToArray()
    if ($req.State -eq 'incomplete') {
        if ($Conn.Data.Length -gt ($script:OIMaxHeaderBytes + $script:OIMaxBodyBytes)) { Close-OIConnection $Conn }
        return
    }
    if ($req.State -eq 'bad') {
        Send-OITcpResponse $Conn (New-OIResponse 400 'text/plain' "Bad Request`n") 'GET' 0
        return
    }
    $hop = [int]$State.Config.imds.hopLimit
    $f = $State.Facts
    if ((Get-OIImdsAdmission $Conn.Remote $f.LocalAddresses $f.ContainerNetworks $req.Method $hop) -ne 'serve') {
        # A token request from a container beyond the hop limit: as on EC2, no answer reaches it.
        Close-OIConnection $Conn
        return
    }
    $State.UtcNow = Get-OIUtcNow
    $State.MonoNow = Get-OIMonoNow
    $r = Invoke-OIImdsRequest $req.Method (Get-OIRequestPath $req.Target) $req.Headers $State
    $ttl = 0
    if ($req.Method -eq 'PUT' -and $r.Status -eq 200) { $ttl = $hop }
    Send-OITcpResponse $Conn $r $req.Method $ttl
}

function Invoke-OIServeTcp {
    # The metadata service's loop: one thread, many connections (select), each answered once and closed, the
    # caches refreshed in between. Iterations > 0, or Until returning $true, ends it (for tests).
    param($Listener, [hashtable]$State, [int]$Iterations = 0, [int]$WaitMicroseconds = 500000, [scriptblock]$Until = $null)
    $conns = New-Object 'System.Collections.Generic.List[hashtable]'
    $lastTick = Get-OIMonoNow
    $turn = 0
    while ($Iterations -le 0 -or $turn -lt $Iterations) {
        if ($null -ne $Until -and (& $Until)) { break }
        $turn++
        try {
            $read = New-Object System.Collections.ArrayList
            [void]$read.Add($Listener.Server)
            foreach ($c in $conns) { [void]$read.Add($c.Socket) }
            [System.Net.Sockets.Socket]::Select($read, $null, $null, $WaitMicroseconds)
            foreach ($c in @($conns)) {
                if (-not $c.Closed -and $read.Contains($c.Socket)) { Receive-OIConnection $c $State }
            }
            while ($Listener.Pending()) { Add-OIConnection $Listener $conns $State }
            $now = Get-OIMonoNow
            $keep = New-Object 'System.Collections.Generic.List[hashtable]'
            foreach ($c in $conns) {
                if (-not $c.Closed -and $now -gt $c.Deadline) { Close-OIConnection $c }
                if (-not $c.Closed) { $keep.Add($c) }
            }
            $conns = $keep
        } catch {
            Write-OILog ('Instance metadata service: {0}' -f $_.Exception.Message)
            Start-Sleep -Milliseconds 200
        }
        if ((Get-OIMonoNow) - $lastTick -ge 1) {
            Invoke-OIServeTick $State
            $lastTick = Get-OIMonoNow
        }
    }
    foreach ($c in $conns) { Close-OIConnection $c }
}

function Start-OIHttpSysListener {
    # The fallback when port 80 is already held by the HTTP Server API (IIS): it shares the port by host name.
    $last = ''
    for ($i = 0; $i -lt 15; $i++) {
        $l = New-Object System.Net.HttpListener
        try {
            $l.Prefixes.Add($script:OIImdsPrefix)
            $l.IgnoreWriteExceptions = $true
            $l.Start()
            return $l
        } catch {
            $last = $_.Exception.Message
            try { $l.Close() } catch { }
            Start-Sleep -Seconds 2
        }
    }
    Write-OILog -Console ('The instance metadata service could not listen through the HTTP Server API: {0}' -f $last)
    return $null
}

function Send-OIResponse {
    param($Response, [hashtable]$Result)
    try {
        $Response.StatusCode = $Result.Status
        $Response.ContentType = $Result.ContentType
        $Response.KeepAlive = $false
        try { $Response.Headers.Set('Server', 'EC2ws') } catch { }
        foreach ($k in $Result.Headers.Keys) { $Response.Headers.Set([string]$k, [string]$Result.Headers[$k]) }
        $body = [byte[]]$Result.Body
        $Response.ContentLength64 = $body.Length
        if ($body.Length -gt 0) { $Response.OutputStream.Write($body, 0, $body.Length) }
        $Response.Close()
    } catch {
        try { $Response.Abort() } catch { }
    }
}

function Invoke-OIServeRequest {
    param($Context, [hashtable]$State)
    $req = $Context.Request
    $resp = $Context.Response
    try {
        $method = [string]$req.HttpMethod
        $remote = [string]$req.RemoteEndPoint.Address
        $hop = [int]$State.Config.imds.hopLimit
        $f = $State.Facts
        $verdict = Get-OIImdsAdmission $remote $f.LocalAddresses $f.ContainerNetworks $method $hop
        if ($verdict -eq 'refuse' -and ((Get-OIMonoNow) - $f.Taken) -gt 2) {
            $State.Facts = Get-OIHostFacts
            $f = $State.Facts
            $verdict = Get-OIImdsAdmission $remote $f.LocalAddresses $f.ContainerNetworks $method $hop
        }
        if ($verdict -ne 'serve') {
            $resp.Abort()
            return
        }
        $headers = @{}
        foreach ($k in $req.Headers.AllKeys) { $headers[$k] = $req.Headers[$k] }
        $State.UtcNow = Get-OIUtcNow
        $State.MonoNow = Get-OIMonoNow
        $r = Invoke-OIImdsRequest $method (Get-OIRequestPath $req.RawUrl) $headers $State
        Send-OIResponse $resp $r
    } catch {
        try { $resp.Abort() } catch { }
    }
}

function Invoke-OIServeHttpSys {
    param($Listener, [hashtable]$State)
    $lastTick = Get-OIMonoNow
    while ($true) {
        try {
            $ar = $Listener.BeginGetContext($null, $null)
            while (-not $ar.AsyncWaitHandle.WaitOne(1000)) {
                Invoke-OIServeTick $State
                $lastTick = Get-OIMonoNow
            }
            $ctx = $Listener.EndGetContext($ar)
            Invoke-OIServeRequest $ctx $State
            if ((Get-OIMonoNow) - $lastTick -ge 1) {
                Invoke-OIServeTick $State
                $lastTick = Get-OIMonoNow
            }
        } catch {
            Write-OILog ('Instance metadata service: {0}' -f $_.Exception.Message)
            Start-Sleep -Seconds 1
            if (-not $Listener.IsListening) {
                try { $Listener.Close() } catch { }
                $Listener = Start-OIHttpSysListener
                if ($null -eq $Listener) { return 1 }
            }
        }
    }
}

function Write-OICredentialRefreshLog {
    param([hashtable]$Cache, [hashtable]$Result)
    if ($Result.Ok -and $Result.Stale) {
        Write-OILog "The credentials just received have already expired by this instance's clock: check its time synchronization"
    } elseif ($Result.Ok) {
        Write-OILog ('Credentials refreshed (expire {0}, next refresh {1})' -f $Cache.Creds.Expiration, (Format-OIIso8601 $Cache.RefreshAt))
    } else {
        Write-OILog ('Credential refresh failed: {0}' -f $Result.Message)
    }
}

function Invoke-OIServeTick {
    param([hashtable]$State)
    try {
        $now = Get-OIUtcNow
        $mono = Get-OIMonoNow
        if ($null -ne $State.Creds -and (Test-OICredentialRefreshDue $State.Creds $now)) {
            $r = Invoke-OICredentialRefresh $State.Creds $now
            Write-OICredentialRefreshLog $State.Creds $r
        }
        if ($null -ne $State.Identity -and (Test-OIIdentityRefreshDue $State.Identity $mono)) {
            $r = Invoke-OIIdentityRefresh $State.Identity $mono
            if (-not $r.Ok) { Write-OILog ('Instance identity document refresh failed: {0}' -f $r.Message) }
        }
        if (($mono - $State.Facts.Taken) -gt 10) { $State.Facts = Get-OIHostFacts }
    } catch {
        Write-OILog ('Instance metadata background work failed: {0}' -f $_.Exception.Message)
    }
}

function New-OIServeState {
    # The metadata service's state, from the launch CD.
    param([string]$LaunchDir, [hashtable]$Config)
    $roots = $null
    $ca = Read-OICaFile (Join-Path $LaunchDir $script:OIPlatformCaName)
    if ($ca.Ok) { $roots = New-OICertificateCollection $ca.Certificates }
    elseif ($Config.role -or $Config.identityUrl) { Write-OILog ('{0}: {1}' -f $script:OIPlatformCaName, $ca.Message) }
    $userData = $null
    $udPath = Join-Path $LaunchDir $script:OIUserDataName
    if ([System.IO.File]::Exists($udPath)) { $userData = [System.IO.File]::ReadAllBytes($udPath) }
    $state = @{
        Config = $Config; TokenKey = (New-OIRandomBytes 32); Creds = $null; Identity = $null; UserData = $userData
        Facts = (Get-OIHostFacts); UtcNow = (Get-OIUtcNow); MonoNow = (Get-OIMonoNow)
    }
    if ($Config.role) {
        $c = New-OICredentialCache { param($cache) Get-OIShimCredentials $cache }
        $c.Url = $Config.credentialsUrl
        $c.Roots = $roots
        $state.Creds = $c
    }
    if ($Config.identityUrl) {
        $i = New-OIIdentityCache { param($cache) Get-OIShimIdentity $cache }
        $i.Url = $Config.identityUrl
        $i.Roots = $roots
        $state.Identity = $i
    }
    return $state
}

function Start-OIServeCaches {
    # Warm the credentials (so the first SDK call is answered at once) and fetch the signed identity document.
    param([hashtable]$State)
    $cfg = $State.Config
    if ($null -ne $State.Creds) {
        Write-OILog ('Instance profile role {0}: its credentials come from the platform' -f $cfg.role)
        $deadline = (Get-OIMonoNow) + 10
        while ($true) {
            $r = Update-OICredentialCache $State.Creds (Get-OIUtcNow)
            if ($r.Ok) {
                Write-OICredentialRefreshLog $State.Creds $r
                break
            }
            if ((Get-OIMonoNow) + 2 -gt $deadline) {
                Write-OILog ('Starting without credentials ({0}); retrying in the background' -f $r.Message)
                $State.Creds.NextAttempt = (Get-OIUtcNow) + 5
                break
            }
            Start-Sleep -Seconds 2
        }
    } else {
        Write-OILog 'No instance profile: iam/ metadata is not served'
    }
    if ($null -ne $State.Identity) {
        $r = Invoke-OIIdentityRefresh $State.Identity (Get-OIMonoNow)
        if ($r.Ok) { Write-OILog 'Signed instance identity document received' }
        else { Write-OILog ('Serving the unsigned identity document until the signed one arrives: {0}' -f $r.Message) }
    }
}

function Invoke-OIServe {
    $here = Split-Path -Parent $PSCommandPath
    $cfg = Read-OILaunchConfig $here
    if (-not $cfg.imds.enabled) { return 0 }
    $state = New-OIServeState $here $cfg
    $options = 'httpTokens={0}, hop limit {1}' -f $cfg.imds.httpTokens, $cfg.imds.hopLimit
    $tcp = Start-OITcpListener
    if ($null -ne $tcp.Listener) {
        Write-OILog -Console ('Instance metadata service on {0}:80 ({1})' -f $script:OIImdsAddress, $options)
        Start-OIServeCaches $state
        Invoke-OIServeTcp $tcp.Listener $state
        return 1
    }
    if (-not $tcp.InUse) {
        Write-OILog -Console ('The instance metadata service could not listen on {0}:80: {1}' -f $script:OIImdsAddress, $tcp.Message)
        return 1
    }
    # Port 80 is held exclusively, by the HTTP Server API when IIS runs: serve through it, sharing the port by
    # host name. The token response's IP TTL cannot be set there; a container's token request is still refused
    # at hop limit 1.
    $listener = Start-OIHttpSysListener
    if ($null -eq $listener) { return 1 }
    Write-OILog -Console ('Instance metadata service on {0}:80 through the HTTP Server API, which holds port 80 ({1})' -f $script:OIImdsAddress, $options)
    Start-OIServeCaches $state
    return (Invoke-OIServeHttpSys $listener $state)
}

function Stop-OIStaleServe {
    # A -Serve process left from an earlier -Run of this boot holds the listener: stop it.
    try {
        foreach ($p in @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction Stop)) {
            $cl = [string]$p.CommandLine
            if ($p.ProcessId -ne $PID -and $cl -like ('*' + $script:OIAgentFileName + '*') -and $cl -match '\s-Serve(\s|$)') {
                Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
                Write-OILog ('Stopped an earlier instance metadata service process ({0})' -f $p.ProcessId)
            }
        }
    } catch { }
}

function Start-OIServeProcess {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = Get-OIPowerShellExe
    $psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Serve'
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WorkingDirectory = Join-Path $env:SystemRoot 'System32'
    $p = [System.Diagnostics.Process]::Start($psi)
    Write-OILog ('Started the instance metadata service (process {0})' -f $p.Id)
    return $p
}

function ConvertFrom-OIHttpResponseText {
    # A response as received -> @{ Status (0 when it is not HTTP); Body }.
    param([string]$Text)
    $m = [regex]::Match([string]$Text, '^HTTP/[0-9]+\.[0-9]+ ([0-9]{3})')
    if (-not $m.Success) { return @{ Status = 0; Body = '' } }
    $body = ''
    $i = $Text.IndexOf("`r`n`r`n")
    if ($i -ge 0) { $body = $Text.Substring($i + 4) }
    return @{ Status = [int]$m.Groups[1].Value; Body = $body }
}

function Invoke-OIImdsRawRequest {
    # One request over a plain TCP connection from this instance -> the response text. Throws with the socket's
    # reason when it cannot connect or gets no answer.
    param([string]$Request, [string]$Address = $script:OIImdsAddress, [int]$Port = 80, [int]$TimeoutMs = 3000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $client.BeginConnect($Address, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs)) { throw ('connecting to {0}:{1} timed out' -f $Address, $Port) }
        $client.EndConnect($ar)
        $client.ReceiveTimeout = $TimeoutMs
        $client.SendTimeout = $TimeoutMs
        $stream = $client.GetStream()
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($Request)
        $stream.Write($bytes, 0, $bytes.Length)
        $ms = New-Object System.IO.MemoryStream
        $buf = New-Object byte[] 4096
        while ($true) {
            $n = $stream.Read($buf, 0, $buf.Length)
            if ($n -le 0) { break }
            $ms.Write($buf, 0, $n)
        }
        return $script:OILatin1.GetString($ms.ToArray())
    } finally {
        $client.Close()
    }
}

function Test-OIImdsAnswers {
    # The self-check: from this instance, connect to 169.254.169.254:80, get a token, and GET the instance id.
    # -> @{ Ok; Message }.
    param([string]$Address = $script:OIImdsAddress, [int]$Port = 80)
    try {
        $tokenHeader = ''
        $put = ConvertFrom-OIHttpResponseText (Invoke-OIImdsRawRequest ("PUT /latest/api/token HTTP/1.1`r`nHost: 169.254.169.254`r`nX-aws-ec2-metadata-token-ttl-seconds: 60`r`nContent-Length: 0`r`n`r`n") $Address $Port)
        if ($put.Status -eq 200) { $tokenHeader = $script:OITokenHeader + ': ' + $put.Body + "`r`n" }
        $get = ConvertFrom-OIHttpResponseText (Invoke-OIImdsRawRequest ("GET /latest/meta-data/instance-id HTTP/1.1`r`nHost: 169.254.169.254`r`n" + $tokenHeader + "`r`n") $Address $Port)
        if ($get.Status -eq 200) { return @{ Ok = $true; Message = '' } }
        return @{ Ok = $false; Message = ('GET /latest/meta-data/instance-id answered HTTP {0} (token request: HTTP {1})' -f $get.Status, $put.Status) }
    } catch {
        $e = $_.Exception
        while ($null -ne $e.InnerException -and -not ($e -is [System.Net.Sockets.SocketException])) { $e = $e.InnerException }
        return @{ Ok = $false; Message = $e.Message }
    }
}

function Wait-OIImdsReady {
    # -> @{ Ok; Message }: the self-check passed, or why it did not within TimeoutSeconds.
    param([int]$TimeoutSeconds, $Process)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $last = @{ Ok = $false; Message = 'no answer' }
    while ((Get-Date) -lt $deadline) {
        $last = Test-OIImdsAnswers
        if ($last.Ok) { return $last }
        if ($null -ne $Process -and $Process.HasExited) {
            return @{ Ok = $false; Message = ('the instance metadata service process exited (code {0}); last check: {1}' -f $Process.ExitCode, $last.Message) }
        }
        Start-Sleep -Seconds 1
    }
    return $last
}

# ---------------------------------------------------------------------------------------------------------
# First boot: the root partition (EC2Launch v2's extendRootPartition).
# ---------------------------------------------------------------------------------------------------------

function Expand-OIRootPartition {
    try {
        Update-HostStorageCache -ErrorAction SilentlyContinue
        $part = Get-Partition -DriveLetter C -ErrorAction Stop
        $size = Get-PartitionSupportedSize -DriveLetter C -ErrorAction Stop
        if ($size.SizeMax - $part.Size -gt 1MB) {
            Resize-Partition -DriveLetter C -Size $size.SizeMax -ErrorAction Stop
            Write-OILog -Console ('Extended the root partition (C:) from {0:N1} GiB to {1:N1} GiB' -f ($part.Size / 1GB), ($size.SizeMax / 1GB))
        } else {
            Write-OILog ('The root partition (C:) already fills its disk ({0:N1} GiB)' -f ($part.Size / 1GB))
        }
        return $true
    } catch {
        Write-OILog -Console ('Extending the root partition (C:) failed: {0}' -f $_.Exception.Message)
        return $false
    }
}

function Read-OIStateFile {
    if (-not [System.IO.File]::Exists($script:OIStatePath)) { return $null }
    try { return (ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($script:OIStatePath)) -ErrorAction Stop) }
    catch { return $null }
}

function Write-OIStateFile {
    param([hashtable]$State)
    try {
        [System.IO.File]::WriteAllText($script:OIStatePath, (ConvertTo-Json -InputObject $State), (New-Object System.Text.UTF8Encoding $false))
    } catch {
        Write-OILog ('Could not save {0}: {1}' -f $script:OIStatePath, $_.Exception.Message)
    }
}

# ---------------------------------------------------------------------------------------------------------
# User data: run as LocalSystem, after instance metadata answers, output and errors to userdata.log.
# ---------------------------------------------------------------------------------------------------------

function Get-OIUserDataTasks {
    param([string]$LaunchDir, [hashtable]$InstanceState)
    $none = @{ Tasks = @() }
    $path = Join-Path $LaunchDir $script:OIUserDataName
    if (-not [System.IO.File]::Exists($path)) {
        Write-OILog -Console 'No user data'
        return $none
    }
    $ud = Read-OIUserData ([System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($path)))
    if ($ud.Format -eq 'empty') {
        Write-OILog -Console 'User data is empty'
        return $none
    }
    if ($ud.Format -eq 'yaml') {
        Write-OILog -Console 'User data is in the YAML format (version: 1.0), which is not run here: use the XML format (<powershell> and <script> blocks)'
        return $none
    }
    if ($ud.Format -eq 'untagged') {
        Write-OILog -Console 'User data has no <powershell> or <script> block, so it is not run'
        return $none
    }
    if (-not (Test-OIUserDataShouldRun $InstanceState $ud)) {
        Write-OILog -Console 'User data has already run on this instance and does not persist (<persist>true</persist>): not run'
        return $none
    }
    $InstanceState.userDataRan = $true
    Write-OIStateFile $InstanceState
    $blocks = @($ud.Tasks | ForEach-Object { '<' + $_.Type + '>' }) -join ' then '
    $persist = ''
    if ($ud.Persist) { $persist = ', persisted (every boot)' }
    Write-OILog -Console ('User data: XML format, {0}{1}' -f $blocks, $persist)
    return @{ Tasks = $ud.Tasks }
}

function Start-OIUserDataTask {
    param([hashtable]$Task)
    $ext = '.ps1'
    $enc = New-Object System.Text.UTF8Encoding $true
    if ($Task.Type -eq 'script') {
        $ext = '.cmd'
        $enc = New-Object System.Text.UTF8Encoding $false
    }
    $file = Join-Path $script:OIWorkDir ('user-data-' + $Task.Type + $ext)
    [System.IO.File]::WriteAllText($file, [string]$Task.Content, $enc)
    Add-OIFileLine $script:OIUserDataLog (Format-OILogLine (Get-Date) ('<{0}> begins' -f $Task.Type))
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = Join-Path $env:SystemRoot 'System32\cmd.exe'
    $psi.Arguments = Get-OIUserDataCommandLine $Task $file $script:OIUserDataLog (Get-OIPowerShellExe)
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WorkingDirectory = Join-Path $env:SystemRoot 'System32'
    $p = [System.Diagnostics.Process]::Start($psi)
    return @{ Task = $Task; Process = $p; File = $file }
}

function Invoke-OISupervisor {
    # Runs the user data tasks one after the other, and keeps the metadata service (process and address) up.
    # Returns when there is nothing left to do: never while this agent serves instance metadata itself.
    param([object[]]$Tasks, $Serve, [hashtable]$Config)
    $pending = New-Object System.Collections.Queue
    foreach ($t in @($Tasks)) { if ($null -ne $t) { $pending.Enqueue($t) } }
    $current = $null
    $restartAt = $null
    $retry = 30
    $local = $Config.imds.enabled -and -not $Config.imds.outside  # the metadata service is this agent's to keep up
    if ($local -and $null -eq $Serve) { $restartAt = (Get-Date).AddSeconds($retry) }
    $nextAddressCheck = (Get-Date).AddSeconds(30)
    while ($true) {
        try {
            if ($null -eq $current -and $pending.Count -gt 0) {
                $t = $pending.Dequeue()
                Write-OILog -Console ('User data: the <{0}> block begins' -f $t.Type)
                try { $current = Start-OIUserDataTask $t }
                catch {
                    Write-OILog -Console ('User data: the <{0}> block could not start: {1}' -f $t.Type, $_.Exception.Message)
                    $current = $null
                }
            }
            if ($null -ne $current -and $current.Process.HasExited) {
                $code = $current.Process.ExitCode
                Add-OIFileLine $script:OIUserDataLog (Format-OILogLine (Get-Date) ('<{0}> exited with code {1}' -f $current.Task.Type, $code))
                Write-OILog -Console ('User data: the <{0}> block exited with code {1}' -f $current.Task.Type, $code)
                Remove-Item -LiteralPath $current.File -Force -ErrorAction SilentlyContinue
                $current = $null
            }
            if ($local) {
                if ($null -ne $Serve -and $Serve.HasExited) {
                    Write-OILog -Console ('The instance metadata service exited (code {0}); restarting it' -f $Serve.ExitCode)
                    $Serve = $null
                    $restartAt = (Get-Date).AddSeconds(5)
                }
                if ($null -eq $Serve -and $null -ne $restartAt -and (Get-Date) -ge $restartAt) {
                    $restartAt = $null
                    if (Set-OIImdsAddress) {
                        $Serve = Start-OIServeProcess
                        $retry = 30
                    } else {
                        $retry = [Math]::Min($retry * 2, 600)
                        $restartAt = (Get-Date).AddSeconds($retry)
                    }
                }
                if ($null -ne $Serve -and (Get-Date) -ge $nextAddressCheck) {
                    $nextAddressCheck = (Get-Date).AddSeconds(30)
                    if (-not (Test-OIImdsAddressPresent)) {
                        Write-OILog 'The instance metadata address 169.254.169.254 is gone; adding it again'
                        if (-not (Set-OIImdsAddress)) {
                            $retry = [Math]::Min($retry * 2, 600)
                            $nextAddressCheck = (Get-Date).AddSeconds($retry)
                        }
                    }
                }
            } elseif ($null -eq $current -and $pending.Count -eq 0) {
                return 0
            }
        } catch {
            Write-OILog ('Launch agent: {0}' -f $_.Exception.Message)
        }
        Start-Sleep -Milliseconds 500
    }
}

# ---------------------------------------------------------------------------------------------------------
# The modes.
# ---------------------------------------------------------------------------------------------------------

function Invoke-OIRun {
    Initialize-OIDirectories
    Step-OILogRotation
    $here = Split-Path -Parent $PSCommandPath
    Write-OILog -Console 'OpenInfra launch agent starting'
    $cfg = Read-OILaunchConfig $here
    foreach ($w in $cfg.warnings) { Write-OILog -Console $w }
    Write-OILog -Console ('Instance {0} ({1}, image {2}) in {3}' -f $cfg.instanceId, $cfg.instanceType, $cfg.imageId, $cfg.availabilityZone)
    try { Set-OIPlatformTrust $here }
    catch { Write-OILog -Console ('Trusting the platform CAs failed: {0}' -f $_.Exception.Message) }
    $serve = $null
    if ($cfg.imds.enabled -and $cfg.imds.outside) {
        Stop-OIStaleServe
        Remove-OIMetadataAdapter
        if (Wait-OIMetadataRoute 120) {
            $ready = Wait-OIImdsReady 120 $null
            if ($ready.Ok) {
                Write-OILog -Console 'Instance metadata is answering at http://169.254.169.254/ (served outside the instance)'
            } else {
                Write-OILog -Console ('Instance metadata did not answer within 2 minutes ({0}); continuing' -f $ready.Message)
                Write-OIInterfaceState
            }
        }
    } elseif ($cfg.imds.enabled) {
        Stop-OIStaleServe
        $ok = $false
        try { $ok = Set-OIImdsAddress }
        catch { Write-OILog -Console ('Adding the instance metadata address failed: {0}' -f $_.Exception.Message) }
        if ($ok) {
            $serve = Start-OIServeProcess
            $ready = Wait-OIImdsReady 120 $serve
            if ($ready.Ok) {
                Write-OILog -Console 'Instance metadata is answering at http://169.254.169.254/'
            } else {
                Write-OILog -Console ('Instance metadata did not answer within 2 minutes ({0}); continuing' -f $ready.Message)
                Write-OIInterfaceState
            }
        }
    } else {
        Write-OILog -Console 'Instance metadata is disabled (metadata options: HttpEndpoint disabled)'
    }
    $inst = Resolve-OIInstanceState (Read-OIStateFile) $cfg.instanceId
    if (-not $inst.rootExtended) {
        Write-OILog -Console 'First boot of this instance: extending the root partition'
        if (Expand-OIRootPartition) { $inst.rootExtended = $true }
        Write-OIStateFile $inst
    }
    Write-OILog -Console 'Message: Windows is Ready to use'
    $plan = @{ Tasks = @() }
    if ($cfg.imds.enabled) {
        try { $plan = Get-OIUserDataTasks $here $inst }
        catch { Write-OILog -Console ('Reading the user data failed: {0}' -f $_.Exception.Message) }
    } else {
        # EC2Launch v2 reads user data from instance metadata, so with it disabled user data does not run.
        Write-OILog -Console 'User data was not run: instance metadata is disabled (HttpEndpoint disabled), and user data is read from it'
    }
    return (Invoke-OISupervisor $plan.Tasks $serve $cfg)
}

function Invoke-OIInstall {
    Initialize-OIDirectories
    Write-OILog -Console ('OpenInfra launch agent: installing the "{0}" task' -f $script:OITaskName)
    [System.IO.File]::WriteAllText($script:OIStubPath, (Get-OIStubSource), (New-Object System.Text.UTF8Encoding $true))
    $xmlPath = Join-Path $script:OIRoot 'launch-task.xml'
    [System.IO.File]::WriteAllText($xmlPath, (Get-OITaskXml $script:OIStubPath (Get-OIPowerShellExe)), [System.Text.Encoding]::Unicode)
    $out = & (Join-Path $env:SystemRoot 'System32\schtasks.exe') /Create /TN $script:OITaskName /XML $xmlPath /F 2>&1 | Out-String
    $code = $LASTEXITCODE
    Remove-Item -LiteralPath $xmlPath -Force -ErrorAction SilentlyContinue
    if ($code -ne 0) {
        Write-OILog -Console ('Registering the "{0}" task failed (exit {1}): {2}' -f $script:OITaskName, $code, $out.Trim())
        return 1
    }
    Write-OILog -Console ('Registered the "{0}" task: at every startup it runs the launch agent from the launch CD' -f $script:OITaskName)
    return 0
}

# Dot-sourcing defines the functions and runs nothing.
if ($MyInvocation.InvocationName -ne '.' -and ($Install -or $Run -or $Serve)) {
    $code = 1
    try {
        if ($Install) { $out = @(Invoke-OIInstall) }
        elseif ($Run) { $out = @(Invoke-OIRun) }
        else { $out = @(Invoke-OIServe) }
        $code = 0
        if ($out.Count -gt 0) { $code = [int]$out[$out.Count - 1] }
    } catch {
        try { Write-OILog -Console ('OpenInfra launch agent failed: {0}' -f $_.Exception.Message) } catch { }
        $code = 1
    }
    exit $code
}
