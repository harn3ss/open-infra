# Tests for windows-launch-agent.ps1: its syntax (Windows PowerShell 5.1, and embeddable in a Go template)
# and its pure logic (user data parsing, the metadata router, IMDSv2 tokens, credential refresh, TLS pinning).
# Runs with PowerShell 7 on Linux or Windows, no modules needed:
#
#   docker run --rm -v "$PWD/platform/abstraction/files:/w" -w /w mcr.microsoft.com/powershell:lts-7.4-ubuntu-22.04 \
#     pwsh -NoProfile -File windows-launch-agent.tests.ps1

$ErrorActionPreference = 'Stop'
$agentPath = Join-Path $PSScriptRoot 'windows-launch-agent.ps1'
$script:passed = 0

function Check {
    param([bool]$Condition, [string]$What)
    if (-not $Condition) { throw ('FAIL: ' + $What) }
    $script:passed++
}

function Check-Equal {
    param($Actual, $Expected, [string]$What)
    if (-not ([string]$Actual -ceq [string]$Expected)) {
        throw ("FAIL: {0}`n  expected: {1}`n  actual:   {2}" -f $What, ($Expected -replace "`n", '\n'), ($Actual -replace "`n", '\n'))
    }
    $script:passed++
}

function Check-Throws {
    param([scriptblock]$Block, [string]$What)
    $threw = $false
    try { & $Block | Out-Null } catch { $threw = $true }
    Check $threw $What
}

# --------------------------------------------------------------------------------------------------------
# Syntax: both files parse; the agent uses no PowerShell 7-only syntax and no Go template delimiters.
# --------------------------------------------------------------------------------------------------------

foreach ($f in @($agentPath, $PSCommandPath)) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$tokens, [ref]$errors)
    $detail = ($errors | ForEach-Object { 'line ' + $_.Extent.StartLineNumber + ': ' + $_.Message }) -join '; '
    Check ($errors.Count -eq 0) ("{0} parses with no errors ({1})" -f (Split-Path -Leaf $f), $detail)
}

$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($agentPath, [ref]$tokens, [ref]$errors)
$lang = 'System.Management.Automation.Language'
$ps7Only = @($ast.FindAll({
            param($n)
            $type = $n.GetType().Name
            if ($type -eq 'TernaryExpressionAst' -or $type -eq 'PipelineChainAst') { return $true }
            if ($n -is [System.Management.Automation.Language.BinaryExpressionAst] -and $n.Operator.ToString() -eq 'QuestionQuestion') { return $true }
            if ($n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Operator.ToString() -eq 'QuestionQuestionEquals') { return $true }
            if (($n -is [System.Management.Automation.Language.MemberExpressionAst] -or $n -is [System.Management.Automation.Language.IndexExpressionAst]) -and $n.NullConditional) { return $true }
            if ($n -is [System.Management.Automation.Language.ScriptBlockAst] -and $null -ne $n.CleanBlock) { return $true }
            return $false
        }, $true))
Check ($ps7Only.Count -eq 0) ('no PowerShell 7-only operators (?:, ??, ??=, ?., &&, ||, clean): ' + (($ps7Only | ForEach-Object { 'line ' + $_.Extent.StartLineNumber }) -join ', '))

$ps7Params = @('Parallel', 'AsHashtable', 'AsByteStream', 'AdditionalChildPath', 'SkipHttpErrorCheck', 'NoProxy', 'DateKind', 'ThrottleLimit')
$bad = New-Object System.Collections.Generic.List[string]
foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
    foreach ($el in $c.CommandElements) {
        if ($el -is [System.Management.Automation.Language.CommandParameterAst] -and $ps7Params -contains $el.ParameterName) {
            $bad.Add(('line {0}: -{1}' -f $el.Extent.StartLineNumber, $el.ParameterName))
        }
    }
    if ($c.GetCommandName() -eq 'Join-Path' -and $c.CommandElements.Count -gt 3) { $bad.Add(('line {0}: Join-Path with more than two paths' -f $c.Extent.StartLineNumber)) }
}
foreach ($v in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
    if (@('IsWindows', 'IsLinux', 'IsMacOS', 'IsCoreCLR', 'PSStyle') -contains $v.VariablePath.UserPath) { $bad.Add(('line {0}: ${1}' -f $v.Extent.StartLineNumber, $v.VariablePath.UserPath)) }
}
$raw = [System.IO.File]::ReadAllText($agentPath)
if ($raw -match 'utf8NoBOM') { $bad.Add('utf8NoBOM encoding name') }
Check ($bad.Count -eq 0) ('no PowerShell 7-only parameters or variables: ' + ($bad -join '; '))
Check (-not $raw.Contains('{' + '{') -and -not $raw.Contains('}' + '}')) 'the agent contains no Go template delimiters'

# What a customer reads (IMDS bodies, the console, the logs) is in AWS's terms: no string the agent writes
# names Kubernetes or the platform's internals. Exempt: the identity disk's file name and the C# source.
$forbidden = @('ServiceAccount', 'Kubernetes', 'KubeVirt', 'kubectl', 'namespace', 'annotation', 'kind:', 'TokenReview', 'aws-shim', 'cluster.local', 'openinfra.dev/')
$words = New-Object System.Collections.Generic.List[string]
foreach ($sa in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true)) {
    $v = [string]$sa.Value
    if ($v -ceq 'namespace' -or $v.StartsWith('using System;')) { continue }
    foreach ($w in $forbidden) {
        if ($v.IndexOf($w, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $words.Add(('line {0}: {1}' -f $sa.Extent.StartLineNumber, $w)) }
    }
}
Check ($words.Count -eq 0) ('customer-visible text is in AWS terms: ' + ($words -join '; '))

# --------------------------------------------------------------------------------------------------------
# Load the agent: dot-sourcing defines its functions and runs nothing.
# --------------------------------------------------------------------------------------------------------

. $agentPath
Set-StrictMode -Version 2.0
Check ($null -ne (Get-Command Invoke-OIImdsRequest -ErrorAction SilentlyContinue)) 'dot-sourcing defines the functions'

# --------------------------------------------------------------------------------------------------------
# Small helpers.
# --------------------------------------------------------------------------------------------------------

$t = New-Object System.DateTime 2026, 11, 20, 8, 9, 10, ([System.DateTimeKind]::Utc)
Check-Equal (Format-OILogLine $t 'Message: Windows is Ready to use') '2026/11/20 08:09:10Z: Message: Windows is Ready to use' 'console line format'
Check-Equal (Format-OILogLine $t "two`r`nlines") '2026/11/20 08:09:10Z: two lines' 'a log entry stays on one line'

$s = [string][char]0xE9 + '"' + '\' + [char]127 + [char]1 + "`n"
Check-Equal (ConvertTo-OIJsonString $s) '"\u00e9\"\\\u007f\u0001\n"' 'JSON escaping matches json.dumps'
Check-Equal (ConvertTo-OIJsonString $null) 'null' 'JSON null'
$doc = [ordered]@{}
$doc['Code'] = 'Success'
$doc['LastUpdated'] = '2026-11-20T10:00:00Z'
$doc['InstanceProfileArn'] = 'arn:aws:iam::111122223333:instance-profile/app-role'
Check-Equal (ConvertTo-OIAwsJson $doc) ("{`n" + '  "Code" : "Success",' + "`n" + '  "LastUpdated" : "2026-11-20T10:00:00Z",' + "`n" + '  "InstanceProfileArn" : "arn:aws:iam::111122223333:instance-profile/app-role"' + "`n" + '}' + "`n") 'EC2 metadata JSON layout'

$t0 = [double]([System.DateTimeOffset]::new(2026, 11, 20, 10, 0, 0, [System.TimeSpan]::Zero).ToUnixTimeSeconds())
Check ((ConvertFrom-OITimestamp '2026-11-20T10:00:00Z') -eq $t0) 'RFC 3339 with Z'
Check ((ConvertFrom-OITimestamp '2026-11-20T15:30:00+05:30') -eq $t0) 'RFC 3339 with an offset'
Check ((ConvertFrom-OITimestamp '2026-11-20T05:00:00-0500') -eq $t0) 'RFC 3339 with a colonless offset'
Check ((ConvertFrom-OITimestamp '2026-11-20 10:00:00.123Z') -eq $t0) 'fractional seconds and a space separator'
Check ((ConvertFrom-OITimestamp '2026-11-20T10:00:00') -eq $t0) 'no offset is UTC'
Check-Throws { ConvertFrom-OITimestamp 'tomorrow' } 'a malformed timestamp throws'
Check-Throws { ConvertFrom-OITimestamp '2026-11-20t10:00:00z' } 'lower-case t and z are not RFC 3339 as the Linux agent reads it'
Check-Equal (Format-OIIso8601 ($t0 + 0.9)) '2026-11-20T10:00:00Z' 'ISO 8601 output truncates to the second'

Check-Equal (Get-OIInstanceProfileId '111122223333' 'app-role') 'AIPA51D077418161CB6A1' 'instance profile id matches the Linux agent'
Check-Equal (ConvertTo-OIArchitecture 'AMD64') 'x86_64' 'AMD64 is x86_64'
Check-Equal (ConvertTo-OIArchitecture 'ARM64') 'arm64' 'ARM64 is arm64'
Check-Equal (Format-OIMac ([byte[]](2, 0, 0, 170, 187, 204))) '02:00:00:aa:bb:cc' 'MAC address format'
Check ($null -eq (Format-OIMac ([byte[]]@()))) 'no MAC address'
$rb = New-OIRandomBytes 32
Check ($rb -is [byte[]] -and $rb.Length -eq 32) 'random bytes come back as one byte[]'

# --------------------------------------------------------------------------------------------------------
# The launch configuration.
# --------------------------------------------------------------------------------------------------------

$c = ConvertTo-OILaunchConfig @{}
Check-Equal $c.region 'us-east-1' 'default region'
Check-Equal $c.availabilityZone 'us-east-1a' 'default availability zone'
Check ($c.imds.enabled -and $c.imds.httpTokens -eq 'optional' -and $c.imds.hopLimit -eq 1 -and $c.warnings.Count -eq 0) 'default metadata options'
foreach ($hop in @(0, 65, 'many')) {
    $c = ConvertTo-OILaunchConfig @{ imds = @{ hopLimit = $hop } }
    Check ($c.imds.hopLimit -eq 1 -and $c.warnings.Count -eq 1) ("hopLimit {0} falls back to 1 with a warning" -f $hop)
}
Check ((ConvertTo-OILaunchConfig @{ imds = @{ hopLimit = 2 } }).imds.hopLimit -eq 2) 'hopLimit 2 is kept'
$c = ConvertTo-OILaunchConfig @{ imds = @{ httpTokens = 'Required' } }
Check ($c.imds.httpTokens -ceq 'required' -and $c.warnings.Count -eq 1) 'an unknown httpTokens value means required'
Check (-not (ConvertTo-OILaunchConfig @{ imds = @{ enabled = $false } }).imds.enabled) 'metadata can be disabled'
$json = '{"instanceId":"i-0123456789abcdef0","region":"eu-west-1","launchTime":"2026-11-20T10:00:00Z","role":"","securityGroups":[],"imds":{"enabled":true,"httpTokens":"required","hopLimit":2}}'
$c = ConvertTo-OILaunchConfig (ConvertFrom-Json $json)
Check-Equal $c.launchTime '2026-11-20T10:00:00Z' 'launchTime keeps its RFC 3339 text even where ConvertFrom-Json makes it a date'
Check-Equal $c.availabilityZone 'eu-west-1a' 'availability zone from the region'
Check ($c.securityGroups.Count -eq 0 -and $c.imds.httpTokens -eq 'required' -and $c.imds.hopLimit -eq 2) 'launch-config.json is read'

# --------------------------------------------------------------------------------------------------------
# User data, as EC2Launch v2 reads it.
# --------------------------------------------------------------------------------------------------------

$u = Read-OIUserData '<powershell>Write-Output 1</powershell>'
Check ($u.Format -eq 'xml' -and $u.Tasks.Count -eq 1 -and -not $u.Persist) 'a <powershell> block'
Check ($u.Tasks[0].Type -eq 'powershell' -and $u.Tasks[0].Content -ceq 'Write-Output 1') 'its content'
Check-Equal $u.Tasks[0].Args '-NoProfile -NonInteractive -ExecutionPolicy Bypass' 'default PowerShell arguments'
$u = Read-OIUserData "<powershell>`r`n`$a = 1`r`n</powershell>`r`n<script>`r`necho b`r`n</script>"
Check ($u.Tasks.Count -eq 2 -and $u.Tasks[0].Type -eq 'script' -and $u.Tasks[1].Type -eq 'powershell') '<script> runs before <powershell>'
Check-Equal $u.Tasks[0].Content "`r`necho b`r`n" 'block content is kept as written'
$u = Read-OIUserData "<script>echo a</script>`n<persist>true</persist>"
Check ($u.Persist -and $u.Tasks[0].Persist) '<persist>true</persist>'
Check (-not (Read-OIUserData '<script>x</script><persist>false</persist>').Persist) '<persist>false</persist>'
$u = Read-OIUserData '<powershell>x</powershell><powershellArguments>-ExecutionPolicy Unrestricted -NoProfile</powershellArguments>'
Check-Equal $u.Tasks[0].Args '-ExecutionPolicy Unrestricted -NoProfile' '<powershellArguments>'
Check ((Read-OIUserData '<PowerShell>x</PowerShell>').Format -eq 'xml') 'tags are case-insensitive'
Check ((Read-OIUserData ([string][char]0xFEFF + '<script>x</script>')).Format -eq 'xml') 'a byte order mark is ignored'
Check ((Read-OIUserData "version: 1.0`ntasks:`n  - frequency: always`n    tasks:`n      - task: executeScript").Format -eq 'yaml') 'YAML user data'
Check ((Read-OIUserData "# comment`nversion: 1.1`ntasks: []").Format -eq 'yaml') 'YAML user data after a comment'
Check ((Read-OIUserData "version: 1.0`n<powershell>x</powershell>").Format -eq 'yaml') 'YAML wins over tags inside it'
Check ((Read-OIUserData 'Write-Output untagged').Format -eq 'untagged') 'untagged user data'
Check ((Read-OIUserData "#!/bin/bash`necho hi").Format -eq 'untagged') 'a shell script is untagged'
Check ((Read-OIUserData '<powershell>x').Format -eq 'untagged') 'an unclosed block is not run'
Check ((Read-OIUserData '').Format -eq 'empty') 'empty user data'
Check ((Read-OIUserData "  `r`n").Format -eq 'empty') 'blank user data'
Check ((Read-OIUserData $null).Format -eq 'none') 'no user data'

$cl = Get-OIUserDataCommandLine @{ Type = 'script'; Args = '' } 'C:\w\user-data-script.cmd' 'C:\l\userdata.log' 'C:\ps.exe'
Check-Equal $cl '/d /s /c ""C:\w\user-data-script.cmd" >> "C:\l\userdata.log" 2>&1"' 'cmd.exe line for <script>'
$cl = Get-OIUserDataCommandLine @{ Type = 'powershell'; Args = '-NoProfile -NonInteractive -ExecutionPolicy Bypass' } 'C:\w\user-data-powershell.ps1' 'C:\l\userdata.log' 'C:\ps.exe'
Check-Equal $cl '/d /s /c ""C:\ps.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\w\user-data-powershell.ps1" >> "C:\l\userdata.log" 2>&1"' 'cmd.exe line for <powershell>'

$fresh = Resolve-OIInstanceState $null 'i-0aaaaaaaaaaaaaaa1'
Check (-not $fresh.rootExtended -and -not $fresh.userDataRan) 'no saved state: first boot'
$saved = ConvertFrom-Json '{"instanceId":"i-0aaaaaaaaaaaaaaa1","rootExtended":true,"userDataRan":true}'
$same = Resolve-OIInstanceState $saved 'i-0aaaaaaaaaaaaaaa1'
Check ($same.rootExtended -and $same.userDataRan) 'state of this instance is kept'
$other = Resolve-OIInstanceState $saved 'i-0bbbbbbbbbbbbbbb2'
Check (-not $other.rootExtended -and -not $other.userDataRan -and $other.instanceId -eq 'i-0bbbbbbbbbbbbbbb2') 'an image made from another instance: first boot'
$xmlUd = Read-OIUserData '<script>x</script>'
$xmlPersist = Read-OIUserData '<script>x</script><persist>true</persist>'
Check (Test-OIUserDataShouldRun $fresh $xmlUd) 'user data runs on the first boot'
Check (-not (Test-OIUserDataShouldRun $same $xmlUd)) 'user data does not run again'
Check (Test-OIUserDataShouldRun $same $xmlPersist) 'persisted user data runs every boot'
Check (-not (Test-OIUserDataShouldRun $fresh (Read-OIUserData 'version: 1.0'))) 'YAML user data is not run'

# --------------------------------------------------------------------------------------------------------
# IMDSv2 tokens.
# --------------------------------------------------------------------------------------------------------

$key = New-OIRandomBytes 32
$tok = New-OIImdsToken $key 1000.0 1
Check ($tok.Length -eq 44 -and $tok -notmatch '[+/]') 'a token is 32 bytes, URL-safe base64'
Check (Test-OIImdsToken $key 1000.5 $tok) 'a token is valid within its TTL'
Check (-not (Test-OIImdsToken $key 1001.5 $tok)) 'a token expires'
Check (-not (Test-OIImdsToken (New-OIRandomBytes 32) 1000.5 $tok)) 'a token from another process is refused'
$flip = $tok.Substring(0, 20) + $(if ($tok[20] -eq 'A') { 'B' } else { 'A' }) + $tok.Substring(21)
Check (-not (Test-OIImdsToken $key 1000.5 $flip)) 'a tampered token is refused'
foreach ($junk in @('', 'garbage', 'AAAA', $null)) { Check (-not (Test-OIImdsToken $key 1000.5 $junk)) ("junk token '{0}' is refused" -f $junk) }
Check (Test-OIImdsToken $key 21000.0 (New-OIImdsToken $key 1000.0 21600)) 'a 6-hour token'

# --------------------------------------------------------------------------------------------------------
# The metadata router.
# --------------------------------------------------------------------------------------------------------

$shimCreds = @{ AccessKeyId = 'ASIAEXAMPLEKEYID0001'; SecretAccessKey = 'example-secret-key'; Token = 'example-session-token'; Expiration = '2026-11-20T11:00:00Z' }
function New-FakeCache {
    param([hashtable]$Creds)
    $cache = New-OICredentialCache { param($cc) $cc.Calls++; return @{ Ok = $true; Creds = $cc.Next } }
    $cache.Calls = 0
    $cache.Next = $Creds
    return $cache
}
$cfgRaw = @{
    instanceId = 'i-0123456789abcdef0'; imageId = 'ami-0fedcba9876543210'; instanceType = 'm5.large'
    region = 'us-east-1'; availabilityZone = 'us-east-1a'; accountId = '111122223333'
    launchTime = '2026-11-20T10:00:00Z'; role = 'app-role'
    credentialsUrl = 'https://aws-shim.example.test:4567/v1/vm-credentials'; identityUrl = ''
    securityGroups = @('sg-web', 'sg-db'); imds = @{ enabled = $true; httpTokens = 'optional'; hopLimit = 1 }
}
function New-TestState {
    param([hashtable]$Raw = $cfgRaw)
    return @{
        Config = (ConvertTo-OILaunchConfig $Raw); TokenKey = $key; UtcNow = $t0; MonoNow = 1000.0
        Facts = @{ Hostname = 'EC2AMAZ-TEST01'; LocalIPv4 = '10.0.2.2'; Mac = '02:00:00:aa:bb:cc'; Architecture = 'x86_64'; BootTime = ($t0 - 60) }
        Creds = (New-FakeCache $shimCreds); Identity = $null
        UserData = [System.Text.Encoding]::UTF8.GetBytes('<powershell>Write-Output hi</powershell>')
    }
}
function Get-Imds {
    param([hashtable]$State, [string]$Path, [hashtable]$Headers = @{}, [string]$Method = 'GET')
    $r = Invoke-OIImdsRequest $Method $Path $Headers $State
    $r.Text = [System.Text.Encoding]::UTF8.GetString($r.Body)
    return $r
}

$st = New-TestState
$r = Get-Imds $st '/'
Check ($r.Status -eq 200 -and $r.Text.StartsWith("1.0`n2007-01-19") -and $r.Text.EndsWith("2022-09-24`nlatest")) 'the root lists the API versions'
Check-Equal (Get-Imds $st '/latest').Text "dynamic`nmeta-data`nuser-data" 'the version root lists its categories'
Check-Equal (Get-Imds $st '/2021-07-15/').Text "dynamic`nmeta-data`nuser-data" 'a dated version is served too'
$expectedMd = @('ami-id', 'ami-launch-index', 'hostname', 'iam/', 'instance-action', 'instance-id', 'instance-life-cycle', 'instance-type', 'local-hostname', 'local-ipv4', 'mac', 'network/', 'placement/', 'security-groups', 'services/') -join "`n"
Check-Equal (Get-Imds $st '/latest/meta-data/').Text $expectedMd 'meta-data/ listing'
Check-Equal (Get-Imds $st '/latest/meta-data').Text $expectedMd 'meta-data listing without the trailing slash'
$leaves = [ordered]@{
    'instance-id' = 'i-0123456789abcdef0'; 'ami-id' = 'ami-0fedcba9876543210'; 'instance-type' = 'm5.large'
    'local-ipv4' = '10.0.2.2'; 'local-hostname' = 'EC2AMAZ-TEST01'; 'hostname' = 'EC2AMAZ-TEST01'; 'mac' = '02:00:00:aa:bb:cc'
    'ami-launch-index' = '0'; 'instance-action' = 'none'; 'instance-life-cycle' = 'on-demand'
    'placement/availability-zone' = 'us-east-1a'; 'placement/region' = 'us-east-1'
    'services/domain' = 'amazonaws.com'; 'services/partition' = 'aws'; 'security-groups' = "sg-web`nsg-db"
    'network/interfaces/macs/02:00:00:aa:bb:cc/local-ipv4s' = '10.0.2.2'
    'network/interfaces/macs/02:00:00:aa:bb:cc/device-number' = '0'
}
foreach ($p in $leaves.Keys) {
    $r = Get-Imds $st ('/latest/meta-data/' + $p)
    Check ($r.Status -eq 200 -and $r.ContentType -eq 'text/plain') ("meta-data/{0} is served" -f $p)
    Check-Equal $r.Text $leaves[$p] ("meta-data/{0}" -f $p)
}
Check-Equal (Get-Imds $st '/latest/meta-data/placement/').Text "availability-zone`nregion" 'placement/ listing'
Check-Equal (Get-Imds $st '/latest/meta-data/services/').Text "domain`npartition" 'services/ listing'
Check-Equal (Get-Imds $st '/latest/meta-data/network/interfaces/macs/').Text '02:00:00:aa:bb:cc/' 'macs/ listing'
Check-Equal (Get-Imds $st '/latest/meta-data/network/interfaces/macs/02:00:00:aa:bb:cc/').Text "device-number`nlocal-hostname`nlocal-ipv4s`nmac" 'the interface listing'
Check-Equal (Get-Imds $st '/latest/meta-data/iam/').Text "info`nsecurity-credentials/" 'iam/ listing'
Check-Equal (Get-Imds $st '/latest/meta-data/iam/security-credentials/').Text 'app-role' 'security-credentials/ lists the role'

$info = "{`n" + '  "Code" : "Success",' + "`n" + '  "LastUpdated" : "2026-11-20T10:00:00Z",' + "`n" + '  "InstanceProfileArn" : "arn:aws:iam::111122223333:instance-profile/app-role",' + "`n" + '  "InstanceProfileId" : "AIPA51D077418161CB6A1"' + "`n" + '}' + "`n"
Check-Equal (Get-Imds $st '/latest/meta-data/iam/info').Text $info 'iam/info'
$credsBody = "{`n" + (@(
        '  "Code" : "Success"', '  "LastUpdated" : "2026-11-20T10:00:00Z"', '  "Type" : "AWS-HMAC"',
        '  "AccessKeyId" : "ASIAEXAMPLEKEYID0001"', '  "SecretAccessKey" : "example-secret-key"',
        '  "Token" : "example-session-token"', '  "Expiration" : "2026-11-20T11:00:00Z"') -join ",`n") + "`n" + '}' + "`n"
Check-Equal (Get-Imds $st '/latest/meta-data/iam/security-credentials/app-role').Text $credsBody 'the role credentials'
Check ($st.Creds.Calls -eq 1) 'the first credentials request fetches them'
$st.UtcNow = $t0 + 600
[void](Get-Imds $st '/latest/meta-data/iam/security-credentials/app-role')
Check ($st.Creds.Calls -eq 1) 'later requests are answered from the cache'
Check ((Get-Imds $st '/latest/meta-data/iam/security-credentials/app-role/').Status -eq 200) 'a trailing slash is ignored, as by the Linux agent'
Check ((Get-Imds $st '/latest/meta-data/iam/security-credentials/other-role').Status -eq 404) 'another role is not served'

foreach ($case in @(@{ Status = 403; Code = 'AssumeRoleUnauthorizedAccess' }, @{ Status = 401; Code = 'AssumeRoleUnauthorizedAccess' }, @{ Status = $null; Code = 'InternalError' }, @{ Status = 500; Code = 'InternalError' })) {
    $es = New-TestState
    $es.Creds = New-OICredentialCache { param($cc) return @{ Ok = $false; Status = $cc.FailStatus; Message = 'aws-shim answered no' } }
    $es.Creds.FailStatus = $case.Status
    $body = (Get-Imds $es '/latest/meta-data/iam/security-credentials/app-role').Text
    $expected = "{`n" + '  "Code" : "' + $case.Code + '",' + "`n" + '  "Message" : "aws-shim answered no",' + "`n" + '  "LastUpdated" : "2026-11-20T10:00:00Z"' + "`n" + '}' + "`n"
    Check-Equal $body $expected ("a credentials failure with status {0} is {1}" -f $case.Status, $case.Code)
}

$identity = "{`n" + (@(
        '  "accountId" : "111122223333"', '  "architecture" : "x86_64"', '  "availabilityZone" : "us-east-1a"',
        '  "billingProducts" : null', '  "devpayProductCodes" : null', '  "marketplaceProductCodes" : null',
        '  "imageId" : "ami-0fedcba9876543210"', '  "instanceId" : "i-0123456789abcdef0"', '  "instanceType" : "m5.large"',
        '  "kernelId" : null', '  "pendingTime" : "2026-11-20T10:00:00Z"', '  "privateIp" : "10.0.2.2"',
        '  "ramdiskId" : null', '  "region" : "us-east-1"', '  "version" : "2017-09-30"') -join ",`n") + "`n" + '}' + "`n"
Check-Equal (Get-Imds $st '/latest/dynamic/instance-identity/').Text 'document' 'unsigned: only the document'
Check-Equal (Get-Imds $st '/latest/dynamic/instance-identity/document').Text $identity 'the unsigned identity document'
Check ((Get-Imds $st '/latest/dynamic/instance-identity/signature').Status -eq 404) 'unsigned: no signature'
$noLaunch = $cfgRaw.Clone()
$noLaunch.launchTime = ''
$nl = New-TestState $noLaunch
Check ((Get-Imds $nl '/latest/dynamic/instance-identity/document').Text.Contains('"pendingTime" : "2026-11-20T09:59:00Z"')) 'pendingTime falls back to the boot time'

$signedDoc = '{"accountId":"111122223333","instanceId":"i-0123456789abcdef0"}'
$st.Identity = New-OIIdentityCache { param($ic) return @{ Ok = $true; Signed = @{ document = $ic.Doc; signature = "c2lnbmF0dXJl`nbGluZTI="; pkcs7 = 'cGtjczc='; rsa2048 = 'cnNhMjA0OA=='; expiresInSeconds = 3600 } } }
$st.Identity.Doc = $signedDoc
[void](Invoke-OIIdentityRefresh $st.Identity 1000.0)
Check-Equal (Get-Imds $st '/latest/dynamic/instance-identity/').Text "document`npkcs7`nrsa2048`nsignature" 'signed: the document and its signatures'
Check-Equal (Get-Imds $st '/latest/dynamic/instance-identity/document').Text $signedDoc 'the signed document is served as received'
Check-Equal (Get-Imds $st '/latest/dynamic/instance-identity/signature').Text "c2lnbmF0dXJl`nbGluZTI=" 'the signature is served as received'
Check-Equal (Get-Imds $st '/latest/dynamic/instance-identity/pkcs7').Text 'cGtjczc=' 'pkcs7'
$st.MonoNow = 1000.0 + 3600
Check-Equal (Get-Imds $st '/latest/dynamic/instance-identity/').Text 'document' 'an expired signed document is no longer served'
$st.MonoNow = 1000.0
$st.Identity = $null

$ud = Get-Imds $st '/latest/user-data'
Check ($ud.Status -eq 200 -and $ud.Text -ceq '<powershell>Write-Output hi</powershell>') 'user-data is served exactly'
$st.UserData = [byte[]]@()
$ud = Get-Imds $st '/latest/user-data'
Check ($ud.Status -eq 200 -and $ud.Body.Length -eq 0) 'empty user data is served empty'
$st.UserData = $null
Check ((Get-Imds $st '/latest/user-data').Status -eq 404) 'no user data: 404'
Check-Equal (Get-Imds $st '/latest/').Text "dynamic`nmeta-data" 'no user data: not listed'

$nf = Get-Imds $st '/latest/meta-data/nope'
Check ($nf.Status -eq 404 -and $nf.ContentType -eq 'text/html' -and $nf.Text -ceq $script:OINotFoundBody) 'an unknown path is EC2''s 404 page'
Check ($nf.Text.Contains('<title>404 - Not Found</title>') -and $nf.Text.Contains("`n`t""http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"">")) 'the 404 page body'
foreach ($p in @('/2099-01-01/meta-data/', '/latest/Meta-Data/', '/latest/meta-data/instance-id/extra', '/LATEST/', '/latest/meta-data/placement/zone')) {
    Check ((Get-Imds $st $p).Status -eq 404) ("{0} is not found" -f $p)
}

$nr = $cfgRaw.Clone()
$nr.role = ''
$nr.securityGroups = @()
$ns = New-TestState $nr
$ns.Creds = $null
$ns.Facts.Mac = $null
$listing = (Get-Imds $ns '/latest/meta-data/').Text
Check (-not $listing.Contains('iam/') -and -not $listing.Contains('security-groups') -and -not $listing.Contains('network/') -and -not $listing.Contains("`nmac")) 'no role, groups or MAC: not listed'
Check ((Get-Imds $ns '/latest/meta-data/iam/info').Status -eq 404) 'no role: iam/ is not served'
Check ((Get-Imds $ns '/latest/meta-data/security-groups').Status -eq 404) 'no security groups: 404'

# IMDSv2 over the router.
$ttlHeader = @{}
$ttlHeader['X-aws-ec2-metadata-token-ttl-seconds'] = '21600'
$put = Get-Imds $st '/latest/api/token' $ttlHeader 'PUT'
Check ($put.Status -eq 200 -and $put.Headers['X-aws-ec2-metadata-token-ttl-seconds'] -eq '21600') 'PUT /latest/api/token issues a token and echoes its TTL'
$withToken = @{ 'x-aws-ec2-metadata-token' = $put.Text }
Check-Equal (Get-Imds $st '/latest/meta-data/instance-id' $withToken).Text 'i-0123456789abcdef0' 'a token works (header names are case-insensitive)'
Check ((Get-Imds $st '/latest/meta-data/instance-id' @{ 'X-aws-ec2-metadata-token' = 'bogus' }).Status -eq 401) 'an invalid token is refused, even when tokens are optional'
Check ((Get-Imds $st '/latest/meta-data/instance-id' @{ 'X-aws-ec2-metadata-token' = '' }).Status -eq 401) 'an empty token is refused'
foreach ($ttl in @('0', '21601', 'abc', '-5', '', ' ')) {
    $h = @{ 'X-aws-ec2-metadata-token-ttl-seconds' = $ttl }
    Check ((Get-Imds $st '/latest/api/token' $h 'PUT').Status -eq 400) ("TTL '{0}' is a bad request" -f $ttl)
}
Check ((Get-Imds $st '/latest/api/token' @{} 'PUT').Status -eq 400) 'a token request without a TTL is a bad request'
Check ((Get-Imds $st '/latest/api/token' @{ 'X-aws-ec2-metadata-token-ttl-seconds' = ' 60 ' } 'PUT').Status -eq 200) 'the TTL may carry spaces'
$xff = @{ 'X-aws-ec2-metadata-token-ttl-seconds' = '60'; 'X-Forwarded-For' = '203.0.113.9' }
$r = Get-Imds $st '/latest/api/token' $xff 'PUT'
Check ($r.Status -eq 403 -and $r.Text -eq "Forbidden`n") 'a token request through a proxy (X-Forwarded-For) is forbidden'
$r = Get-Imds $st '/latest/meta-data/' $ttlHeader 'PUT'
Check ($r.Status -eq 405 -and $r.Headers['Allow'] -eq 'GET, PUT') 'PUT elsewhere is not allowed'
Check ((Get-Imds $st '/latest/meta-data/' @{} 'POST').Status -eq 405) 'POST is not allowed'
Check ((Get-Imds $st '/latest/meta-data/instance-id' @{} 'HEAD').Status -eq 200) 'HEAD is answered as GET'

$rq = $cfgRaw.Clone()
$rq.imds = @{ enabled = $true; httpTokens = 'required'; hopLimit = 1 }
$rs = New-TestState $rq
$r = Get-Imds $rs '/latest/meta-data/instance-id'
Check ($r.Status -eq 401 -and $r.Text -eq "Unauthorized`n") 'httpTokens required: no token, 401'
$tk = (Get-Imds $rs '/latest/api/token' @{ 'X-aws-ec2-metadata-token-ttl-seconds' = '60' } 'PUT').Text
Check ((Get-Imds $rs '/latest/meta-data/instance-id' @{ 'X-aws-ec2-metadata-token' = $tk }).Status -eq 200) 'httpTokens required: with a token, 200'
$rs.MonoNow = 1000.0 + 61
Check ((Get-Imds $rs '/latest/meta-data/instance-id' @{ 'X-aws-ec2-metadata-token' = $tk }).Status -eq 401) 'an expired token is refused'

Check-Equal (Get-OIRequestPath '/latest/meta-data/instance-id?x=1') '/latest/meta-data/instance-id' 'the query is not part of the path'
Check-Equal (Get-OIRequestPath 'http://169.254.169.254/latest/meta-data/#frag') '/latest/meta-data/' 'an absolute request target'
Check-Equal (Get-OIRequestPath '/') '/' 'the root'

# --------------------------------------------------------------------------------------------------------
# Credential refresh.
# --------------------------------------------------------------------------------------------------------

Check ((Get-OICredentialRefreshAt ($t0 + 3600) $t0) -eq ($t0 + 3600 - 1200)) '1-hour credentials refresh 20 minutes ahead'
Check ((Get-OICredentialRefreshAt ($t0 + 1800) $t0) -eq ($t0 + 1800 - 600)) '30-minute credentials refresh with a third left'
Check ((Get-OICredentialRefreshAt ($t0 + 900) $t0) -eq ($t0 + 900 - 300)) '15-minute credentials refresh 5 minutes ahead'
Check ((Get-OICredentialRefreshAt ($t0 + 43200) $t0) -eq ($t0 + 43200 - 1200)) 'long credentials refresh at most 20 minutes ahead'

$cache = New-FakeCache $shimCreds
$exp = $t0 + 3600
Check (Test-OICredentialRefreshDue $cache $t0) 'an empty cache is due'
$r = Get-OICachedCredentials $cache $t0
Check ($r.Ok -and $cache.Calls -eq 1 -and $cache.RefreshAt -eq ($exp - 1200) -and $cache.LastUpdated -eq $t0) 'the first get fetches and schedules the refresh'
Check (-not (Test-OICredentialRefreshDue $cache ($t0 + 100))) 'not due before the refresh time'
Check (Test-OICredentialRefreshDue $cache ($exp - 1200)) 'due at the refresh time'
[void](Get-OICachedCredentials $cache ($exp - 1200))
Check ($cache.Calls -eq 1) 'a due refresh does not delay a caller: the cached credentials are served'
$cache.Fetch = { param($cc) $cc.Calls++; return @{ Ok = $false; Status = $null; Message = 'cannot reach the aws-shim' } }
$backoffs = New-Object System.Collections.Generic.List[double]
$now = $exp - 1200
for ($i = 0; $i -lt 6; $i++) {
    $before = $cache.Backoff
    $r = Invoke-OICredentialRefresh $cache $now
    Check (-not $r.Ok -and $cache.NextAttempt -eq ($now + $before)) 'a failed refresh waits for the backoff'
    Check (-not (Test-OICredentialRefreshDue $cache ($now + $before - 1))) 'no retry before the backoff'
    $backoffs.Add($before)
    $now = $cache.NextAttempt
}
Check-Equal ($backoffs -join ',') '5,10,20,40,60,60' 'the backoff doubles to a minute'
$r = Get-OICachedCredentials $cache ($exp - 61)
Check ($r.Ok -and $r.Creds.AccessKeyId -eq 'ASIAEXAMPLEKEYID0001') 'after failed refreshes the cached credentials are served until they expire'
$calls = $cache.Calls
$r = Get-OICachedCredentials $cache ($exp - 60)
Check (-not $r.Ok -and $cache.Calls -eq ($calls + 1) -and $r.Message -eq 'cannot reach the aws-shim') 'expired credentials are fetched again, and the failure is reported'
$cache.Fetch = { param($cc) $cc.Calls++; return @{ Ok = $true; Creds = $cc.Next } }
$cache.Next = @{ AccessKeyId = 'ASIAEXAMPLEKEYID0002'; SecretAccessKey = 's2'; Token = 't2'; Expiration = '2026-11-20T12:00:00Z' }
$r = Invoke-OICredentialRefresh $cache ($exp - 50)
Check ($r.Ok -and $cache.Backoff -eq 5 -and $cache.NextAttempt -eq 0 -and $cache.Creds.AccessKeyId -eq 'ASIAEXAMPLEKEYID0002') 'a successful refresh resets the backoff'
$cache.Next = @{ AccessKeyId = 'ASIAEXAMPLEKEYID0003'; SecretAccessKey = 's3'; Token = 't3'; Expiration = '2026-11-20T09:00:00Z' }
$r = Invoke-OICredentialRefresh $cache $t0
Check ($r.Ok -and $r.Stale -and $cache.NextAttempt -eq ($t0 + 5)) 'credentials already expired by this clock are flagged and retried'

$ic = New-OIIdentityCache { param($c2) $c2.Calls++; return $c2.Answer }
$ic.Calls = 0
$ic.Answer = @{ Ok = $true; Signed = @{ document = '{}'; signature = 's'; pkcs7 = 'p'; rsa2048 = 'r'; expiresInSeconds = 3600 } }
[void](Invoke-OIIdentityRefresh $ic 100.0)
Check ($ic.Expires -eq 3670 -and $ic.RefreshAt -eq 1900) 'the identity document refreshes at half its lifetime and expires 30 s early'
Check ($null -ne (Get-OICurrentIdentity $ic 3669.0) -and $null -eq (Get-OICurrentIdentity $ic 3670.0)) 'the identity document expires'
Check (-not (Test-OIIdentityRefreshDue $ic 1899.0) -and (Test-OIIdentityRefreshDue $ic 1900.0)) 'identity refresh is due at half its lifetime'
$ic.Answer = @{ Ok = $false; Status = 404; Message = 'no such endpoint' }
[void](Invoke-OIIdentityRefresh $ic 2000.0)
Check ($ic.NextAttempt -eq 2900 -and $null -ne (Get-OICurrentIdentity $ic 2000.0)) 'a shim without the endpoint is asked again in 15 minutes; the current document stays'
$ic.Answer = @{ Ok = $false; Status = $null; Message = 'unreachable' }
$ic.Backoff = 5.0
[void](Invoke-OIIdentityRefresh $ic 3000.0)
Check ($ic.NextAttempt -eq 3005 -and $ic.Backoff -eq 10) 'other identity failures back off'
$ic.Answer = @{ Ok = $true; Signed = @{ document = '{}'; signature = 's'; pkcs7 = 'p'; rsa2048 = 'r'; expiresInSeconds = 5 } }
[void](Invoke-OIIdentityRefresh $ic 100.0)
Check ($ic.Expires -eq 130) 'a document is kept at least a minute'

# --------------------------------------------------------------------------------------------------------
# The platform's answers.
# --------------------------------------------------------------------------------------------------------

$m = Format-OIShimHttpError 'credentials' 403 "role not assumable by this instance`n" $script:OICredsHints
Check-Equal $m "the platform's instance credentials service answered HTTP 403: role not assumable by this instance - the instance profile's role does not trust ec2.amazonaws.com" 'a 403 explains the trust policy, in AWS terms'
$m = Format-OIShimHttpError 'identity' 401 'unauthorized' $script:OIIdentityHints
Check-Equal $m "the platform's instance identity service answered HTTP 401: unauthorized - the instance's identity was not accepted by the platform" 'a 401 explains the identity, in AWS terms'
$m = Format-OIShimHttpError 'credentials' 500 ('e' * 400) $script:OICredsHints
Check ($m.Length -eq ("the platform's instance credentials service answered HTTP 500: ".Length + 300)) 'the detail is capped at 300 characters'
Check-Equal (Get-OIWebFailureText 'NameResolutionFailure') 'its name does not resolve' 'a failure is described without the host'
Check-Equal (Get-OIWebFailureText 'ProtocolError') 'the request failed (ProtocolError)' 'an unlisted failure'
Check-Equal (Get-OIWebFailureText '') 'the request failed' 'no failure status'

$good = '{"AccessKeyId":"ASIAEXAMPLEKEYID0001","SecretAccessKey":"example-secret-key","Token":"example-session-token","Expiration":"2026-11-20T11:00:00Z"}'
$r = ConvertFrom-OICredentialsDocument $good
Check ($r.Ok -and $r.Creds.Expiration -ceq '2026-11-20T11:00:00Z' -and $r.Creds.Token -ceq 'example-session-token') 'a credentials document'
$r = ConvertFrom-OICredentialsDocument '{"AccessKeyId":"A","SecretAccessKey":"S","Expiration":"2026-11-20T11:00:00Z"}'
Check (-not $r.Ok -and $r.Message.EndsWith('no Token')) 'a credentials document without a Token'
$r = ConvertFrom-OICredentialsDocument '{"AccessKeyId":"A","SecretAccessKey":"TOPSECRETVALUE", oops'
Check (-not $r.Ok -and -not $r.Message.Contains('TOPSECRETVALUE')) 'an unusable credentials document is never quoted'
$r = ConvertFrom-OICredentialsDocument '{"AccessKeyId":"A","SecretAccessKey":"S","Token":"T","Expiration":"soon"}'
Check (-not $r.Ok) 'a credentials document with a bad Expiration'
$idJson = '{"document":"{\"instanceId\":\"i-0123456789abcdef0\"}","signature":"s","pkcs7":"p","rsa2048":"r","expiresInSeconds":3600}'
$r = ConvertFrom-OIIdentityDocument $idJson
Check ($r.Ok -and $r.Signed.expiresInSeconds -eq 3600 -and $r.Signed.document -ceq '{"instanceId":"i-0123456789abcdef0"}') 'an identity document'
Check (-not (ConvertFrom-OIIdentityDocument '{"document":"{}","signature":"s","pkcs7":"p","rsa2048":"r","expiresInSeconds":3600}').Ok) 'an identity document naming no instance'
Check (-not (ConvertFrom-OIIdentityDocument '{"document":"{\"instanceId\":\"i-1\"}","signature":"s","pkcs7":"p"}').Ok) 'an identity document without rsa2048'

$tokenFile = Join-Path ([System.IO.Path]::GetTempPath()) ('oi-token-' + [guid]::NewGuid().ToString('N'))
[System.IO.File]::WriteAllText($tokenFile, "header.payload.signature`n")
try {
    $r = Invoke-OIShimGet -Url 'http://aws-shim.example.test:4567/v1/vm-credentials' -TokenPath $tokenFile -Roots $null -Hints @{}
    Check (-not $r.Ok -and $r.Message.Contains('without TLS') -and -not $r.Message.Contains('example.test')) 'the identity is never sent over plain HTTP, and the host is not named'
    $r = Invoke-OIShimGet -Url 'https://aws-shim.example.test:4567/v1/vm-credentials' -TokenPath $tokenFile -Roots $null -Hints @{}
    Check (-not $r.Ok -and $r.Message.Contains('no platform root CA')) 'nothing is fetched without the platform root CA'
} finally {
    Remove-Item -LiteralPath $tokenFile -Force -ErrorAction SilentlyContinue
}

# --------------------------------------------------------------------------------------------------------
# Certificates and TLS pinning.
# --------------------------------------------------------------------------------------------------------

$X = 'System.Security.Cryptography.X509Certificates'
function New-TestCa {
    param([string]$Name, $Issuer = $null)
    $k = [System.Security.Cryptography.RSA]::Create(2048)
    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=' + $Name, $k, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $req.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
    $req.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]'KeyCertSign, CrlSign', $true))
    $req.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($req.PublicKey, $false))
    $from = [System.DateTimeOffset]::UtcNow.AddDays(-1)
    $to = [System.DateTimeOffset]::UtcNow.AddDays(30)
    if ($null -eq $Issuer) { return $req.CreateSelfSigned($from, $to) }
    $cert = $req.Create($Issuer, $from, $to.AddDays(-1), [byte[]](1, 2, 3, 4, 5, 6, 7, 9))
    return [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($cert, $k)
}
function New-TestLeaf {
    param($Issuer, [string]$DnsName)
    $k = [System.Security.Cryptography.RSA]::Create(2048)
    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=' + $DnsName, $k, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $req.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true))
    $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $san.AddDnsName($DnsName)
    $req.CertificateExtensions.Add($san.Build())
    $from = [System.DateTimeOffset]::UtcNow.AddHours(-1)
    $to = [System.DateTimeOffset]::UtcNow.AddDays(7)
    if ($null -eq $Issuer) { return $req.CreateSelfSigned($from, $to) }
    return $req.Create($Issuer, $from, $to, [byte[]](9, 8, 7, 6, 5, 4, 3, 2))
}

$rootA = New-TestCa 'Example Platform Root A'
$rootB = New-TestCa 'Example Platform Root B'
$interA = New-TestCa 'Example Platform Intermediate A' $rootA
$leafA = New-TestLeaf $rootA 'aws-shim.example.test'
$leafB = New-TestLeaf $rootB 'aws-shim.example.test'
$leafViaInter = New-TestLeaf $interA 'aws-shim.example.test'
$selfSigned = New-TestLeaf $null 'aws-shim.example.test'

$pemA = ConvertTo-OIPem $rootA.RawData
Check ($pemA.StartsWith("-----BEGIN CERTIFICATE-----`n") -and $pemA.EndsWith("`n-----END CERTIFICATE-----`n")) 'PEM framing'
Check (@($pemA -split "`n" | Where-Object { $_.Length -gt 64 }).Count -eq 0) 'PEM lines are at most 64 columns'
$ders = ConvertFrom-OIPemCertificates ($pemA + $pemA + (ConvertTo-OIPem $rootB.RawData))
Check ($ders.Count -eq 2 -and [Convert]::ToBase64String($ders[0]) -eq [Convert]::ToBase64String($rootA.RawData)) 'PEM certificates parse, duplicates dropped'
$one = ConvertFrom-OIPemCertificates ($pemA -replace "`n", "`r`n")
Check ($one.Count -eq 1 -and $one[0] -is [byte[]]) 'CRLF PEM, a single certificate stays one certificate'
Check-Throws { ConvertFrom-OIPemCertificates ("-----BEGIN PRIVATE KEY-----`nAAAA`n-----END PRIVATE KEY-----`n") } 'a private key block is refused'
Check-Throws { ConvertFrom-OIPemCertificates ('junk' + "`n" + $pemA) } 'content outside the PEM blocks is refused'
Check-Throws { ConvertFrom-OIPemCertificates 'no pem here' } 'no PEM block'
Check-Throws { ConvertFrom-OIPemCertificates ("-----BEGIN CERTIFICATE-----`n!!!notbase64!!!`n-----END CERTIFICATE-----`n") } 'bad base64 is refused'
$ca = ConvertFrom-OICaPem ($pemA + (ConvertTo-OIPem $interA.RawData))
Check ($ca.Ok -and $ca.Certificates.Count -eq 2) 'CA certificates are accepted'
$ca = ConvertFrom-OICaPem (ConvertTo-OIPem $leafA.RawData)
Check (-not $ca.Ok -and $ca.Message.Contains('not a CA')) 'a server certificate is not a CA'
$bundle = New-OICaBundle @($rootA.RawData, $rootB.RawData) @($rootB.RawData, $interA.RawData)
$bundleCerts = ConvertFrom-OIPemCertificates $bundle
Check ($bundleCerts.Count -eq 3 -and [Convert]::ToBase64String($bundleCerts[2]) -eq [Convert]::ToBase64String($interA.RawData)) 'the CA bundle: the store, then the platform CAs it lacks, each once'

Initialize-OIRootPin
$none = [System.Net.Security.SslPolicyErrors]::None
$chainErrors = [System.Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors
$mismatch = [System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch
function Test-Pin {
    param($Roots, $Leaf, $Intermediates, $Errors)
    $failure = $null
    $ok = [OpenInfraLaunch.RootPin]::Check((New-OICertificateCollection $Roots), $Leaf, (New-OICertificateCollection $Intermediates), $Errors, [ref]$failure)
    return @{ Ok = $ok; Failure = $failure }
}
$p = Test-Pin @($rootA) $leafA @() $chainErrors
Check ($p.Ok) ('a server certificate from the pinned root verifies (the machine need not trust the root): ' + $p.Failure)
$p = Test-Pin @($rootA) $leafViaInter @($interA) $none
Check ($p.Ok) ('a chain through an intermediate verifies: ' + $p.Failure)
$p = Test-Pin @($rootB) $leafA @() $none
Check (-not $p.Ok -and $p.Failure.Contains('does not chain')) 'a certificate from another root is refused, even one the machine trusts'
$p = Test-Pin @($rootA) $leafB @() $none
Check (-not $p.Ok) 'a certificate signed by another CA is refused'
$p = Test-Pin @($rootA) $selfSigned @() $none
Check (-not $p.Ok) 'a self-signed server certificate is refused'
$p = Test-Pin @($rootA) $leafA @() $mismatch
Check (-not $p.Ok -and $p.Failure.Contains('does not name the host')) 'a certificate for another host name is refused'
$p = Test-Pin @() $leafA @() $none
Check (-not $p.Ok) 'no pinned root: refused'

# --------------------------------------------------------------------------------------------------------
# HTTP on the metadata socket.
# --------------------------------------------------------------------------------------------------------

function Get-AsciiBytes {
    param([string]$Text)
    return , ([System.Text.Encoding]::ASCII.GetBytes($Text))
}
$req = ConvertFrom-OIHttpRequest (Get-AsciiBytes "GET /latest/meta-data/ HTTP/1.1`r`nHost: 169.254.169.254`r`nX-aws-ec2-metadata-token: abc`r`n`r`n")
Check ($req.State -eq 'complete' -and $req.Method -ceq 'GET' -and $req.Target -ceq '/latest/meta-data/') 'a GET request'
Check-Equal (Get-OIHeader $req.Headers 'x-aws-ec2-metadata-token') 'abc' 'request header names are case-insensitive'
Check ((ConvertFrom-OIHttpRequest (Get-AsciiBytes "GET / HTTP/1.1`r`nHost: x`r`n")).State -eq 'incomplete') 'headers still arriving'
Check ((ConvertFrom-OIHttpRequest (Get-AsciiBytes "GET / HTTP/1.0`n`n")).State -eq 'complete') 'bare LF line ends'
$putHead = "PUT /latest/api/token HTTP/1.1`r`nX-aws-ec2-metadata-token-ttl-seconds: 60`r`nContent-Length: 4`r`n`r`n"
Check ((ConvertFrom-OIHttpRequest (Get-AsciiBytes ($putHead + 'ab'))).State -eq 'incomplete') 'a body still arriving'
Check ((ConvertFrom-OIHttpRequest (Get-AsciiBytes ($putHead + 'abcd'))).State -eq 'complete') 'a request with its body'
Check ((ConvertFrom-OIHttpRequest (Get-AsciiBytes "PUT /latest/api/token HTTP/1.1`r`nContent-Length: 0`r`n`r`n")).State -eq 'complete') 'Content-Length: 0'
Check ((ConvertFrom-OIHttpRequest (Get-AsciiBytes "PUT / HTTP/1.1`r`nContent-Length: 999999`r`n`r`n")).State -eq 'complete') 'a large body is not waited for'
$dup = ConvertFrom-OIHttpRequest (Get-AsciiBytes "GET / HTTP/1.1`r`nX-A: 1`r`nx-a: 2`r`n`r`n")
Check-Equal (Get-OIHeader $dup.Headers 'X-A') '1, 2' 'repeated headers are joined'
$malformed = @(
    "GET /`r`n`r`n", "GET / HTTP/1.1 extra`r`n`r`n", "GET / FTP/1.0`r`n`r`n", "G@T / HTTP/1.1`r`n`r`n",
    "GET / HTTP/1.1`r`nNoColon`r`n`r`n", "GET / HTTP/1.1`r`nBad Name: x`r`n`r`n",
    "GET / HTTP/1.1`r`nContent-Length: -1`r`n`r`n", "GET / HTTP/1.1`r`nContent-Length: 1`r`nContent-Length: 1`r`n`r`n"
)
foreach ($badReq in $malformed) {
    Check ((ConvertFrom-OIHttpRequest (Get-AsciiBytes $badReq)).State -eq 'bad') ('a malformed request is refused: ' + ($badReq -replace "`r`n", '\r\n'))
}
Check ((ConvertFrom-OIHttpRequest (Get-AsciiBytes ("GET / HTTP/1.1`r`nX: " + ('a' * 40000)))).State -eq 'bad') 'an oversized header block is refused'

$date = New-Object System.DateTime 2026, 11, 20, 10, 0, 0, ([System.DateTimeKind]::Utc)
$hdr = @{}
$hdr['X-aws-ec2-metadata-token-ttl-seconds'] = '60'
$wire = [System.Text.Encoding]::ASCII.GetString((ConvertTo-OIHttpResponse (New-OIResponse 200 'text/plain' 'TOKEN' $hdr) 'PUT' $date))
Check-Equal $wire ("HTTP/1.1 200 OK`r`nServer: EC2ws`r`nDate: Fri, 20 Nov 2026 10:00:00 GMT`r`nContent-Type: text/plain`r`nContent-Length: 5`r`nX-aws-ec2-metadata-token-ttl-seconds: 60`r`nConnection: close`r`n`r`nTOKEN") 'a token response on the wire'
$wire = [System.Text.Encoding]::ASCII.GetString((ConvertTo-OIHttpResponse (New-OIResponse 200 'text/plain' 'i-0123') 'HEAD' $date))
Check ($wire.EndsWith("Content-Length: 6`r`nConnection: close`r`n`r`n")) 'HEAD: the length, no body'
$wire = [System.Text.Encoding]::ASCII.GetString((ConvertTo-OIHttpResponse (New-OIResponse 405 'text/plain' "Method Not Allowed`n" @{ Allow = 'GET, PUT' }) 'POST' $date))
Check ($wire.StartsWith("HTTP/1.1 405 Method Not Allowed`r`n") -and $wire.Contains("`r`nAllow: GET, PUT`r`n")) 'a 405 with its Allow header'

# The TCP server end to end: the client runs in a thread job, the server loop here until the client is done.
$tcp = Start-OITcpListener -Address '127.0.0.1' -Port 0 -Attempts 1
Check ($null -ne $tcp.Listener) ('a TCP listener starts: ' + $tcp.Message)
$port = $tcp.Listener.LocalEndpoint.Port
$ts = New-TestState
$ts.Facts.LocalAddresses = @('127.0.0.1')
$ts.Facts.ContainerNetworks = @()
$ts.Facts.Taken = Get-OIMonoNow
$clientScript = {
    param([int]$Port, [string[]]$Chunks, [int]$PauseMs)
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect('127.0.0.1', $Port)
    $client.ReceiveTimeout = 5000
    $stream = $client.GetStream()
    $first = $true
    foreach ($chunk in $Chunks) {
        if (-not $first) { Start-Sleep -Milliseconds $PauseMs }
        $first = $false
        $b = [System.Text.Encoding]::ASCII.GetBytes($chunk)
        $stream.Write($b, 0, $b.Length)
        $stream.Flush()
    }
    $ms = New-Object System.IO.MemoryStream
    $buf = New-Object byte[] 4096
    try {
        while ($true) {
            $n = $stream.Read($buf, 0, $buf.Length)
            if ($n -le 0) { break }
            $ms.Write($buf, 0, $n)
        }
    } catch { }
    $client.Close()
    [System.Text.Encoding]::UTF8.GetString($ms.ToArray())
}
function Invoke-TcpExchange {
    param([string[]]$Chunks, [int]$PauseMs = 0)
    $job = Start-ThreadJob -ScriptBlock $clientScript -ArgumentList $port, $Chunks, $PauseMs
    Invoke-OIServeTcp $tcp.Listener $ts -Iterations 100 -WaitMicroseconds 100000 -Until { $job.State -ne 'Running' -and $job.State -ne 'NotStarted' }
    return [string](Receive-Job -Job $job -Wait -AutoRemoveJob)
}
$out = Invoke-TcpExchange @("PUT /latest/api/token HTTP/1.1`r`nHost: 169.254.169.254`r`nX-aws-ec2-metadata-token-ttl-seconds: 60`r`nContent-Length: 0`r`n`r`n")
Check ($out.StartsWith("HTTP/1.1 200 OK`r`n") -and $out.Contains("`r`nX-aws-ec2-metadata-token-ttl-seconds: 60`r`n") -and $out.Contains("`r`nServer: EC2ws`r`n")) ('the TCP server issues a token: ' + ($out -replace "`r`n", '\r\n'))
$wireToken = ($out -split "`r`n`r`n", 2)[1]
Check (Test-OIImdsToken $ts.TokenKey (Get-OIMonoNow) $wireToken) 'the token from the wire is valid'
$out = Invoke-TcpExchange @("GET /latest/meta-data/instance-id HTTP/1.1`r`nHost: 169.254.169.254`r`nX-aws-ec2-metadata-", ("token: " + $wireToken + "`r`n`r`n")) 300
Check ($out.StartsWith("HTTP/1.1 200 OK`r`n") -and $out.EndsWith("`r`n`r`ni-0123456789abcdef0")) ('a request split across reads is answered: ' + ($out -replace "`r`n", '\r\n'))
$out = Invoke-TcpExchange @("GET /latest/meta-data/instance-id HTTP/1.1`r`nX-aws-ec2-metadata-token: forged`r`n`r`n")
Check ($out.StartsWith("HTTP/1.1 401 Unauthorized`r`n")) 'the TCP server refuses a forged token'
$out = Invoke-TcpExchange @("HELLO`r`n`r`n")
Check ($out.StartsWith("HTTP/1.1 400 Bad Request`r`n")) 'the TCP server refuses a malformed request'
$tcp.Listener.Stop()

$r = Invoke-OIShimGet -Url 'https://aws-shim.example.test:4567/v1/vm-identity' -TokenPath '' -Roots (New-OICertificateCollection @($rootA)) -Hints @{} -Service 'identity'
Check-Equal $r.Message "the instance's identity disk is not attached, so the platform's instance identity service cannot be asked" 'no identity disk'

# --------------------------------------------------------------------------------------------------------
# Who may use the metadata service.
# --------------------------------------------------------------------------------------------------------

Check ((ConvertTo-OIIPv4Number '10.0.0.1') -eq 167772161) 'IPv4 to number'
Check ((ConvertTo-OIIPv4Number '::ffff:10.0.0.1') -eq 167772161) 'IPv4-mapped IPv6'
Check ($null -eq (ConvertTo-OIIPv4Number 'fe80::1')) 'IPv6 is not IPv4'
Check ((ConvertTo-OIIPv4Mask 0) -eq 0 -and (ConvertTo-OIIPv4Mask 32) -eq 4294967295 -and (ConvertTo-OIIPv4Mask 24) -eq 4294967040 -and (ConvertTo-OIIPv4Mask 20) -eq 4294963200) 'prefix masks'
$localAddrs = @('127.0.0.1', '169.254.169.254', '10.0.2.2', '172.20.0.1')
$nets = @(@{ Network = (ConvertTo-OIIPv4Number '172.20.0.0'); Mask = (ConvertTo-OIIPv4Mask 20) })
Check-Equal (Get-OIImdsAdmission '127.0.0.1' $localAddrs $nets 'PUT' 1) 'serve' 'loopback'
Check-Equal (Get-OIImdsAdmission '10.0.2.2' $localAddrs $nets 'PUT' 1) 'serve' 'this instance'
Check-Equal (Get-OIImdsAdmission '169.254.169.254' $localAddrs $nets 'GET' 1) 'serve' 'the metadata address itself'
Check-Equal (Get-OIImdsAdmission '::1' $localAddrs $nets 'GET' 1) 'serve' 'IPv6 loopback'
Check-Equal (Get-OIImdsAdmission '172.20.3.7' $localAddrs $nets 'GET' 1) 'serve' 'a container (IMDSv1 GET, one hop)'
Check-Equal (Get-OIImdsAdmission '172.20.3.7' $localAddrs $nets 'PUT' 1) 'drop' 'a container token request beyond hop limit 1'
Check-Equal (Get-OIImdsAdmission '172.20.3.7' $localAddrs $nets 'PUT' 2) 'serve' 'a container token request within hop limit 2'
Check-Equal (Get-OIImdsAdmission '10.0.2.1' $localAddrs $nets 'GET' 64) 'refuse' 'the gateway is another host'
Check-Equal (Get-OIImdsAdmission '192.0.2.50' $localAddrs $nets 'GET' 64) 'refuse' 'a LAN neighbour is refused'
Check-Equal (Get-OIImdsAdmission 'fe80::1' $localAddrs $nets 'GET' 64) 'refuse' 'link-local IPv6'
Check-Equal (Get-OIImdsAdmission 'not-an-ip' $localAddrs $nets 'GET' 64) 'refuse' 'garbage'

# --------------------------------------------------------------------------------------------------------
# What -Install writes.
# --------------------------------------------------------------------------------------------------------

$stub = Get-OIStubSource
$tokens = $null
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseInput($stub, [ref]$tokens, [ref]$errors)
Check ($errors.Count -eq 0) 'the boot stub parses'
Check ($stub.Contains("'openinfra-launch.ps1'") -and $stub.Contains("'launch-config.json'") -and $stub.Contains('-File $agent -Run')) 'the stub runs -Run from the launch CD'
$x = [xml](Get-OITaskXml 'C:\ProgramData\openinfra\launch\launch-stub.ps1' 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')
Check ($null -ne $x.Task.Triggers.BootTrigger) 'the task runs at startup'
Check ($x.Task.Principals.Principal.UserId -eq 'S-1-5-18' -and $x.Task.Principals.Principal.RunLevel -eq 'HighestAvailable') 'as LocalSystem with the highest privileges'
Check ($x.Task.Settings.ExecutionTimeLimit -eq 'PT0S' -and $x.Task.Settings.RestartOnFailure.Count -eq '999') 'no time limit, restarted on failure'
Check-Equal $x.Task.Actions.Exec.Arguments '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\ProgramData\openinfra\launch\launch-stub.ps1"' 'the task runs the stub'
Check-Equal $x.Task.RegistrationInfo.URI '\OpenInfra Launch' 'the task name'

Write-Host ('ok: {0} checks passed' -f $script:passed)
