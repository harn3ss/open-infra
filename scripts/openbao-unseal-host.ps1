<#
.SYNOPSIS
The OpenBao unseal host: a small OpenBao on one Windows PC outside the cluster, whose only job is
to unseal the cluster's OpenBao members when they start.

.DESCRIPTION
The cluster's OpenBao keeps its root key encrypted by a key that never leaves this PC (a transit
key, created non-exportable). A member that starts asks this PC to decrypt it. While this PC is
off or sealed, a starting member stays sealed and retries; members already running keep serving.

This PC's own OpenBao is sealed by 3 unseal keys, any 2 of which unseal it. After every restart of
this PC, unseal it from any PowerShell window (no administrator needed), one key each time:

    bao operator unseal
    bao operator unseal

Install keeps a copy of this script in C:\Program Files\OpenBao for the other actions, such as:

    powershell -ExecutionPolicy Bypass -File "C:\Program Files\OpenBao\openbao-unseal-host.ps1" -Action Status

Install sets up, in one run:
  - OpenBao (pinned version, SHA-256 checked) in C:\Program Files\OpenBao
  - its data, logs and TLS files in C:\ProgramData\OpenBao, readable by SYSTEM and Administrators
  - a scheduled task that runs it as SYSTEM at startup
  - an audit log of every request (C:\ProgramData\OpenBao\logs\audit.log)
  - port 8200 (TLS 1.3), open to the cluster nodes' subnet only, and a port on 127.0.0.1 for this PC
  - the transit key 'autounseal', and a cluster token that can only encrypt and decrypt with it
  - an admin token that can mint a new cluster token, renew the TLS certificate and take a backup
  - a first backup
It then shows, once, and stores nowhere:
  - the 3 unseal keys and the admin token. Keep them apart (a password manager, paper), and never
    on the cluster, a NAS, a shared drive or in a chat.
  - the cluster token, with the commands that put it into the cluster. You run those yourself.

A lost or broken PC is rebuilt from a backup and 2 unseal keys (-Action Restore). Without both, the
cluster's OpenBao can never be unsealed again and its data is lost: keep a backup off this PC.

Turn on BitLocker: an unsealed OpenBao's memory can reach the page file and the hibernation file.
Windows Firewall must be on: it is what limits port 8200 to the cluster.

.PARAMETER Action
Install (the default), Unseal, Status, NewClusterToken, RenewCertificate, Backup, Restore or Remove.

.PARAMETER ListenIp
This PC's fixed LAN address, which the cluster connects to. For Install, Restore and
RenewCertificate.

.PARAMETER ClusterSubnet
The cluster nodes' subnet (CIDR): the only source allowed to reach port 8200. For Install and
Restore.

.PARAMETER BackupDir
Where Backup writes, and Install its first backup. Default: C:\ProgramData\OpenBao\backup.

.PARAMETER BackupFile
The backup that Restore reads.

.EXAMPLE
.\openbao-unseal-host.ps1 -ListenIp 192.0.2.10 -ClusterSubnet 192.0.2.0/24

.EXAMPLE
.\openbao-unseal-host.ps1 -Action Unseal
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Unseal', 'Status', 'NewClusterToken', 'RenewCertificate', 'Backup', 'Restore', 'Remove')]
    [string]$Action = 'Install',
    [string]$ListenIp,
    [string]$ClusterSubnet,
    [string]$BackupDir,
    [string]$BackupFile
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# OpenBao release, and the SHA-256 of each Windows zip from its checksums.txt (whose GPG signature
# by OpenBao's release key was verified when these were pinned).
$Version = '2.7.2'
$ZipSha256 = @{
    amd64 = 'b058d30eac461e78e56305d3aa7371c061405a060f364aa20999dc3a309264f4'
    arm64 = 'e1acf36792e35c7242742fb59f4bdb15f66282732d6ab753092363ff9b3a6ec1'
}

$InstallDir   = Join-Path $env:ProgramFiles 'OpenBao'
$Bao          = Join-Path $InstallDir 'bao.exe'
$RootDir      = Join-Path $env:ProgramData 'OpenBao'
$DataDir      = Join-Path $RootDir 'data'
$TlsDir       = Join-Path $RootDir 'tls'
$LogDir       = Join-Path $RootDir 'logs'
$ConfigFile   = Join-Path $RootDir 'config.hcl'
$AccessorFile = Join-Path $RootDir 'cluster-token.accessor'
$TaskName     = 'OpenBao unseal host'
$FirewallRule = 'OpenBao unseal host (cluster)'
$Port         = 8200        # the cluster's listener (TLS)
$ClusterBind  = '0.0.0.0'   # every interface, so a late network at boot cannot stop it; the firewall limits who connects
$LocalPort    = 8210        # this PC's listener, on 127.0.0.1 only
$LocalAddr    = "http://127.0.0.1:$LocalPort"
$Utf8         = New-Object System.Text.UTF8Encoding $false

$AutounsealPolicy = @'
# The cluster's members: encrypt and decrypt with the unseal key, nothing else.
path "transit/encrypt/autounseal" {
  capabilities = ["update"]
}
path "transit/decrypt/autounseal" {
  capabilities = ["update"]
}
'@

$AdminPolicy = @'
# This script's maintenance actions. It cannot decrypt, read or change the unseal key.
path "auth/token/create/cluster-seal" {
  capabilities = ["update"]
}
path "auth/token/revoke-accessor" {
  capabilities = ["update"]
}
path "pki/issue/listener" {
  capabilities = ["update"]
}
path "sys/storage/raft/snapshot" {
  capabilities = ["read"]
}
# Together with 2 unseal keys, a root token can still be generated if one is ever needed.
path "sys/generate-root-token/*" {
  capabilities = ["read", "update", "delete"]
}
'@

function Write-Step([string]$Text) { Write-Host "==> $Text" -ForegroundColor Cyan }

function Write-TextFile([string]$Path, [string]$Text) { [IO.File]::WriteAllText($Path, $Text, $Utf8) }

function ConvertTo-HclPath([string]$Path) { return $Path -replace '\\', '/' }

function Read-Secret([string]$Prompt) {
    $secure = Read-Host -Prompt $Prompt -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Assert-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this from an elevated PowerShell (Run as administrator).'
    }
}

function Assert-ListenIp {
    if (-not $ListenIp) { throw "-ListenIp is required: this PC's fixed LAN address, which the cluster connects to." }
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($ListenIp, [ref]$parsed) -or $parsed.AddressFamily -ne 'InterNetwork') {
        throw "-ListenIp '$ListenIp' is not an IPv4 address."
    }
    $mine = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $ListenIp })
    if ($mine.Count -eq 0) { throw "$ListenIp is not an address of this PC (see ipconfig)." }
    if ($mine[0].PrefixOrigin -eq 'Dhcp') {
        Write-Warning "$ListenIp came from DHCP: reserve it for this PC on your router, or the cluster loses this PC when the lease changes."
    }
}

function Assert-ClusterSubnet {
    if (-not $ClusterSubnet) {
        throw "-ClusterSubnet is required: the cluster nodes' subnet in CIDR form (such as 192.0.2.0/24), the only source allowed to reach port $Port."
    }
    if ($ClusterSubnet -notmatch '^(\d{1,3}\.){3}\d{1,3}/(\d|[12]\d|3[0-2])$') {
        throw "-ClusterSubnet '$ClusterSubnet' is not an IPv4 subnet in CIDR form (such as 192.0.2.0/24)."
    }
}

function Assert-NotInstalled {
    if (Test-Path (Join-Path $DataDir '*')) {
        throw "This PC already has an unseal host ($DataDir). '-Action Status' shows it; '-Action Remove' deletes it."
    }
}

# One call to this PC's OpenBao, on its 127.0.0.1 listener. Returns the parsed response.
function Invoke-Bao {
    param(
        [Parameter(Mandatory = $true, Position = 0)][ValidateSet('GET', 'PUT', 'POST')][string]$Method,
        [Parameter(Mandatory = $true, Position = 1)][string]$Path,
        [Parameter(Position = 2)][hashtable]$Body,
        [string]$Token
    )
    $request = @{ Uri = "$LocalAddr/v1/$Path"; Method = $Method; UseBasicParsing = $true; TimeoutSec = 60 }
    if ($Token) { $request.Headers = @{ 'X-Vault-Token' = $Token } }
    if ($Method -ne 'GET') {
        if (-not $Body) { $Body = @{} }
        $request.Body = ConvertTo-Json -InputObject $Body -Depth 5 -Compress
        $request.ContentType = 'application/json; charset=utf-8'
    }
    try { return Invoke-RestMethod @request }
    catch {
        $failure = $_
        $detail = $failure.Exception.Message
        if ($failure.ErrorDetails -and $failure.ErrorDetails.Message) {
            $detail = $failure.ErrorDetails.Message
            try { $detail = (ConvertFrom-Json $failure.ErrorDetails.Message).errors -join '; ' } catch { }
        }
        throw "OpenBao refused $Method ${Path}: $detail"
    }
}

function Get-SealStatus {
    try { return Invoke-RestMethod -Uri "$LocalAddr/v1/sys/seal-status" -UseBasicParsing -TimeoutSec 5 }
    catch { return $null }
}

function Wait-Bao([ValidateSet('Up', 'Active')][string]$For, [int]$Seconds = 90) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if ($For -eq 'Up') {
            if (Get-SealStatus) { return }
        } else {
            try {
                $leader = Invoke-RestMethod -Uri "$LocalAddr/v1/sys/leader" -UseBasicParsing -TimeoutSec 5
                if ($leader.is_self) { return }
            } catch { }
        }
        Start-Sleep -Milliseconds 500
    }
    throw "OpenBao did not become $($For.ToLower()) within $Seconds seconds; see $(Join-Path $LogDir 'bao.log')."
}

function Unlock-WithKeys([string[]]$Keys) {
    $status = $null
    foreach ($key in $Keys) {
        $status = Invoke-Bao PUT 'sys/unseal' @{ key = $key }
        if (-not $status.sealed) { break }
    }
    if ($status.sealed) { throw 'Still sealed after the unseal keys given.' }
    Wait-Bao Active
}

function Unlock-Interactive {
    $status = Get-SealStatus
    if (-not $status) { throw "This PC's OpenBao is not running. Start it with: Start-ScheduledTask '$TaskName'" }
    if (-not $status.initialized) { throw "This PC's OpenBao is not set up yet: run '-Action Install'." }
    while ($status -and $status.sealed) {
        $key = Read-Secret ('Unseal key ({0} of {1})' -f ($status.progress + 1), $status.t)
        if (-not $key) { throw 'No key entered: still sealed.' }
        try { $status = Invoke-Bao PUT 'sys/unseal' @{ key = $key } }
        catch {
            Write-Warning $_.Exception.Message
            $status = Get-SealStatus
        }
        $key = $null
    }
    if (-not $status) { throw "This PC's OpenBao stopped answering; see $(Join-Path $LogDir 'bao.log')." }
    Wait-Bao Active
    Write-Host "Unsealed: the cluster's members can unseal again." -ForegroundColor Green
}

function Use-AdminToken {
    $token = Read-Secret 'Admin token'
    $self = Invoke-Bao GET 'auth/token/lookup-self' -Token $token
    if (@($self.data.policies) -notcontains 'unseal-host-admin') { throw 'That is not the admin token.' }
    $null = Invoke-Bao POST 'auth/token/renew-self' -Token $token   # keeps its 10-year period from lapsing
    return $token
}

function Install-Binary {
    $arch = 'amd64'
    if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { $arch = 'arm64' }
    $present = $false
    if (Test-Path $Bao) {
        $installed = (& $Bao version | Out-String)
        if ($installed -notlike "OpenBao v$Version *") { throw "$Bao is another version ($($installed.Trim())); remove it first." }
        Write-Step "OpenBao $Version is already installed"
        $present = $true
    }
    if (-not $present) {
        $name = "openbao_${Version}_windows_$arch.zip"
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('openbao-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $tmp | Out-Null
        try {
            $zip = Join-Path $tmp $name
            Write-Step "Downloading OpenBao $Version ($arch)"
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/openbao/openbao/releases/download/v$Version/$name" -OutFile $zip
            $sha = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLowerInvariant()
            if ($sha -ne $ZipSha256[$arch]) { throw "Checksum mismatch for $name (got $sha): not installing it." }
            Expand-Archive -Path $zip -DestinationPath $tmp
            New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
            Copy-Item -Path (Join-Path $tmp 'bao.exe') -Destination $Bao
        } finally {
            Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
        }
    }
    # This script, beside the binary, for the later actions.
    $copy = Join-Path $InstallDir 'openbao-unseal-host.ps1'
    if ($PSCommandPath -and $PSCommandPath -ne $copy) { Copy-Item -Path $PSCommandPath -Destination $copy -Force }
    # So any shell on this PC can run 'bao operator unseal' against its OpenBao.
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if (-not $machinePath) { $machinePath = '' }
    if (($machinePath -split ';') -notcontains $InstallDir) {
        [Environment]::SetEnvironmentVariable('Path', ($machinePath.TrimEnd(';') + ';' + $InstallDir), 'Machine')
    }
    [Environment]::SetEnvironmentVariable('BAO_ADDR', $LocalAddr, 'Machine')
}

function New-StateDirectories {
    New-Item -ItemType Directory -Force -Path $RootDir | Out-Null
    # SYSTEM and Administrators only; everything below inherits it.
    & icacls.exe $RootDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not restrict access to $RootDir (icacls exit $LASTEXITCODE)." }
    foreach ($dir in @($DataDir, $TlsDir, $LogDir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
}

function Write-Config([string]$Ip, [switch]$WithClusterListener) {
    $text = @"
# OpenBao unseal host for open-infra, written by openbao-unseal-host.ps1. Re-run it rather than editing this.
ui                = false
max_lease_ttl     = "87600h"
default_lease_ttl = "768h"
api_addr          = "https://${Ip}:$Port"
cluster_addr      = "https://127.0.0.1:$($LocalPort + 1)"

storage "raft" {
  path    = "$(ConvertTo-HclPath $DataDir)"
  node_id = "unseal-host"
}

# This PC only: the script's own calls.
listener "tcp" {
  address         = "127.0.0.1:$LocalPort"
  cluster_address = "127.0.0.1:$($LocalPort + 1)"
  tls_disable     = true
}

# Every request, sensitive fields HMAC'd. The path must stay the same: a restored backup expects it.
audit "file" "audit-log" {
  description = "every request to the unseal host"
  options {
    file_path = "$(ConvertTo-HclPath (Join-Path $LogDir 'audit.log'))"
  }
}

"@
    if ($WithClusterListener) {
        $text += @"
# The cluster's members: TLS 1.3, reachable from the cluster's subnet only (Windows Firewall).
listener "tcp" {
  address         = "${ClusterBind}:$Port"
  cluster_address = "127.0.0.1:$($Port + 1)"
  tls_cert_file   = "$(ConvertTo-HclPath (Join-Path $TlsDir 'server.crt'))"
  tls_key_file    = "$(ConvertTo-HclPath (Join-Path $TlsDir 'server.key'))"
  tls_min_version = "tls13"
}

"@
    }
    Write-TextFile $ConfigFile $text
}

function Register-ServerTask {
    $arguments = 'server "-config={0}" "-log-file={1}" -log-rotate-bytes=10485760 -log-rotate-max-files=10' -f $ConfigFile, (Join-Path $LogDir 'bao.log')
    $taskAction = New-ScheduledTaskAction -Execute $Bao -Argument $arguments -WorkingDirectory $RootDir
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 `
        -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $taskAction -Trigger $trigger -Principal $principal `
        -Settings $settings -Description "Unseals the open-infra cluster's OpenBao. Managed by openbao-unseal-host.ps1." -Force | Out-Null
}

function Stop-Server {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    for ($i = 0; $i -lt 30 -and (Get-Process -Name bao -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Seconds 1 }
    Get-Process -Name bao -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 1
}

function Restart-Server {
    Stop-Server
    Start-ScheduledTask -TaskName $TaskName
    Wait-Bao Up
}

function Add-FirewallRule {
    Get-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName $FirewallRule -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port `
        -RemoteAddress $ClusterSubnet -Program $Bao -Profile Any | Out-Null
}

# Issues the cluster listener's certificate for $Ip from this PC's own CA, and writes the CA beside it.
function New-ListenerCertificate([string]$Token, [string]$Ip) {
    $issued = Invoke-Bao POST 'pki/issue/listener' @{ common_name = 'openbao-unseal-host'; ip_sans = $Ip; ttl = '43800h' } -Token $Token
    Write-TextFile (Join-Path $TlsDir 'server.crt') ($issued.data.certificate + "`n" + $issued.data.issuing_ca + "`n")
    Write-TextFile (Join-Path $TlsDir 'server.key') ($issued.data.private_key + "`n")
    Write-TextFile (Join-Path $TlsDir 'ca.pem') ($issued.data.issuing_ca + "`n")
}

function New-ClusterToken([string]$Token) {
    $created = Invoke-Bao POST 'auth/token/create/cluster-seal' @{ display_name = 'open-infra-cluster' } -Token $Token
    Write-TextFile $AccessorFile ($created.auth.accessor + "`n")   # not a secret: lets a later run revoke this token
    return $created.auth.client_token
}

function Save-Backup([string]$Token, [string]$Dir) {
    if (-not $Dir) { $Dir = Join-Path $RootDir 'backup' }
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    $file = Join-Path $Dir ('unseal-host-{0:yyyyMMdd-HHmmss}.snap' -f (Get-Date))
    Invoke-WebRequest -UseBasicParsing -Uri "$LocalAddr/v1/sys/storage/raft/snapshot" -Headers @{ 'X-Vault-Token' = $Token } -OutFile $file
    if ((Get-Item $file).Length -lt 1024) { throw "The backup $file is too small to be a snapshot." }
    return $file
}

function Read-PemCertificate([string]$Path) {
    $pem = [IO.File]::ReadAllText($Path)
    $base64 = [regex]::Match($pem, '-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----', 'Singleline').Groups[1].Value -replace '\s', ''
    return , [Convert]::FromBase64String($base64)
}

function Get-Fingerprint([string]$Path) {
    $der = Read-PemCertificate $Path
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash($der) } finally { $sha.Dispose() }
    return (($hash | ForEach-Object { $_.ToString('X2') }) -join ':')
}

function Get-CertificateExpiry([string]$Path) {
    $certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, (Read-PemCertificate $Path))
    return $certificate.NotAfter
}

function Show-ClusterToken([string]$Token, [switch]$Replace) {
    Write-Host ' Cluster token: you put it into the cluster, once. On the control plane, run these and'
    Write-Host ' paste the token at the prompt (it is not shown):'
    Write-Host ''
    if ($Replace) {
        Write-Host '   kubectl -n openbao delete secret openbao-seal --ignore-not-found' -ForegroundColor Cyan
    } else {
        Write-Host '   kubectl get namespace openbao >/dev/null 2>&1 || kubectl create namespace openbao' -ForegroundColor Cyan
    }
    Write-Host '   read -rsp "cluster token: " T; echo; printf %s "$T" | kubectl -n openbao create secret generic openbao-seal --from-file=token=/dev/stdin; unset T' -ForegroundColor Cyan
    Write-Host ''
    Write-Host "   token: $Token" -ForegroundColor Green
    Write-Host ''
}

function Show-Summary([string]$Ip, [string]$Backup) {
    Write-Host ''
    Write-Host " The unseal host is running and unsealed." -ForegroundColor Green
    Write-Host "   address, for the cluster:   https://${Ip}:$Port"
    Write-Host "   CA SHA-256 fingerprint:     $(Get-Fingerprint (Join-Path $TlsDir 'ca.pem'))"
    Write-Host "   certificate valid until:    $((Get-CertificateExpiry (Join-Path $TlsDir 'server.crt')).ToString('yyyy-MM-dd'))"
    if ($Backup) {
        Write-Host "   backup:                     $Backup"
        Write-Host '     Copy it off this PC (a USB stick, say), kept apart from the unseal keys.'
    }
    Write-Host ''
    Write-Host " After every restart of this PC, open PowerShell and run 'bao operator unseal' twice, one key each time."
    Write-Host " Status and the other actions:"
    Write-Host "   powershell -ExecutionPolicy Bypass -File `"$(Join-Path $InstallDir 'openbao-unseal-host.ps1')`" -Action Status"
    Write-Host ''
}

function Wait-ForOperator([string]$What) {
    $null = Read-Host "Press Enter once $What (the screen is then cleared)"
    Clear-Host
}

function Install-UnsealHost {
    Assert-Admin
    Assert-ListenIp
    Assert-ClusterSubnet
    Assert-NotInstalled
    Install-Binary
    Write-Step "Preparing $RootDir"
    New-StateDirectories
    Write-Config -Ip $ListenIp
    Register-ServerTask
    Write-Step 'Starting OpenBao'
    Restart-Server
    $status = Get-SealStatus
    if ($status.initialized) { throw "This PC's OpenBao is already initialised; '-Action Remove' deletes it." }

    Write-Step 'Initialising: 3 unseal keys, any 2 of which unseal it'
    $init = Invoke-Bao PUT 'sys/init' @{ secret_shares = 3; secret_threshold = 2 }
    $keys = @($init.keys_base64)
    $root = $init.root_token
    try {
        Unlock-WithKeys $keys[0..1]
        Write-Step 'Creating the unseal key, the policies and the TLS certificate'
        $null = Invoke-Bao POST 'sys/mounts/transit' @{ type = 'transit'; description = "the cluster's unseal key" } -Token $root
        $null = Invoke-Bao POST 'transit/keys/autounseal' @{ type = 'aes256-gcm96'; exportable = $false; allow_plaintext_backup = $false } -Token $root
        $null = Invoke-Bao PUT 'sys/policies/acl/autounseal' @{ policy = $AutounsealPolicy } -Token $root
        $null = Invoke-Bao PUT 'sys/policies/acl/unseal-host-admin' @{ policy = $AdminPolicy } -Token $root
        # Cluster tokens: orphans, renewed by the members; one that goes a year without renewal lapses.
        $null = Invoke-Bao POST 'auth/token/roles/cluster-seal' @{ allowed_policies = 'autounseal'; orphan = $true; renewable = $true; token_period = '8760h' } -Token $root
        $null = Invoke-Bao POST 'sys/mounts/pki' @{ type = 'pki'; description = "this PC's listener CA"; config = @{ max_lease_ttl = '87600h' } } -Token $root
        $null = Invoke-Bao POST 'pki/root/generate/internal' @{ common_name = 'open-infra unseal host CA'; key_type = 'ec'; key_bits = 256; ttl = '87600h' } -Token $root
        $null = Invoke-Bao POST 'pki/roles/listener' @{ allow_any_name = $true; enforce_hostnames = $false; allow_ip_sans = $true; key_type = 'ec'; key_bits = 256; max_ttl = '43800h' } -Token $root
        New-ListenerCertificate -Token $root -Ip $ListenIp

        Write-Step 'Creating the admin token and the cluster token'
        $admin = (Invoke-Bao POST 'auth/token/create' @{ policies = @('unseal-host-admin'); no_parent = $true; period = '87600h'; display_name = 'unseal-host-admin' } -Token $root).auth.client_token
        $cluster = New-ClusterToken -Token $root

        Write-Step 'Taking the first backup'
        $backup = Save-Backup -Token $root -Dir $BackupDir

        Write-Step "Opening port $Port to the cluster"
        Write-Config -Ip $ListenIp -WithClusterListener
        Restart-Server
        Unlock-WithKeys $keys[0..1]
        Add-FirewallRule

        $null = Invoke-Bao POST 'auth/token/revoke-self' -Token $root   # no root token outlives the install
        $root = $null
    } catch {
        Write-Host ''
        Write-Host "Setup stopped: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Nothing depends on this OpenBao yet. Run '.\openbao-unseal-host.ps1 -Action Remove', then install again." -ForegroundColor Red
        throw
    }

    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Yellow
    Write-Host ' Shown once and stored nowhere. Store them now.' -ForegroundColor Yellow
    Write-Host ('=' * 78) -ForegroundColor Yellow
    Write-Host ''
    Write-Host " Unseal keys: any 2 of the 3 unseal this PC's OpenBao after it restarts."
    for ($i = 0; $i -lt $keys.Count; $i++) { Write-Host ('   {0}: {1}' -f ($i + 1), $keys[$i]) -ForegroundColor Green }
    Write-Host ''
    Write-Host ' Admin token: for -Action NewClusterToken, RenewCertificate and Backup.'
    Write-Host "   $admin" -ForegroundColor Green
    Write-Host ''
    Write-Host ' Keep the keys apart (a password manager, paper), never on the cluster, a NAS, a shared'
    Write-Host " drive or in a chat. A backup and 2 keys rebuild this PC; without both, the cluster's"
    Write-Host ' OpenBao data is lost.'
    Write-Host ''
    Show-ClusterToken -Token $cluster
    $keys = $null; $admin = $null; $cluster = $null
    Wait-ForOperator 'the keys and the admin token are stored and the cluster token is in the cluster'
    Show-Summary -Ip $ListenIp -Backup $backup
}

function Restore-UnsealHost {
    Assert-Admin
    Assert-ListenIp
    Assert-ClusterSubnet
    if (-not $BackupFile -or -not (Test-Path $BackupFile)) { throw '-BackupFile is required: a backup taken by this script.' }
    Assert-NotInstalled
    Install-Binary
    New-StateDirectories
    Write-Config -Ip $ListenIp
    Register-ServerTask
    Restart-Server

    Write-Step 'Restoring the backup into a fresh OpenBao'
    $init = Invoke-Bao PUT 'sys/init' @{ secret_shares = 1; secret_threshold = 1 }
    Unlock-WithKeys @($init.keys_base64[0])
    Invoke-WebRequest -UseBasicParsing -Method Post -Uri "$LocalAddr/v1/sys/storage/raft/snapshot-force" `
        -Headers @{ 'X-Vault-Token' = $init.root_token } -InFile $BackupFile -ContentType 'application/octet-stream' | Out-Null
    $init = $null
    # OpenBao seals itself once the backup is applied; it reads the backup's unseal settings on restart.
    $deadline = (Get-Date).AddSeconds(60)
    do { Start-Sleep -Milliseconds 500; $status = Get-SealStatus } until (($status -and $status.sealed) -or (Get-Date) -gt $deadline)
    Start-Sleep -Seconds 2
    Restart-Server
    $status = Get-SealStatus
    if (-not $status -or ($status.n -eq 1 -and $status.t -eq 1)) {
        throw "The backup was not applied. Run '-Action Remove', then '-Action Restore' again."
    }

    Write-Host "It is now the backed-up OpenBao: unseal it with 2 of the ORIGINAL unseal keys." -ForegroundColor Yellow
    Unlock-Interactive
    Write-Host 'Now the ORIGINAL admin token, to issue the listener certificate for this PC.' -ForegroundColor Yellow
    $token = Use-AdminToken
    New-ListenerCertificate -Token $token -Ip $ListenIp
    $token = $null
    Write-Config -Ip $ListenIp -WithClusterListener
    Restart-Server
    Unlock-Interactive
    Add-FirewallRule
    Show-Summary -Ip $ListenIp
    Write-Host ' The CA is the one in the backup, so the cluster needs no change unless the address did.'
}

function Update-ClusterToken {
    Assert-Admin
    $token = Use-AdminToken
    $previous = $null
    if (Test-Path $AccessorFile) { $previous = ([IO.File]::ReadAllText($AccessorFile)).Trim() }
    $cluster = New-ClusterToken -Token $token
    if ($previous) {
        try {
            $null = Invoke-Bao POST 'auth/token/revoke-accessor' @{ accessor = $previous } -Token $token
            Write-Host 'The previous cluster token is revoked. Members already running keep serving; a member that' -ForegroundColor Yellow
            Write-Host 'starts before the cluster holds the new token stays sealed.' -ForegroundColor Yellow
        } catch {
            Write-Warning "The previous cluster token was not revoked: $($_.Exception.Message)"
        }
    }
    $token = $null
    Write-Host ''
    Show-ClusterToken -Token $cluster -Replace
    Write-Host ' Then restart the members one at a time so each reads it.'
    $cluster = $null
    Wait-ForOperator 'the new cluster token is in the cluster'
}

function Update-Certificate {
    Assert-Admin
    Assert-ListenIp
    $token = Use-AdminToken
    New-ListenerCertificate -Token $token -Ip $ListenIp
    $token = $null
    Write-Config -Ip $ListenIp -WithClusterListener
    Write-Step 'Restarting OpenBao with the new certificate'
    Restart-Server
    Unlock-Interactive
    Show-Summary -Ip $ListenIp
}

function Backup-UnsealHost {
    Assert-Admin
    $token = Use-AdminToken
    $file = Save-Backup -Token $token -Dir $BackupDir
    $token = $null
    Write-Host "Backup written: $file" -ForegroundColor Green
    Write-Host 'Copy it off this PC (a USB stick, say), kept apart from the unseal keys.'
}

function Show-Status {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) { Write-Host 'No unseal host on this PC.'; return }
    $status = Get-SealStatus
    $state = 'not running'
    if ($status -and -not $status.initialized) { $state = 'running, not set up' }
    elseif ($status -and $status.sealed) { $state = "SEALED: run '-Action Unseal'" }
    elseif ($status) { $state = 'unsealed: the cluster can unseal' }
    Write-Host " OpenBao $Version, task '$TaskName': $($task.State); $state"
    $crt = Join-Path $TlsDir 'server.crt'
    if (Test-Path $crt) {
        Write-Host "   certificate valid until:  $((Get-CertificateExpiry $crt).ToString('yyyy-MM-dd'))"
        Write-Host "   CA SHA-256 fingerprint:   $(Get-Fingerprint (Join-Path $TlsDir 'ca.pem'))"
    }
    $rule = Get-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue
    if ($rule) {
        $from = ($rule | Get-NetFirewallAddressFilter).RemoteAddress -join ', '
        Write-Host "   port ${Port}:                open to $from"
    } else {
        Write-Host "   port ${Port}:                no firewall rule: the cluster cannot reach this PC" -ForegroundColor Yellow
    }
    $off = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
    if ($off.Count -gt 0) { Write-Host "   Windows Firewall is OFF for: $($off -join ', ')" -ForegroundColor Yellow }
    $backups = @(Get-ChildItem -Path (Join-Path $RootDir 'backup') -Filter '*.snap' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime)
    if ($backups.Count -gt 0) { Write-Host "   newest backup here:       $($backups[-1].FullName)" }
}

function Remove-UnsealHost {
    Assert-Admin
    Write-Warning "This deletes this PC's OpenBao, its unseal key and its backups in $RootDir."
    Write-Warning "If the cluster already uses it, the cluster's OpenBao can then only be unsealed again from a backup kept elsewhere."
    $answer = Read-Host 'Type REMOVE to delete it'
    if ($answer -cne 'REMOVE') { Write-Host 'Nothing removed.'; return }
    Stop-Server
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Get-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Remove-Item -Recurse -Force -Path $RootDir -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force -Path $InstallDir -ErrorAction SilentlyContinue
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    [Environment]::SetEnvironmentVariable('Path', (($machinePath -split ';' | Where-Object { $_ -and $_ -ne $InstallDir }) -join ';'), 'Machine')
    [Environment]::SetEnvironmentVariable('BAO_ADDR', $null, 'Machine')
    Write-Host 'Removed.'
}

# Dot-sourcing the script loads its functions without running an action.
if ($MyInvocation.InvocationName -ne '.') {
    switch ($Action) {
        'Install'          { Install-UnsealHost }
        'Unseal'           { Unlock-Interactive }
        'Status'           { Show-Status }
        'NewClusterToken'  { Update-ClusterToken }
        'RenewCertificate' { Update-Certificate }
        'Backup'           { Backup-UnsealHost }
        'Restore'          { Restore-UnsealHost }
        'Remove'           { Remove-UnsealHost }
    }
}
