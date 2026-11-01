<#
LAN-client reachability of a routed/announced ingress endpoint, for Windows clients. Same check and
exit codes as probe/lan-ingress-reachability.sh (read its header for the full rationale).

Run it from the workstation an end user would actually use. A cluster NODE reaches its own
LoadBalancer IPs locally, so a run on a node cannot see the failure this probe exists for.

Env-driven (or parameters), no site addresses baked in:
  INGRESS_URL / -Url           (required) the external URL a LAN client should reach
  EXPECT_STATUS / -ExpectStatus (optional) an HTTP status to require; default: any HTTP response passes
  TIMEOUT / -TimeoutSec         (optional) seconds (default 8)
  FORCE_LAN_CLIENT=1 / -Force   (optional) skip the node guard

Exit 0 = reachable (PASS), 1 = a reachability FAILURE (reset/timeout/refused), 42 = INCONCLUSIVE.
Works on Windows PowerShell 5.1 and PowerShell 7.

  $env:INGRESS_URL = "https://app.example"; .\probe\lan-ingress-reachability.ps1
#>
param(
  [string]$Url = $env:INGRESS_URL,
  [string]$ExpectStatus = $env:EXPECT_STATUS,
  [int]$TimeoutSec = $(if ($env:TIMEOUT) { [int]$env:TIMEOUT } else { 8 }),
  [switch]$Force = ($env:FORCE_LAN_CLIENT -eq "1")
)

function Fail([string]$m) { Write-Host "FAIL: $m" -ForegroundColor Red; exit 1 }
function Inconclusive([string]$m) { Write-Host "INCONCLUSIVE: $m" -ForegroundColor Yellow; exit 42 }

if (-not $Url) { Inconclusive "set INGRESS_URL (or -Url) to the external endpoint a LAN client should reach" }

# Node guard: a Windows Kubernetes node runs kubelet (and usually kube-proxy) as services.
if (-not $Force -and (Get-Command Get-Service -ErrorAction SilentlyContinue)) {
  foreach ($svc in @("kubelet", "kube-proxy", "rke2")) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s -and $s.Status -eq "Running") {
      Inconclusive "this host looks like a cluster NODE (the $svc service is running): a node reaches its own LB IPs locally. Re-run from a separate LAN host (or pass -Force)."
    }
  }
}

$timeoutMsg = "connection TIMED OUT: the classic asymmetric-routing symptom (the SYN reaches the node but the reply bypasses the router, which then drops the flow). Replies must return through the router; platform/networking/vip-return.yaml does this for routed (BGP) VIPs."
$refusedMsg = "connection REFUSED or unreachable: nothing answers at the VIP from the LAN. Likely an unannounced MetalLB address or a VIP whose backend is down."
$resetMsg   = "connection RESET / closed mid-request or mid-TLS: same asymmetric-routing / unannounced-VIP class."

# TLS verification is off: a lab self-signed certificate is a separate concern; this tests L3/L4 reachability.
Write-Host "probing $Url as a LAN client (timeout ${TimeoutSec}s, TLS verification off)"
$code = $null
if ($PSVersionTable.PSVersion.Major -ge 6) {
  # PowerShell 7+: Invoke-WebRequest returns any HTTP status with -SkipHttpErrorCheck.
  try {
    $r = Invoke-WebRequest -Uri $Url -Method Get -SkipCertificateCheck -SkipHttpErrorCheck -MaximumRedirection 0 -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
    $code = [int]$r.StatusCode
  } catch {
    $e = $_.Exception
    $all = @(); $x = $e; while ($x) { $all += $x; $x = $x.InnerException }
    $text = ($all | ForEach-Object { "$($_.GetType().Name): $($_.Message)" }) -join " / "
    $sock = $all | Where-Object { $_ -is [System.Net.Sockets.SocketException] } | Select-Object -First 1
    if ($all | Where-Object { $_ -is [System.Threading.Tasks.TaskCanceledException] -or $_ -is [System.TimeoutException] }) { Fail "$timeoutMsg $text" }
    elseif ($sock -and "$($sock.SocketErrorCode)" -eq "TimedOut") { Fail "$timeoutMsg $text" }
    elseif ($sock -and "$($sock.SocketErrorCode)" -in @("ConnectionRefused", "HostUnreachable", "NetworkUnreachable")) { Fail "$refusedMsg $text" }
    elseif ($sock -and "$($sock.SocketErrorCode)" -in @("HostNotFound", "TryAgain", "NoData")) { Inconclusive "could not resolve the host in $Url (DNS), so reachability was not tested. $text" }
    elseif ($sock -and "$($sock.SocketErrorCode)" -eq "ConnectionReset") { Fail "$resetMsg $text" }
    elseif ($all | Where-Object { $_ -is [System.IO.IOException] -or $_ -is [System.Security.Authentication.AuthenticationException] }) { Fail "$resetMsg $text" }
    else { Fail "could not reach ${Url}: $text" }
  }
} else {
  # Windows PowerShell 5.1: HttpWebRequest with a compiled trust-all certificate policy.
  if (-not ("TrustAllCertsPolicy" -as [type])) {
    Add-Type -TypeDefinition @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
  public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
  }
  [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
  [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls
  try {
    $req = [System.Net.HttpWebRequest]::Create($Url)
    $req.Method = "GET"; $req.AllowAutoRedirect = $false
    $req.Timeout = $TimeoutSec * 1000; $req.ReadWriteTimeout = $TimeoutSec * 1000
    $resp = $req.GetResponse(); $code = [int]$resp.StatusCode; $resp.Close()
  } catch [System.Net.WebException] {
    $ex = $_.Exception
    if ($ex.Response) { $code = [int]$ex.Response.StatusCode; $ex.Response.Close() }   # an HTTP error status: the path works
    else {
      switch ("$($ex.Status)") {
        "Timeout"               { Fail "$timeoutMsg $($ex.Message)" }
        "ConnectFailure"        { Fail "$refusedMsg $($ex.Message)" }
        "NameResolutionFailure" { Inconclusive "could not resolve the host in $Url (DNS), so reachability was not tested. $($ex.Message)" }
        { $_ -in @("ReceiveFailure", "SecureChannelFailure", "ConnectionClosed", "KeepAliveFailure") } { Fail "$resetMsg $($ex.Message)" }
        default                 { Fail "could not reach $Url ($($ex.Status)): $($ex.Message)" }
      }
    }
  }
}

if ($ExpectStatus -and ("$code" -ne "$ExpectStatus")) {
  Fail "reachable, but HTTP status $code != expected $ExpectStatus (the LAN path is fine; this is an app/ingress-config concern)"
}
Write-Host "PASS: $Url is reachable from this LAN host (HTTP $code); the routed/announced ingress path works end to end." -ForegroundColor Green
exit 0
