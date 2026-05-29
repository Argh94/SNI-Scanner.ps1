# =========================================
#   SNI Scanner - Windows (نسخه نهایی)
# =========================================

param(
    [string]$File = "targets.txt",
    [string]$Ports = "443,2053,2083,2087,2096,8443",
    [int]$Timeout = 5,
    [int]$Retries = 3,
    [string]$Log = "scan_log.txt",
    [switch]$IPCheck,
    [string]$ManualIP = ""
)

Clear-Host
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "         SNI Scanner - Windows           " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "Error: PowerShell 7 or higher is required." -ForegroundColor Red
    exit 1
}

Write-Host "PowerShell $($PSVersionTable.PSVersion) detected." -ForegroundColor Green

if (-not (Test-Path $File)) {
    Write-Host "Creating sample targets.txt ..." -ForegroundColor Yellow
    @"
# Put your domains or IPs here (one per line)
example.com
cloudflare.com
1.1.1.1
"@ | Out-File -FilePath $File -Encoding UTF8
    Write-Host "targets.txt created. Please edit it with your list." -ForegroundColor Yellow
    Start-Sleep 3
    exit
}

$Concurrency = 20
$PortList = $Ports -split ',' | ForEach-Object { $_.Trim() }

if (Test-Path $Log) { Clear-Content $Log -Force }

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp | $Message" | Out-File -FilePath $Log -Append -Encoding UTF8
}

function Get-PublicIP {
    param([string]$Manual = "")
    if ($Manual) { return $Manual }
    Write-Host "Detecting your public IP..." -ForegroundColor Cyan
    $apis = @("http://chabokan.net/ip/", "https://api.ipify.org?format=json")
    foreach ($api in $apis) {
        try {
            $r = Invoke-RestMethod -Uri $api -TimeoutSec 10
            $ip = if ($r.ip) { $r.ip } else { $r }
            if ($ip) {
                Write-Host "[INFO] Auto Detected IP: $ip" -ForegroundColor Green
                return $ip
            }
        } catch {}
    }
    return $null
}

function Check-Port {
    param($IP, $Port, $TimeoutSec)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $connect = $tcp.BeginConnect($IP, $Port, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne($TimeoutSec*1000, $false)
        if ($wait) { $tcp.EndConnect($connect) | Out-Null }
        $tcp.Close()
        return $true
    } catch { return $false }
}

function Check-RealIP {
    param($Domain, $IP, $PublicIP)
    try {
        $res = Invoke-WebRequest -Uri "https://$Domain/cdn-cgi/trace" -Headers @{"Host"=$Domain} -TimeoutSec 10 -SkipCertificateCheck -UseBasicParsing
        $detected = ($res.Content -split "`n" | Where-Object {$_ -like "ip=*"} | Select-Object -First 1) -replace "ip=",""
        if ($detected -eq $PublicIP) { " IP✔" } else { " IP✖($detected)" }
    } catch { " IP✖" }
}

# ===================== Start =====================
$PublicIP = if ($IPCheck) { Get-PublicIP -Manual $ManualIP }

$targets = Get-Content $File | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object { $_.Trim() }

Write-Host "Starting scan of $($targets.Count) targets..." -ForegroundColor Yellow
Write-Log "Scan started | Targets: $File | Ports: $Ports | Timeout: ${Timeout}s | Retries: $Retries"

$allResults = @()

$targets | ForEach-Object -Parallel {
    $target = $_
    $PortList = $using:PortList
    $Timeout = $using:Timeout
    $Retries = $using:Retries
    $PublicIP = $using:PublicIP
    $IPCheck = $using:IPCheck

    try {
        $display = $target
        $ips = @()

        if ($target -match '^\d+\.\d+\.\d+\.\d+$') {
            $ips = @($target)
            try {
                $ptr = Resolve-DnsName $target -Type PTR -ErrorAction SilentlyContinue
                if ($ptr) { $display = "$target ($($ptr.NameHost))" }
            } catch {}
        } else {
            $ips = (Resolve-DnsName $target -Type A -ErrorAction SilentlyContinue).IPAddress
        }

        if (-not $ips) {
            "[ERROR] $target (Could not resolve)"
            return
        }

        foreach ($ip in $ips) {
            if ($ip -like "10.*") {
                "[FILTERED] $display -> $ip (Blocked/Internal IP)"
                continue
            }

            $line = "$display -> $ip ->"
            $openCount = 0

            foreach ($port in $PortList) {
                $isOpen = $false
                for ($i=1; $i -le $Retries; $i++) {
                    if (Check-Port -IP $ip -Port $port -TimeoutSec $Timeout) {
                        $isOpen = $true
                        break
                    }
                }
                if ($isOpen) {
                    $line += " ${port}✔"
                    $openCount++
                } else {
                    $line += " ${port}✖"
                }
            }

            if ($openCount -gt 0) {
                $ipCheckResult = if ($IPCheck -and $PublicIP) { Check-RealIP -Domain $target -IP $ip -PublicIP $PublicIP } else { "" }
                "[OK] $line$ipCheckResult"
            } else {
                "[FAIL] $line"
            }
        }
    } catch {
        "[ERROR] $target"
    }
} -ThrottleLimit $Concurrency | ForEach-Object {
    $allResults += $_
    $_ | Out-File $Log -Append -Encoding UTF8
    Write-Host $_
}

# ===================== Final Summary =====================
$OK_COUNT = ($allResults | Where-Object { $_ -match '^\[OK\]' }).Count
$FAIL_COUNT = ($allResults | Where-Object { $_ -match '^\[FAIL\]' }).Count
$FILTERED_COUNT = ($allResults | Where-Object { $_ -match '^\[FILTERED\]' }).Count
$ERROR_COUNT = ($allResults | Where-Object { $_ -match '^\[ERROR\]' }).Count

@"

---------------------------------------------------
===================================================
                   FINAL SUMMARY                   
===================================================

=== OK (at least one open port) [$OK_COUNT] ===
$($allResults | Where-Object { $_ -match '^\[OK\]' } | Out-String)

=== FAIL (all ports closed) [$FAIL_COUNT] ===
$($allResults | Where-Object { $_ -match '^\[FAIL\]' } | Out-String)

=== RESOLVE FAILED [$ERROR_COUNT] ===
$($allResults | Where-Object { $_ -match '^\[ERROR\]' } | Out-String)

=== FILTERED [$FILTERED_COUNT] ===
$($allResults | Where-Object { $_ -match '^\[FILTERED\]' } | Out-String)

---------------------------------------------------
Scan fully completed at $(Get-Date)
"@ | Out-File $Log -Append -Encoding UTF8

Write-Host "`nFull scan activity and summary saved to: $Log" -ForegroundColor Green
Write-Host "Done!" -ForegroundColor Cyan
