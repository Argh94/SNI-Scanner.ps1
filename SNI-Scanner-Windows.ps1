# =========================================
#   SNI Scanner - Windows (نسخه نهایی)
# =========================================

param(
    [string]$File = "targets.txt",
    [string]$Ports = "443,2053,2083,2087,2096,8443",
    [int]$Timeout = 3,
    [int]$Retries = 2,
    [string]$Log = "scan_log.txt",
    [string]$CsvOutput = "scan_results.csv",
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

$PortList = $Ports -split ',' | ForEach-Object { $_.Trim() }

# ایجاد فایل نمونه در صورت نبودن
if (-not (Test-Path $File)) {
    Write-Host "Creating sample targets.txt ..." -ForegroundColor Yellow
    @"
# Put your domains or IPs here (one per line)
example.com
cloudflare.com
1.1.1.1
"@ | Out-File -FilePath $File -Encoding UTF8
    Write-Host "targets.txt created. Edit it and run again." -ForegroundColor Yellow
    Start-Sleep 3
    exit
}

if (Test-Path $Log) { Clear-Content $Log -Force }

function Write-Log {
    param([string]$Message)
    "$((Get-Date -Format "yyyy-MM-dd HH:mm:ss")) | $Message" | Out-File -FilePath $Log -Append -Encoding UTF8
}

function Check-Port {
    param($IP, $Port, $TimeoutSec)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $connect = $tcp.BeginConnect($IP, $Port, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne($TimeoutSec * 1000, $false)
        if ($wait) { $tcp.EndConnect($connect) | Out-Null }
        $tcp.Close()
        return $true
    } catch { return $false }
}

function Check-RealIP {
    param($Domain, $PublicIP)
    try {
        $result = Invoke-WebRequest -Uri "https://$Domain/cdn-cgi/trace" `
            -Headers @{"Host"=$Domain} -TimeoutSec 8 -SkipCertificateCheck -UseBasicParsing
        $detected = ($result.Content -split "`n" | Where-Object { $_ -like "ip=*" } | Select-Object -First 1) -replace "ip=", ""
        if ($detected -eq $PublicIP) { " IP✔" } else { " IP✖($detected)" }
    } catch { " IP✖" }
}

# ===================== Main Scan =====================
$PublicIP = $null
if ($IPCheck) {
    Write-Host "Detecting your public IP..." -ForegroundColor Cyan
    $apis = @("http://chabokan.net/ip/", "https://api.ipify.org?format=json")
    foreach ($api in $apis) {
        try {
            $r = Invoke-RestMethod -Uri $api -TimeoutSec 8 -UseBasicParsing
            $ip = if ($r.ip) { $r.ip } else { $r.ToString() }
            if ($ip) {
                Write-Host "[INFO] Public IP: $ip" -ForegroundColor Green
                $PublicIP = $ip
                break
            }
        } catch {}
    }
    if (-not $PublicIP) {
        Write-Host "[WARN] Could not detect public IP" -ForegroundColor Yellow
    }
}

$targets = Get-Content $File | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object { $_.Trim() }

Write-Host "Starting scan of $($targets.Count) targets..." -ForegroundColor Yellow
Write-Log "Scan started | Targets: $($targets.Count) | Ports: $Ports | Timeout: ${Timeout}s | Retries: $Retries"

$results = $targets | ForEach-Object -Parallel {
    $target = $_
    $PortList = $using:PortList
    $Timeout = $using:Timeout
    $Retries = $using:Retries
    $PublicIP = $using:PublicIP
    $IPCheck = $using:IPCheck

    try {
        $displayName = $target
        $ips = @()

        if ($target -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $ips = @($target)
        } else {
            $ips = (Resolve-DnsName -Name $target -Type A -ErrorAction SilentlyContinue).IPAddress
        }

        if (-not $ips) {
            "[ERROR] $target (Could not resolve)"
            return
        }

        foreach ($ip in $ips) {
            if ($ip -match '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|169\.254\.|::1)') {
                "[FILTERED] $displayName -> $ip (Private IP)"
                continue
            }

            $resultStr = "$displayName -> $ip ->"
            $openCount = 0

            foreach ($port in $PortList) {
                $isOpen = $false
                for ($i = 1; $i -le $Retries; $i++) {
                    if (Check-Port -IP $ip -Port $port -TimeoutSec $Timeout) {
                        $isOpen = $true
                        break
                    }
                }
                if ($isOpen) {
                    $resultStr += " ${port}✔"
                    $openCount++
                } else {
                    $resultStr += " ${port}✖"
                }
            }

            $ipResult = if ($IPCheck -and $PublicIP) { 
                Check-RealIP -Domain $target -PublicIP $PublicIP 
            } else { "" }

            if ($openCount -gt 0) {
                "[OK] $resultStr$ipResult"
            } else {
                "[FAIL] $resultStr"
            }
        }
    } 
    catch {
        "[ERROR] $target"
    }
} -ThrottleLimit 20

# نمایش نتایج روی صفحه + ذخیره در لاگ
$results | ForEach-Object {
    $_ | Out-File $Log -Append -Encoding UTF8
    Write-Host $_
}

# خروجی CSV
$results | ForEach-Object {
    if ($_ -match '^\[(.+?)\]\s+(.+?)\s+->\s+([\d\.]+)\s+->(.+)$') {
        [PSCustomObject]@{
            Status    = $matches[1]
            Target    = $matches[2].Trim()
            IP        = $matches[3]
            Ports     = $matches[4].Trim()
            Time      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
    }
} | Export-Csv -Path $CsvOutput -NoTypeInformation -Encoding UTF8

# ===================== Final Summary =====================
$OK_COUNT = ($results | Where-Object { $_ -match '^\[OK\]' }).Count
$FAIL_COUNT = ($results | Where-Object { $_ -match '^\[FAIL\]' }).Count
$FILTERED_COUNT = ($results | Where-Object { $_ -match '^\[FILTERED\]' }).Count
$ERROR_COUNT = ($results | Where-Object { $_ -match '^\[ERROR\]' }).Count

@"

---------------------------------------------------
===================================================
                   FINAL SUMMARY                   
===================================================

OK     : $OK_COUNT
FAIL   : $FAIL_COUNT
FILTERED: $FILTERED_COUNT
ERROR  : $ERROR_COUNT

Scan completed at $(Get-Date)
CSV Report saved to: $CsvOutput
"@ | Out-File $Log -Append -Encoding UTF8

Write-Host "`nScan completed successfully!" -ForegroundColor Green
Write-Host "Log file     : $Log" -ForegroundColor Cyan
Write-Host "CSV Report   : $CsvOutput" -ForegroundColor Cyan
Write-Host "Done!" -ForegroundColor Cyan
