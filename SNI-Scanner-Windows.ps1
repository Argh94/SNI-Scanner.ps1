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

Write-Host "PowerShell $($PSVersionTable.PSVersion) detected." -ForegroundColor Green

# ===================== Read Targets =====================
if (-not (Test-Path $File)) {
    Write-Host "Creating sample targets.txt ..." -ForegroundColor Yellow
    @"
# Put your domains or IPs here (one per line)
cloudflare.com
google.com
1.1.1.1
chess.com
"@ | Out-File -FilePath $File -Encoding UTF8
    Write-Host "targets.txt created. Please edit it with your list." -ForegroundColor Yellow
    Start-Sleep 3
    exit
}

$rawTargets = Get-Content $File
Write-Host "`nTargets loaded:" -ForegroundColor Yellow
$rawTargets | ForEach-Object { Write-Host "  $_" }

$targets = $rawTargets | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object { $_.Trim() }

$PortList = $Ports -split ',' | ForEach-Object { $_.Trim() }
if (Test-Path $Log) { Clear-Content $Log -Force }

# ===================== Functions =====================
function Get-PublicIP {
    param([string]$Manual = "")
    if ($Manual) { return $Manual }
    Write-Host "`nDetecting your public IP..." -ForegroundColor Cyan
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
        $wait = $connect.AsyncWaitHandle.WaitOne($TimeoutSec * 1000, $false)
        if ($wait) { $tcp.EndConnect($connect) | Out-Null }
        $tcp.Close()
        return $true
    } catch { return $false }
}

# ===================== Main Scan =====================
$PublicIP = if ($IPCheck) { Get-PublicIP -Manual $ManualIP }

Write-Host "`nStarting scan of $($targets.Count) targets..." -ForegroundColor Yellow

foreach ($target in $targets) {
    $display = $target
    $ips = @()

    try {
        if ($target -match '^\d{1,3}(\.\d{1,3}){3}$') {
            # IP وارد شده
            $ips = @($target)
            try {
                $ptr = [System.Net.Dns]::GetHostEntry($target).HostName
                if ($ptr -and $ptr -ne $target) { $display = "$target ($ptr)" }
            } catch {}
        } 
        else {
            # دامنه وارد شده
            $ips = [System.Net.Dns]::GetHostAddresses($target) | Select-Object -ExpandProperty IPAddressToString
        }

        if (-not $ips) { throw "Could not resolve" }
    }
    catch {
        $msg = "[ERROR] $target (Could not resolve)"
        Write-Host $msg -ForegroundColor Red
        $msg | Out-File $Log -Append -Encoding UTF8
        continue
    }

    foreach ($ip in $ips) {
        if ($ip -like "10.*") {
            $msg = "[FILTERED] $display -> $ip (Blocked/Internal IP)"
            Write-Host $msg -ForegroundColor Yellow
            $msg | Out-File $Log -Append -Encoding UTF8
            continue
        }

        $line = "$display -> $ip ->"
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
                $line += " ${port}✔"
                $openCount++
            } else {
                $line += " ${port}✖"
            }
        }

        if ($openCount -gt 0) {
            $final = "[OK] $line"
            Write-Host $final -ForegroundColor Green
        } else {
            $final = "[FAIL] $line"
            Write-Host $final -ForegroundColor Red
        }
        $final | Out-File $Log -Append -Encoding UTF8
    }
}

# ===================== Final Summary =====================
$logContent = Get-Content $Log
$OK_COUNT = ($logContent | Where-Object { $_ -match '^\[OK\]' }).Count
$FAIL_COUNT = ($logContent | Where-Object { $_ -match '^\[FAIL\]' }).Count
$ERROR_COUNT = ($logContent | Where-Object { $_ -match '^\[ERROR\]' }).Count
$FILTERED_COUNT = ($logContent | Where-Object { $_ -match '^\[FILTERED\]' }).Count

@"

---------------------------------------------------
===================================================
                   FINAL SUMMARY                   
===================================================

=== OK (at least one open port) [$OK_COUNT] ===
$($logContent | Where-Object { $_ -match '^\[OK\]' } | Out-String)

=== FAIL (all ports closed) [$FAIL_COUNT] ===
$($logContent | Where-Object { $_ -match '^\[FAIL\]' } | Out-String)

=== RESOLVE FAILED [$ERROR_COUNT] ===
$($logContent | Where-Object { $_ -match '^\[ERROR\]' } | Out-String)

=== FILTERED [$FILTERED_COUNT] ===
$($logContent | Where-Object { $_ -match '^\[FILTERED\]' } | Out-String)

---------------------------------------------------
Scan fully completed at $(Get-Date)
"@ | Out-File $Log -Append -Encoding UTF8

Write-Host "`nFull scan activity and summary saved to: $Log" -ForegroundColor Green
Write-Host "Done!" -ForegroundColor Cyan
