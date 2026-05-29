# =========================================
#   SNI Scanner - Windows 
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
    Write-Host "PowerShell 7 or higher is required." -ForegroundColor Red
    Write-Host "Trying to install PowerShell 7 automatically..." -ForegroundColor Yellow
    
    try {
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            winget install --id Microsoft.PowerShell --silent --accept-source-agreements --accept-package-agreements
        } else {
            Write-Host "Downloading PowerShell 7 installer..." -ForegroundColor Yellow
            $url = "https://github.com/PowerShell/PowerShell/releases/latest/download/PowerShell-7.5.0-win-x64.msi"
            Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\PS7.msi"
            Start-Process msiexec.exe -ArgumentList "/i `"$env:TEMP\PS7.msi`" /quiet /qn ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ADD_PATH=1" -Wait
        }
        Write-Host "PowerShell 7 installed. Please close this window and run the script again using 'pwsh'." -ForegroundColor Green
        Start-Sleep 6
        exit 0
    } catch {
        Write-Host "Auto-install failed. Please install PowerShell 7 manually from Microsoft website." -ForegroundColor Red
        exit 1
    }
}

Write-Host "PowerShell $($PSVersionTable.PSVersion) detected." -ForegroundColor Green

# ===================== Create targets.txt if not exists =====================
if (-not (Test-Path $File)) {
    Write-Host "Creating sample targets.txt ..." -ForegroundColor Yellow
    @"
# Put your domains or IPs here (one per line)
example.com
cloudflare.com
your-domain.com
"@ | Out-File -FilePath $File -Encoding UTF8
    Write-Host "targets.txt created. Please edit it with your list and run the script again." -ForegroundColor Yellow
    Start-Sleep 4
    exit
}

# ===================== Functions =====================
$Concurrency = 30

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp | $Message" | Out-File -FilePath $Log -Append -Encoding UTF8
    Write-Host "[$timestamp] $Message"
}

function Get-PublicIP {
    param([string]$Manual = "")
    if ($Manual) { 
        Write-Host "[INFO] Using Manual IP: $Manual" -ForegroundColor Cyan
        return $Manual 
    }
    Write-Host "Detecting your public IP..." -ForegroundColor Cyan
    $apis = @("http://chabokan.net/ip/", "https://api.ipify.org?format=json", "https://ipinfo.io/json")
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
    Write-Host "[WARNING] Could not detect public IP" -ForegroundColor Yellow
    return $null
}

function Check-Port {
    param($IP, $Port, $TimeoutSec)
    $tcp = New-Object System.Net.Sockets.TcpClient
    $connect = $tcp.BeginConnect($IP, $Port, $null, $null)
    $wait = $connect.AsyncWaitHandle.WaitOne($TimeoutSec * 1000, $false)
    if ($wait) {
        try { $tcp.EndConnect($connect) | Out-Null } catch {}
        $tcp.Close()
        return $true
    } else {
        $tcp.Close()
        return $false
    }
}

function Check-RealIP {
    param($Domain, $IP, $PublicIP)
    try {
        $result = Invoke-WebRequest -Uri "https://$Domain/cdn-cgi/trace" `
            -Headers @{"Host"=$Domain} -TimeoutSec 12 -SkipCertificateCheck -UseBasicParsing
        $detected = ($result.Content -split "`n" | Where-Object { $_ -like "ip=*" } | Select-Object -First 1) -replace "ip=", ""
        if ($detected -eq $PublicIP) { return " IP✔" } else { return " IP✖($detected)" }
    } catch { return " IP✖" }
}

# ===================== Start Scanning =====================
if (Test-Path $Log) { Clear-Content $Log -Force }

$PortList = $Ports -split ',' | ForEach-Object { $_.Trim() }

$PublicIP = $null
if ($IPCheck) {
    $PublicIP = Get-PublicIP -Manual $ManualIP
}

$targets = Get-Content $File | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object { $_.Trim() }

Write-Host "Starting scan of $($targets.Count) targets..." -ForegroundColor Yellow
Write-Log "Scan started | Targets: $File | Ports: $Ports | Timeout: ${Timeout}s | Retries: $Retries"

$targets | ForEach-Object -Parallel {
    $target = $_
    $PortList = $using:PortList
    $Timeout = $using:Timeout
    $Retries = $using:Retries
    $PublicIP = $using:PublicIP
    $IPCheck = $using:IPCheck
    $Log = $using:Log

    try {
        if ($target -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $ips = @($target)
        } else {
            $ips = (Resolve-DnsName -Name $target -Type A -ErrorAction SilentlyContinue).IPAddress
        }

        if (-not $ips) {
            "[ERROR] $target (Could not resolve)" | Out-File $Log -Append -Encoding UTF8
            return
        }

        foreach ($ip in $ips) {
            if ($ip -like "10.*") {
                "[FILTERED] $target -> $ip (Blocked/Internal IP)" | Out-File $Log -Append -Encoding UTF8
                continue
            }

            $openCount = 0
            $resultStr = "$target -> $ip ->"

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

            if ($openCount -gt 0) {
                $ipResult = if ($IPCheck -and $PublicIP) { Check-RealIP -Domain $target -IP $ip -PublicIP $PublicIP } else { "" }
                "[OK] $resultStr$ipResult" | Out-File $Log -Append -Encoding UTF8
            } else {
                "[FAIL] $resultStr" | Out-File $Log -Append -Encoding UTF8
            }
        }
    } catch {
        "[ERROR] $target" | Out-File $Log -Append -Encoding UTF8
    }
} -ThrottleLimit $Concurrency

# ===================== Final Summary (مثل لینوکس) =====================
$OK_COUNT = (Select-String -Path $Log -Pattern "^\[OK\]" -AllMatches).Count
$FAIL_COUNT = (Select-String -Path $Log -Pattern "^\[FAIL\]" -AllMatches).Count
$FILTERED_COUNT = (Select-String -Path $Log -Pattern "^\[FILTERED\]" -AllMatches).Count
$ERROR_COUNT = (Select-String -Path $Log -Pattern "^\[ERROR\]" -AllMatches).Count

@"

---------------------------------------------------
===================================================
                   FINAL SUMMARY                   
===================================================

=== OK (at least one open port) [$OK_COUNT] ===
$((Get-Content $Log | Where-Object { $_ -match '^\[OK\]' }) -join "`n")

=== FAIL (all ports closed) [$FAIL_COUNT] ===
$((Get-Content $Log | Where-Object { $_ -match '^\[FAIL\]' }) -join "`n")

=== RESOLVE FAILED [$ERROR_COUNT] ===
$((Get-Content $Log | Where-Object { $_ -match '^\[ERROR\]' }) -join "`n")

=== FILTERED (Blocked/IP 10.x) [$FILTERED_COUNT] ===
$((Get-Content $Log | Where-Object { $_ -match '^\[FILTERED\]' }) -join "`n")

---------------------------------------------------
Scan fully completed at $(Get-Date)
"@ | Out-File $Log -Append -Encoding UTF8

Write-Host "`nFull scan activity and summary saved to: $Log" -ForegroundColor Green
Write-Host "Done!" -ForegroundColor Cyan
