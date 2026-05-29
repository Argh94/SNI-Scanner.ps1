# SNI Scanner for Windows

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

# ====================== Auto Setup ======================
function Install-Dependencies {
    Write-Host "Checking prerequisites..." -ForegroundColor Yellow

    # Check PowerShell Version
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Host "Error: PowerShell 7 or higher is required." -ForegroundColor Red
        Write-Host "Please install PowerShell 7 and run this script again." -ForegroundColor Yellow
        exit 1
    } else {
        Write-Host "PowerShell $($PSVersionTable.PSVersion) detected." -ForegroundColor Green
    }

    # Create targets.txt if it doesn't exist
    if (-not (Test-Path $File)) {
        Write-Host "Creating sample $File ..." -ForegroundColor Yellow
        @"
# Enter one domain or IP per line
example.com
sub.example.com
185.22.34.56
"@ | Out-File -FilePath $File -Encoding UTF8
        Write-Host "Sample $File created." -ForegroundColor Green
    }

    if (Test-Path $Log) { Clear-Content $Log -Force }
    
    Write-Host "All prerequisites are ready.`n" -ForegroundColor Green
}

# Run setup
Install-Dependencies

# ====================== Configuration ======================
$Concurrency = 25

# ====================== Helper Functions ======================
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp | $Message" | Out-File -FilePath $Log -Append -Encoding UTF8
    Write-Host "[$timestamp] $Message"
}

function Get-PublicIP {
    param([string]$Manual = "")
    
    if ($Manual) { 
        Write-Host "Using Manual IP: $Manual" -ForegroundColor Cyan
        return $Manual 
    }
    
    Write-Host "Detecting your public IP..." -ForegroundColor Cyan
    
    $apis = @(
        "http://chabokan.net/ip/",
        "https://api.ipify.org?format=json",
        "https://ipinfo.io/json"
    )

    foreach ($api in $apis) {
        try {
            $r = Invoke-WebRequest -Uri $api -TimeoutSec 10 -UseBasicParsing
            if ($api -like "*chabokan*") { 
                $ip = ($r.Content | ConvertFrom-Json).ip 
            }
            elseif ($api -like "*ipify*") { 
                $ip = ($r.Content | ConvertFrom-Json).ip 
            }
            else { 
                $ip = ($r.Content | ConvertFrom-Json).ip 
            }
            
            if ($ip) {
                Write-Host "Public IP detected: $ip" -ForegroundColor Green
                return $ip
            }
        } catch {}
    }
    Write-Host "Could not detect public IP." -ForegroundColor Yellow
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
            -Headers @{"Host" = $Domain} `
            -TimeoutSec 12 `
            -SkipCertificateCheck `
            -UseBasicParsing

        $detected = ($result.Content -split "`n" | Where-Object { $_ -like "ip=*" } | Select-Object -First 1) -replace "ip=", ""
        
        if ($detected -eq $PublicIP) {
            return " IP✔"
        } else {
            return " IP✖($detected)"
        }
    } catch {
        return " IP✖"
    }
}

# ====================== Start Scan ======================
$PortList = $Ports -split ',' | ForEach-Object { $_.Trim() }

$PublicIP = $null
if ($IPCheck) {
    $PublicIP = Get-PublicIP -Manual $ManualIP
}

$targets = Get-Content $File | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object { $_.Trim() }

Write-Host "Starting scan of $($targets.Count) targets on $($PortList.Count) ports..." -ForegroundColor Yellow
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
        # DNS Resolution
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
                "[FILTERED] $target -> $ip (Internal IP)" | Out-File $Log -Append -Encoding UTF8
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
                $ipResult = ""
                if ($IPCheck -and $PublicIP) {
                    $ipResult = Check-RealIP -Domain $target -IP $ip -PublicIP $PublicIP
                }
                "[OK] $resultStr$ipResult" | Out-File $Log -Append -Encoding UTF8
            } else {
                "[FAIL] $resultStr" | Out-File $Log -Append -Encoding UTF8
            }
        }
    } catch {
        "[ERROR] $target - $($_.Exception.Message)" | Out-File $Log -Append -Encoding UTF8
    }
} -ThrottleLimit $Concurrency

# ====================== Final Summary ======================
Write-Host "`nScan completed. Generating summary..." -ForegroundColor Yellow

$logContent = Get-Content $Log -Raw

$OKCount       = ([regex]::Matches($logContent, '\[OK\]')).Count
$FAILCount     = ([regex]::Matches($logContent, '\[FAIL\]')).Count
$ERRORCount    = ([regex]::Matches($logContent, '\[ERROR\]')).Count
$FILTEREDCount = ([regex]::Matches($logContent, '\[FILTERED\]')).Count

Write-Host "`n===================================================" -ForegroundColor Cyan
Write-Host "                   FINAL SUMMARY                    " -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan

if ($OKCount -gt 0) {
    Write-Host "`n=== OK [$OKCount] ===" -ForegroundColor Green
    Get-Content $Log | Where-Object { $_ -like "[OK]*" }
}

if ($FAILCount -gt 0) {
    Write-Host "`n=== FAIL [$FAILCount] ===" -ForegroundColor Red
    Get-Content $Log | Where-Object { $_ -like "[FAIL]*" }
}

if ($ERRORCount -gt 0) {
    Write-Host "`n=== RESOLVE FAILED [$ERRORCount] ===" -ForegroundColor Yellow
    Get-Content $Log | Where-Object { $_ -like "[ERROR]*" }
}

if ($FILTEREDCount -gt 0) {
    Write-Host "`n=== FILTERED [$FILTEREDCount] ===" -ForegroundColor Yellow
    Get-Content $Log | Where-Object { $_ -like "[FILTERED]*" }
}

Write-Host "`n===================================================" -ForegroundColor Cyan
Write-Host "Scan finished at $(Get-Date)" -ForegroundColor Cyan
Write-Host "Full results saved to: $Log" -ForegroundColor Cyan
