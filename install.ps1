# install.ps1 — Install tun2proxy module via adb (Windows PowerShell)
param(
    [string]$Serial = "",
    [string]$ZipFile = ""
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($ZipFile -eq "") {
    $ZipFile = Join-Path (Split-Path -Parent $scriptDir) "tun2proxy-for-KernelSU-v1.0.0.zip"
}

if (-not (Test-Path $ZipFile)) {
    Write-Host "ERROR: ZIP not found: $ZipFile" -ForegroundColor Red
    Write-Host "Run .\pack.ps1 first to create the package."
    exit 1
}

Write-Host "=== Tun2Proxy for KernelSU — adb Install ===" -ForegroundColor Cyan

# Check adb
$adb = Get-Command adb -ErrorAction SilentlyContinue
if (-not $adb) {
    # Try common locations
    if (Test-Path "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe") {
        $adbExe = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
    } elseif (Test-Path "C:\adb\adb.exe") {
        $adbExe = "C:\adb\adb.exe"
    } else {
        Write-Host "ERROR: adb not found in PATH or common locations" -ForegroundColor Red
        exit 1
    }
} else {
    $adbExe = "adb"
}

function adb { & $adbExe @args }
function adbSu { adb shell "su -c `"$args`"" }

$serialArg = if ($Serial) { @("-s", $Serial) } else { @() }

# Check device
Write-Host "[1/5] Checking device..."
$devices = adb devices 2>&1 | Select-String "device$"
if ($devices.Count -eq 0) {
    Write-Host "ERROR: No device connected" -ForegroundColor Red
    exit 1
}
Write-Host "  Device(s): $devices"

# Check root
Write-Host "[2/5] Checking root..."
$uid = adb shell "su -c 'id -u'" 2>&1
Write-Host "  uid=$($uid.Trim())"

# Push zip
Write-Host "[3/5] Pushing ZIP to device..."
adb push $serialArg $ZipFile /data/local/tmp/tun2proxy-module.zip

# Install
Write-Host "[4/5] Installing module..."
adb shell "su -c 'rm -rf /data/adb/modules/tun2proxy; mkdir -p /data/adb/modules/tun2proxy; unzip -o /data/local/tmp/tun2proxy-module.zip -d /data/adb/modules/tun2proxy'" 2>&1

# Run customize.sh
Write-Host "[5/5] Running customize.sh..."
adb shell "su -c 'chmod +x /data/adb/modules/tun2proxy/*.sh /data/adb/modules/tun2proxy/system/bin/*; sh /data/adb/modules/tun2proxy/customize.sh'" 2>&1

# Cleanup
adb shell "su -c 'rm -f /data/local/tmp/tun2proxy-module.zip'" 2>&1

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Module installed to /data/adb/modules/tun2proxy" -ForegroundColor Green
Write-Host ""
Write-Host "  Reboot to start the service automatically."
Write-Host "  Or start now: adb shell su -c 'sh /data/adb/modules/tun2proxy/service.sh'"
Write-Host ""
Write-Host "  Web UI: http://<phone-ip>:8080"
Write-Host "============================================" -ForegroundColor Green
