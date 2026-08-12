# download.ps1 — Download latest tun2proxy prebuilt binary from GitHub Releases
# Run this script before pack.ps1 to include the tun2proxy binary in the module zip.
param(
    [string]$Version = "latest",
    [string]$Target = "aarch64-unknown-linux-musl"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$binDir = "$scriptDir\system\bin"
$outputBin = "$binDir\tun2proxy"

Write-Host "=== Downloading tun2proxy for Android (ARM64) ==="

# Create bin dir
if (-not (Test-Path $binDir)) {
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
}

# Get release info
$apiUrl = if ($Version -eq "latest") {
    "https://api.github.com/repos/tun2proxy/tun2proxy/releases/latest"
} else {
    "https://api.github.com/repos/tun2proxy/tun2proxy/releases/tags/$Version"
}

Write-Host "[1/3] Fetching release info..."
try {
    $release = Invoke-RestMethod -Uri $apiUrl -TimeoutSec 30
    Write-Host "  Release: $($release.tag_name) ($($release.published_at))"
} catch {
    Write-Host "  ERROR: Cannot reach GitHub API: $_"
    Write-Host ""
    Write-Host "  Manual download steps:"
    Write-Host "    1. Open https://github.com/tun2proxy/tun2proxy/releases"
    Write-Host "    2. Download the aarch64 Linux binary (musl or gnu)"
    Write-Host "    3. Extract and rename to: $outputBin"
    Write-Host ""
    exit 1
}

# Find the right asset
# Common patterns for Rust release assets on GitHub
$patterns = @(
    "*aarch64-unknown-linux-musl*",
    "*aarch64-unknown-linux-gnu*",
    "*aarch64-linux-android*",
    "*arm64*linux*",
    "*linux*aarch64*",
    "*linux*arm64*"
)

$asset = $null
foreach ($pattern in $patterns) {
    $asset = $release.assets | Where-Object { $_.name -like $pattern } | Select-Object -First 1
    if ($asset) {
        Write-Host "  Found asset: $($asset.name) ($([math]::Round($asset.size/1MB,1)) MB)"
        break
    }
}

if (-not $asset) {
    Write-Host "  ERROR: No matching asset found."
    Write-Host "  Available assets:"
    $release.assets | ForEach-Object { Write-Host "    - $($_.name)" }
    Write-Host ""
    Write-Host "  Please download manually from: $($release.html_url)"
    exit 1
}

# Download
Write-Host "[2/3] Downloading $($asset.name)..."
$tmpDir = "$env:TEMP\tun2proxy-dl-$([System.Guid]::NewGuid().ToString().Substring(0,8))"
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
$dlPath = Join-Path $tmpDir $asset.name

try {
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $dlPath -TimeoutSec 120
} catch {
    Write-Host "  ERROR: Download failed: $_"
    Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
    exit 1
}

# Extract
Write-Host "[3/3] Extracting..."
$extractDir = Join-Path $tmpDir "extracted"
New-Item -ItemType Directory -Path $extractDir -Force | Out-Null

if ($dlPath -like "*.tar.gz" -or $dlPath -like "*.tgz") {
    # Use tar (Windows 10+ has tar built-in)
    tar -xzf $dlPath -C $extractDir 2>$null
    if ($LASTEXITCODE -ne 0) {
        # Fallback: try 7z
        & 7z x $dlPath -o"$extractDir" -y 2>$null
    }
} elseif ($dlPath -like "*.zip") {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($dlPath, $extractDir)
} elseif ($dlPath -like "*.gz") {
    tar -xzf $dlPath -C $extractDir
} else {
    # Assume it's a raw binary, just copy
    Copy-Item $dlPath $outputBin -Force
    Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
    Write-Host ""
    Write-Host "  Binary saved to: $outputBin"
    Write-Host "  Size: $([math]::Round((Get-Item $outputBin).Length/1MB,1)) MB"
    return
}

# Find the binary in the extracted directory
$found = Get-ChildItem -Path $extractDir -Recurse -File -Name "tun2proxy*" |
    Where-Object { $_ -notlike "*.dll" -and $_ -notlike "*.so" -and $_ -notlike "*.dylib" } |
    Select-Object -First 1

if (-not $found) {
    $found = Get-ChildItem -Path $extractDir -Recurse -File |
        Where-Object { $_.Name -like "tun2proxy*" -and $_.Length -gt 1000000 } |
        Select-Object -First 1 -ExpandProperty FullName
}

if ($found) {
    Copy-Item $found $outputBin -Force
    Write-Host "  Binary saved to: $outputBin"
    Write-Host "  Size: $([math]::Round((Get-Item $outputBin).Length/1MB,1)) MB"
} else {
    Write-Host "  WARNING: Could not find tun2proxy binary in archive."
    Write-Host "  Extracted files:"
    Get-ChildItem -Path $extractDir -Recurse -File | ForEach-Object { Write-Host "    $($_.Name)" } | Select-Object -First 20
}

# Cleanup
Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Done! Now run: .\pack.ps1"
