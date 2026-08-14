# build-tun2proxy.ps1 — Cross-compile the tun2proxy CLI for Android (aarch64)
#
# The official tun2proxy GitHub Releases do NOT ship a standalone Android CLI
# binary (only glibc Linux builds + libtun2proxy.so/.a), so we compile the
# `tun2proxy-bin` target from source against Android's bionic libc.
#
# Prerequisites:
#   * Rust 1.85+  (https://rustup.rs)
#   * Android NDK (windows-x86_64)  — install via Android Studio SDK Manager
#
# Usage:
#   .\build-tun2proxy.ps1                     # latest release tag
#   .\build-tun2proxy.ps1 -Ref v0.8.3         # specific tag/branch
#   .\build-tun2proxy.ps1 -Ndk C:\android-ndk # explicit NDK path
#
# (On a machine with WSL + Linux NDK, `bash build-tun2proxy.sh` works too.)
param(
    [string]$Ref = "",
    [string]$Api = "26",
    [string]$Ndk = ""
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$binDir = Join-Path $scriptDir "system\bin"
$output = Join-Path $binDir "tun2proxy"

function Info([string]$m) { Write-Host "==> $m" }
function Die([string]$m)  { Write-Host "ERROR: $m" -ForegroundColor Red; exit 1 }

# --- Locate the Android NDK (windows-x86_64) ---
$ndkPath = $Ndk
if (-not $ndkPath) { $ndkPath = $env:ANDROID_NDK_HOME }
if (-not $ndkPath) { $ndkPath = $env:ANDROID_NDK_ROOT }
if (-not $ndkPath) { $ndkPath = $env:ANDROID_NDK }
if (-not $ndkPath) {
    $sdk = $env:ANDROID_HOME
    if (-not $sdk) { $sdk = $env:ANDROID_SDK_ROOT }
    if (-not $sdk) { $sdk = Join-Path $env:LOCALAPPDATA "Android\Sdk" }
    $ndkBase = Join-Path $sdk "ndk"
    if (Test-Path $ndkBase) {
        $ndkPath = Get-ChildItem $ndkBase -Directory |
            Sort-Object Name -Descending |
            Select-Object -First 1 -ExpandProperty FullName
    }
}
if (-not $ndkPath -or -not (Test-Path (Join-Path $ndkPath "toolchains\llvm\prebuilt\windows-x86_64\bin"))) {
    Die "Android NDK not found. Install via Android Studio SDK Manager, or pass -Ndk C:\path\to\ndk"
}

# --- Toolchain ---
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { Die "Rust not found. Install: https://rustup.rs" }
if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) { Die "rustup not found" }
if (-not (Get-Command git -ErrorAction SilentlyContinue))   { Die "git not found" }

Info "NDK: $ndkPath"
Info "Adding aarch64-linux-android target..."
rustup target add aarch64-linux-android

if (-not (Get-Command cargo-ndk -ErrorAction SilentlyContinue)) {
    Info "Installing cargo-ndk (handles NDK linker/clang setup)..."
    cargo install cargo-ndk
}

# --- Fetch source into a temp dir (not committed to the repo) ---
$work = Join-Path $env:TEMP ("tun2proxy-build-" + [System.Guid]::NewGuid().ToString().Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null
Push-Location $work
try {
    if (-not $Ref) {
        Info "Resolving latest release tag..."
        try {
            $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/tun2proxy/tun2proxy/releases/latest" -TimeoutSec 20
            $Ref = $rel.tag_name
        } catch { $Ref = "main" }
    }
    Info "Building tun2proxy @ $Ref"

    $cloneArgs = @("clone", "--depth", "1")
    if ($Ref) { $cloneArgs += @("--branch", $Ref) }
    $cloneArgs += @("https://github.com/tun2proxy/tun2proxy.git", (Join-Path $work "src"))
    git @cloneArgs
    if ($LASTEXITCODE -ne 0) { throw "git clone failed (network?)" }

    # --- Cross-compile ---
    $env:ANDROID_NDK_HOME = $ndkPath
    # 16KB page alignment: Android 15+ (API 35) enforces 16KB pages on some devices.
    $env:RUSTFLAGS = "--cfg ANDROID_PAGE_SIZE_16K -C link-arg=-Wl,-z,common-page-size=16384 -C link-arg=-Wl,-z,max-page-size=16384"

    Info "Cross-compiling tun2proxy-bin (aarch64-linux-android)..."
    Set-Location (Join-Path $work "src")
    cargo ndk -t arm64-v8a -p $Api build --release --bin tun2proxy-bin
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

    $built = Join-Path $work "src\target\aarch64-linux-android\release\tun2proxy-bin"
    if (-not (Test-Path $built)) { throw "Build artifact not found: $built" }

    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
    Copy-Item $built $output -Force

    Info "Done: $output"
    $sz = "{0:N1}" -f ((Get-Item $output).Length / 1MB)
    Info "size: ${sz} MB"
    Info "Next: .\pack.ps1"
} finally {
    Pop-Location
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
