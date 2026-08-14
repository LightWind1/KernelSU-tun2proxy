# Tun2Proxy for KernelSU

KernelSU module packaging [tun2proxy](https://github.com/tun2proxy/tun2proxy) (Rust TUN→SOCKS5/HTTP proxy) for Android, with a Go web API server and browser-based management UI.

## Architecture

```
tun2proxy binary (system/bin/tun2proxy)  →  TUN interface, routes traffic to proxy
                                                   ↓
tun2proxy-web (system/bin/tun2proxy-web)  →  REST API (:8080)  ←  Browser UI (webroot/)
                                                   ↓
tun2proxyctl (system/bin/tun2proxyctl)    →  Shell CLI for process management
```

### Components

| Component | Path | Purpose |
|---|---|---|
| tun2proxy | `system/bin/tun2proxy` | Rust TUN proxy engine — cross-compiled from source (`aarch64-linux-android`) |
| tun2proxy-web | `cmd/tun2proxy-web/main.go` | Go HTTP API server — manages tun2proxy lifecycle, serves UI |
| tun2proxyctl | `system/bin/tun2proxyctl` | Shell CLI for start/stop/status/auto-start |
| Web UI | `webroot/index.html` | Single-page management interface (dark theme) |
| Config | `config/config.json` | Default configuration template |

### Data flow

1. `service.sh` launches `tun2proxy-web` at boot (late_start)
2. `tun2proxy-web` reads/writes `/data/adb/tun2proxy/config.json`
3. Web UI loads from `webroot/index.html`, polls `/api/status` every 5s
4. User configures proxy settings → PUT `/api/config` → saves to config.json
5. User clicks Start → POST `/api/start` → `tun2proxyctl start` → `nohup tun2proxy ...`
6. `tun2proxy` creates TUN interface, routes traffic through specified proxy
7. Logs written to `/data/adb/tun2proxy/logs/tun2proxy.log`

## API Reference

All endpoints are on `http://<phone-ip>:8080` with CORS enabled.

| Method | Route | Description |
|---|---|---|
| GET | `/api/status` | JSON: running state, PID, uptime, config, TUN availability |
| GET | `/api/config` | Return current config JSON |
| PUT | `/api/config` | Save new config (body: full Config JSON) |
| POST | `/api/start` | Start tun2proxy with config (optional body: save config first) |
| POST | `/api/stop` | Stop tun2proxy |
| POST | `/api/restart` | Restart tun2proxy |
| GET | `/api/logs?lines=N` | Return last N lines of tun2proxy log (default 200) |
| GET | `/api/check` | Environment diagnostics (text/plain) |
| GET | `/api/health` | Health check: `{"status":"ok"}` |
| GET | `/` | Serve web UI (index.html) |

### Config JSON Schema

```json
{
  "version": "1.0",
  "enabled": false,
  "tun_name": "tun0",
  "proxy_url": "socks5://127.0.0.1:1080",
  "dns_mode": "virtual",
  "bypass_ips": ["10.0.0.0/8", "192.168.0.0/16"],
  "tcp_timeout": 30,
  "udp_timeout": 30,
  "udpgw_server": ""
}
```

- `dns_mode`: `"virtual"` (maps DNS to 198.18.0.0/15, proxy resolves) | `"over-tcp"` (DNS over TCP via proxy) | `"direct"` (system DNS)
- `bypass_ips`: IP/CIDR ranges that skip the proxy
- `udpgw_server`: Optional UDP gateway address (e.g. `127.0.0.1:7300`)

## Build & Package

### Prerequisites

- **Go 1.21+** for the web backend
- **Rust** with `aarch64-linux-android` target for tun2proxy
- **Android NDK** for cross-compiling Rust to Android

### Build tun2proxy (cross-compile from source)

> **There is no prebuilt Android CLI binary.** The official
> [tun2proxy releases](https://github.com/tun2proxy/tun2proxy/releases) only ship
> glibc/musl Linux builds (`aarch64-unknown-linux-gnu`/`-musl`, which are
> dynamically linked against glibc and **will not run** on Android's bionic libc)
> and `tun2proxy-android-libs.zip` (only `libtun2proxy.so`/`.a` + a C header — no
> CLI). So the `tun2proxy-bin` binary target must be compiled from source against
> Android.

Use the bundled cross-compile script (clones the source to a temp dir, builds,
and copies the binary to `system/bin/tun2proxy`):

```bash
# Linux / macOS / WSL / Git Bash
ANDROID_NDK=/path/to/android-ndk bash build-tun2proxy.sh

# Windows PowerShell (uses cargo-ndk)
.\build-tun2proxy.ps1
```

Pass a specific tag/branch to pin a version (default = latest release tag):

```bash
ANDROID_NDK=/path/to/android-ndk bash build-tun2proxy.sh v0.8.3
.\build-tun2proxy.ps1 -Ref v0.8.3
```

**Prerequisites:** Rust 1.85+ (with `aarch64-linux-android` target) and the
Android NDK. The script also sets `-Wl,-z,common-page-size=16384
-Wl,-z,max-page-size=16384 --cfg ANDROID_PAGE_SIZE_16K` so the binary works on
Android 15+ devices with 16 KB memory pages.

If you prefer to build manually:

```bash
rustup target add aarch64-linux-android
export ANDROID_NDK=/path/to/android-ndk
export CC_aarch64_linux_android="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang"
export AR_aarch64_linux_android="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC_aarch64_linux_android"
export RUSTFLAGS="-C link-arg=-Wl,-z,common-page-size=16384 -C link-arg=-Wl,-z,max-page-size=16384 --cfg ANDROID_PAGE_SIZE_16K"

git clone --depth 1 https://github.com/tun2proxy/tun2proxy.git
cd tun2proxy
cargo build --release --target aarch64-linux-android --bin tun2proxy-bin
cp target/aarch64-linux-android/release/tun2proxy-bin ../system/bin/tun2proxy
```

### Build tun2proxy-web (Go → ARM64)

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o system/bin/tun2proxy-web ./cmd/tun2proxy-web/
```

The `-ldflags="-s -w"` strips debug symbols to reduce binary size.

### Package the module

```bash
# Linux/macOS/Git Bash
bash pack.sh
# Output: ../tun2proxy-for-KernelSU-v1.0.0.zip

# Windows PowerShell
.\pack.ps1
# Output: ../tun2proxy-for-KernelSU-v1.0.0.zip
```

**Excluded from zip** (build-time only): `.git/`, `.claude/`, `tun2proxy/` (Rust source), `cmd/` (Go source), `META-INF/`, `pack.*`, `build-tun2proxy.*`, `install.*`, `CLAUDE.md`, `go.mod`, `go.sum`.

## Installation

1. Build both binaries and place them in `system/bin/`
2. Run `bash pack.sh` (or `.\pack.ps1`)
3. Transfer the zip to your Android device
4. KernelSU Manager → Modules → Install from storage → select zip
5. Reboot
6. Open WebUI from KernelSU Manager or navigate to `http://<phone-ip>:8080`

## CLI Usage (on device via adb shell)

```bash
su -c tun2proxyctl start      # Start with saved config
su -c tun2proxyctl stop        # Stop
su -c tun2proxyctl restart     # Restart
su -c tun2proxyctl status      # Show status
su -c tun2proxyctl check       # Environment diagnostics
su -c tun2proxyctl logs 100    # View last 100 log lines
```

## Updating tun2proxy

To update the tun2proxy binary to a newer version, rebuild it from source:

```bash
# Latest release tag
ANDROID_NDK=/path/to/android-ndk bash build-tun2proxy.sh
# ...or a specific version
ANDROID_NDK=/path/to/android-ndk bash build-tun2proxy.sh v0.8.3

# Windows PowerShell
.\build-tun2proxy.ps1 -Ref v0.8.3
```

Then rebuild the Go backend if needed, and repackage:

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o system/bin/tun2proxy-web ./cmd/tun2proxy-web/
.\pack.ps1
```

## SELinux

Minimal rules in `sepolicy.rule`. If you encounter denials:

```bash
su -c dmesg | grep avc
```

Add corresponding `allow` rules to `sepolicy.rule` and reinstall.
