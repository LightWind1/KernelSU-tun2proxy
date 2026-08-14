#!/bin/bash
# build-tun2proxy.sh — Cross-compile the tun2proxy CLI for Android (aarch64)
#
# The official tun2proxy GitHub Releases do NOT ship a standalone Android CLI
# binary. They only provide:
#   * aarch64-unknown-linux-gnu / -musl  → glibc/musl Linux builds (won't run on
#     Android, which uses bionic libc)
#   * tun2proxy-android-libs.zip         → libtun2proxy.so/.a + tun2proxy.h (no CLI)
#
# So we compile the `tun2proxy-bin` binary target from source against bionic.
# This mirrors upstream's own build-android.sh.
#
# Prerequisites:
#   * Rust 1.85+  (https://rustup.rs)
#   * Android NDK  (26.x recommended; 25.x also works)
#
# Usage:
#   ANDROID_NDK=/path/to/android-ndk bash build-tun2proxy.sh            # latest release
#   ANDROID_NDK=/path/to/android-ndk bash build-tun2proxy.sh v0.8.3     # specific tag
#   ANDROID_NDK=/path/to/android-ndk ANDROID_API=31 bash build-tun2proxy.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$SCRIPT_DIR/system/bin"
OUTPUT="$BIN_DIR/tun2proxy"
REF="${1:-}"                 # optional git tag/branch; default = latest release tag
ANDROID_API="${ANDROID_API:-26}"

info()  { echo "==> $*"; }
die()   { echo "ERROR: $*" >&2; exit 1; }

# --- Locate the Android NDK ---
NDK="${ANDROID_NDK:-${ANDROID_NDK_HOME:-}}"
if [ -z "$NDK" ]; then
  for candidate in \
    "$HOME/Android/Sdk/ndk"/* \
    "$HOME/Library/Android/sdk/ndk"/* \
    "$ANDROID_HOME/ndk"/* \
    "$ANDROID_SDK_ROOT/ndk"/* \
    "/opt/android-ndk" \
    "/usr/local/android-ndk"; do
    if [ -d "$candidate/toolchains/llvm/prebuilt" ]; then
      NDK="$candidate"; break
    fi
  done
fi
[ -n "$NDK" ] || die "Android NDK not found. Set ANDROID_NDK=/path/to/android-ndk"

# --- Resolve host prebuilt (linux/darwin) ---
HOST=""
for h in linux-x86_64 darwin-x86_64 darwin-aarch64 windows-x86_64; do
  if [ -d "$NDK/toolchains/llvm/prebuilt/$h/bin" ]; then
    HOST="$h"; break
  fi
done
[ -n "$HOST" ] || die "No LLVM prebuilt found under $NDK/toolchains/llvm/prebuilt"

CLANG="$NDK/toolchains/llvm/prebuilt/$HOST/bin/aarch64-linux-android${ANDROID_API}-clang"
AR="$NDK/toolchains/llvm/prebuilt/$HOST/bin/llvm-ar"
[ -x "$CLANG" ] || die "Missing $CLANG (is API level $ANDROID_API available in this NDK?)"

# --- Rust toolchain ---
command -v cargo  >/dev/null 2>&1 || die "Rust not found. Install: https://rustup.rs"
command -v rustup >/dev/null 2>&1 || die "rustup not found"
command -v git    >/dev/null 2>&1 || die "git not found"

info "NDK:    $NDK"
info "Host:   $HOST"
info "API:    $ANDROID_API"
info "Adding aarch64-linux-android target..."
rustup target add aarch64-linux-android

# --- Fetch source into a temp dir (not committed to the repo) ---
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tun2proxy-build.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

if [ -z "$REF" ]; then
  info "Resolving latest release tag..."
  REF="$(curl -sSL --connect-timeout 15 "https://api.github.com/repos/tun2proxy/tun2proxy/releases/latest" 2>/dev/null \
       | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/' || true)"
  [ -n "$REF" ] || REF="main"
fi
info "Building tun2proxy @ $REF"

git clone --depth 1 ${REF:+--branch "$REF"} https://github.com/tun2proxy/tun2proxy.git "$WORK/src" \
  || die "git clone failed (network?)"

# --- Cross-compile ---
export CC_aarch64_linux_android="$CLANG"
export AR_aarch64_linux_android="$AR"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CLANG"
# 16KB page alignment: Android 15+ (API 35) enforces 16KB pages on some devices.
export RUSTFLAGS="-C link-arg=-Wl,-z,common-page-size=16384 -C link-arg=-Wl,-z,max-page-size=16384 --cfg ANDROID_PAGE_SIZE_16K"

info "Cross-compiling tun2proxy-bin (aarch64-linux-android)..."
( cd "$WORK/src" && cargo build --release --target aarch64-linux-android --bin tun2proxy-bin )

# --- Install ---
mkdir -p "$BIN_DIR"
cp "$WORK/src/target/aarch64-linux-android/release/tun2proxy-bin" "$OUTPUT"
chmod +x "$OUTPUT"

info "Done: $OUTPUT"
ls -lh "$OUTPUT" | awk '{print "  size: " $5}'
info "Next: bash pack.sh"
