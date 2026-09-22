#!/bin/bash
# pack.sh — Package the module into a flashable zip for KernelSU
# Works on Linux, macOS, and Windows (Git Bash / MSYS2 with zip installed)
#
# NOTE: cmd/ (Go source) is intentionally excluded.
# Only runtime assets go into the module zip.
set -e

VERSION="v1.0.24"
MODULE_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT="$MODULE_DIR/../tun2proxy-for-KernelSU-${VERSION}.zip"

echo "=== Packing Tun2Proxy for Android ${VERSION} ==="
echo "Module dir: $MODULE_DIR"

if [ ! -x "$MODULE_DIR/system/bin/tun2proxy" ]; then
    echo "ERROR: missing executable system/bin/tun2proxy"
    echo "Build it first with: ANDROID_NDK=/path/to/android-ndk bash build-tun2proxy.sh"
    exit 1
fi

cd "$MODULE_DIR"
if [ -e "$OUTPUT" ]; then
    echo "Release ZIP exists. Increment the patch version before packaging again."
    exit 1
fi

# Pack all module files, excluding source code and build tools
zip -r "$OUTPUT" . \
    -x ".git/*" ".git" \
       ".claude/*" ".claude" \
       "cmd/*" "cmd" \
       "META-INF/*" "META-INF" \
       "pack.sh" "pack.ps1" \
       "build-tun2proxy.sh" "build-tun2proxy.ps1" \
       "install.sh" "install.ps1" \
       "go.mod" "go.sum" \
       "CLAUDE.md" \
       ".gitignore" \
       "*.zip"

echo ""
echo "Package created: $OUTPUT"
echo "Install via: KernelSU Manager > Modules > Install from storage"
