#!/bin/bash
# pack.sh — Package the module into a flashable zip for KernelSU
# Works on Linux, macOS, and Windows (Git Bash / MSYS2 with zip installed)
#
# NOTE: tun2proxy/ (Rust source) and cmd/ (Go source) are intentionally excluded.
# Only runtime assets go into the module zip.
set -e

VERSION="v1.0.0"
MODULE_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT="$MODULE_DIR/../tun2proxy-for-KernelSU-${VERSION}.zip"

echo "=== Packing Tun2Proxy for Android ${VERSION} ==="
echo "Module dir: $MODULE_DIR"

cd "$MODULE_DIR"
rm -f "$OUTPUT"

# Pack all module files, excluding source code and build artifacts
zip -r "$OUTPUT" . \
    -x ".git/*" ".git" \
       ".claude/*" ".claude" \
       "cmd/*" "cmd" \
       "tun2proxy/*" "tun2proxy" \
       "META-INF/*" "META-INF" \
       "pack.sh" "pack.ps1" \
       "go.mod" "go.sum" \
       "CLAUDE.md" \
       ".gitignore" ".gitmodules" \
       "*.zip"

echo ""
echo "Package created: $OUTPUT"
echo "Install via: KernelSU Manager > Modules > Install from storage"
