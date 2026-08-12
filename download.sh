#!/bin/bash
# download.sh — Download latest tun2proxy prebuilt binary from GitHub Releases
# Usage: bash download.sh [version]
#   version: "latest" (default) or "v0.8.2" etc.
set -e

VERSION="${1:-latest}"
TARGET="aarch64-unknown-linux-musl"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$SCRIPT_DIR/system/bin"
OUTPUT_BIN="$BIN_DIR/tun2proxy"

echo "=== Downloading tun2proxy for Android (ARM64) ==="

mkdir -p "$BIN_DIR"

# Get release info
if [ "$VERSION" = "latest" ]; then
    API_URL="https://api.github.com/repos/tun2proxy/tun2proxy/releases/latest"
else
    API_URL="https://api.github.com/repos/tun2proxy/tun2proxy/releases/tags/$VERSION"
fi

echo "[1/3] Fetching release info..."
RELEASE_JSON=$(curl -sS --connect-timeout 15 "$API_URL" 2>/dev/null)
if [ -z "$RELEASE_JSON" ] || echo "$RELEASE_JSON" | grep -q "Not Found"; then
    echo "  ERROR: Cannot reach GitHub API or release not found."
    echo ""
    echo "  Manual download: https://github.com/tun2proxy/tun2proxy/releases"
    exit 1
fi

TAG=$(echo "$RELEASE_JSON" | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
echo "  Release: $TAG"

# Find the right asset URL
ASSET_URL=""
for pattern in "*aarch64-unknown-linux-musl*" "*aarch64-unknown-linux-gnu*" "*aarch64-linux-android*" "*arm64*linux*" "*linux*aarch64*" "*linux*arm64*"; do
    ASSET_URL=$(echo "$RELEASE_JSON" | grep -o '"browser_download_url": *"[^"]*'"$pattern"'[^"]*"' | head -1 | sed 's/.*"browser_download_url": *"\([^"]*\)".*/\1/')
    [ -n "$ASSET_URL" ] && break
done

if [ -z "$ASSET_URL" ]; then
    echo "  ERROR: No matching ARM64 asset found."
    echo "  Available assets:"
    echo "$RELEASE_JSON" | grep -o '"name": *"[^"]*"' | sed 's/"name": *"\([^"]*\)"/  - \1/'
    echo ""
    HTML_URL=$(echo "$RELEASE_JSON" | grep -o '"html_url": *"[^"]*"' | head -1 | sed 's/.*"html_url": *"\([^"]*\)".*/\1/')
    echo "  Manual download: $HTML_URL"
    exit 1
fi

ASSET_NAME=$(basename "$ASSET_URL")
echo "  Found asset: $ASSET_NAME"

# Download
echo "[2/3] Downloading $ASSET_NAME..."
TMP_DIR=$(mktemp -d -t tun2proxy-dl-XXXXXX)
DL_PATH="$TMP_DIR/$ASSET_NAME"
curl -sSL --connect-timeout 30 --max-time 120 -o "$DL_PATH" "$ASSET_URL"

# Extract
echo "[3/3] Extracting..."
EXTRACT_DIR="$TMP_DIR/extracted"
mkdir -p "$EXTRACT_DIR"

case "$ASSET_NAME" in
    *.tar.gz|*.tgz)
        tar -xzf "$DL_PATH" -C "$EXTRACT_DIR"
        ;;
    *.tar.xz)
        tar -xJf "$DL_PATH" -C "$EXTRACT_DIR"
        ;;
    *.zip)
        unzip -qo "$DL_PATH" -d "$EXTRACT_DIR" 2>/dev/null || python3 -m zipfile -e "$DL_PATH" "$EXTRACT_DIR" 2>/dev/null
        ;;
    *.gz)
        gunzip -c "$DL_PATH" > "$OUTPUT_BIN"
        chmod +x "$OUTPUT_BIN"
        rm -rf "$TMP_DIR"
        echo ""
        echo "  Binary saved to: $OUTPUT_BIN"
        ls -lh "$OUTPUT_BIN" | awk '{print "  Size: " $5}'
        exit 0
        ;;
    *)
        cp "$DL_PATH" "$OUTPUT_BIN"
        chmod +x "$OUTPUT_BIN"
        rm -rf "$TMP_DIR"
        echo ""
        echo "  Binary saved to: $OUTPUT_BIN"
        ls -lh "$OUTPUT_BIN" | awk '{print "  Size: " $5}'
        exit 0
        ;;
esac

# Find the binary
FOUND=$(find "$EXTRACT_DIR" -type f -name "tun2proxy*" ! -name "*.dll" ! -name "*.so" ! -name "*.dylib" 2>/dev/null | head -1)
if [ -z "$FOUND" ]; then
    FOUND=$(find "$EXTRACT_DIR" -type f -name "tun2proxy*" -size +1M 2>/dev/null | head -1)
fi

if [ -n "$FOUND" ]; then
    cp "$FOUND" "$OUTPUT_BIN"
    chmod +x "$OUTPUT_BIN"
    echo "  Binary saved to: $OUTPUT_BIN"
    ls -lh "$OUTPUT_BIN" | awk '{print "  Size: " $5}'
else
    echo "  WARNING: Could not find tun2proxy binary in archive."
    echo "  Extracted files:"
    find "$EXTRACT_DIR" -type f | head -20 | while read f; do echo "    $(basename "$f")"; done
fi

rm -rf "$TMP_DIR"
echo ""
echo "Done! Now run: bash pack.sh"
