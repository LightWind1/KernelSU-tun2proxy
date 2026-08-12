#!/bin/bash
# install.sh — Install tun2proxy module via adb
# Usage: bash install.sh [device_serial]
set -e

ZIP_FILE="tun2proxy-for-KernelSU-v1.0.0.zip"
MODULE_DIR="/data/adb/modules/tun2proxy"
TMP_PATH="/data/local/tmp/$ZIP_FILE"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZIP_PATH="$SCRIPT_DIR/../$ZIP_FILE"

# Check if zip exists
if [ ! -f "$ZIP_PATH" ]; then
    echo "ERROR: $ZIP_FILE not found at $ZIP_PATH"
    echo "Run 'bash pack.sh' first."
    exit 1
fi

echo "=== Tun2Proxy for KernelSU — adb Install ==="

# Check adb
if ! command -v adb &>/dev/null; then
    echo "ERROR: adb not found in PATH"
    exit 1
fi

# Check device
DEVICE_COUNT=$(adb devices | grep -v "List of" | grep -c "device" 2>/dev/null || echo 0)
if [ "$DEVICE_COUNT" -eq 0 ]; then
    echo "ERROR: No device connected"
    exit 1
fi
echo "Device: $(adb devices | grep 'device$' | head -1 | awk '{print $1}')"

# Check root
echo "[1/5] Checking root..."
ROOT=$(adb shell "su -c 'id -u'" 2>/dev/null | tr -d '\r\n')
if [ "$ROOT" != "0" ]; then
    echo "  WARNING: Root check failed. Continuing anyway..."
fi
echo "  uid=$ROOT"

# Push zip
echo "[2/5] Pushing $ZIP_FILE to device..."
adb push "$ZIP_PATH" "$TMP_PATH"

# Remove old module if exists
echo "[3/5] Removing old module (if exists)..."
adb shell "su -c 'rm -rf $MODULE_DIR'" 2>/dev/null || true

# Extract
echo "[4/5] Extracting module to $MODULE_DIR..."
adb shell "su -c 'mkdir -p $MODULE_DIR && unzip -o $TMP_PATH -d $MODULE_DIR'" 2>/dev/null

# Run customize.sh
echo "[5/5] Running customize.sh..."
adb shell "su -c 'chmod +x $MODULE_DIR/*.sh && sh $MODULE_DIR/customize.sh'"

# Cleanup temp file
adb shell "su -c 'rm -f $TMP_PATH'" 2>/dev/null || true

echo ""
echo "============================================"
echo "  Module installed!"
echo "  Module dir: $MODULE_DIR"
echo ""
echo "  Next: reboot, then visit:"
echo "    http://<phone-ip>:8080"
echo ""
echo "  Or start manually right now:"
echo "    adb shell su -c '$MODULE_DIR/service.sh'"
echo "============================================"
