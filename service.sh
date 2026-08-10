#!/system/bin/sh
# service.sh — late_start service: launch daemons after boot completes
MODDIR=${0%/*}

# Export environment for child processes
export TUN2PROXY_MODDIR="$MODDIR"
export TUN2PROXY_CONFIG="$MODDIR/config/config.json"
export TUN2PROXY_DATA="/data/adb/tun2proxy"
export TUN2PROXY_LOG="/data/adb/tun2proxy/logs/tun2proxy.log"
export TUN2PROXY_RUN_DIR="/data/adb/tun2proxy/run"

# Ensure data directories exist (idempotent)
mkdir -p "$TUN2PROXY_DATA/logs" "$TUN2PROXY_DATA/run" "$TUN2PROXY_DATA/config"
chmod 755 "$TUN2PROXY_DATA/logs" "$TUN2PROXY_DATA/run" "$TUN2PROXY_DATA/config"

# Copy default config if not present
if [ ! -f "$TUN2PROXY_DATA/config/config.json" ] && [ -f "$MODDIR/config/config.json" ]; then
    cp "$MODDIR/config/config.json" "$TUN2PROXY_DATA/config/config.json"
    chmod 644 "$TUN2PROXY_DATA/config/config.json"
fi

# Start Web UI backend server
if [ -x "$MODDIR/system/bin/tun2proxy-web" ]; then
    nohup "$MODDIR/system/bin/tun2proxy-web" >> "$TUN2PROXY_LOG" 2>&1 &
    echo "[$(date)] tun2proxy-web started, pid=$!" >> "$TUN2PROXY_LOG"
fi

# Auto-start tun2proxy if enabled in config
if [ -x "$MODDIR/system/bin/tun2proxyctl" ]; then
    sleep 3
    "$MODDIR/system/bin/tun2proxyctl" auto-start >> "$TUN2PROXY_LOG" 2>&1 &
fi
