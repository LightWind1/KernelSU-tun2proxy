#!/system/bin/sh
# uninstall.sh — cleanup on module removal

# Stop any running tun2proxy processes
pkill -f tun2proxy 2>/dev/null
pkill -f tun2proxy-web 2>/dev/null

# Remove module data directory
rm -rf /data/adb/tun2proxy 2>/dev/null

echo "[$(date)] Tun2Proxy for Android uninstalled"
