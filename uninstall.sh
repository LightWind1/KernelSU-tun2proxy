#!/system/bin/sh
# uninstall.sh — cleanup on module removal

# Stop any running tun2proxy processes
MODDIR=${0%/*}
TUN2PROXY_MODDIR="$MODDIR" "$MODDIR/system/bin/tun2proxy-web" --cert-remove
cert_cleanup=$?
"$MODPATH/system/bin/tun2proxy-web" --routes-stop 2>/dev/null || "${0%/*}/system/bin/tun2proxy-web" --routes-stop
pkill -f tun2proxy 2>/dev/null
pkill -f tun2proxy-web 2>/dev/null

# Remove module data directory
if [ "$cert_cleanup" -eq 0 ]; then
    rm -rf /data/adb/tun2proxy 2>/dev/null
else
    echo "Certificate mounts need reboot; retaining private data for safe recovery"
fi

echo "[$(date)] Tun2Proxy for Android uninstalled"
