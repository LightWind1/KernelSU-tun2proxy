#!/system/bin/sh
# Certificate lifecycle is independent of tun2proxy and never downloads on boot.
MODDIR=${0%/certificate/*}
i=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ "$i" -lt 120 ]; do
    sleep 1
    i=$((i + 1))
done
export TUN2PROXY_MODDIR="$MODDIR"
"$MODDIR/system/bin/tun2proxy-web" --cert-apply
