#!/system/bin/sh
# post-fs-data.sh — early boot (no blocking operations)
MODDIR=${0%/*}

# Only create data directories — no mounts, no process launches
mkdir -p /data/adb/tun2proxy/logs
mkdir -p /data/adb/tun2proxy/run
mkdir -p /data/adb/tun2proxy/config

chmod 700 /data/adb/tun2proxy
chmod 755 /data/adb/tun2proxy/logs /data/adb/tun2proxy/run /data/adb/tun2proxy/config

# Some Android kernels enable CONFIG_TUN but do not ship the device node.
# Create the standard TUN char device when possible; mknod is harmless when
# the node already exists and failures are handled by the runtime check.
if [ ! -c /dev/net/tun ] && [ ! -c /dev/tun ]; then
    mkdir -p /dev/net 2>/dev/null
    mknod /dev/net/tun c 10 200 2>/dev/null || mknod /dev/tun c 10 200 2>/dev/null || true
    chmod 600 /dev/net/tun /dev/tun 2>/dev/null || true
fi
