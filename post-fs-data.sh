#!/system/bin/sh
# post-fs-data.sh — early boot (no blocking operations)
MODDIR=${0%/*}

# Only create data directories — no mounts, no process launches
mkdir -p /data/adb/tun2proxy/logs
mkdir -p /data/adb/tun2proxy/run
mkdir -p /data/adb/tun2proxy/config

chmod 700 /data/adb/tun2proxy
chmod 755 /data/adb/tun2proxy/logs /data/adb/tun2proxy/run /data/adb/tun2proxy/config
