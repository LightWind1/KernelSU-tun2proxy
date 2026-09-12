#!/system/bin/sh
# customize.sh — runs during module installation
# KernelSU calls this when the module is installed/updated

# KernelSU provides MODPATH while installing a module.  During installation
# $0 may be only "customize.sh" (without a directory component), so dirname
# "$0" can resolve to the installer working directory instead of the module.
MODDIR="${MODPATH:-$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd)}"
ui_print() { echo "$@"; }

if [ -z "$MODDIR" ] || [ ! -d "$MODDIR" ]; then
    ui_print "  [!] Invalid module path: $MODDIR"
    exit 1
fi

ui_print "========================================"
ui_print "  Tun2Proxy for Android $(sed -n 's/^version=//p' "$MODDIR/module.prop")"
ui_print "  KernelSU module"
ui_print "========================================"

# Set executable permissions on all scripts
chmod +x "$MODDIR/post-fs-data.sh"
chmod +x "$MODDIR/service.sh"
chmod +x "$MODDIR/uninstall.sh"
chmod +x "$MODDIR/system/bin/tun2proxyctl"
if [ -f "$MODDIR/system/bin/tun2proxy-tun-launcher" ]; then
    chmod +x "$MODDIR/system/bin/tun2proxy-tun-launcher"
fi

# Set executable on web backend
if [ -f "$MODDIR/system/bin/tun2proxy-web" ]; then
    chmod +x "$MODDIR/system/bin/tun2proxy-web"
    ui_print "  [x] tun2proxy-web backend found"
else
    ui_print "  [!] tun2proxy-web not found in module"
    ui_print "      Build it: cd cmd/tun2proxy-web && go build -o ../../system/bin/tun2proxy-web"
fi

# Set executable on tun2proxy binary
if [ -f "$MODDIR/system/bin/tun2proxy" ]; then
    chmod +x "$MODDIR/system/bin/tun2proxy"
    ui_print "  [x] tun2proxy binary found"
else
    ui_print "  [!] tun2proxy binary not in module"
    ui_print "      Cross-compile from tun2proxy/ submodule:"
    ui_print "        cd tun2proxy && cargo build --release --target aarch64-linux-android"
    ui_print "        cp target/aarch64-linux-android/release/tun2proxy \$MODDIR/system/bin/"
fi

ui_print ""
ui_print "  Usage after boot:"
ui_print "    su -c tun2proxyctl start"
ui_print "    su -c tun2proxyctl status"
ui_print ""
ui_print "  Web UI: http://<phone-ip>:38765"
ui_print "  Find IP: su -c ip addr show wlan0"
ui_print "========================================"
