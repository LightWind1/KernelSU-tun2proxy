# Root TUN routing

The Web UI supports off, selected primary-user apps, and all local non-root UIDs.
Packages are resolved to UIDs at each start; shared-UID packages move together.
This does not register Android VpnService. Root (UID 0) and tethered/forwarded
traffic are excluded. A TUN interface remains visible to applications.

An IPv4 proxy endpoint and virtual DNS mode are required. IPv4 policy rules at
priority 9000 use private table 38765. Throw routes exclude the proxy endpoint,
localhost, multicast/broadcast and configured IPv4 bypass destinations. Existing
Android rules are preserved. The engine runs as root, so its upstream sockets
do not enter the tunnel.

HTTP capture cannot carry arbitrary UDP. Dedicated T2P_CAPTURE owner rules reject
non-DNS UDP and external IPv6 for the selected UID scope. This encourages TCP/IPv4
fallback but UDP-only/IPv6-only apps may fail. Bypassed IPv4 destinations retain
direct UDP. In selected mode, DNS delegated to an unselected system resolver
can go direct. Isolated processes, secondary users and root app subprocesses
are not guaranteed to follow the selected primary-app UID.

Each route/firewall mutation is journaled under run/routes.json. Stop and failed
setup reverse only the module's recorded changes. A separate watcher checks
the engine PID, executable path and process start time and removes rules when
the engine exits. Changes are not persistent kernel configuration. Failed
cleanup keeps its journal and reports an error for retry.

Device validation: selected system browser UID 10118 and all-mode shell UID 2000
returned HTTP 200 through TUN to the configured Yakit HTTP proxy. Packet capture
on tun0 confirmed the marked example.com request. Unselected UID route queries
continued through wlan0. Stop and engine termination removed module rules.
This validates HTTP routing, not TLS trust, certificate pinning or VPN-detection
evasion. App request visibility in Yakit is the end-to-end acceptance criterion.
