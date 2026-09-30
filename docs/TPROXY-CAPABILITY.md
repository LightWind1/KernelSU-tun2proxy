# TPROXY capability investigation — 2026-10-01

## Phase 0: repository and read-only device investigation

Existing lifecycle: `system/bin/tun2proxyctl` delegates to the native web
backend controller; its legacy branch retains the TUN implementation.
`cmd/tun2proxy-web/backend.go` converts the existing ProxyURL, authentication,
route mode and App package selection into the generic native configuration.
App packages are resolved to UIDs by the integration layer, not the core.
Boot/service and uninstall use this controller. No lifecycle changes in this phase.

The independent Go module `ebpf-proxy/` already separates `internal/relay`
(opaque bidirectional TCP, half-close/backpressure/timeouts) from
`internal/upstream` (SOCKS5 handshake/authentication/CONNECT). Its eBPF daemon
owns loading/control, but the relay resolver is backend-independent. TPROXY
adds `internal/tproxy`; no parent-module, WebUI, certificate or upstream-product
dependency. Current default remains TUN. Existing eBPF code/tests are retained.

Build: Go 1.26.4; standalone Go module; Linux arm64 with CGO disabled. Existing
NDK BPF build remains unchanged. Current root execution is `u:r:ksu:s0`,
SELinux Enforcing; no new policy allow rules were added.

## Capability Report: tested device

| Check | Actual result |
| --- | --- |
| Android / SDK | 15 / 35 |
| Kernel | 5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284 |
| iptables / ip6tables | 1.8.10 (legacy) |
| Kernel TPROXY IPv4 / IPv6 | Both enabled; registered targets visible |
| owner UID / MARK / mark / socket | Config enabled, registered; extension help exit 0 |
| IPv4 / IPv6 multiple routing tables | Config enabled; rule/route queries exit 0 |
| IP_TRANSPARENT / IPV6_TRANSPARENT | Real socket setsockopt and getsockopt both succeed with value 1 |
| xtables wait | `iptables -w 2 -t mangle -S` succeeds |
| nft | Binary absent; config explicitly `CONFIG_NF_TABLES` not set |
| Root network namespace | net:[4026532071] |
| Isolated namespace | `unshare -n ip rule show` succeeds, only priorities 0/32766/32767 |
| Automatic live-network setup | Disabled: mark collision risk |

The probe opens and closes sockets without binding. It does not create network
namespaces or write firewall, routing, sysctl, BPF or Android proxy settings.
Missing config or missing commands are reported separately, not interpreted as
proof of missing kernel support. Each executed query retains exit code/stderr.
Full system firewall dumps are consumed for analysis but omitted from normal
output (digest and relevant mark references retained).

Read-only CLI:

```sh
su -c '/data/local/tmp/tproxy-probe tproxy probe'
```

## fwmark analysis

Current Android IPv4 and IPv6 priorities: 0, 10000, 11000, 16000, 17000,
18000, 19000, 20000, 23000, 31000, 32000. Rules use masks including
`0xd0000`, `0x1ffff`, `0xdffff`, `0xc0000`, `0x10000`, `0xffff`.
No current ip rule matches bit 22 (`0x00400000`). This is a **candidate only**,
not a proved free bit. Future live setup must freshly validate table/priority
and require explicit risk acknowledgement rather than automatically enabling it.

Actual conflicting/risk references include:

```text
routectrl_mangle_INPUT: --set-xmark 0xf0064/0x7fefffff (ccmni0)
routectrl_mangle_INPUT: --set-xmark 0x30065/0x7fefffff (wlan0)
bw_raw_PREROUTING: --mark 0xdeadc1a7 (full-width exact sentinel)
wakeupctrl_mangle_INPUT: --mark 0x80000000/0x80000000
tc_limiter_OUTPUT: CONNMARK 0x20000000/0x30000000 and 0x10000000
```

Ingress masks cover bit 22 but are interface-specific. The full-width sentinel
is not proof that all bits are allocated; the probe conservatively reports it.
CONNMARK and packet MARK are separate namespaces and are identified separately.
Vendor pinned BPF programs are also present. AOSP's reserved bits alone cannot
certify this vendor ROM. Therefore: **TPROXY mark collision risk**; no automatic
rule installation in Android's root namespace.

Reference [AOSP Fwmark layout](https://android.googlesource.com/platform/system/netd/+/refs/heads/main/include/Fwmark.h):
bits 0–15 netId, 16 explicitly selected, 17 protected from VPN, 18–19 permission,
20 billing, 21–28 reserved, 29–30 vendor, 31 ingress wakeup. This is a reference
layout, not a claim that vendor implementations preserve all reserved bits.

## Minimal IPv4 PoC plan

Use a **fresh isolated network namespace on the same Android kernel**. Bind a
transparent listener before interception. Destination-only OUTPUT marking of
`198.18.0.1:443` uses `--set-xmark 0x00400000/0x00400000`; priority 9001 selects
table 38766, containing a local host route through lo. PREROUTING jumps to an
owned chain with TPROXY port 18080. Source is test-only `192.0.2.2`.

This namespace needs a specific main-table host route for the initial route
lookup before OUTPUT. It is **not Android's main table**; no default route is
changed. Only owned test resources are removed, in reverse order; ingress is
enabled last and disabled first. Namespace destruction supplies crash cleanup.
The PoC must reject the host namespace and non-empty namespace firewall/routes.

Acceptance is a real TCP handshake with original destination exactly
`198.18.0.1:443`, plus nonzero MARK/TPROXY counters and successful rollback.
No TUN, VPN, eBPF attachment, DNS or upstream is involved.

This proves the kernel data path, **not** App UID / live Android fwmark / SOCKS5 /
MITM behavior. Direct relay, selected/nonselected UIDs and upstream verification
are subsequent stages; WebUI integration remains gated on those tests.
IPv6 socket capability is confirmed, but IPv6 TPROXY traffic is not yet tested.

Reference: [Linux TPROXY documentation](https://www.kernel.org/doc/html/latest/networking/tproxy.html).
