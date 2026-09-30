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
| Current recommendation | Preserve default TUN; investigate TPROXY further, eBPF blocked by exclusive netd connect hooks |

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

## Phase A: implemented and tested minimum IPv4 PoC

Files: `ebpf-proxy/internal/tproxy/listener_linux.go`, `poc_linux.go`,
`poc_linux_test.go`; CLI `cmd/ebpf-proxy/tproxy_linux.go`; standalone README;
actual device evidence in `docs/tproxy-poc-android.json` and compact capability
report in `docs/tproxy-capability-android.json`. No WebUI, module lifecycle,
existing saved profiles or certificate code was modified.

Device commands (binaries pushed only to `/data/local/tmp`, not installed):

```sh
su -c 'unshare -n /data/local/tmp/tproxy-probe tproxy poc-isolated'
su -c 'TP_RUN_PRIVILEGED=1 /data/local/tmp/tproxy-tests -test.v'
su -c '/data/local/tmp/tproxy-module-tests -test.v'
```

Actual acceptance evidence:

```text
Host namespace:    net:[4026532071]
PoC namespace:     net:[4026536078]
Original dst:      198.18.0.1:443
OUTPUT MARK:       3 packets, 164 bytes
PREROUTING TPROXY: 3 packets, 164 bytes
Rule:             9001 fwmark 0x400000/0x400000 lookup 38766
Route:            local 198.18.0.1 dev lo scope host
Rollback:         11 commands, all exit 0
after_rule:       only 0 / 32766 / 32767
after_firewall:   no ATP_POC chains or jumps
Android rules4/6:  identical before and after PoC
```

Network mutation: **only inside newly created private namespaces**. No permanent
or root-namespace rules, global proxy, sysctl writes, TUN, VPNService or BPF
attachment. Root `iptables -t mangle -S ATP_POC_OUT` returns “No chain/target/match
by that name”. Existing `tunl0` is the stock IPIP tunnel device, not a created
TUN device; do not misclassify it from the name prefix.

Tests passed:

- Standalone core `go test ./...` and `go vet ./...` on Windows.
- Actual Android test suite: successful interception, fault injection after
  steps 2/5/8/10/11 with complete owned-resource rollback, host-namespace
  rejection, original destination resolver and read-only query allowlist.
- Android main-module tests: default backend, eBPF adapter, App label parser,
  certificate API boundaries, install/update transactions, profile migration,
  per-endpoint isolation and existing routing journal/error tests.
- Existing certificate/Yakit package tests and Node App picker/backend tests.
- Linux arm64 daemon/test binary build and unchanged NDK BPF object build.

During rollback validation the kernel retained its automatically created
127/8 loopback local routes after lo was brought down. These are **not owned
test routes**. Validation explicitly checks absence of test addresses/table
rather than deleting kernel routes to make the output artificially empty.
Namespace destruction removes them; Android's loopback was never touched.

Known limitations: first proof is destination-only, no UID or upstream yet;
no direct relay, SOCKS5/MITM, HTTP/2/WebSocket, live ROM interception, network
switch or IPv6 TPROXY traffic acceptance. No production setup/repair/watchdog
or KernelSU integration is exposed. Candidate bit safety remains unresolved;
live testing requires an explicit narrow mark override and fresh collision
checks. Subsequent work: direct-relay namespace fixture, UID/bypass isolation,
then SOCKS5 reachability/MITM and live-network risk review, before any WebUI work.

Phase 0 commit: `8029ab5` (`feat: add read-only tproxy capability probe`).
Phase A commit can be identified by message
`feat: verify isolated ipv4 tproxy interception and rollback`.
No release ZIP was repacked and no version was incremented in this investigation.
