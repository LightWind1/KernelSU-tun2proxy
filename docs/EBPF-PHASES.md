# eBPF TCP backend development record

## Phase 0 — baseline (2026-09-30)

The existing default backend remains TUN/tun2proxy. No backend selector exists.
The WebUI writes `proxy_url`, `route_mode`, `app_packages`, DNS, bypass and
timeouts to `/data/adb/tun2proxy/config.json`; saved computers use `profiles.json`.
`proxy_url` contains protocol, host, port and optional authentication.
The live saved upstream is HTTP CONNECT at `192.168.30.102:8083`, not an
already-confirmed SOCKS5 endpoint. A SOCKS5 handshake must precede eBPF startup.

Startup: `service.sh` launches the Go API and independent certificate service,
then calls `tun2proxyctl auto-start`. API start calls the shell controller,
which launches the Android TUN launcher and tun2proxy, brings the interface up,
then invokes the Go route manager. Package names are resolved to primary-user
UIDs; root bypass and IPv4 policy routing are installed with a rollback journal.
The current TUN path restricts IPv6 and non-DNS UDP in captured ranges.

Build: Go 1.26.4, Android arm64 CGO-free web backend; Rust/Android NDK engine;
PowerShell/bash release packaging. Android NDK 28.2 clang has a BPF target.

Device: Android 15 SDK 35, arm64, kernel
`5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284`.
`CONFIG_BPF`, `BPF_SYSCALL`, `CGROUP_BPF`, `BPF_JIT`, `NET`, `INET`, `IPV6`
are enabled. `CONFIG_DEBUG_INFO_BTF` is disabled and no vmlinux BTF is exposed.
Cgroup v2 is mounted at `/sys/fs/cgroup`; bpffs at `/sys/fs/bpf`.
KernelSU root runs in `u:r:ksu:s0`; SELinux is Enforcing. Existing policy rules
name `su`, so they are not evidence of permission for this actual domain.
Map/program/helper/link availability requires syscall probes and verifier tests.

## Boundaries and intended files

`ebpf-proxy/` is its own Go module with generic config, SOCKS5 adapter, byte
relay, BPF loader, shared versioned ABI and CLI. It must build without parent
source or module runtime paths. The integration adapter lives in the existing
Go controller and converts saved proxy URL / selected packages into core config.
Only installation, lifecycle and WebUI files change outside these boundaries.

Original destination plan: connect4/6 records destination under a client socket
cookie. A sockops callback joins that cookie to the complete local/remote TCP
tuple after source-port assignment. Accept resolves the tuple, never TLS/DNS.
Client and accepted sockets have different cookies. Tuple records include
cookie, UID and monotonic timestamp; stale cleanup must compare cookie before
deleting a reused tuple. Native unpinned cgroup BPF link FDs provide crash detach;
legacy persistent attach is not an acceptable fail-open fallback.

IPv4 and IPv6 share a family + 16-byte-address ABI. UDP passes. Daemon UID is
always bypassed. No kernel payload processing, VPNService, TUN or TCP stack in
the new component. No kernel BTF means stable UAPI contexts, without CO-RE
kernel-field reads, are the first candidate.

## References

- [Linux v5.10 socket-cookie selftest](https://github.com/torvalds/linux/blob/v5.10/tools/testing/selftests/bpf/progs/socket_cookie_prog.c)
- [Socket-local storage](https://www.kernel.org/doc/html/next/bpf/map_sk_storage.html)
- [eCapture Android engineering reference](https://github.com/gojue/ecapture)
- [eCapture author's Android notes](https://www.cnxct.com/ecapture-for-android/)

eCapture is a reference only; no runtime dependency or TLS probe architecture
is imported. Phases 1–7 require their own build/test evidence; upstream MITM
observability must not be claimed when the external proxy is unavailable.

## Phase 1 — independent relay

Added standalone Go module, generic JSON config, SOCKS5 adapter (IPv4/IPv6/domain
and RFC1929 authentication), fixed-destination PoC CLI and bounded byte relay.
TCP half-close preserves responses after client FIN. Read/write idle deadlines
and cancellation close broken or stalled streams without unbounded queues.
Windows tests cover fragmented SOCKS replies, authentication and address forms.
Android arm64 tests passed 1000 short connections and a 2 MiB delayed-reader /
half-close roundtrip through a local SOCKS5 fixture. All payloads were compared.
The external saved endpoint failed TCP connect on 2026-09-30, so actual external
MITM/CA/HTTP2 request-response verification is pending, not claimed passed.
No module configuration, service or device routing changed in this phase.
Extraction requires no source changes; Go and optional Android cross-build only.
