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

## Phases 2–4 — native redirect core, dynamic UID and IPv6

Added versioned ABI, connect4/connect6, SK_STORAGE original destination,
sockops tuple publication, LRU flow map, UID/bypass maps, explicit CIDR bypass,
monotonic kernel heartbeat lease, native link loader and private Unix CLI.
Object verifier passed on Android 5.10.236 and Linux 6.6.87.2 (3 programs/7 maps).
An initial IPv6 modified-context-pointer verifier rejection was corrected using
explicit UAPI field loads. No kernel BTF is required.

Privileged isolated-cgroup tests on Linux 6.6 passed 1002 redirected TCP streams
(IPv4 and IPv6), exact SOCKS5 payload relay, 1000 concurrent-batched short
connections, UID add/del, non-target direct, daemon UID/CIDR bypass, UDP pass,
disable and heartbeat expiry. Zero upstream/metadata failures or residual flows.
This is not Android end-to-end evidence.

Real Android probes returned EPERM on additional connect links. Root query
identified netd program IDs 23/24 with attach flags 0 (exclusive), explaining
ancestor attach rejection. Sockops native attach succeeded in a disposable
empty child cgroup. No matching BPF SELinux denial was found. Loader refuses
foreign-program replacement; no SELinux broadening or default-backend change.
Current Android transparent acceptance is blocked by netd exclusive attachments.
External saved proxy TCP reachability also remains unverified/failed.

## Phase 5 — module adapter

Added backend controller and independent config translation. Optional `backend`
defaults to TUN when absent; optional `ebpf_port` defaults to 18080. Existing
proxy_url supplies host, port and decoded authentication; existing route_mode,
app_packages and bypass_ips supply UID/CIDR policy. No second upstream settings.
HTTP CONNECT is explicitly rejected for eBPF rather than assumed SOCKS5.
Native TCP leaves DNS/UDP direct; stored TUN network fields remain unchanged.

Controller serializes start/stop, checks capability before launch, checks daemon
readiness, and refuses backend switching while another engine runs. Shell service
auto-start and uninstall use the same controller; TUN implementation is retained.
Build adapter installs only binary and BPF object. No new SELinux allow rule.
New native links are not pinned; SIGKILL lifetime test confirms all three hooks
detach on Linux 6.6. Runtime lock/privacy tests cover duplicate daemons, public
directories and symlink rejection. Original Android app/profile/certificate/route
tests and adapter tests passed on the device.

An isolated module staging directory on Android tested actual controller start:
exclusive root netd hook ID 23 / flags 0 was reported before process launch.
Existing installed config, TUN routes, system programs and certificate state were
untouched. This is safe rejection evidence, not successful Android redirect.

## Phase 6 — WebUI

Added backend selection and configurable loopback port, program/daemon/listener/
upstream/UID/flow/counter status, capability and SOCKS5 checks, eBPF log category,
and a section in existing diagnostics. HTTP configuration is retained unchanged;
capability checking does not require assuming an HTTP port speaks SOCKS5.
Node tests validate actual form serialization (IPv6/auth/App selection/TUN field
preservation), syntax, defaults and state formatting. Existing App picker tests
pass. Sensitive eBPF diagnostics reuse the local-only, same-origin HTTP guard.

## Phase 7 status

Core Linux tests passed lease expiry, daemon UID bypass, CIDR bypass and UDP
pass; forced subprocess SIGKILL removed all three native links. Android runtime
directory lock/security test passed. External Yakit, Android transparent TCP,
HTTP2/WebSocket end-to-end, network transitions, module disable/enable and device
reboot remain unverified. No broad compatibility or full acceptance claim.

TUN fallback was started and stopped through the new controller in an isolated
Android module staging directory (route_mode off, ep-fallback interface). Native
engine PID 22550 was verified to originate from that staging path; stop removed
the temporary interface. No capture rules were installed. External upstream
192.168.30.102:8083 still failed TCP connect on this test date. Existing installed
module/config were not replaced; no device reboot was needed.

Additional failure tests cover relay idle timeout, cancellation, client RST and
unreachable upstream (no leaked active stream). Native daemon control was
exercised on Linux in a private cgroup: readiness, uid add/del/list/clear, stop
and control-socket cleanup passed. Control-server failure or socket removal
disables interception; shutdown joins resolver handlers before map destruction.
C compile-time assertions and Go tests validate shared ABI structure sizes.

Release v1.0.27 keeps TUN default, includes the independently built native binary,
BPF object, WebUI integration and license notices, and excludes ebpf-proxy source/
tests from runtime ZIP. External proxy and Android exclusive-hook blockers are
not bypassed. Phase 7 complete production acceptance remains outstanding.

Final regression also separates IPv4/IPv6 bypass tries (an IPv6 ::/0 must not
bypass IPv4), validates map ABI sizes before load, and tests 100 refused connects
that never reach accept: sockops lifecycle cleanup leaves no stale tuple entry.
Core-directory extraction into a fresh directory outside the repository passed
tests and Android/BPF builds with no parent sources. Latest object contains three
programs and eight maps (the extra map isolates IPv6 CIDR policy).
