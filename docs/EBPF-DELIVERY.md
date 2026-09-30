# eBPF backend delivery — v1.0.27

## Outcome

Implemented the independently extractable TCP redirect core and module/WebUI
integration. Existing TUN is retained and remains the default for legacy config.
Full Android/Yakit acceptance is NOT complete on the current test device.

## Phase commits

- a7fed8f: baseline, configuration/lifecycle and device investigation.
- af3fc3c: independent SOCKS5 relay PoC and Android fixture tests.
- 5acc203: versioned BPF ABI, connect4/6, original-destination recovery and UID maps.
- cbff626: optional module backend adapter, preflight and lifecycle.
- 22c079b: WebUI selector/status/diagnostics, existing configuration reuse.
- Final release commit: failure/lifecycle regression and v1.0.27 packaging.

Phases 2–4 share one core implementation commit, while IPv4/IPv6/dynamic UID
behaviors have separate assertions. Phase 7 production/device acceptance is pending.

## Components and files

- ebpf-proxy/bpf/: native connect hooks, socket storage, sockops publication,
  separate IPv4/IPv6 CIDR tries, UID/bypass maps and counters. No payload handling.
- ebpf-proxy/include/flow.h: centralized versioned C ABI, compile-time assertions.
- ebpf-proxy/internal/redirect/: native-link loader, hierarchy conflict detection,
  map ABI validation, full-tuple recovery, cookie-aware cleanup and monotonic lease.
- ebpf-proxy/internal/relay/ and upstream/: bounded opaque TCP stream relay and
  generic SOCKS5 IPv4/IPv6/domain/RFC1929 adapter.
- ebpf-proxy/internal/daemon/: private Unix control API, runtime locking,
  listener/upstream readiness, graceful stop and resolver/map lifetime management.
- cmd/tun2proxy-web/backend.go: module-only config translation and controller.
- webroot/backend.js and index.html: selection, status and diagnostics.
- system/bin/tun2proxyctl, customize.sh, uninstall.sh: lifecycle/install integration.
- build-ebpf.ps1, pack.ps1, pack.sh, cmd/test-release.ps1: builds/package validation.
- LICENSES/ebpf-proxy/: core MIT and cilium/Go dependency notices.

Core source never imports module/WebUI/KernelSU packages, reads their config, or
invokes tun2proxy. Copying the core directory outside this repository passed
independent Go tests and Android native/BPF builds. eCapture is a reference only.

## Configuration

Only optional backend (default tun) and ebpf_port (default 18080) were added.
Each saved computer profile carries them. Existing proxy_url provides host,
port, scheme and decoded authentication. route_mode/app_packages resolve to UID
policy; bypass_ips supplies CIDRs; root/daemon UID is bypassed. Config translation
produces a separate generic JSON file under private runtime storage (0600).
No duplicate host/port/password inputs. HTTP CONNECT is explicitly not assumed
to be SOCKS5. Existing DNS/TUN/UDP/Auto Start fields and implementation are retained.
eBPF DNS/UDP pass natively; existing TUN network settings apply when switching back.

## Proven tests

- Android arm64: original App label, profile, certificate transaction/API and
  routing regressions plus new adapter/default tests passed.
- Node: existing App name/package multi-selection and new backend form/state/
  IPv6/auth/network-field preservation tests passed.
- Android: SOCKS5 fixture relay, 2 MiB half-close/backpressure, 1000 short
  connections, idle timeout, cancellation, RST and offline upstream passed.
- Android: private runtime permissions, duplicate lock and symlink rejection passed.
- Android 5.10.236: actual BPF object verifier passed 3 programs / 8 maps without
  kernel BTF. Real attach preflight rejected exclusive netd ancestor hooks.
- Linux 6.6.87.2 private cgroup: 1003 successful redirected connections through
  SOCKS5 with matching bytes, IPv4/IPv6 original destinations, target/non-target
  UID, dynamic add/del, root/CIDR bypass, IPv6 ::/0 isolation, UDP pass, disable
  and lease expiry passed. Additional 100 refused connects left no stale tuples.
  Final counters: redirect=1103, flow_published=1103, metadata_failures=0;
  relay accepted=1003, upstream_failures=0, residual flow entries=0.
- Linux: SIGKILL removed all 3 native links; daemon readiness, UID control,
  stop, restart and control-socket cleanup passed.
- Android TUN fallback: isolated route-off engine startup/stop passed; temporary
  ep-fallback interface was removed. Existing installed config was not replaced.
- Cross-builds and go vet passed. ZIP checked required runtime assets, source
  exclusions, Android arm64 ELF, BPF ELF and version/versionCode metadata.

Privileged child tests only join dedicated test cgroups; foreign programs are not
detached, replaced or overridden. No SELinux broadening, global proxy change,
TLS hook, HTTP parsing, packet capture or new TCP/IP stack was introduced.

## Device blockers and remaining acceptance

Current device: Android 15 SDK35, arm64, kernel
5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284; KernelSU domain u:r:ksu:s0,
SELinux Enforcing. BPF/CGROUP_BPF/JIT/INET/IPV6 are enabled; kernel BTF absent.

Root connect4/connect6 netd programs IDs 23/24 use exclusive attach flags 0.
Private child connect link tests returned EPERM; sockops native link succeeded.
The loader rejects the identified hierarchy conflict before enabling interception.
No matching BPF denial was found that justified a SELinux allow-rule change.
Do not replace netd programs merely to bypass this limitation.

Saved external endpoint 192.168.30.102:8083 failed TCP reachability during tests.
It has therefore not been proven to provide a usable SOCKS5 upstream on this run.

Target-APP Android HTTPS/Yakit request-response modification/plugins, external
HTTP2/WebSocket, mobile/Wi-Fi transitions, module disable/enable, device reboot,
other Android kernels and Conscrypt behavior with this backend remain unverified.
Proceed using a device/kernel that permits safe cgroup attachment, and a reachable
verified SOCKS5 proxy. Existing active TCP streams do not migrate on failure;
fail-open covers new connects. Metadata publication failure rejects the affected
stream rather than guessing its original destination.

## Release

Artifact: D:/Android-Projects/tun2proxy-for-KernelSU-v1.0.27.zip

SHA256: 22EABA803870B0CE4C24DD75F620E9B1FA565601C2B374D4007A20DE543ECF26

Built once with patch/versionCode incremented. Not flashed over the installed
module and no reboot performed. This report was added after ZIP validation;
it is repository evidence, not a claim that all device acceptance passed.
