# ebpf-proxy

An independently buildable native TCP relay and cgroup eBPF redirect component.
This directory is its own Go module. It has no dependency on its parent project,
WebUI, package manager, module layout, or any specific proxy product.
The upstream adapter currently implements SOCKS5 CONNECT (IPv4, IPv6, domain,
optional username/password). The relay treats bytes as opaque TCP streams.

## Phase 1

Build: Go 1.26.4, `make` or `go build ./cmd/ebpf-proxy`.
Android arm64: `make android` (CGO disabled).
Run a fixed-destination PoC, without kernel hooks:

```sh
ebpf-proxy probe-upstream --config config.json
ebpf-proxy poc --config config.json --destination 93.184.215.14:443
```

Configure a local listener and generic SOCKS5 endpoint using
`config.example.json`. Keep credential-bearing files private (mode 0600).
The daemon has bounded concurrent connections, bounded copy buffers, per
direction idle timeouts, EOF half-close, and cancellation cleanup.
No payload is logged or parsed. IPv6 is supported by the SOCKS5 adapter; BPF
redirect and transparent original-destination recovery are subsequent phases.

No Android versions are yet claimed as fully supported. Android cgroup BPF
loading requires syscall and SELinux checks even with root. UDP policy is pass.
Kernel data structures will use stable UAPI contexts and a versioned shared ABI.
Native cgroup links will be required for crash detach; legacy persistent attach
will not be used. No CO-RE kernel field access is planned for kernels without BTF.

Testing: `go test ./internal/...` (and race testing on supported hosts).
Yakit MITM can be an example SOCKS5 upstream, but the component has no special
behavior for it. The user's trusted CA and upstream MITM behavior remain outside
this component. HTTP/2 and WebSocket bytes pass unchanged.

## Native redirect and control

`build.ps1 -Go <go.exe>` builds an Android arm64 daemon and BPF object with
Android NDK clang (BPF target). The object uses stable UAPI contexts and its own
BTF map descriptions, not kernel BTF/CO-RE. Linux daemon: `GOOS=linux go build`.
Set `bpf.object`, `bpf.cgroup` and a private absolute `runtime_dir` in config.

```sh
ebpf-proxy probe-kernel
ebpf-proxy verify-object --object redirect.bpf.o
ebpf-proxy run --config config.json
ebpf-proxy status --runtime-dir /private/runtime
ebpf-proxy uid --runtime-dir /private/runtime add 10234
ebpf-proxy uid --runtime-dir /private/runtime del 10234
ebpf-proxy uid --runtime-dir /private/runtime clear
ebpf-proxy uid --runtime-dir /private/runtime list
ebpf-proxy debug --runtime-dir /private/runtime flows
ebpf-proxy stop --runtime-dir /private/runtime
```

CLI flags precede positional subcommands. Control is private Unix HTTP (0600),
not a WebUI dependency. Daemon UID is always bypassed. UID allowlist or all
non-bypass policy, IPv4/IPv6 CIDR bypass and UDP pass are supported.

Connect4/6 save socket-local storage with a cookie and original destination.
Sockops TCP_CONNECT_CB publishes a full client/listener/family/port tuple before
the SYN, after ephemeral port assignment. Accept consumes that record. Close
cleanup checks the cookie; LRU capacity and timestamps bound stale metadata.
Shared structs live in include/flow.h and internal/redirect/abi.go (version 1).

Native unpinned BPF links detach on process death. A three-second kernel lease
also disables new interception if heartbeat stalls. Upstream greeting is checked
before attachment; interception is enabled last. Stop disables, detaches, then
drains streams for three seconds before cancellation. Existing failed/active
streams cannot transparently migrate to direct connections; fail-open applies
to new connects. No global proxy, routes or TUN interfaces are touched.

## Verified kernels and limitations

Linux 6.6.87.2 WSL2: isolated-cgroup integration test passed IPv4, IPv6,
1000 connections through SOCKS5, exact payload comparison, dynamic UID policy,
non-target direct, UID/CIDR bypass, UDP pass and lease expiry. Test invocation:
`EP_RUN_PRIVILEGED=1 EP_BPF_OBJECT=/path/redirect.bpf.o ./redirect-tests -test.v`
where `go test -c ./internal/redirect` builds redirect-tests. Only test child
processes enter a private cgroup; the root hierarchy is never changed.

Android 15 / 5.10.236: three actual programs and eight maps passed verifier
without kernel BTF. However Android netd connect4/6 programs occupy the root
cgroup with exclusive attach flags 0. The loader rejects this ancestor conflict,
preserving foreign programs and device networking. No Android transparent
redirect or external MITM acceptance is claimed. Root alone is insufficient;
the target must permit cgroup attachments (and SELinux BPF operations). No policy
allow rules are added absent specific denials. Native links and sk_storage are
required; legacy persistent attachments are not used as fallback.

IPv6 listener is ::1 at the same port. Upstream must actually speak SOCKS5;
an HTTP CONNECT port is not assumed compatible. DNS and all UDP remain native.
No TLS hooks, payload logging, capture or pinning bypass. Dynamic allowlist
commands have no effect in all_non_bypass mode. Map capacity is 16384 flows;
Socket-storage allocation failure passes the connection before redirect. A later
tuple publication/lookup failure rejects that single stream rather than guessing
its destination. LRU eviction can also fail a delayed accept under extreme load.

Extraction: copy this directory to a new repository and run the same builds;
there are no parent-relative source dependencies. Production module integration,
multi-device validation and network-change stability remain subsequent phases.
