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

## TPROXY investigation (experimental; no live-network controller yet)

`internal/tproxy` adds a read-only Linux/Android capability probe and transparent
TCP listener, without depending on BPF flow maps or any integration layer.
`OriginalDestination` uses the accepted socket's local address (getsockname),
and has the existing generic relay resolver signature. SOCKS5 and byte relay
remain unchanged. IPv4/IPv6 transparent socket options are supported; actual
TPROXY packet interception has only been tested with IPv4 so far.

```sh
ebpf-proxy tproxy probe
# Isolated kernel-path proof ONLY; refuses the host network namespace:
unshare -n ebpf-proxy tproxy poc-isolated
```

The probe returns command exit codes/stderr, kernel configuration, socket-option
tests, routing and mark references. Full system firewall dumps are not emitted.
It never writes firewall/routing/sysctl/BPF settings. Mark 0x00400000 is only a
candidate; vendor ingress masks and future netd/BPF behavior mean automatic
live-network installation is **not allowed**. No universal ROM profile is claimed.

The isolated PoC installs two owned chains, priority 9001 and table 38766, then
connects to a non-local test destination and checks exact original destination.
A specific initial host route and a test source address are created only in the
fresh namespace. Interception is enabled last; rollback removes entrance jumps
first and all resources in reverse order. A destroyed namespace also cleans up
after crashes. No existing Android chains/netd programs or host routes are changed.
KernelSU domain policy on the tested device permits the socket options and this
isolated test; no additional SELinux permission is added or assumed for other ROMs.

Tests: `go test ./...`; privileged Linux/Android tests opt in using
`TP_RUN_PRIVILEGED=1 ./tproxy-tests -test.v`, built with
`go test -c ./internal/tproxy`. Each real interception or injected setup-failure
case runs in a newly created network namespace. Host-namespace refusal is tested
without performing writes. This is NOT yet an App UID, direct-relay or SOCKS5
MITM acceptance result. No production setup/repair API is exposed prematurely.
UDP/DNS/QUIC remain untouched. Existing TUN/eBPF defaults and tests remain intact.

### Direct relay and UID/SOCKS5 fixtures

```sh
unshare -n ebpf-proxy tproxy relay-isolated
unshare -n ebpf-proxy tproxy socks5-isolated
ebpf-proxy tproxy test-upstream --address 192.0.2.10:1080
# Optional explicit HTTP diagnostic; this is NOT intercepted traffic:
ebpf-proxy tproxy test-upstream --address 192.0.2.10:1080 \
  --http-destination example.com:80 --http-host example.com
```

The two fixtures reject the host namespace and existing routes/firewall/policy.
Root-owned executable files need mode 0755 so child UID 41001/41002 can execute
them; no credential-bearing files or writable directories are shared. Root is
deliberately also selected in the fixture to prove that daemon UID bypass wins.
Both child UIDs connect simultaneously to the same destination, with distinct
64 KiB opaque payloads and half-close. Only UID 41001 must enter the relay.
Target UID UDP/443 passes a separate 4096-byte datagram without interception.
Upstream IP/port bypass and new direct connections after stopping the relay are
verified. Stop removes the OUTPUT entrance before cancelling the relay.
On Android with procfs hidepid, the root launcher passes a verified namespace
descriptor to workers so they need not read /proc/1; no policy is relaxed.

The direct connector and SOCKS5 share the same generic Connector interface.
Fixture SOCKS5 protocol implementation is isolated in `internal/testutil`, not
the TPROXY backend; it only forwards one exact test destination. Relay and BPF
code do not parse HTTP. The optional HTTP parser is strictly a CLI diagnostic
client, not a proxy data path. Only status and response size are emitted, not
payload. The address flag is transient, not a second persisted upstream config;
authenticated checks continue to use `probe-upstream --config` with the existing
generic private config.

The local original-destination fixture intentionally exercises UID separation
and relay correctness separately from the earlier nonlocal policy-routing PoC.
It does not prove routing of a real Android App through an external MITM server.
Mark safety, live-network setup, crash watchdog, IPv6 traffic and integration
remain gated. UDP/DNS are not intercepted; HTTP/3 may bypass interception.

### Transactional destination-only rule planner

`internal/tproxy/plan.go` generates validated IPv4 destination-only test rules;
`transaction.go` executes trusted argv steps, retaining ownership in memory.
The nonlocal isolated PoC now uses these components. Interception is enabled
last and disabled first. Removal uses exact `-D` rules rather than chain flush.
Failed removal stops dependency cleanup and preserves the outstanding steps
for retry. Setup after a failed stop is rejected, not reported as ready.
Repeated setup/teardown on the same controller is idempotent and serialized.
Pre-existing resources are never adopted after a failed create.

Privileged `TestPrivilegedTransactions` checks three repeated lifecycle cycles,
failure after each of eight rule-plan steps, and preservation of an unrelated
same-name chain, all inside a private network namespace. Unit tests additionally
cover failed disable/retry, partial rollback, concurrent lifecycle calls and
invalid addresses/prefixes/marks/table/priority. Android verification details are
in the parent repository's `docs/TPROXY-TRANSACTIONS.md` (not a build dependency).

This is **not** a production recovery controller. Ownership is not persisted,
command timeout can leave an uncertain outcome, and another administrator can
alter resources externally. A durable intent journal, namespace-bound ownership
verification, preflight conflict checks and an independent watchdog are still
required before live setup/repair is exposed. Nothing here claims mark safety
on a vendor ROM or SIGKILL recovery. No new WebUI or module backend is enabled.

### Experimental durable recovery (isolated namespaces only)

`journal.go` defines a versioned, size-bounded record with boot ID, namespace,
typed plan, committed owned-step count, pending intent and snapshot digest.
`journal_linux.go` provides `OpenDurableIsolated`, `Setup` and `Recover`; it
refuses the host namespace. Records never carry executable commands. Recovery
regenerates the plan and requires an independently supplied matching plan.
Private state must be owned 0700 directories and owned single-link 0600 files;
symlinks are refused. File/directory fsync, atomic rename and nonblocking flock
provide durable commits and one cooperative cross-process owner.

`guardian_linux.go` provides `WatchIsolatedWorker` for a surviving parent. It
waits for the actual child exit, then reopens the journal and removes exact
owned resources, starting with OUTPUT interception. Android tests SIGKILL the
worker at 8 committed add and 8 committed remove boundaries. Repeated recovery,
concurrent-owner exclusion and refusal of unexpected external changes are
tested. An initial journal-write failure must leave the kernel unchanged.

This updates the previous phase's in-process-only status, **not** its production
gate. A pending intent between command execution and durable commit is still
ambiguous and blocks automatic recovery. A killed guardian is not automatically
restarted. Whole-private-namespace snapshots are unsuitable for a live Android
firewall that netd modifies. No host-network setup CLI, watchdog service, WebUI
or module integration is exposed. Tests create their private state using
`os.MkdirTemp` and remove only those test directories after completion. Set
`TMPDIR=/data/local/tmp` when running tests on Android without `/tmp`.

Parent-repository evidence: `docs/TPROXY-RECOVERY.md`. This document and the
test fixtures remain independent of KernelSU/Yakit runtime dependencies.
