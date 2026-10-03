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
gate. Unwitnessed pending intents block automatic recovery. Version-2 witnessed
outcomes and a surviving pidfd anchor are described below; no guardian is
automatically restarted. Whole-private-namespace snapshots are unsuitable for
a live Android firewall that netd modifies. No host-network setup CLI, watchdog service
or WebUI interception control is exposed. Tests create their private state using
`os.MkdirTemp` and remove only those test directories after completion. Set
`TMPDIR=/data/local/tmp` when running tests on Android without `/tmp`.

Parent-repository evidence: `docs/TPROXY-RECOVERY.md`. This document and the
test fixtures remain independent of KernelSU/Yakit runtime dependencies.

### Witnessed pending outcomes and replacement guardian

Version 2 adds `pending_proof`, a digest of the namespace excluding individually
verified planned resources. Before every mutation the controller checks all
eight resources and commits that witness. After a crash, only the original
owned-step profile or exactly one planned add/remove is admissible, with an
unchanged residual digest. Rule checks use exact `iptables -C`; unknown,
duplicate or mismatched resources are rejected, not adopted. Changes during
observation are also rejected. Version 1 stays readable, but legacy pending
intents without a witness still refuse automatic recovery.

The Android suite SIGKILLs workers in 32 pending windows: before/after the kernel
operation, for all eight add and eight remove operations. Committed-boundary
tests remain intact. A foreign chain introduced in a pending window is preserved
and blocks recovery until that change is removed by its owner.

`WatchIsolatedPIDFD` allows a surviving trusted anchor to replace a lost
guardian. It duplicates and validates a trusted pidfd, polls for that actual
process to exit, then acquires the state lock and recovers. It does not accept a
PID to kill, signal processes, or claim an unknown exit code. Cancellation and
ordinary non-pidfd files do not trigger cleanup. The test launcher pins the
worker identity while the original guardian is alive and verifies start time;
only the verified test pidfd is signalled. A real guardian SIGKILL and live
orphan/lock-exclusion test passes on the tested Android device.

These proofs assume an exclusive cooperative writer in a private namespace.
An external privileged actor recreating an identical planned resource cannot be
distinguished from the original writer. There is no guarantee after the entire
supervision tree/anchor is killed. No host setup API, production restart service,
WebUI integration or mark-safety approval is introduced.

Evidence and file list: `docs/TPROXY-PENDING-RECOVERY.md` in the parent repository.

### Read-only live-network preflight

```
ebpf-proxy tproxy preflight --config config.json
ebpf-proxy tproxy preflight --config - --probe-upstream
```

The second form accepts generic configuration through stdin, avoiding another
persisted credential file. `--probe-upstream` optionally opens TCP connections
and negotiates SOCKS5/authentication, but sends no CONNECT or payload. Neither
form binds the listener, changes a namespace, modifies routing/firewall rules,
loads BPF or enables interception. No setup/override option exists here.

Candidate selectors are configurable using `--mark-value`, `--mark-mask`,
`--table`, `--priority` and `--prefix`; defaults are bit 22, table 38766,
priority 9001 and ATP_LIVE. They are not claimed to be vendor-safe. Invalid
selectors fail before system queries. Reports distinguish query failures,
occupied/referenced tables, priorities, chain prefixes, listener ports and
packet-mark mask overlap. IPv4/IPv6 resources are checked even for an IPv4 PoC.
Structural state is observed before/after; changing state blocks the report.
Full firewall dumps and credentials are omitted from output.

Preflight always returns `status=blocked`, `automatic_setup_allowed=false`,
and exit 1 after emitting JSON. Vendor mark safety, live-resource ownership and
a production supervisor remain required. Finite UID allowlists (at most 32)
are required by the planned live PoC; empty, system or bypass-overlapping UIDs
are reported, not silently changed. All-UID and IPv6 policies are not downgraded.
This gate does not prove App interception, HTTPS MITM or crash recovery on the
host network. Reports are observations, not authorization for later writes.

The parent integration has a CLI-only `--backend-action tproxy-preflight`
adapter reusing saved upstream/authentication/UID configuration over stdin. It
does not create a runtime directory/lock, change profiles or enable a TPROXY
backend. An HTTP upstream produces a protocol-mismatch report, never an implicit
conversion to SOCKS5. Standalone preflight has no dependency on this adapter.

Device evidence: `docs/TPROXY-PREFLIGHT.md` and
`docs/tproxy-preflight-android.json` in the parent repository.

### Scoped recovery experiment (IPv4 private namespaces only)

`OpenScopedIsolated` selects a separate version-3 journal mode. It inherits
private owned state, strict identity/plan validation, flock/fsync and exact
reverse removal from `DurableIsolated`, but witnesses only the eight reserved
resources. Changes to unrelated firewall chains, disjoint policy marks/tables
and outside routes do not invalidate recovery. Two complete observations must
agree on the reserved footprint; exact rule checks still use `iptables -C`.

Reserved-prefix collisions, unexpected chain jumps/gotos, priority/table
references, routes in the reserved table and overlapping packet-mark use are
conflicts, not resources to adopt/delete. Unknown table aliases and duplicate
or modified owned resources also fail closed for recovery. The separate
preflight/vendor mark-safety gate is unchanged.

Each v3 pending proof excludes exactly the intended resource, preserving the
other seven. Reconciliation still permits only no operation or exactly one
planned operation. `WatchScopedIsolatedWorker` waits for the actual trusted
child exit before acquiring state and recovering. Version 1/2 readers reject
v3; the v3 reader rejects v1/2. No automatic migration weakens old journals.

Android tests cover three repeated cycles, interference refusal without
mutation, and all 32 before/after add/remove crash windows with unrelated
netd-shaped fixtures present. Existing strict recovery and relay tests remain.
These are private fixtures, not real netd concurrency. This mode still rejects
the host namespace. No host setup CLI, production supervisor deployment, UID
production planner, IPv6 recovery or WebUI backend is introduced. An external
privileged writer replacing an identical resource is not distinguishable;
observing then modifying the kernel is not an atomic transaction against it.
Loss of the entire supervision tree is not guaranteed fail-open.

Phase evidence and limitations: `docs/TPROXY-SCOPED-RECOVERY.md` in the parent
repository. The core remains independently buildable without module/UI paths.

### Bounded scoped supervisor experiment

`SuperviseScopedIsolated(ctx, stateDir, plan, options, factory)` is an independent
native API, not a host-network setup CLI. It refuses the host namespace before
calling a factory. The trusted factory only constructs a fresh, unstarted
`exec.Cmd`; no shell or product/module configuration is interpreted. The
supervisor starts/reaps the exact child and pins its identity with pidfd before
allowing concurrent Wait. Prestarted processes are never adopted or signalled.

FD 3 carries a single size-bounded newline-terminated readiness JSON:
`{"version":1,"ready":true}`. This must be emitted by the trusted worker only
after listener/upstream/policy readiness; stdout/stderr are not readiness.
Incomplete, oversized, unsupported or unknown-field records are rejected
without logging their contents. The supervisor does not independently prove
the worker's claimed data-path readiness.

One private owned `supervisor.lock` spans cleanup, child lifetime and backoff,
preventing a second launcher between workers. Before the first launch and
after every verified exit, v3 cleanup must succeed. Recovery failure blocks
restart; it never adopts conflicting resources. Retry budget is 0–3 restarts,
never reset by healthy time. Zero exit after readiness completes normally.
Readiness is bounded to 30 seconds, TERM grace to 10 seconds, verified KILL
wait to 5 seconds, backoff to 1 second, and recovery command context to 120
seconds. Defaults are supplied by the consumer; tests use an 8-second grace
because a 3-second grace interrupted legitimate Android rule cleanup.

Cancellation requests TERM through pidfd: the worker must disable interception
and drain/clean before exiting. After grace, pidfd KILL is the fallback. No
restart/cleanup is attempted if actual exit is unverified. Cancellation cleanup
has an independent bounded context, not the already-cancelled run context.
Network command deadlines propagate through scoped observations and removals;
timeout can leave a journaled partial state and blocks restart. File I/O/fsync
and a faulty blocking factory are not hard-real-time bounded by this API.

This is not production watchdog deployment or a guarantee after the supervisor
is killed. The subsequent scoped anchor/command-lease experiment below covers
a surviving trusted parent and a guarded in-flight direct command; arbitrary
process-tree crashes, readiness authenticity and host admission remain required.
The initial bounded-supervisor tests killed only steady-state fixtures.
No WebUI, installed backend selection, CA lifecycle or connection configuration
is changed. Evidence: `docs/TPROXY-BOUNDED-SUPERVISOR.md` in the parent repository.

### Scoped surviving anchor and command lease

`WatchScopedIsolatedPIDFD(ctx, trustedWorkerPidfd, stateDir, plan)` explicitly
recovers v3 state after the kernel-pinned worker exits. It duplicates the
descriptor, validates pidfd type, polls with cancellation, never signals the
worker and never reports an unobserved exit code. It rejects the host netns.
Recovery observes the caller's context; a cancelled observer does not adopt
ownership. Strict `WatchIsolatedPIDFD` continues to use strict v1/v2 recovery.

All default v3 controller observations/mutations, including supervised and
anchor recovery, now execute through a native re-exec command guard. The guard
inherits the **same open file description** for the private owned journal
flock on FD 3. It retains that descriptor until its direct command has been
waited/reaped, even if its original worker/launcher dies. A replacement
controller sees `state locked` while that command is outstanding; it must not
recover or start interception. Cancellation sends TERM to the guard; the guard
kills/reaps its direct command before closing its lease. No shell is used.

The standalone main dispatches `CommandGuardEntry(os.Args)` before normal CLI
parsing. Native tests dispatch the same entry in `TestMain`. A future embedding
executable must preserve this dispatch; copying this directory as a standalone
project already preserves it. Omitting dispatch is unsupported; there is no
fallback to an unleased runner. This internal helper accepts
only privileged trusted caller argv/inherited descriptors, not WebUI input or
an IPC request. It validates private netns and the regular owned 0600 lease.

The guard's direct child receives the lease as an additional layer and uses
Linux PDEATHSIG with the guard's creating thread kept alive through Wait.
However, this is **not** an arbitrary process-tree guarantee: unrelated guard
SIGKILL, all-anchor loss, executables that daemonize/close inherited descriptors,
uninterruptible kernel commands and external noncooperative privileged writers
remain limitations. The 8-second command context is not a hard wall-clock
quiescence guarantee; ownership remains blocked until the lease is released.
The supported experiment is a surviving guard around a trusted direct command,
with a surviving anchor pinning identities before launcher loss.

Android fixtures kill the actual bounded supervisor and worker while the final
entry-rule command is paused after its durable pending intent. The surviving
guard blocks ownership with zero recovery mutations; after the command is
released and both command/guard exits are observed via pidfd, the scoped anchor
reconciles the actual applied rule and removes eight owned steps. Unrelated
netd-shaped fixtures remain intact. A separate cancellation test verifies
command/guard exit and lock reacquisition without kernel mutations.

Still no production anchor deployment, host-network setup, mark-risk override,
UID production planner, IPv6 recovery or WebUI backend activation. Evidence:
`docs/TPROXY-SCOPED-SURVIVOR.md` in the parent repository.

### Guard-loss exit witness experiment

Flock availability is **not** proof of command quiescence: a direct command
can clear PDEATHSIG and discard its inherited lease, then outlive a killed
guard. The worker-only `WatchScopedIsolatedPIDFD` and bounded supervisor do not
automatically solve that case. Do not use them as guard-loss recovery admission.

`AcquireScopedCommandWitness(workerPidfd, guardPidfd, commandPidfd)` creates an
opaque owned witness while all three distinct identities are still live in the
same private netns. It duplicates descriptors, validates kernel pidfd type,
reads live fdinfo PID metadata only for namespace/distinctness validation, and
rechecks liveness. No numeric PID signaling or stale-journal adoption. Ordinary,
missing, duplicate, exited and foreign-namespace identities are refused.

`witness.Recover(ctx, stateDir, plan)` requires an explicit context deadline and
waits for **all three** pinned identities to exit before opening the journal.
It then uses the existing exact v3 pending proof/reverse cleanup. Cancellation
while an unleased command is alive makes zero recovery mutations. Polling only
outstanding identities avoids spinning on already-readable dead pidfds. Caller
closure/reuse of source descriptors does not affect the owned copies; `Close`
is idempotent and serialized with Recover (cancel first to interrupt a wait).
Keep the returned pointer; do not copy the witness value containing ownership
and a mutex.

Android fixtures kill supervisor, worker and guard in both supported tests:
the normal direct child exits via PDEATHSIG and pending add was not applied
(seven owned steps recovered); the lease/PDEATHSIG-discarding child stays alive
even though flock is available, so the witness blocks. Only after fixture-owner
release applies the final rule and the command exits does recovery reconcile
and remove eight steps. Foreign fixture rules are retained.

This is a trusted closed set for **one direct command**, not automatic command
registration or arbitrary process-tree tracking. The consumer must bind the
live witness to its state/plan before launcher loss and retain a surviving
anchor. The current command guard/supervisor does not yet transmit those pidfds
to a deployed anchor. Missing handoff, unknown descendants, all-anchor loss and
noncooperative privileged writers remain unadmitted. No live setup, production
watchdog, WebUI, UDP/DNS interception or backend default change is introduced.
Evidence: `docs/TPROXY-GUARD-LOSS-WITNESS.md` in the parent repository.

### Pre-exec admission primitive (isolated, opt-in)

`StartPausedScopedCommand(ctx, argv, lease)` launches a native exec stub with
the private journal lease on FD 3 and an inherited SOCK_SEQPACKET gate on FD 4.
It requires a live deadline within eight seconds and refuses the host netns.
No shell is introduced. The stub cannot exec until it receives exactly one
version-1 acknowledgement; EOF, timeout, malformed data or ancillary FDs fail.

`paused.Admit(workerPidfd, guardPidfd)` first acquires the three-identity exit
witness, then sends the acknowledgement. Failed validation is terminal and
kills/reaps the stub. Repeated admission is refused. Exec preserves the pinned
command identity. Keep the returned witness pointer in a trusted surviving
anchor bound to the exact state/plan. `Wait` reaps; `Abort` kills/reaps only this
owned direct command. Cancel the launch context to interrupt a running Wait.

`Admit` is a **local trusted-launcher primitive**; the cross-process opt-in
`HandoffScoped` alternative is described below. The guard dispatch understands the
stub token, but its ordinary v1 runner and the supervisor remain unchanged.
No automatic safe-recovery claim applies to those old paths. Production still
needs deployment of a registered runner/surviving anchor using the protocol below,
and tests of integrated guard loss at every command boundary. Arbitrary descendants,
all-anchor loss, host-network activation and mark-risk override remain outside
admission. Android tests prove refused commands have no file side effect and
an admitted real iptables chain is created/deleted only in a private netns.
Evidence: `docs/TPROXY-COMMAND-ADMISSION.md` in the parent repository.

### Cross-process command registration (isolated, one-shot)

`paused.HandoffScoped(ctx, channelFd, workerPidfd, guardPidfd, stateDir, plan)`
transfers three live pidfds **and the execution gate** via SCM_RIGHTS to an
independent anchor. Use a fresh inherited AF_UNIX/SOCK_SEQPACKET socketpair for
each command; no public IPC pathname or multiplexing is implemented.

The trusted launcher creates the receiver using
`NewScopedCommandAnchor(channelFd, expectedWorkerPidfd, expectedGuardPidfd,
stateDir, plan)`. `anchor.Accept(ctx)` checks pre-pinned role identities, namespace,
exact packet/FD count and state/plan binding, then owns a witness before echoing
the versioned nonce ACK. Sender validates it and sends a nonce-bound confirmation;
only then does the anchor release the exec gate. Sender
does not keep a second gate capability. An anchor killed before release causes
EOF/refusal, including the ACK-before-release crash window. ACK only proves
registration: `paused.Wait()` must still succeed before committing an operation.

The request/ACK/confirmation state machine uses a 65-byte packet carrying
version, random nonce and SHA-256 binding, never a
path, command, proxy configuration or credential. Binding includes private
directory identity/canonical path, boot, netns and exact plan. Numeric PIDs from
pidfd metadata are used solely for live-role comparison, never signaling/adoption.
Authentication relies on exclusive inherited capabilities plus pinned roles;
SO_PEERCRED on an inherited socketpair is not claimed to identify a later child.

Keep the `RegisteredScopedCommand` pointer returned by Accept, even if non-nil
alongside a release error. Its `Recover(ctx)` revalidates binding and waits for
all three exits before existing v3 recovery. Close/cancel lifetime is explicit;
cancel Accept before concurrently closing an anchor. Anchor and sender are
single-use. Missing/invalid ACK or confirmation refuses release without falling
back to local/worker-only admission.

Successful confirmation send is the execution commit point. Cancellation after
commit may kill the command but cannot undo side effects; Wait still decides
operation success. ACK alone never authorizes execution or journal commit.

Android tests cover 25 cross-process cases plus directory/plan binding checks,
including lost anchor before/after receive, before ACK and after ACK, malformed
packets/FDs, missing/bad confirmation, timeout/cancellation, source FD closure and eight-step recovery with
foreign rules preserved. Guard/worker roles in the new IPC fixture are trusted
independently pinned native processes, not deployment of the existing v1 guard.
The ordinary guard runner/supervisor/default backend remain unchanged. All-anchor
loss after release, arbitrary descendants, noncooperative privileged writers,
production UID/IPv6 lifecycle and host mark safety remain unadmitted.
Evidence: `docs/TPROXY-COMMAND-HANDOFF.md` in the parent repository.
