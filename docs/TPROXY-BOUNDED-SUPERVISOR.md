# TPROXY bounded scoped supervisor — 2026-10-03

## Phase / status

Implemented a generic native API for finite restart budgets, startup readiness,
pidfd stop escalation, session ownership and context-aware v3 recovery. All
operation remains experimental/private-namespace only. No host setup API,
production watchdog deployment, module/backend switch or WebUI integration.

## Files / key changes

- `ebpf-proxy/internal/tproxy/supervisor.go`: options bounds and sanitized
  versioned attempt/result schema. No upstream product/module configuration.
- `supervisor_linux.go`: private-namespace/pidfd preflight, secure session lock,
  trusted fresh child factory, dedicated readiness pipe, verified child reaping,
  TERM/KILL grace and finite retries gated on successful v3 cleanup.
- `supervisor_test.go`, `supervisor_linux_test.go`: options/readiness, host
  refusal, crash/restart, budget exhaustion, graceful/hung/timeout/failed startup,
  conflict refusal, cancellation, session/symlink/prestarted-process security.
- `probe_linux.go`: `queryContext`; existing `query` retains its 8-second
  per-command behavior with background context.
- `witness_linux.go`, `scoped_linux.go`: injectable command runner for bounded
  snapshots/exact rule checks; default strict/scoped behavior unchanged.
- `journal_linux.go`: initialized command runner for scoped observations and
  mutations; supervisor supplies one recovery deadline. No schema migration.
- Standalone README and this evidence record.

Core extraction remains unchanged: all new logic resides in `ebpf-proxy/`,
recognizes typed plans/UID-neutral resources/standard child processes, and does
not depend on KernelSU, WebUI, Yakit or tun2proxy. No persistent connection
fields were added, duplicated or rewritten.

## Lifecycle / contracts

Before invoking a factory: validate bounded options/plan, verify private netns,
probe pidfd open/signal-0 support, acquire a private owned 0600 no-follow
`supervisor.lock` under the existing secure owned 0700 state root, recover old
v3 state. This lock spans backoff and child lifetime in addition to the journal
lock used by workers, preventing concurrent launchers between child exits.

The trusted factory must construct and promptly return an unstarted command
without ExtraFiles. The supervisor supplies FD 3, starts the process, opens a
pidfd **before** concurrent Wait can reap/reuse the PID, and waits for dedicated
readiness `{"version":1,"ready":true}\n` (maximum 256 bytes). Contents/credentials
are not logged. Readiness claims are from a trusted worker, not an independent
proof of App/upstream interception. The worker is responsible for listener
first, upstream verification and policy last.

After readiness, normal running may continue until child exit or cancellation.
Cancellation requests pidfd TERM so the worker disables policy/drains/cleans;
after configured grace it escalates to pidfd KILL and bounded exit wait. Cleanup
is never started before actual exit, except a failed launch where no child ran.
Prestarted/unverified processes are not killed, reaped or adopted. Exit-unknown
and ownership/recovery failure are blocked states, not false clean results.

Each verified exit must be followed by successful v3 reconciliation/recovery
before another launch. Cleanup gets a fresh bounded context even when the run
context was cancelled. Kernel commands/observations share that deadline, while
the existing 8-second per-command ceiling remains. Recovery errors stop rather
than retrying ambiguous ownership. Any partial journal state is preserved for
explicit later investigation/recovery.

Budget is at most 3 restarts/4 attempts, including launch failures; it never
resets. Backoff is cancellable, maximum 1 second. Readiness maximum 30 seconds,
TERM grace maximum 10 seconds, KILL exit wait maximum 5 seconds, recovery
command context maximum 120 seconds. A healthy daemon's lifetime is not capped;
consumer context controls stopping. Zero exit after readiness completes
normally rather than silently respawning.

## Actual device tests / first failure

Android test device `5D5X5TFYDMGAEEWK`; tests run through ADB root in verified
disposable private netns. Installed module/profiles were not modified.

```
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o build/tproxy-supervisor-tests ./internal/tproxy
adb push build/tproxy-supervisor-tests /data/local/tmp/tproxy-supervisor-tests
adb shell su -c 'chmod 755 /data/local/tmp/tproxy-supervisor-tests'
adb shell su -c 'chown 0:0 /data/local/tmp/tproxy-supervisor-tests'
adb shell su -c 'TMPDIR=/data/local/tmp TP_RUN_PRIVILEGED=1 /data/local/tmp/tproxy-supervisor-tests -test.v -test.run Supervisor'
```

First run exposed an inadequate 3-second TERM grace. `graceful_stop` was
escalated to KILL before legitimate rule cleanup completed, with 3 steps left
for the parent to recover. Parent verified exit/recovered successfully; the
test correctly failed its no-KILL graceful-stop expectation. Other crash,
budget, ignored-TERM, readiness and conflict cases passed. Initial bounded suite
83.21 seconds, **FAIL**, not counted as a successful run.

Grace was corrected to 8 seconds in tests, with a configurable hard upper bound
of 10 seconds. The ignored-TERM case retains a 100 ms test grace to prove KILL
fallback; no failure handling or old test was deleted.

Corrected targeted run: bounded supervisor **PASS (83.92 s)**; admission
**PASS (7.60 s)**. Final full native `./internal/tproxy` regression, using
`-test.v` without a test filter, exited **0 / PASS**. Its supervisor suite
passed in **92.72 s**, admission in **9.24 s**. Key actual outputs:

```
crash_then_normal: state=completed attempts=2 restarts=1 clean=true
crash_budget: state=exhausted attempts=2 restarts=1 clean=true
graceful_stop: state=stopped attempts=1 clean=true term=true kill=false
ignored_term: state=stopped attempts=1 clean=true term=true kill=true
readiness_timeout: state=exhausted attempts=1 clean=true term=true kill=false
invalid_readiness: state=exhausted attempts=1 clean=true term=true kill=false
startup_failure: state=exhausted attempts=2 restarts=1 clean=true
foreign ownership conflict: blocked, one launch only
session contention/symlink/prestarted process refused
cancelled recovery: zero mutations; explicit retry clean
```

Finite factory failures and cancellation with independent cleanup also passed.
Existing strict 16 committed-boundary windows (54.27 s), strict 32 pending
windows (103.37 s), scoped 32 pending windows (220.56 s), scoped lifecycle
(33.29 s), UID/direct/SOCKS relay and rollback tests were retained and passed.
Fixture-worker tests are skipped at top level and invoked by their parent
tests; this is not a missing privileged suite.

Windows standalone `go test -count=1 ./...`, certificate/Yakit tests, existing
Node App picker/backend tests, Linux arm64 `go vet ./...`, standalone Android
native/BPF build and module backend build passed. The existing native module
regression binary was re-run on-device and passed.

After all privileged tests, fresh host `ip rule show`, `ip -6 rule show`,
IPv4/IPv6 `mangle -S`, and IPv4/IPv6 table 38766 reads all exited 0 and matched
the pre-test baseline exactly after CRLF/trailing-newline normalization. Both reserved tables
remained empty. Existing host `tun0` references were present in the baseline
and retained; this round makes no claim that the whole phone has no VPN/TUN.
Device: Android 15 / SDK 35, kernel
`5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284`, UID 0 in
`u:r:ksu:s0`, SELinux Enforcing, host netns `net:[4026532071]`.
See `tproxy-bounded-supervisor-android.json` for sanitized machine evidence.

## Network scope / rollback / limitations / next

Parent and child independently refuse `/proc/1/ns/net`. Test workers bind a
transparent listener before private rules, and fixture cleanup removes only
exact owned entries. Existing foreign netd-shaped resources must remain intact.
No host rule, Android global proxy, TUN/VPN, netd BPF program, upstream setting,
stock/user CA or installed backend is modified. No release ZIP/version bump.

This API does not solve loss of the supervisor itself or all anchors. It does
not guarantee hard deadlines for filesystem/fsync or a faulty blocking factory.
It does not guarantee command-descendant quiescence after arbitrary worker
SIGKILL: steady-state fixture crashes contain no in-flight commands. Readiness
is a trusted child assertion; production upstream/listener/policy validation
still needs deployment. Recovery conflicts/timeouts may leave owned state and
are explicitly blocked rather than claimed universally fail-open.

Next: integrate a surviving anchor and verified process-tree/command lifetime,
exercise supervisor-loss/replacement privately, then implement host admission
and UID production planning. Mark risk remains unapproved, IPv6/live App HTTPS
MITM/netd concurrency/network/backend-switch acceptance remain unverified.
Repeated requests to continue do not authorize live risk override. Do not
enable WebUI/live interception yet.

Git commit: supplied in the final handoff, not embedded self-referentially here.
