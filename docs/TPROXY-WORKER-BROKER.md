# TPROXY P0: worker-wide broker, membership and restart gate

Date: 2026-10-03. Scope: cooperative trusted worker in a verified private network
namespace; destination-only IPv4 plan. Host setup remains unavailable. No netd
BPF detach, mark-risk override, WebUI/default change, saved configuration/CA
change, module installation or release ZIP. Version unchanged without repack.

## Changes

- `internal/tproxy/worker_broker_linux.go`: exact-command broker protocol,
  closed serial command registry, opt-in journal runner, durable admission
  marker and opt-in bounded worker-wide supervisor.
- `worker_broker_linux_test.go`: membership/security tests and actual native
  worker/guard/anchor/launcher crash tests.
- `registered_command_linux.go`: trusted broker can bind native guard/anchor to
  its actual pinned worker child. Public one-command entry remains self-bound;
  only internal broker Wait admits a verified recovered/all-three-exit report.
- `supervisor_linux.go`: shared attempt machinery accepts an explicit private
  broker channel, callback after child pinning and owned PDEATHSIG attributes.
  Legacy entry retains its original behavior.
- `journal_linux.go`: close opt-in broker capability with journal controller.

The independent core does not read module config or call KernelSU/Yakit APIs.

## Closed membership / execution contract

Worker readiness is FD3; inherited broker is FD4. Every journal operation uses
`OpenBrokeredScopedIsolated`; its `d.run` delegates queries/checks/adds/removes to
the parent instead of invoking an unregistered local process. The client
serializes concurrent callers and refuses local fallback on protocol loss.

The server validates strict versioned JSON, increasing request IDs, plan/state
binding, exact permitted argv and exact private owned lease inode received via
SCM_RIGHTS. Read queries are mangle `-S`, `ip rule show` and `ip route show table
all`. Mutations/checks derive only from eight plan steps. No arbitrary shell,
absolute executable, flush command, caller-supplied state path or credentials.

Reserve happens before process launch; only one command may be outstanding.
Completion requires real guard and anchor exits plus the anchor's direct-command
quiescence proof. Prior anchors have exited before the next command starts, so
one active anchor cannot recover concurrently with another registered command.
No completed-command counter is incremented on missing proof.

Before cleanup/restart: worker exit must be observed; broker must be drained and
sealed; Requested must equal Completed; Active and Blocked must both be false;
the original state binding must still match. V3 pending/resource proof then
decides whether exact reverse recovery is permissible. Foreign interference
remains a recovery blocker. Reply loss stops the worker; it does not itself
erase an already-observed exit proof. Operation failure is not proof failure.

On worker death during a command, native anchor waits for worker+guard+command
and performs existing v3 recovery. On worker death after final command exit but
before journal commit, the parent has complete command membership and resolves
the pending record. Launcher-loss PDEATHSIG uses a creating OS thread locked
through attempt exit, not an unsafe short-lived Go spawning thread.

## Admission persistence / failure behavior

Session flock spans child execution, recovery, backoff and restart. Exclusive
0600 `broker-session.json` is synced, followed by directory fsync, before any
child launch. No runtime argv or PID is written into it. It is deliberately a
blocking admission marker, not a recoverable process registry.

Missing proof retains the marker and forbids cleanup/restart. An incoming
launcher must not remove it just because flock is free. Prior nonempty journal
state is not adopted either. Exact successful cleanup removes and directory-syncs
the marker. This trades automatic availability after launcher loss for explicit
fail-closed safety; ordinary continuation is not authority to remove it.

## Tests and device evidence

Device: Android 15 SDK35, arm64 kernel
`5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284`, KernelSU
`u:r:ksu:s0`, SELinux Enforcing.

Initial nine-case native worker-broker batch: **PASS 129.81 seconds** (child
129.78), prior to adding cancellation/protocol/command-failure and launcher-loss
cases. Evidence:

| Case | Result |
| --- | --- |
| Normal setup/recover | completed; 450 registered / 450 verified |
| Last add applied before journal commit SIGKILL | exhausted; clean; 206 / 206 |
| Steady worker SIGKILL | exhausted; clean; 220 / 220 |
| Worker loss during command | exhausted; clean; 206 / 206 |
| Worker+guard loss, direct command discards lease | exhausted; clean; 206 / 206 |
| Worker executable missing | exhausted; clean; 0 / 0 |
| Crash then normal worker | completed; two attempts / one restart |
| Stale admission marker | no launch, no cleanup/adoption |
| Active anchor SIGKILL | blocked; 206 requested / 205 verified; marker retained; no retry |

Final-source launcher-loss test: **PASS 11.06 seconds** (child 11.05).
Four live identities were transferred through an inherited private channel,
not reconstructed from files. SIGKILL of pinned launcher caused pinned worker
exit. Independent anchor kept pending state unchanged while the direct command
was alive, then recovered eight owned steps. Foreign fixture was preserved.
Replacement launcher refused the remaining marker without launching a worker.

Final native registry/command-boundary unit tests: PASS. Portable core tests,
Linux/arm64 vet, Android native/BPF build, native module regression and existing
Node App picker/backend tests: PASS. Final expanded broker batch: **16 cases
PASS 142.70 seconds** (child 142.68). Additional results:

- Concurrent journal callers: completed, 464 requested / 464 verified.
- Cancel while final command pending: stopped, clean, 206 / 206, no restart.
- Command executable fails: exhausted after clean recovery, 25 / 25; execution
  failure is correctly distinguished from unknown process lifetime.
- Malformed sequence, wrong lease inode, extra descriptor: blocked with no
  command execution, cleanup or retry.
- Startup failure before command admission: exhausted and clean, 0 / 0.
- Pre-exec worker loss: **PASS 8.02 seconds** (child 8.00); 206 requested / 205
  verified, persistent block and no cleanup/restart.
- Launcher loss re-run on final expanded binary: **PASS 12.58 seconds** (child
  12.56), including refusal of replacement after isolated recovery.

Full Android `internal/tproxy` regression: **exit 0 / PASS**. Includes existing
admission/handoff, guard/survivor loss, 16 strict committed boundaries, 32 strict
pending boundaries, 32 scoped pending boundaries, transaction/UID relay and
legacy bounded supervisor tests. Scoped pending suite passed in 260.67 s;
legacy supervisor in 91.26 s; 13-case broker batch in 155.82 s; pre-exec loss
in 9.84 s. Its binary includes final production source but predates only the
expanded descriptor/concurrency and launcher-loss test fixtures; those tests
were run separately on the final expanded binary above.

After all test processes completed, all six read-only host snapshots matched
the captured baseline: IPv4/IPv6 policy rules, IPv4/IPv6 mangle rules and both
families of table 38766 (empty). Existing host TUN/VPN references were retained;
no claim is made that the entire phone has no preexisting TUN/VPN. No host
network write or corresponding host rollback occurred. Only exact fixture
resources in private namespaces were mutated. Lost-proof fixtures intentionally
leave owned state blocked until their disposable namespace is destroyed.

Example test workflow (only scratch test binaries, not installed module):

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o build/tproxy-broker-tests ./internal/tproxy
adb push build/tproxy-broker-tests /data/local/tmp/tproxy-broker-tests
adb shell su -c 'chmod 755 /data/local/tmp/tproxy-broker-tests; chown 0:0 /data/local/tmp/tproxy-broker-tests'
adb shell su -c 'TMPDIR=/data/local/tmp TP_RUN_PRIVILEGED=1 /data/local/tmp/tproxy-broker-tests -test.v'
```

## Remaining P0 gates / limitations

- This is a new opt-in cooperative worker API, not conversion of all legacy
  entry points. Mixing legacy/local writers into a brokered worker invalidates
  closed membership. Real relay/module worker adoption is not claimed.
- Admission marker blocks replacement after launcher loss; no verified durable
  cross-launcher transfer of the complete cohort or automatic repair is provided.
- Anchor loss during its own recovery, combined loss of witnesses, hostile root
  mutation and arbitrary/unreaped descendants remain unadmitted. Recovery errors
  block rather than grant restart permission.
- Parent cleanup uses existing leased guards; guard/recovery failure must remain
  blocked. Crash-window coverage of those recovery commands needs expansion.
- Concurrent callers and basic protocol/descriptor faults are covered. Need
  broader packet truncation/replay/channel loss matrices and long-running
  repeated worker attempts before claiming all P0 invariants universally proven.
- Host fwmark safety, actual App/Yakit HTTPS, IPv6 traffic, network transitions,
  module lifecycle and UI integration remain later phases, not this P0 result.
