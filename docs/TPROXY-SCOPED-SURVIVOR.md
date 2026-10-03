# TPROXY scoped survivor / command lease — 2026-10-03

## Phase and scope

Implemented explicit scoped-v3 pidfd recovery for a surviving trusted anchor,
and a standalone native command guard retaining journal ownership across
worker/launcher death. This is an isolated IPv4 lifecycle experiment, not a
deployed production watchdog or permission to install host network rules.
Core code remains entirely in `ebpf-proxy/`; no KernelSU API, Yakit protocol,
certificate dependency, duplicate connection fields or backend selection.

## Changes

- `internal/tproxy/command_guard_linux.go`: native re-exec entry, private netns
  and owned lease checks, inherited flock ownership, TERM cancellation/direct
  child kill and Wait, creating-thread lifetime for PDEATHSIG.
- `internal/tproxy/journal_linux.go`: default v3 command runner uses that lease;
  strict v1/v2 keeps the previous runner. Journal schemas are unchanged.
- `internal/tproxy/probe_linux.go`: shared result collection; read-only probes
  still run their original exact argv directly without a helper.
- `internal/tproxy/supervisor_linux.go`: deadline-aware scoped cleanup retains
  its lease through the command guard rather than bypassing it.
- `internal/tproxy/guardian_linux.go`: `WatchScopedIsolatedPIDFD`, separate
  scoped context-aware recovery; old strict pidfd guardian remains available.
- `cmd/ebpf-proxy/main.go`, `tproxy_linux.go`, `tproxy_other.go`: native helper
  dispatch before normal CLI parsing, inert on non-Linux platforms.
- `internal/tproxy/survivor_linux_test.go`: native test dispatch and isolated
  actual supervisor/worker SIGKILL, pending-command ownership, pidfd recovery,
  cancelled-command and host/descriptor refusal tests.
- Standalone README, this report and sanitized machine evidence.

## Ownership / recovery protocol

1. Scoped controller owns secure journal flock. Its command guard inherits the
   same open file description, not a newly opened path or a numeric PID.
2. Guard keeps the lease while starting/waiting the exact direct command. It
   survives its launching worker's death. Each command is bounded by an
   8-second context; cancellation TERM asks the guard to kill/reap its child.
3. The trusted surviving anchor duplicates an already identity-pinned worker
   pidfd. No killing/adopting by PID or process name. While worker is alive,
   cancellation returns without recovery.
4. After worker exit, a still-running guard retains flock. Recovery reports
   blocked `state locked`; it does not modify rules or assume command exit.
5. After command/guard exits, a caller may retry. Pending proof allows only
   exactly no operation or the one planned operation, preserving other seven
   resources. Foreign references/conflicts still block recovery.

This test anchor is a trusted surviving native parent, not a newly deployed
Android service. Its identity files are private test fixtures with start-time
verification before/after pidfd acquisition, not a production IPC/authentication
design. Future embedding binaries must dispatch `CommandGuardEntry` before
ordinary parsing; the standalone directory already contains that dispatch.

## Actual targeted device evidence

Commands (each selector executed separately, avoiding ADB shell pipe quoting):

```
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o build/tproxy-survivor-tests ./internal/tproxy
adb push build/tproxy-survivor-tests /data/local/tmp/tproxy-survivor-tests
adb shell su -c 'TMPDIR=/data/local/tmp TP_RUN_PRIVILEGED=1 /data/local/tmp/tproxy-survivor-tests -test.v -test.run ScopedAnchorHostRejected'
adb shell su -c 'TMPDIR=/data/local/tmp TP_RUN_PRIVILEGED=1 /data/local/tmp/tproxy-survivor-tests -test.v -test.run PrivilegedScopedSurvivor'
adb shell su -c 'TMPDIR=/data/local/tmp TP_RUN_PRIVILEGED=1 /data/local/tmp/tproxy-survivor-tests -test.v -test.run PrivilegedCommandGuardCancellation'
```

All targeted tests passed. Scoped survivor 9.12 seconds; command cancellation
0.11 seconds. Actual output:

```
supervisor SIGKILL + worker SIGKILL: command/guard alive;
anchor exit_observed=true clean=false state locked; zero rule mutations
command/guard pidfd exit verified; pending add reconciled;
recovered=8 clean=true foreign fixture preserved
cancelled query: command and guard exited; lock reacquired; zero kernel mutations
```

The delayed fixture command executes the actual final iptables plan entry only
after fixture-owner release. The worker is killed while its journal says
pending add/owned=7. It cannot finish/save that mutation; the replacement anchor
must reconcile the actual resulting owned=8 state, not use fake command output.
An initial combined regex selector was split by ADB's shell quoting and failed
as a command invocation; no passing test result is attributed to that attempt.

Windows standalone `go test -count=1 ./...`, Linux arm64 `go vet ./...`, Android
native/BPF compilation, existing certificate/Yakit Go tests, App picker/backend
Node tests and original module-backend compilation passed. Freshly compiled
native module tests passed on Android, including profiles, certificate
transactions, backend defaults, App labels and saved-config/private-pipe
preflight. The actual standalone CLI internal guard rejects the host netns with
exit 1. The module binary produced by compatibility compilation was restored
to its original tracked version; no unrelated binary change is included.

Full native `./internal/tproxy` regression (`-test.v`, no selector) exited 0 /
**PASS**. Actual parent test durations: strict 16 committed windows 52.59 s;
strict 32 pending windows 104.45 s; scoped lifecycle 47.72 s; scoped 32 pending
windows 291.91 s; bounded supervisor 119.15 s; supervisor admission 10.67 s;
new scoped survivor 13.83 s; command cancellation 0.22 s. Graceful stop still
reports TERM=true/KILL=false, and ignored TERM still TERM=true/KILL=true.
Fixture worker tests skip only at top level and are invoked by parent tests.
No old test or assertion was removed. These timings are not a performance
benchmark; extra native re-execs increase scoped lifecycle overhead.

Fresh host baseline reads all exited 0. IPv4/IPv6 policy rules were identical;
IPv4/IPv6 table 38766 remained empty, with no own chain or priority entry.
**Full IPv4/IPv6 mangle baselines were not identical.** The only observed
differences were `tc_limiter_OUTPUT` owner-UID/CONNMARK rules: UID 10225 removed,
UIDs 10174, 10127, 10124, 10122 added, in both families. After excluding only
those exact vendor-chain owner rules, the rest of each mangle snapshot was
identical. The actor causing that system-chain change was not traced; do not
claim a whole-firewall unchanged result. No test manages that chain, and every
mutation fixture verifies a private namespace before operating. These external
system rules were neither adopted nor restored to an old snapshot.

Device: `5D5X5TFYDMGAEEWK`, Android 15 / SDK 35,
`5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284`, root `u:r:ksu:s0`,
SELinux Enforcing, host netns `net:[4026532071]`. Sanitized evidence:
`tproxy-scoped-survivor-android.json`. No full firewall dump is committed.

## Limitations / next phase

No guarantee after killing the command guard itself or losing all anchors.
PDEATHSIG and child lease are additional protection, not proof of arbitrary
descendant quiescence. Unknown programs that fork/daemonize or discard FDs need
separate process-tree admission. Direct-child Wait/file locking/file I/O/fsync
and uninterruptible kernel commands are not hard-real-time bounded.

Private netns only; host rule setup and mark override remain unavailable.
No installed module, WebUI, saved proxy profile, user/stock CA, global proxy,
netd BPF attach or release ZIP/version was changed. Existing host TUN/VPN state
is retained, not used as proof of a phone-wide no-TUN condition.

Next: test guard-loss/lease-discard refusal and define production command/anchor
admission plus identity handoff. Then implement UID production planning and
explicit host mark-risk admission. Real App HTTPS/Yakit, IPv6, network switching
and production fail-open acceptance remain separate unverified gates.

Git commit is supplied in the final handoff, not self-referentially embedded.
