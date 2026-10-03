# TPROXY guard-loss exit witness — 2026-10-03

## Phase / scope

Added an explicit, independently usable native exit-witness gate for one
trusted worker/guard/direct-command set. It closes the tested gap where a
command discards its inherited lease and clears PDEATHSIG before guard loss.
The gate is opt-in private-netns API, **not** deployed production recovery and
not automatically wired into every existing supervisor/controller.

## Files / implementation

- `ebpf-proxy/internal/tproxy/command_witness_linux.go`: opaque owned witness,
  live same-netns/distinct pidfd validation, ownership-preserving duplication,
  deadline-aware all-exit polling, then existing v3 reconciliation/recovery.
- `guard_loss_linux_test.go`: actual guard SIGKILL with retained and discarded
  lease/PDEATHSIG; live-command refusal even when flock is available; missing,
  duplicate, ordinary, exited, host/foreign-netns and closed witness refusal;
  source descriptor closure, bounded cancellation and foreign preservation.
- `survivor_linux_test.go`: existing delayed command fixture gains explicit
  opt-in lease/PDEATHSIG discard mode; default and old tests remain unchanged.
- Standalone README, this report and sanitized machine evidence.

No main CLI, WebUI, module lifecycle, saved upstream/profile, UID routing,
certificate code/schema or public BPF ABI was changed. No core config fields.
The directory remains standalone-buildable; core API has no Yakit, KernelSU,
WebUI or tun2proxy dependency.

## Trust / admission contract

Trusted launcher supplies kernel-pinned live descriptors before process loss.
Constructor owns copies, rejects non-pidfds, unavailable PID metadata, duplicate
identities, already exited processes and different netns. It reads numerical
PIDs only for namespace metadata; never signals or adopts by PID/process name.
It rechecks pinned liveness after metadata reads to refuse raced handoff.

Caller must bind this exact command set to its state directory/plan and prevent
unregistered commands. The API cannot prove an arbitrary descendant tree or
authenticate a future production IPC channel. Zero/closed/nil objects do not
authorize recovery. A lost handoff is not reconstructed from a PID inventory.

Recover requires an explicit deadline, refuses the host netns, waits for all
three pinned processes, and only then opens v3 state. The original scoped
pending proof remains unchanged. Cancellation/unobserved exit is not `clean`.
Conflicts still block cleanup. Close is serialized; cancel the observer before
closing. Polling one outstanding pidfd at a time avoids a dead-fd busy loop.

**Important:** old worker-only scoped recovery/available flock is not a safe
fallback when the guard dies and the direct command can discard its lease.
This round does not silently claim that existing paths now have that admission.

## Actual targeted Android tests

```
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o build/tproxy-guard-loss-tests ./internal/tproxy
adb push build/tproxy-guard-loss-tests /data/local/tmp/tproxy-guard-loss-tests
adb shell su -c 'chmod 755 /data/local/tmp/tproxy-guard-loss-tests'
adb shell su -c 'chown 0:0 /data/local/tmp/tproxy-guard-loss-tests'
adb shell su -c 'TMPDIR=/data/local/tmp TP_RUN_PRIVILEGED=1 /data/local/tmp/tproxy-guard-loss-tests -test.v -test.run CommandWitnessHostRejected'
adb shell su -c 'TMPDIR=/data/local/tmp TP_RUN_PRIVILEGED=1 /data/local/tmp/tproxy-guard-loss-tests -test.v -test.run PrivilegedGuardLossWitness'
```

Initial targeted run passed 24.44 s; final run with additional missing/foreign
identity checks passed **23.56 s**. One intermediate upload reset executable
permissions and invocation failed `Permission denied`; explicit chmod/chown
was restored and the final test rerun. That invocation is not counted as PASS.

Actual output:

```
guard SIGKILL: inherited-lease direct command exits via PDEATHSIG;
pending final add not applied
three pinned exits observed; recovered=7 clean=true foreign fixture preserved

guard SIGKILL with discarded lease/PDEATHSIG:
lock available but command alive; witness blocks recovery; zero mutations
three pinned exits observed; recovered=8 clean=true foreign fixture preserved
```

The second fixture closes FD 3 and calls PR_SET_PDEATHSIG=0 before advertising
readiness. After supervisor/worker/guard SIGKILL, its pidfd is still live while
OpenScopedIsolated can acquire flock. The test deliberately does not invoke old
worker-only cleanup. New witness cancellation leaves rule snapshots unchanged.
Fixture-owner release then executes the real final iptables rule, command
exits, and the witness reconciles that actual pending result before cleanup.

Windows core tests, Linux arm64 vet, standalone Android native/BPF build,
certificate/Yakit tests, Node App picker/backend regressions and module-backend
compatibility build passed. Module build outputs go to ignored build storage,
not the tracked release binary. Fresh native module tests also passed on-device
(App labels, profiles, certificate transactions, backend defaults and preflight).

Full native `./internal/tproxy` suite (`-test.v`, no selector) exited **0 / PASS**.
Actual parent durations: new guard-loss witness 24.68 s; strict 16 committed
windows 69.35 s; strict 32 pending windows 128.65 s; scoped lifecycle 52.16 s;
scoped 32 pending windows 285.18 s; bounded supervisor 120.46 s; supervisor
admission 10.25 s; previous scoped survivor 12.02 s; command cancellation 0.12 s.
All old tests and assertions were retained. Top-level fixture skips are expected;
their parent tests invoke those fixture processes. Timings are not benchmarks.

Fresh post-suite host reads all exited 0. IPv4/IPv6 policy rules, mangle rules
and dedicated table 38766 were identical to this round's pre-test snapshots
after CRLF/trailing-newline normalization. Both tables remained empty, own
chains were absent and priority 9001 was absent. Unlike the previous phase's
observed system-chain delta, this round's six baseline checks all match. Do not
rewrite that earlier evidence or claim the phone as a whole has no VPN/TUN:
existing host tun0 references were retained.

Device: `5D5X5TFYDMGAEEWK`, Android 15 / SDK 35,
`5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284`, root `u:r:ksu:s0`,
SELinux Enforcing, host netns `net:[4026532071]`. Machine evidence:
`tproxy-guard-loss-witness-android.json`; no full firewall dump or credentials.

## Limitations / next

Only a complete pre-acquired set for one direct command is proven. No automatic
FD handoff, authenticated production registry, arbitrary fork/daemon tracking,
all-anchor-loss guarantee or production watchdog has been added. Filesystem,
fsync, uninterruptible commands and external writers remain non-real-time /
nontransactional limits. Constructor fdinfo availability is verified only on
the actual test device, not asserted across all Android/kernel versions.

Next: integrate direct-command registration/pidfd handoff with the surviving
anchor before admitting commands to execute, and test missing/lost handoff
refusal. Then host mark-risk and UID production planning. Host network setup,
real App HTTPS/Yakit, IPv6 and network/backend-switch acceptance remain gated.
No WebUI/release ZIP/version change, no host rule writes or netd BPF changes.

Git commit is supplied in the final handoff rather than self-embedded here.
