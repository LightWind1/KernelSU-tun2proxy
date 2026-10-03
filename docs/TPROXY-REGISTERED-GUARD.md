# TPROXY actual registered guard / single-command supervisor — 2026-10-03

## Phase / delivered scope

The previous IPC fixture used separately pinned native role processes. This
round connects the protocol to an actual native registered command guard and
independently spawned native survivor. Added single-command start/wait supervision
and tested actual worker/guard SIGKILL through real pending-plan execution.

This does **not** replace the old worker-wide restart supervisor or assert that
a partially registered worker is globally quiescent. No host-network setup,
WebUI/backend default, saved proxy/profile, certificate store, netd BPF, module
installation or release ZIP. Packaging version unchanged (no repack).

Files:

- `ebpf-proxy/internal/tproxy/registered_command_linux.go`: native guard/anchor
  entries, trusted configuration pipe, session supervision, capped output/report.
- `registered_command_linux_test.go`: actual native lifecycle/crash fixtures.
- `command_guard_linux.go`: dispatch two explicit native tokens; ordinary v1
  guard/admission dispatch and implementation unchanged.
- Standalone README, report and sanitized JSON evidence.

No new runtime dependency. Components remain generic and standalone-buildable;
no KernelSU API, Yakit identifier, proxy configuration parsing or module path.

## Launch / lifetime

`StartRegisteredScopedCommand` refuses host netns and validates private state,
exact plan and inherited owned 0600 lease. Launch ctx requires a live deadline
within eight seconds. The trusted launcher owns worker pidfd, starts the guard,
pins it before Wait, then starts/pins a separate anchor. No PDEATHSIG ties the
registered guard/anchor to the launcher; direct-command quiescence comes from
the owned exit witnesses, not a parent-death assumption.

Guard: FD3 lease, FD4 channel, FD5 worker pidfd, FD6 strict versioned JSON pipe.
Anchor: FD3 channel, FD4 worker pidfd, FD5 guard pidfd, FD6 configuration pipe,
FD7 private status pipe. Configuration carries only trusted state/plan. Decoder
rejects unknown fields/trailing data; all control descriptors use CLOEXEC before
command exec or recovery. The anchor never inherits/holds the journal lease.

Guard creates the real paused native stub and performs request/ACK/confirmation.
Only the independently holding anchor releases execution. Guard handles TERM/INT
via cancellation, kills/reaps its direct command while retaining its lease, and
propagates command failure/signal status. Guard command budget eight seconds.

Anchor accepts within eight seconds, then independently observes for forty
seconds. If worker exits, it waits for worker+guard+direct-command pidfds, checks
binding and invokes exact v3 pending proof/reverse cleanup. If guard and command
exit while worker remains live, it sends quiescent status and exits **without
editing that worker's journal**. Failed report alone does not authorize cleaning
a live worker. Worker death detected instead may proceed to all-exit recovery.

`session.Wait(ctx)` owns reaping exactly once, checks both actual ProcessStates
and anchor exit/status report. Cancellation sends TERM only to the pinned guard;
independent fifty-second observation does not kill the sole survivor anchor.
Unverified exits, missing/malformed/blocked report or anchor SIGKILL returns an
error without cleanup/retry authority. Execution failure can be genuinely
quiescent but remains a failed operation. `SuperviseRegisteredScopedCommand`
is the synchronous one-command wrapper. Always pair Start with Wait; keep the
returned pointer and do not copy/abandon it. Nil/zero/reused sessions are refused.

Each stdout/stderr capture is capped at 65536 bytes. Overflow flags an error and
synthetic unsafe `Command.ExitCode=-1`; partial output cannot be treated as a
complete firewall/route observation. Quiescence remains an independent fact.
No command output/proxy credential/payload is added to default logs.

## Device commands / evidence

```
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o build/registered-final-tests ./internal/tproxy
adb push build/registered-final-tests /data/local/tmp/tproxy-registered-final-tests
adb shell su -c 'chmod 755 /data/local/tmp/tproxy-registered-final-tests; chown 0:0 /data/local/tmp/tproxy-registered-final-tests'
adb shell su -c 'TMPDIR=/data/local/tmp TP_RUN_PRIVILEGED=1 /data/local/tmp/tproxy-registered-final-tests -test.v'
```

Initial targeted test before output-overflow case: command lifecycle **0.39 s**
and three actual worker-loss cases **34.55 s**, PASS. Cases:

- success: actual guard/anchor exits and quiescence verified, command exit 0;
- nonexistent executable: quiescence true, command exit 1, error returned;
- cancellation: quiescence true, command killed (guard returns 137);
- guard SIGKILL: command kept running; no premature quiescence; after fixture
  release both exits observed, quiescent true, guard signal remains failure;
- anchor SIGKILL: exits observed but quiescent false, error returned;
- worker SIGKILL alone;
- worker+guard SIGKILL with command lease retained;
- worker+guard SIGKILL with lease/PDEATHSIG discarded.

Final source also tests capture overflow refusal. Host/zero guards are tested
outside private netns without modifying host resources.

The anchor validates FD7 is a pipe before emitting any report. The final native
bad-report test supplied an ordinary owned sentinel file: anchor rejected it,
returned failure and left its contents unchanged (PASS, 0.04 s).

## Final verification

- Final-source Android registered suite: PASS. Six command cases 0.39 s;
  three worker-loss cases 37.25 s (child 37.23 s). Each survivor waited for the
  command, reconciled pending work, removed all eight owned steps and preserved
  the foreign fixture.
- Android full `internal/tproxy` suite: PASS, including existing admission,
  handoff, survivor, strict/scoped pending recovery, supervisor and transaction
  tests. This binary preceded only the final report-pipe validation; the final
  registered suite above includes that validation and its new sentinel test.
- Final-source Windows `ebpf-proxy` portable tests: PASS (`go test -count=1 ./...`).
- Linux/arm64 vet: PASS for both core and module backend.
- Core Android native binary/BPF object build and module backend Android build:
  PASS. Module backend native Android tests: PASS, including old backend default,
  proxy/profile configuration, certificate boundary/update/rollback and routes.
- Direct full module tests on Windows: not runnable; existing Linux-only
  `syscall.Flock` APIs fail compilation. Portable certificate/Yakit packages pass;
  the actual module suite was therefore run on Android, not marked Windows PASS.

Device: Android 15 / SDK 35, arm64,
`5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284`, KernelSU root domain
`u:r:ksu:s0`, SELinux Enforcing.

After all mutating private-namespace fixtures, six read-only host snapshots
matched the baseline exactly: IPv4/IPv6 `ip rule`, IPv4/IPv6 mangle rules and
IPv4/IPv6 table 38766. Both test routing tables were empty. No host network
rules were installed, no existing netd program was changed and no unrelated
rule was restored/deleted. Existing host tun0/VPN-related rules predate this
round: this evidence is not a claim that the phone has no VPN or TUN globally.

No release ZIP was built and no installed module was replaced this round.

Actual command fixture verifies no pidfd/socket control capability leaks into
the direct command. It holds at the final pending add and performs that exact
real iptables operation only after the fixture release. For the discard case,
flock is available after worker/guard death, but snapshot remains unchanged and
the survivor stays alive: no premature cleanup. Once the direct command exits,
survivor reconciles pending add and removes eight owned steps; foreign fixture
chain/rule/route preserved and journal is Owned=0 / Pending empty.

Identity transport to the outer test uses a private inherited channel carrying
kernel pidfds. Files are fixture-ready/release barriers, not PID files or identity
adoption. The cooperative test command waits/reaps its one iptables query child;
this is not proof of arbitrary-descendant tracking.

## Next integration gates / limitations

1. Whole-worker command registry: every command/session must be accounted for,
   including launch failure, no-handoff, last-command quiescence/commit window and
   outstanding anchors at worker exit. Then wire explicit cleanup/restart gating
   into an opt-in worker-wide supervisor. The old `SuperviseScopedIsolated` remains
   unchanged and is **not** a safe fallback for partial registration/guard loss.
2. Survivor loss after release or during its own leased recovery commands remains
   unadmitted. No stale PID/available-flock reconstruction or “clean” assumption.
3. Unknown descendants, noncooperative privileged writers, hostile root races and
   hard-real-time I/O guarantees remain unsupported. Quiet is not command success.
4. Host mark risk still unresolved; no explicit override. No real App/Yakit host
   HTTPS, network-switch, IPv6 lifecycle, production module/WebUI deployment claimed.

The component can be copied with ebpf-proxy; eventual extraction needs API/
packaging promotion rather than KernelSU config parsing. This phase intentionally
adds no automatic backend change or broad firewall/SELinux permissions.
