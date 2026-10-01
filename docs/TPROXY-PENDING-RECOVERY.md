# TPROXY witnessed pending recovery — 2026-10-01

## Phase / status

Completed version-2 pending-operation witnesses, safe two-outcome reconciliation
in private namespaces, and recovery through a surviving pidfd anchor after loss
of the first guardian. Production TPROXY setup, module/WebUI integration and
vendor mark safety are **not** enabled by this phase.

## Modified files

- `ebpf-proxy/internal/tproxy/witness_linux.go`: resource classification,
  exact-rule verification, duplicate detection and residual witness.
- `ebpf-proxy/internal/tproxy/witness_linux_test.go`: selector/mark/duplicate/
  foreign-content validation tests.
- `ebpf-proxy/internal/tproxy/journal.go`: version-2 schema and witness validation.
- `ebpf-proxy/internal/tproxy/journal_test.go`: valid v2 and invalid witness tests;
  retains v1 compatibility/security coverage.
- `ebpf-proxy/internal/tproxy/journal_linux.go`: persist witnesses before commands,
  reconcile before/after outcomes, preserve pending state on commit failures.
- `ebpf-proxy/internal/tproxy/journal_linux_test.go`: pending crash seams and
  existing committed-boundary regression tests.
- `ebpf-proxy/internal/tproxy/pending_linux_test.go`: all 32 pending crash windows
  and foreign-resource refusal.
- `ebpf-proxy/internal/tproxy/guardian_linux.go`: trusted pidfd observer and
  shared exit recovery; distinguish known and unknown exit codes.
- `ebpf-proxy/internal/tproxy/guardian_loss_linux_test.go`: actual guardian loss,
  pinned orphan identity, cancellation and replacement recovery tests.
- `ebpf-proxy/README.md` and this report: current guarantees and limits.

## Implementation and ownership model

Journal v2 retains boot ID, namespace, independently matched typed plan and
owned-step count. It additionally persists a `pending_proof` SHA-256 digest.
No command, deletion path, credentials or payload comes from the journal.

Before committing an intent, the controller observes the namespace and verifies
the exact resource profile for the committed count. The eight resources are:
local route, policy rule, PRE chain, exact TPROXY rule, PREROUTING entrance, OUT
chain, exact MARK rule and OUTPUT entrance. Expected iptables rules must also
pass `-C`. Duplicate resources, unexpected policy selectors/marks, route
selectors and wrong rule specifications are rejected. Unknown content stays in
the residual digest; it is never silently ignored.

The observer captures state again after rule checks to detect a mixed/racing
observation. Counter-free `-S` output is used. No full firewall dump is written
to the normal journal; only digests and typed metadata are persisted.

After a pending crash, reconciliation admits only:

1. The committed resource profile is unchanged: the command did not take effect.
2. Exactly the next/last planned resource was added/removed: the command took
   effect but completion was not committed.

In both cases the residual digest must match the durable witness. Any other
outcome is rejected without deletion. The reconciled count/snapshot is committed
before reverse cleanup proceeds. The OUTPUT interception entrance remains the
first resource removed. V1 committed journals remain readable; unwitnessed
legacy pending records continue to refuse automatic recovery.

This proof assumes a cooperative exclusive writer and a private namespace. It
does not identify an external privileged actor that recreates an identical
resource. It is not an ownership proof suitable for concurrent Android netd
changes in the root namespace.

## Guardian loss

`WatchIsolatedPIDFD` accepts a trusted descriptor, not a PID to kill. It duplicates
the descriptor for its own polling lifetime, validates that it is a pidfd, waits
for the pinned process to exit and only then opens the locked journal. A
cancelled observation cannot clean a still-live worker's rules. PIDFD polling
does not provide a child wait status here, so the result marks exit code unknown
rather than inventing one.

The test launcher reads the original guardian's trusted ready message, opens the
worker pidfd while the guardian is alive, and checks the worker start time. It
kills the original guardian using the actual child process handle. The worker
remains alive and retains flock; another controller cannot steal ownership.
The test signals only its verified pidfd, then runs the replacement observer
and verifies recovery of eight owned steps and repeated cleanup.

The independent anchor must survive and retain the namespace/state/descriptor.
This phase does not deploy a service to restart a killed anchor, and does not
claim fail-open after the entire supervision tree is killed.

PIDFD engineering references:
[Linux pidfd_open manual](https://man7.org/linux/man-pages/man2/pidfd_open.2.html),
[Linux pidfd_send_signal manual](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html).
Device support was verified by the actual test, not inferred from kernel version.

## Device / commands

Device `5D5X5TFYDMGAEEWK`, Android 15 / SDK 35, arm64, kernel
`5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284`, SELinux Enforcing.

```powershell
# ebpf-proxy directory, configured Go 1.26.4:
$env:GOOS='linux'; $env:GOARCH='arm64'; $env:CGO_ENABLED='0'
go test -c -o out/tproxy-tests ./internal/tproxy
adb push out/tproxy-tests /data/local/tmp/tproxy-tests
adb shell su -c 'chown 0:0 /data/local/tmp/tproxy-tests'
adb shell su -c 'chmod 755 /data/local/tmp/tproxy-tests'
adb shell su -c 'TMPDIR=/data/local/tmp TP_RUN_PRIVILEGED=1 /data/local/tmp/tproxy-tests -test.v'
```

Privileged test launchers use fresh `unshare -n` namespaces. All host-namespace
refusal tests remain. State is created atomically 0700 and files 0600; no SELinux
change, global proxy change, system firewall flush or netd BPF detach occurs.

## Actual evidence

```text
TestPrivilegedPendingRecovery: PASS
  pending intent/add owned=0..7: reconciled=0..7, clean
  pending intent/remove owned=1..8: reconciled=1..8, clean
  pending applied/add owned=0..7: reconciled=1..8, clean
  pending applied/remove owned=1..8: reconciled=0..7, clean
  foreign pending-window chain preserved;
    recovery refused until external change removed

TestPrivilegedGuardianLoss: PASS
  guardian SIGKILL: orphan remains locked;
  pidfd identity pinned; no premature cleanup;
  replacement recovers 8 steps after orphan exit
  cancelled observer and ordinary file: no cleanup

TestResourceWitnessClassification: PASS
  duplicate, duplicate_rule, route_selector, rule_selector rejected
  wrong mark/rule rejected; foreign content retained

Existing 16 committed add/remove SIGKILL boundaries: PASS

Final root-namespace checks:
  IPv4RulesUnchanged=True
  IPv6RulesUnchanged=True
  no ATP_ / KSU_TPROXY chain entries
  routing table 38766 empty
```

Standalone Go tests and Windows/Linux-arm64 vet pass. Android regression includes
the existing original-destination PoC, direct/SOCKS5/UID/UDP/bypass fixtures,
transaction rollback/idempotence tests and main-module backend/profile/certificate
tests. Original App-picker/backend JavaScript tests and certificate/Yakit Go
tests pass. Android native binary and unchanged BPF object build with the existing
script. No release ZIP was repacked, so the module patch version is unchanged.

## Network mutations / rollback

Writes occurred only in private namespaces. Completed and witnessed pending
resources were removed exactly; foreign resources were preserved. The main
namespace IPv4/IPv6 policy rules are compared with the earlier device baseline,
and own chain/table leftovers are checked after the final suite. No new TUN,
VPNService, tun2proxy process or cgroup/connect attachment was introduced by
these tests. No user/stock certificate was modified.

The guardian-loss fixture probes pidfd support/signal permission before starting
a potentially orphaned worker. Unsupported devices do not enter that fixture;
the tested device completed it without skipping. Identity-check failures leave
the original guardian alive for its bounded child cleanup, instead of killing
the guardian first and abandoning an unverified worker.

## Remaining gates / next phase

- Whole private-namespace witness verification is conservative and not a
  live-netd-compatible ownership scheme.
- An external privileged identical-resource replacement remains indistinguishable.
- Loss of all guardians/anchors is not automatically recovered.
- Candidate mark `0x00400000/0x00400000` still has vendor-ROM collision risk and
  is not approved for automatic host setup.
- No real App → external Yakit HTTPS MITM, IPv6 traffic, network-switch or WebUI
  acceptance is claimed here.

Next prepare a narrowly scoped live preflight/ownership plan and the explicit
mark-risk decision before any root-namespace PoC. Production integration stays
gated; default TUN/eBPF behavior and certificate/upstream configuration are
unchanged.
