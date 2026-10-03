# TPROXY scoped resource recovery — 2026-10-03

## Phase / status

Implemented explicit v3 scoped ownership/reconciliation and a bounded
child-exit guardian, **limited to private IPv4 PoC namespaces**. This removes
the requirement that unrelated resources remain globally unchanged, without
silently weakening existing v1/v2 journals. Production host setup/supervisor
deployment and real-App MITM acceptance are not completed by this phase.

## Changes / interfaces

- `ebpf-proxy/internal/tproxy/scoped_linux.go`: reserved-footprint observation,
  two-pass stability, exact rule verification, per-resource JSON-based digest
  and single-resource exclusion for pending proofs.
- `scoped_linux_test.go`: outside-change tolerance, chain/table/priority/mark/
  route/alias interference, duplicates, modified footprint and pending proof.
- `scoped_recovery_linux_test.go`: private namespace lifecycle, collision
  refusal, pre-existing-resource non-adoption, child SIGKILL recovery.
- `scoped_mark_test.go` and `report.go`: TPROXY mark writes now participate in
  shared mark-use discovery, including read-only preflight conflict detection.
- `journal.go`, `journal_test.go`: explicit journal mode/version validation.
- `journal_linux.go`: `OpenScopedIsolated`, scoped snapshot/profile checks,
  v3 witnesses; preserves strict default mode and private-state protections.
- `guardian_linux.go`: `WatchScopedIsolatedWorker`; observes actual child exit,
  then reconciles/acquires state/cleans exact resources. No name/PID guessing.
- Existing crash-worker/pending test helpers: explicit scoped opt-in for v3,
  unchanged strict defaults; bounded worker timeouts.
- Standalone README and this phase record.

No KernelSU/WebUI integration changes, new connection settings, authentication
storage, certificate changes or release packaging. The independent core still
does not read module settings or depend on an upstream product. Copying
`ebpf-proxy/` out retains build/test/API behavior.

## Key implementation

The typed `IPv4DestinationPlan` still generates the same eight resources:
destination-only route, masked policy rule, PRE chain/rule/entry, OUT
chain/rule/entry. The OUT interception entry remains last to add/first to remove.
No arbitrary commands are deserialized from journals.

V3 separately hashes each verified resource; its full snapshot ignores
outside resources but not its own footprint. Pending proofs omit only the
intended resource, so a second missing/changed resource cannot be explained
away as the pending operation. Actual add/remove outcomes still require the
exact expected contiguous owned-step profile. Both before/after outcomes are
supported; unverified/malformed outcomes are refused.

V1/v2 strict state remains whole-namespace based and retains its foreign-change
refusal. Strict openers reject v3; scoped openers reject v1/v2. There is no
implicit migration/reset. Owned 0700 directories, owned single-link regular
0600 files, no-follow root-relative access, atomic rename/fsync and nonblocking
flock remain required.

Outside firewall changes are only tolerated when they do not collide with
reserved chain prefixes/references or packet mark masks. Foreign policy rules
must not claim the reserved priority/table/mark; reserved routing-table entries
must match the exact planned route. Symbolic table aliases must resolve.
Duplicate, extra, changed or conflicting resources block recovery rather than
being removed. Pre-existing matching resources are never adopted by fresh state.

## Device test commands

Native test binary compiled with Go 1.26.4, `GOOS=linux GOARCH=arm64 CGO_ENABLED=0`:

```
go test -c -o build/tproxy-tests ./internal/tproxy
adb push build/tproxy-tests /data/local/tmp/tproxy-tests
adb shell su -c 'chmod 755 /data/local/tmp/tproxy-tests'
adb shell su -c 'chown 0:0 /data/local/tmp/tproxy-tests'
adb shell su -c 'TMPDIR=/data/local/tmp TP_RUN_PRIVILEGED=1 /data/local/tmp/tproxy-tests -test.v -test.run Scoped'
adb shell su -c 'TMPDIR=/data/local/tmp TP_RUN_PRIVILEGED=1 /data/local/tmp/tproxy-tests -test.v'
```

Only the binary in scratch space was updated; no installed module upgrade.
Device serial `5D5X5TFYDMGAEEWK`. Parent tests use `unshare -n`; child/controller
independently require their namespace to differ from `/proc/1/ns/net` before
mutating anything. New host-controller/guardian rejection tests pass.

## Evidence

First scoped native run:

- `TestScopedJournalModeIsExplicit`, `TestScopedUnrelatedChanges`,
  `TestScopedForeignInterference`, `TestScopedPendingProofExcludesOneResourceOnly`,
  `TestScopedHostRejected`: PASS.
- `TestPrivilegedScopedLifecycle`: PASS (31.96 s). Three repeated setup/setup/
  recover/recover cycles preserve outside firewall/rule/route fixtures.
- External jump into reserved chain, foreign rule referencing reserved table,
  foreign route inside it: recovery refuses, full before/after snapshot unchanged.
  Exact removal by fixture owner allows recovery to retry successfully.
- Pre-existing matching reserved chain: setup refuses, no network mutation.
- `TestPrivilegedScopedPendingRecovery`: PASS (188.13 s). All 32 pending
  intent/applied windows for eight add/eight remove operations; each SIGKILL
  happens after a foreign fixture update in the crash window. Actual child
  exit observed, pending reconciled, owned resources removed, unrelated fixture
  digest preserved, repeated recovery clean.

Fixtures include a separate `FOREIGN_NETD` chain/jump, disjoint bit-16 policy
rule at priority 20000/table 12345, and route `198.19.0.0/24` in that table.
They are **netd-shaped test fixtures**, not the Android netd process. Cleanup
removes exact fixture entries; no system flush commands are used.

After additional mark-mask checks and unambiguous JSON witness encoding, final
full native regression: **PASS, exit 0**. Scoped lifecycle 33.14 s; scoped pending
195.70 s. Original strict 16 committed + 32 pending crash tests also passed
(57.60 s and 108.15 s), bringing total crash windows to 80. Guardian loss/pidfd
replacement, UID/direct/SOCKS5 opaque relay, original transaction and all new
scoped mark/interference tests passed. Windows independent-core/certificate/
Yakit, original Node UI and native Android module regressions passed. Android
arm64 native/BPF/integration builds and Linux arm64 vet passed.
No release ZIP; module version unchanged.
Optional Windows `-race` execution was unavailable: CGO was disabled and no
host GCC was available. It is not counted as a passed race-detector run.

## Network writes / rollback / limits / next

No **host** firewall/routing/network settings, netd BPF attachment, backend
selection or installed connection profile is modified. Privileged tests modify
only verified disposable private namespaces, using exact generated steps.
Final exit-code-checked host queries matched the fresh pre-test IPv4/IPv6
policy-rule and mangle baselines, and dedicated table 38766 remained empty in
both families. No owned ATP_/KSU_TPROXY chains were present. Actual device:
Android 15/SDK 35, kernel 5.10.236-android12-9, UID 0 in u:r:ksu:s0, enforcing.
Sanitized machine evidence: `docs/tproxy-scoped-recovery-android.json`.
A normal scoped
recovery removes only eight owned resources while preserving outside state;
ownership collisions refuse with zero mutations. No host rollback is needed.

This is a necessary component, **not** production permission or completed
production supervision. Remaining gates:

1. Real netd/vendor behavior, atomicity/race constraints, reserved mark safety.
   Bit 22 risk is not waived by repeated requests to continue.
2. Host-safe resource admission (including IPv6 conflicts), UID production
   planner and stop-order/draining integration. Current plan remains an IPv4
   destination-only PoC, not general App routing.
3. Production process-tree/watchdog deployment, bounded restart/repair and
   loss-of-supervisor fail-open behavior. V3 currently has child-exit recovery;
   previous strict pidfd/replacement coverage does not certify v3 replacement.
4. App HTTPS/Yakit, network switching, backend switching, IPv6 and real MITM
   acceptance before WebUI/backend enablement.

An external privileged actor recreating an identical resource cannot be
distinguished from the original owner. Kernel check-plus-operation is not an
atomic transaction against arbitrary external writers. Tests deliberately do
not claim either guarantee. Hook position relative to outside rules is not a
readiness assertion from this ownership digest; future live-path verification
must separately validate effective rule order. Next phase should bound the supervision/restart
mechanism and exercise it privately before admitting host-network mutation.

Git commit: supplied in the final phase handoff (not self-referentially embedded).
