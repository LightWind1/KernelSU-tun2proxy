# TPROXY durable recovery phase — 2026-10-01

## Completed scope

Added an experimental durable controller and surviving-parent guardian for
**private network namespaces only**. Original TUN/eBPF, module defaults, profiles,
certificate management and WebUI remain unchanged. No release ZIP was repacked.

Files:

- `ebpf-proxy/internal/tproxy/journal.go`: strict versioned record validation.
- `ebpf-proxy/internal/tproxy/journal_linux.go`: lock, atomic durable writes,
  conservative setup and exact recovery.
- `ebpf-proxy/internal/tproxy/guardian_linux.go`: actual child-exit supervision.
- `ebpf-proxy/internal/tproxy/journal_test.go`: schema and identity/security tests.
- `ebpf-proxy/internal/tproxy/journal_linux_test.go`: Android crash/security tests.
- `ebpf-proxy/README.md` and this report: boundaries and device evidence.

## Record and ownership boundary

The JSON record contains version, boot ID, network namespace identity, typed
IPv4 plan, committed owned-step count, pending add/remove intent and SHA-256
snapshot digest. It does not contain shell commands, paths to delete, upstream
credentials or payload. The expected plan is supplied independently by the
caller; a record cannot choose a different plan or namespace.

Recovery regenerates trusted argv from the validated plan. The record is limited
to 64 KiB, unknown fields/trailing JSON are rejected and step counts are bounded.
Boot, namespace, configuration and snapshot mismatches stop recovery.

State directories must be owned non-symlink 0700 directories. Journal/lock files
must be owned regular 0600 files with one link. Root-relative file access,
`O_NOFOLLOW`, checked directory identity, fsync/atomic rename/directory fsync and
nonblocking flock constrain access and serialize cooperating processes.

An intent is committed **before** a kernel command. A completed operation and
its new snapshot are committed afterward. Failure before the initial journal
write cannot mutate the kernel. If the operation outcome is ambiguous, recovery
refuses to guess; it does not adopt or delete uncertain resources.

Snapshot reads exclude packet counters and store only the digest, not full
firewall/routing dumps. Unexpected external changes stop cleanup. This
whole-private-namespace scheme is intentionally not usable on Android's live
firewall, where netd legitimately changes state.

## Guardian and lifecycle

The parent starts a trusted child and retains the private namespace. The child
opens a transparent listener before installing test interception. The guardian
waits on that actual `exec.Cmd`; it does not identify processes by stale PID or
name. After child exit, the kernel releases flock and the guardian opens the
record and recovers in reverse order. The OUTPUT entrance is removed first.

Tests explicitly SIGKILL the child after each committed add boundary (owned
steps 1–8) and each committed removal boundary (owned steps 0–7). They verify
signal `killed`, exit code -1, recovered count and zero owned-resource leaks.
Another open instance then repeats recovery to check idempotence.

This is a reusable isolated guardian function, **not a deployed KernelSU
watchdog service**. It requires the parent to survive. There is no guarantee of
automatic fail-open for pending intents, external races or guardian SIGKILL.

## Device commands

Same test device: `5D5X5TFYDMGAEEWK`, Android 15 / SDK 35, arm64,
kernel `5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284`, SELinux Enforcing.

```powershell
# In ebpf-proxy, with the configured Go 1.26.4 toolchain:
$env:GOOS='linux'; $env:GOARCH='arm64'; $env:CGO_ENABLED='0'
go test -c -o out/tproxy-tests ./internal/tproxy
adb push out/tproxy-tests /data/local/tmp/tproxy-tests
adb shell su -c 'chown 0:0 /data/local/tmp/tproxy-tests'
adb shell su -c 'chmod 755 /data/local/tmp/tproxy-tests'
adb shell su -c 'TMPDIR=/data/local/tmp TP_RUN_PRIVILEGED=1 /data/local/tmp/tproxy-tests -test.v'
```

The parent test uses `unshare -n`. Both durable controller and guardian refuse
the host namespace before touching state. Temporary state directories are
atomically created 0700 using `os.MkdirTemp`, not world-writable directories.
Go testing's default child-directory permissions initially failed the strict
check; test directory creation was corrected without weakening backend checks.
The device's route listing includes IPv6 loopback alongside IPv4; preflight
explicitly allows the kernel-generated local `::1` route, not arbitrary routes.

## Actual results

```text
TestDurableHostNamespaceRejected: PASS
TestPrivilegedJournalRecovery:
  SIGKILL after committed add, owned=1..8:
    lock released, exact recovery, repeated recovery clean
  SIGKILL after committed remove, owned=0..7:
    lock released, exact recovery, repeated recovery clean
  security_and_uncertainty: PASS
TestJournalIdentityAndSchema: PASS

Original nonlocal PoC:
  original=198.18.0.1:443 rollback_steps=11 rollback_ok=true
Original direct/SOCKS5 UID fixtures:
  accepted=1 active=0 sent_bytes=65536 received_bytes=65536
  upstream_failures=0 rollback=true
Original transaction fault/lifecycle/collision tests: PASS

Root namespace after tests:
  IPv4RulesUnchanged=True
  IPv6RulesUnchanged=True
  no ATP_ or KSU_TPROXY chains
  no route in table 38766
```

Security tests cover unexpected external chain changes, uncertain intent,
public-readable journals, journal symlinks/hard links, concurrent live ownership,
invalid schema/configuration/boot/namespace/step bounds and malformed JSON.
The staging-write failure test compares snapshots before/after the failed setup.

## Regression/build and untouched system state

Standalone `go test ./...`, Windows/Linux-arm64 `go vet ./...`, Android privileged
tests, original App-picker/backend JavaScript tests and certificate/Yakit Go
tests pass. Existing build script builds the native Android binary and unchanged
BPF object. No release ZIP/version change in this round.

Network mutations occurred only in fresh private namespaces. No Android root
namespace chain, route, rule, sysctl, SELinux policy or netd BPF attachment was
changed. No TUN or VPNService was created. Test state directories are removed
after tests; no device user certificate or stock certificate was touched.

## Known limits / next stage

- Uncommitted add/remove outcomes require investigation; no automatic adoption.
- A guardian killed alongside its child has no external restart/lease mechanism.
- Snapshot checking does not coordinate non-cooperating external administrators.
- This recovery controller is not yet used by production CLI/module lifecycle.
- No new IPv6 traffic, real App Internet path, HTTPS/HTTP2/WebSocket or external
  Yakit MITM acceptance is claimed.
- Candidate mark `0x00400000/0x00400000` remains unapproved for automatic host
  setup because the vendor fwmark collision risk is unresolved.

Next: per-resource ownership witnesses and safe pending-intent reconciliation,
then guardian-loss/lease tests. Only after recovery and mark risk are resolved
should a controlled live App PoC precede module/WebUI integration.
