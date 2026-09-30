# TPROXY transaction phase — 2026-10-01

## Status and scope

Completed a trusted IPv4 destination-only rule planner and an in-process
transaction controller; integrated both into the existing nonlocal isolated
TPROXY PoC. No WebUI, saved backend configuration, installer or live-network
setup API changed. TUN and eBPF remain intact.

The core knows neither KernelSU nor Yakit. A typed plan contains destination,
listener port, single-bit mark/mask, dedicated table, priority and bounded chain
prefix. All commands are argv arrays, never shell expressions or deserialized
recovery commands. Invalid values are rejected before generating commands.

## Files

- `ebpf-proxy/internal/tproxy/plan.go`: typed plan and exact inverse operations.
- `ebpf-proxy/internal/tproxy/transaction.go`: serialized ownership and rollback.
- `ebpf-proxy/internal/tproxy/poc_linux.go`: reuse planner/controller.
- `ebpf-proxy/internal/tproxy/transaction_test.go`: fault/security/lifecycle tests.
- `ebpf-proxy/internal/tproxy/transaction_linux_test.go`: private-netns real tests.
- `ebpf-proxy/README.md` and this report: boundaries and verified evidence.

## Implementation

The route and policy rule precede private chains. OUTPUT interception is the
last setup step, hence the first teardown step. Rollback uses exact rule
deletion, not flush. Only successfully added resources become owned. A create
failure never adopts or deletes a pre-existing resource.

If removal fails, cleanup stops before deleting routing dependencies and keeps
the remaining ownership record for retry. A failed stop cannot be mistaken for
a ready backend. Repeated setup/teardown on the same instance does not duplicate
entries; a mutex serializes concurrent calls.

## Device and commands

Device `5D5X5TFYDMGAEEWK`, Android 15 / SDK 35, arm64,
kernel `5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284`, SELinux Enforcing.
The root namespace remains `net:[4026532071]`. Existing Android netd programs
were not detached, replaced or modified.

Build with the standalone `build.ps1`, then build the test binary:

```powershell
$env:GOOS='linux'; $env:GOARCH='arm64'; $env:CGO_ENABLED='0'
go test -c -o out/tproxy-tests ./internal/tproxy
adb push out/tproxy-tests /data/local/tmp/tproxy-tests
adb shell su -c 'chown 0:0 /data/local/tmp/tproxy-tests'
adb shell su -c 'chmod 755 /data/local/tmp/tproxy-tests'
adb shell su -c 'TP_RUN_PRIVILEGED=1 /data/local/tmp/tproxy-tests -test.v'
```

Test launchers create fresh namespaces with `unshare -n`. The child refuses
the host namespace. No live Android OUTPUT/PREROUTING/routing rules were added.

## Actual device results

```text
TestPrivilegedTransactions:
  three repeated setup/setup/teardown/teardown cycles:
    one entry, no owned resource leaks
  fault injection after all eight route/rule/chain/entry steps:
    reverse rollback verified
  foreign chain collision:
    rejected, foreign chain preserved, own route/rule rolled back
PASS

TestPrivilegedIsolatedPoC:
  original=198.18.0.1:443 rollback_steps=11 rollback_ok=true
  injected failures after 2/5/8/10/11: rollback_ok=true
PASS

TestPrivilegedUIDRelay (direct and SOCKS5 fixture):
  accepted=1 active=0 sent_bytes=65536 received_bytes=65536
  upstream_failures=0 rollback=true
  target/non-target/daemon/upstream bypass/UDP/after-stop direct: PASS
  failed worker: interception disabled and owned resources rolled back
PASS

Android root namespace comparison with prior capability report:
  IPv4RulesUnchanged=True
  IPv6RulesUnchanged=True
  iptables-save contains no ATP_ or KSU_TPROXY chains
```

Synthetic UIDs and destinations are fixtures, not real App Internet/MITM
acceptance. No new upstream/HTTPS/IPv6 traffic acceptance is claimed here.

## Regression and build

Standalone `go test ./...` and `go vet ./...` pass. Android arm64 tests pass,
including planner validation, each setup failure, failed disable/retry, partial
rollback and concurrent idempotent lifecycle. Original App-picker and backend
JavaScript tests pass; certificate/Yakit Go tests pass. Android native binary
and unchanged BPF object are built with the existing standalone build script.
The Windows race test cannot run with the configured CGO-disabled toolchain;
ordinary concurrent tests are not a substitute for race instrumentation.

No release ZIP is repacked in this phase; module version is unchanged.

## Known gaps and next phase

Ownership is in-process only: there is no durable intent journal or independent
crash watchdog yet. Command timeout has ambiguous completion semantics; it is
not safe to infer absence from that failure. Concurrent external administrators
are not coordinated by the in-process mutex. There is no production preflight
for table/priority ownership and no safe recovery across process restarts.

Next implement namespace-bound durable ownership/intents and verified cleanup,
then isolate worker SIGKILL/watchdog tests. Only after those checks and an
explicit resolution of the vendor mark collision risk should live App tests
be enabled. Candidate `0x00400000/0x00400000` remains **unapproved for automatic
host setup**. WebUI integration stays gated on real end-to-end acceptance.
