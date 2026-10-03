# TPROXY command pre-exec admission — 2026-10-03

## Phase and actual scope

Implemented and device-tested an opt-in native pre-exec admission primitive.
This is an incremental step toward survivor registration, **not completion of
the cross-process guard-to-anchor handoff**. No WebUI/backend default, module
installation, saved proxy, UID selection, certificate store, global proxy,
netd BPF or host network rules were changed. No release ZIP was produced, so
the module version was not incremented.

Files: `command_admission_linux.go`, its native tests, the three-line dispatch
in `command_guard_linux.go`, standalone README and this report. Core remains
independent of KernelSU, Yakit, WebUI and module directory layout.

## Implementation / trust boundary

- Private network namespace only; private owned journal lease FD 3.
- Anonymous inherited Unix SOCK_SEQPACKET socketpair FD 4; no filesystem IPC,
  world-writable temporary directory, numeric-PID adoption or shell execution.
- Native stub waits before actual exec. Exact one-byte version-1 ACK only;
  extra data, ancillary descriptors, EOF and timeout refuse execution.
- Trusted launcher pins the stub with pidfd while paused. `Admit` acquires owned
  copies of live, distinct, same-private-netns worker/guard/command pidfds before
  ACK. Validation failure kills/reaps the stub; repeat admission is refused.
- Exec retains the pinned command identity. The witness still waits for every
  identity before existing v3 recovery: lease availability is not sufficient.
- Launch requires a live context deadline within eight seconds. Cancellation
  before admission is checked; cancellation after admission terminates the
  direct process via the launch context. The stub itself also has an eight-second
  receive timeout. Abort owns only its command, not arbitrary descendants.
- Wait/Abort are serialized. To interrupt Wait, cancel the launch context rather
  than waiting for concurrent Abort to acquire its mutex.

The caller is trusted and must bind the witness to the exact state and plan.
The local acquisition-before-ACK ordering does **not** establish that another
surviving process has already stored those descriptors. No external anchor ACK
protocol is implemented in this round. The ordinary guard v1/default journal
runner and bounded supervisor are deliberately unchanged. Do not use this as
proof of production guard-loss safety or fallback to worker-only recovery.

## Device test

Android 15 / SDK 35, arm64 kernel 5.10.236, KernelSU root, SELinux enforcing.

```
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o build/admission-tests ./internal/tproxy
adb push build/admission-tests /data/local/tmp/tproxy-admission-tests
adb shell su -c 'chmod 755 /data/local/tmp/tproxy-admission-tests; chown 0:0 /data/local/tmp/tproxy-admission-tests'
adb shell su -c 'TMPDIR=/data/local/tmp TP_RUN_PRIVILEGED=1 /data/local/tmp/tproxy-admission-tests -test.v'
```

Initial complete new suite passed **1.04 seconds**. After adding safe rejection
of nil/zero-value objects, the final targeted native run passed **0.89 seconds**
(private suite 0.87 seconds), with eleven private-netns subcases:
admit/replay refusal, invalid witness, duplicate identity, missing ACK, bad
version, trailing data, ancillary FD, real 300 ms deadline timeout, cancellation,
cancel-before-admission, and admitted real private iptables command.

Before admission the file side-effect is absent. Rejected paths never create
it. The successful rule case creates `ATP_ADMISSION` only after acquisition
and ACK, verifies it with real iptables, deletes precisely that chain and
verifies absence. It does not flush system chains or perform host setup.

Initial fixture failed the strict private-state check because Go's temporary
directory permissions were not 0700. The fixture now explicitly chmods its own
directory; the backend safety check was not weakened. That initial invocation
is not counted as PASS.

Final-source local `go test -count=1 ./...`, Linux/arm64 `go vet ./...`, standalone
Android arm64 binary/BPF build, certificate/Yakit unit tests, App-picker/backend
Node tests, module Android binary build and module native Android tests passed.
Module native tests include profile switching, certificate rollback and endpoint
isolation; the tracked packaged module binary was not overwritten.

Existing native regressions: guard-loss witness 24.65 seconds,
strict committed-step recovery 69.24 seconds, scoped lifecycle 52.35 seconds,
and all 32 scoped pending windows 288.67 seconds. The full native tproxy suite
completed **PASS, exit 0**, including bounded supervisor 118.48 seconds,
supervisor admission 10.59 seconds, old scoped survivor 13.17 seconds, command
guard cancellation 0.18 seconds and transaction rollback 2.99 seconds. The full
suite binary was compiled before the final nil/zero-object defensive checks;
those checks and all new admission cases were separately recompiled and tested
on the device afterward. Windows tests/vet/build used the final source.

## Host baseline / rollback evidence

Before/after read-only snapshots compared with CRLF/trailing-newline
normalization: IPv4/IPv6 `ip rule` unchanged; IPv4/IPv6 dedicated table 38766
unchanged and empty. Priority 9001 and project `ATP_JOURNAL` / `ATP_ADMISSION`
resources absent. No host interception was enabled.

The complete mangle rules were **not byte-identical**: both families gained
exactly this vendor-chain entry during the test interval:

```
-A tc_limiter_OUTPUT -m owner --uid-owner 10174 -j CONNMARK --set-xmark 0x10000000/0x10000000
```

No other set-membership differences were observed. The actor is untraced; the
tests do not manage this chain and every mutating fixture runs in a private
network namespace. The unrelated host entry was retained, not “rolled back”
from a whole-firewall snapshot. Therefore this report does not claim that the
entire Android firewall remained unchanged. Sanitized structured evidence:
`tproxy-command-admission-android.json`.

## Remaining acceptance gates

1. Cross-process SCM_RIGHTS descriptor transfer to a surviving trusted anchor,
   binding to a state/plan/session, and anchor ACK before command release.
2. Kill anchor/guard/worker at every registration boundary; never reconstruct
   missing witnesses from PID files or a released flock.
3. Integrate the proven protocol as an explicit registered runner, preserving
   old strict/scoped APIs and refusing unsupported descendant cases.
4. Host mark conflict resolution still requires explicit authorization and
   proof. Real selected-App/Yakit HTTPS, network switching, IPv6 lifecycle and
   production WebUI integration are not claimed by these isolated tests.

The host baseline already contains tun0/VPN-related netd references. This round
creates no TUN and attaches/detaches no BPF, but does not claim the entire phone
has no existing VPN/TUN.
