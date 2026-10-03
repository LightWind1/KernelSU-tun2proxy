# TPROXY cross-process command handoff — 2026-10-03

## Phase / scope / files

Completed an opt-in one-command native descriptor-registration protocol with
an independently surviving anchor. Unlike local admission, the receiver owns
the exit witness **and** the only remaining execution-gate capability before
release. Verified on Android in private network namespaces.

- `ebpf-proxy/internal/tproxy/command_handoff_linux.go`: protocol, binding,
  sender handoff, one-shot anchor, bound registered recovery.
- `command_handoff_linux_test.go`: native cross-process crash/negative/recovery
  fixtures and read-only binding tests.
- Standalone README, this report and sanitized structured device evidence.

No existing source was rewritten except current README clarification. Existing
TUN/eBPF, saved upstreams, UID/App selection, certificates, WebUI, default guard
runner/supervisor and module lifecycle remain unchanged. No module installed,
host interception, netd BPF change, new config fields or release ZIP. Therefore
no package version bump. The directory remains independently buildable with
no KernelSU/WebUI/Yakit/tun2proxy dependency in these APIs.

## Protocol / authentication

Use a fresh inherited connected AF_UNIX/SOCK_SEQPACKET socketpair for one
command. The trusted launcher pre-pins the expected worker and guard; anchor
duplicates those descriptors. Receiver's private local state directory and
IPv4 PoC plan are never read from sender-supplied pathname/command data.

Request: exactly 65 bytes (`version=1`, random 32-byte nonce, 32-byte binding)
and exactly four SCM_RIGHTS descriptors: worker, guard, paused command, release
gate. Reply and sender confirmation: exact request echo with no ancillary
descriptors, interpreted in the one-shot request/ACK/confirmation state machine.
Wrong length,
version, descriptor count/type, truncation, binding, role or namespace is refused;
received descriptors are closed on malformed/refused paths. Unexpected SCM data
is rejected; received rights use CLOEXEC. No proxy credentials/payload are logged.

Authentication is the exclusively inherited channel capability plus live
pre-pinned role identity, **not a public socket or SO_PEERCRED**: socketpair peer
credentials identify its creator, not necessarily a later inheriting child.
The consumer must not share the channel with untrusted processes or reuse it
for multiplexed sessions. Replay is refused by one-shot objects and sender
nonce matching; this is not a persistent multi-session command registry.

Metadata numerical PIDs are only compared while expected/received pidfds are
live. No numerical-PID signaling, name lookup, PID-file identity or stale adoption.
Binding hashes canonical absolute directory path, directory device/inode,
boot identity, netns and exact validated plan. Final symlink/unsafe ownership or
permissions are refused. Binding is rechecked before ACK and before recovery.
State/plan arguments are trusted native inputs, not a new root WebUI path API.

## Ordering / failures

1. Command native stub waits with inherited journal lease and private gate.
2. Sender validates/pins identities and sends their copies plus gate capability.
3. Sender closes its gate copy; anchor receives/validates and owns the witness.
4. Anchor echoes nonce/binding ACK **while owning the witness**.
5. Sender validates the ACK and sends a matching confirmation; only after
   validating confirmation does the anchor send one-byte release. Exec retains pidfd
   identity. Registration ACK is not operation success: caller must check Wait.
6. Registered recovery rechecks state binding, observes worker+guard+command
   exits, then invokes the original exact v3 journal proof/reverse cleanup.

Successful confirmation send is the execution commit point. Cancellation after
commit may kill the command but cannot undo side effects; it is not advertised
as transactional rollback of an already executing external command. ACK alone
does not authorize execution. The confirmation step was added during security
review to prevent ACK-loss/cancellation-before-consumption from releasing exec.

Anchor death before release closes the sole gate writer: command refuses EOF,
even when registration ACK already reached the sender. Lost/mismatched ACK or
launch cancellation kills/reaps the sender-owned command, with no local fallback.
Handoff and Accept require live deadlines within eight seconds; nonblocking
send/receive and bounded polling respect cancellation without changing shared
socket status flags. Sender observes its launch context as well as IPC context.

Accept can return a non-nil registration with an error if registration ACK was
sent but releasing the gate failed. Keep/close that handle explicitly; do not
infer execution or successful cleanup from ACK. Cancel Accept before concurrent
Close (mutex serializes); cancel launch context to interrupt command Wait.

All-anchor loss **after release** remains unadmitted. No mechanism can claim
lost in-memory witness recovery from a released flock or stale PID list. Unknown
descendants and noncooperative privileged writers remain unsupported. Directory
identity checks do not claim confinement against hostile root racing replacements.

## Native test commands and actual observations

```
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o build/handoff-final-tests ./internal/tproxy
adb push build/handoff-final-tests /data/local/tmp/tproxy-handoff-final-tests
adb shell su -c 'chmod 755 /data/local/tmp/tproxy-handoff-final-tests; chown 0:0 /data/local/tmp/tproxy-handoff-final-tests'
adb shell su -c 'TMPDIR=/data/local/tmp TP_RUN_PRIVILEGED=1 /data/local/tmp/tproxy-handoff-final-tests -test.v'
```

Final request/ACK/confirmation target was separately compiled to
`build/handoff-release-tests`, pushed/chmod/chown to
`/data/local/tmp/tproxy-handoff-release-tests`, and run with the same TMPDIR/
privileged environment plus `-test.run=CommandHandoff -test.v`.

Final protocol suite: **25 cross-process cases passed, 10.53 seconds**;
binding suite **0.07 seconds**. Initial 17-case run passed 13.79 seconds, then
the 20-case ACK-boundary/cancellation additions passed 13.73 seconds. The full
regression binary began before final confirmation hardening; the final new
protocol/binding tests were recompiled and rerun separately, and final-source
local tests/vet/build rerun. One development
compile initially failed a test-helper argument mismatch; fixed before native
execution, not counted as a test PASS.

Cases: success; anchor SIGKILL before receive, after receive, before ACK and
after ACK and after confirmation/before release; wrong ACK nonce; absent ACK
deadline; launch cancellation; missing/bad/ancillary confirmation; cancellation
after ACK without confirming;
wrong plan/expected role; bad version, short/extra packet, missing/extra/ordinary/
duplicate/foreign pidfd, wrong binding; source FD closure plus full recovery.
Additional binding checks: canonical path stability, changed plan, symlink,
unsafe permissions and replaced directory. Refusals produce no command file
side effect / namespace mutation.

Actual recovery output:

```
anchor owns transferred witnesses after source FD closure;
all exits observed; recovered=8 clean=true
```

The fixture's worker/guard roles are two independently started native processes
with trusted pidfds. Command uses the real paused native stub/exec; anchor is a
separate native test process receiving capabilities on inherited FDs. The private
controller first installs the real eight-step scoped plan; anchor later observes
all three exits and recovers it. Foreign chain/rule/route fixture preserved.
The new test does **not** claim the ordinary v1 guard/supervisor has been deployed
with this protocol or that an arbitrary App already uses host TPROXY.

The pre-existing guard-loss tests still separately exercise actual v1 guard
SIGKILL with retained and discarded lease/PDEATHSIG. The combined registered
runner/default-supervisor integration is the next phase, not inferred from these
two independent test families.

## Regression / build results

Full native tproxy suite **PASS, exit 0**: existing actual guard-loss witness
21.35 seconds, strict committed recovery 58.73 seconds, scoped lifecycle
43.30 seconds, all 32 scoped pending windows 276.01 seconds, bounded supervisor
120.11 seconds, supervisor admission 9.34 seconds, old survivor 11.37 seconds,
command cancellation 0.11 seconds, transaction rollback 2.45 seconds.
This full binary was compiled before final confirmation hardening; the final
new protocol/binding suite was independently recompiled and passed afterward.
No existing guard/journal/supervisor source was changed by this phase.

Final-source Windows core tests, Linux/arm64 vet and Android native/BPF build
passed. Existing certificate/Yakit unit tests, Node App-picker/backend tests,
module Android binary build and module native Android tests passed. Packaged
tracked binary was not overwritten, no module ZIP created or phone installation.

## Device / host network audit

Android 15 / SDK 35; kernel
`5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284`, KernelSU root domain
`u:r:ksu:s0`, SELinux Enforcing, host netns `net:[4026532071]`.

Read-only before/after comparison: IPv4/IPv6 `ip rule` identical; IPv4/IPv6
table 38766 identical and empty. Project ATP_JOURNAL/ATP_ADMISSION resources
absent. All mutating new/regression fixtures run only in private netns.

Complete mangle snapshots were **not identical**: both families lost exactly
this unrelated vendor entry during the interval:

```
-A tc_limiter_OUTPUT -m owner --uid-owner 10174 -j CONNMARK --set-xmark 0x10000000/0x10000000
```

No other set-membership differences observed. Actor is untraced. Tests do not
manage this chain, and no whole-firewall restore was attempted. Do not describe
the entire Android firewall as unchanged. Existing host tun0/VPN-related netd
references remain baseline; no new TUN/VPN/BPF attach was created by this phase.
Structured evidence: `tproxy-command-handoff-android.json`.

## Known remaining work / extraction

Deploy an explicit registered runner using the protocol, arrange independently
surviving anchor ownership for every actual command, and test command/session
boundaries under guard/worker/controller loss. Keep old paths explicit; no
automatic worker-only fallback when registration is missing.

Host mark 0x00400000/0x00400000 is still only a candidate with vendor collision
risk. No explicit override or production setup occurred. Real selected-App/Yakit
HTTPS, network switching, IPv6 lifecycle, production watchdog/WebUI and package
release remain future acceptance gates. Core can be copied with ebpf-proxy;
extraction needs packaging/API promotion, not KernelSU configuration parsing.
