# TPROXY read-only host preflight — 2026-10-01

## Phase / status

Completed a generic read-only CLI gate and a CLI-only saved-configuration
adapter. No production setup, new backend selection, WebUI changes or release
ZIP. The existing TUN/eBPF lifecycle remains unchanged. This is not real-App
TPROXY/Yakit acceptance.

## Files and boundaries

- `ebpf-proxy/internal/tproxy/preflight.go`: pure candidate/resource/policy
  evaluation, listener-table parsing, stable structured blocking codes.
- `preflight_linux.go`: read-only command collection, transparent socket option
  checks, before/after structural digest, optional SOCKS5 handshake.
- `preflight_test.go`, `preflight_linux_test.go`: resource/query/mark/policy/
  port/selector/redaction tests and command inventory safety.
- `ebpf-proxy/internal/config/config.go`, `config_test.go`: strict stdin reader,
  1 MiB bound (including trailing whitespace), preserved validation/auth.
- `ebpf-proxy/cmd/ebpf-proxy/tproxy_linux.go`: `tproxy preflight` CLI.
- `cmd/tun2proxy-web/backend.go`, `backend_test.go`: saved configuration through
  private stdin before runtime directory/lock creation; HTTP rejection and
  subprocess stderr/credential isolation tests.
- Standalone README and this report; sanitized actual evidence in
  `docs/tproxy-preflight-android.json`.

No new saved configuration fields. Adapter reuses ProxyURL (scheme, host, port,
username/password), RouteMode, AppPackages resolved via existing appsList(),
BypassIPs and EBPFPort/default 18080 through the existing core-config converter.
It preserves all_non_bypass and IPv6 choices rather than downgrading them to
make the PoC appear ready. The core knows only generic SOCKS5/UID configuration.
Copying `ebpf-proxy/` out retains independent build/run/test behavior.

## Device commands and actual evidence

Test device: Android 15 / SDK 35, arm64 kernel
`5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284`,
`uid=0 context=u:r:ksu:s0`, SELinux Enforcing.

Only scratch binaries were updated, not the installed module:

```
TUN2PROXY_MODDIR=/data/local/tmp/atp-preflight-round \
TUN2PROXY_RUN_DIR=/data/local/tmp/atp-preflight-round/must-not-be-created \
/data/local/tmp/tproxy-preflight-integration --backend-action tproxy-preflight

/data/local/tmp/tproxy-probe tproxy preflight \
  --config /data/local/tmp/ep-stage/run/ebpf/config.json --probe-upstream
```

Saved module configuration reported upstream **http** at
`192.168.30.102:8083`, blocked with `SAVED_UPSTREAM_IS_NOT_SOCKS5`, exit 1.
No implicit protocol conversion or saved-setting change was made.

The second command used an **existing scratch generic SOCKS5 config**, not
the current saved UI profile. Actual results:

- TCP `192.168.30.102:8083` reachable; SOCKS5 negotiation accepted, no CONNECT
  or payload. This is not proof of HTTPS MITM traffic in Yakit.
- IP_TRANSPARENT and IPV6_TRANSPARENT: setsockopt/getsockopt succeeded;
  sockets closed without binding.
- iptables/ip6tables 1.8.10 legacy; TPROXY/owner/MARK/mark help exit 0.
- Kernel TPROXY IPv4/IPv6 and multiple routing tables configured.
- Candidate `0x00400000/0x00400000`, table 38766, priority 9001, ATP_LIVE.
- Table empty both families; candidate priority/prefix/listener port not
  observed occupied. Six packet-mark references overlap the candidate mask,
  including vendor `0x7fefffff` and full-mask comparisons.
- Scratch UID list empty and IPv6 enabled: `NO_TARGET_UIDS` and
  `LIVE_IPV6_DATA_PATH_NOT_VALIDATED` remain explicit blockers.
- `snapshot_stable=true`; before/after structural digest
  `2d652110fb6d09f2e21fbfe616c1b3df8a17e1058460b0f056903eb3108e561b`.
- Always blocked on vendor mark safety, live ownership and production
  supervision. No risk override is exposed in this phase.

Saved config.json/profiles.json hashes unchanged. The configured nonexistent
scratch runtime remained nonexistent: no backend.lock or credential file.
Root IPv4/IPv6 rules matched the original capability baseline; no ATP_ or
KSU_TPROXY chain or dedicated route remained in the root namespace.

## Tests / build

- Fresh Windows `go test -count=1 ./...` for independent core: pass, retaining
  original relay/upstream tests. `go vet ./...` for Linux arm64 core/module: pass.
- Original Node app-picker/backend syntax/state/default/IPv6/auth tests: pass.
- Certificate/Yakit package tests on Windows: pass. An initial cross-target
  attempt could not execute Linux arm64 tests on Windows; rerun with correct
  native target passed, not treated as a test success.
- Android main module native test binary: pass, including new read-only
  protocol mismatch/private stdin tests and existing profiles/certificates/
  app-label/config/route tests.
- Android TPROXY suite with `TMPDIR=/data/local/tmp TP_RUN_PRIVILEGED=1`: pass.
  Actual rerun: 16 committed SIGKILL boundaries, 32 pending boundaries,
  guardian-loss/pidfd recovery, foreign-resource refusal, exact rollback and
  repeated lifecycle. Full privileged execution takes about 200 seconds.
- Nonlocal original destination `198.18.0.1:443` recovered in isolated netns.
  Direct/SOCKS5 UID 41001 target, UID 41002 direct, root daemon/upstream bypass,
  UDP pass, after-stop direct: pass. 65536-byte opaque TCP stream/half-close
  equal; worker failure rolled back; three repeated transaction cycles clean.
- Latest preflight tests rerun natively after final code changes: pass.
- Device CLI invalid mask and nonexistent risk-override option both returned
  exit 1 without a report/setup. No hidden override enables network writes.
- Android arm64 standalone binary and unchanged BPF object build: pass.
  Integration helper build: pass. **No release ZIP or module upgrade**; patch
  version is unchanged (next release packaging must increment it).

## Network writes / rollback / next phase

Preflight made **zero host network rule writes**; no host rollback was needed.
Privileged regression tests wrote only verified private namespaces, then
removed their owned resources; rollback proofs are not host-network proofs.
No new TUN, VPNService or cgroup BPF attachment was made by this phase; netd BPF
was not detached/replaced. Existing backend processes were not switched.

Next: implement live-resource ownership/reconciliation tolerant of unrelated
netd changes and a bounded production supervisor, first using tests. Before
any live interception, resolve vendor mark risk or obtain a separate explicit
human risk override for exact selectors, explicitly select SOCKS5 and finite
test App UIDs, and freshly recheck resources. A repeated request to continue
does not constitute that override. Actual App HTTPS/Yakit, IPv6, network-switch
and backend-switch acceptance remain unverified. Do not expose WebUI yet.

Commit: recorded in the phase's Git commit/final handoff (not embedded here to
avoid a self-referential commit hash).
