# TPROXY next phase: direct relay, UID isolation and SOCKS5 — 2026-10-01

## Phase B — complete inside isolated Android namespaces

Implemented generic `upstream.Direct` using the existing Connector interface.
The transparent listener's getsockname resolver feeds the unchanged TCP relay.
Fixtures start real child processes with kernel credentials UID 41001/41002;
package names and WebUI configuration are not present in core code.

Rule ordering: processed-bit return, daemon UID return, special-address returns,
upstream address/port return, selected UID masked MARK. Root is intentionally
also included as a target to verify that daemon bypass takes precedence.
Only one OUTPUT and one PREROUTING jump enter owned `ATP_UID_*` chains.
Table 38766/priority 9001 and bit 0x00400000 remain confined to private netns.

Actual device command:

```sh
su -c 'unshare -n /data/local/tmp/tproxy-probe tproxy relay-isolated'
```

Results (full commands/counters/rollback in `tproxy-direct-uid-android.json`):

```text
target UID=41001       65536 bytes each direction, exact opaque payload, half-close OK
non-target UID=41002   same destination concurrently, direct, exact payload
daemon UID=0          bypass (even though selected), exact payload
upstream tuple        selected UID to 198.18.0.1:8443 bypasses interception
UDP UID=41001         4096-byte UDP/443 echo passes, no relay accept
after stop            target UID direct request succeeds with relay stopped
accepted              1 (only the selected target TCP connection)
original destination  198.18.0.1:443
active / failures     0 / 0
sent / received       65536 / 65536
policy disable        exit 0, before relay cancellation
rollback              true; owned chains, rules, table and address absent
```

This fixture uses a locally assigned target IP so the direct connector can
reach the same original destination. The earlier nonlocal PoC separately
proved OUTPUT marking / dedicated policy rerouting / PREROUTING interception.
These two proofs must not be reported as a real App Internet-routing test.

Android compatibility finding: non-root workers cannot read `/proc/1/ns/net`
due to procfs visibility restrictions. The root launcher verifies isolation and
passes its open namespace descriptor via `ExtraFiles` (FD 3). Workers verify the
inherited descriptor against their own namespace and check their actual UID.
No procfs setting, SELinux permission or global network state was weakened.
An initial worker-check failure also exercised complete rollback.

## Phase C — SOCKS5 fixture complete; real upstream HTTP diagnostic complete

```sh
su -c 'unshare -n /data/local/tmp/tproxy-probe tproxy socks5-isolated'
su -c '/data/local/tmp/tproxy-probe tproxy test-upstream \
  --address 192.168.30.102:8083 \
  --http-destination example.com:80 --http-host example.com'
```

The SOCKS5 fixture is in `internal/testutil`, not a backend protocol
implementation. It allows only `198.18.0.1:443`. The relay uses the existing
SOCKS5 adapter unchanged except for preserving TCP dial error causes.
It neither parses nor changes HTTP/TLS payloads.

Actual fixture results (`tproxy-socks5-uid-android.json`): all Phase B cases pass;
relay accepts exactly one connection; SOCKS5 server sees the exact original
destination twice (target relay stream and explicit upstream-bypass stream).
Both directions remain 65536 bytes; UDP passes; stop restores direct access;
all owned resources are removed.

Actual real upstream diagnostic (`tproxy-upstream-http-android.json`):

```text
192.168.30.102:8083 TCP reachable: true
SOCKS5 no-auth handshake:        true
example.com HTTP response:      200
response bytes:                 713
network rules changed:          false
path: root diagnostic -> SOCKS5 (NO TPROXY)
request marker: X-Transparent-Proxy-Probe: direct-uid-phase
```

This demonstrates a real HTTP round trip through the configured endpoint,
not inspection of the desktop MITM console. Yakit GUI records/modification and
HTTPS/CA trust have not been independently verified in this phase. No private
key, credentials, request body or response body is emitted. The optional HTTP
parser lives solely in the CLI diagnostic client, never in relay/backend/BPF.
CLI address is transient; no second saved connection configuration is created.
Authenticated probes still use existing `probe-upstream --config`.

Failure diagnostic: `test-upstream --address 127.0.0.1:1` exits 1 and reports
`connect: connection refused`, `tcp_reachable=false`, `timeout=false`, with no
network rules changed. Generic SOCKS5 errors now preserve errno/cancellation
identity without dumping authentication data.

## Tests/build/changes

- Android `TP_RUN_PRIVILEGED=1 /data/local/tmp/tproxy-tests -test.v`: previous
  interception/five fault-injection cases, host refusal, UID direct/SOCKS5 cases,
  UDP pass, stop-to-direct, and forced worker-failure cleanup.
- Standalone `go test ./...`; Windows and Linux-arm64 `go vet ./...`.
- Generic direct connector/cancellation/error-redaction tests; SOCKS5 fixture
  rejects destinations outside its exact allowlist.
- Existing App picker/backend Node tests; actual Android main-module test binary
  (profiles, routing, certificate transactions, backend defaults/adaptation);
  existing certificate and Yakit package tests.
- Android arm64 daemon/test binary and unchanged NDK BPF build pass.
- Android original IPv4 and IPv6 ip rule outputs remain identical to the stored
  capability baseline; root namespace has no `ATP_UID_OUT` chain.

Changed/new source files: `internal/upstream/direct.go`, `direct_test.go`,
`socks5.go`; `internal/tproxy/relay_poc_linux.go`, `relay_poc_linux_test.go`;
`internal/testutil/socks5.go`, `socks5_test.go`; `cmd/ebpf-proxy/tproxy_linux.go`;
standalone README and this report plus the three device JSON reports.

Git: `6036e69` adds the independent direct connector/error diagnostics. The
phase fixture/test/report commit is titled
`feat: verify tproxy uid isolation and direct socks5 relay lifecycles`.

## Scope and next stage

System rule mutation: only fresh isolated namespaces. Root namespace receives
only read-only queries and normal explicit SOCKS5 diagnostic connections.
No TUN, VPNService, new cgroup BPF hook, netd detach, global proxy changes,
certificate changes, WebUI changes, module installation, reboot or ZIP repack.
Default TUN and optional eBPF backend remain intact. No version bump is necessary
without a repack. Production watchdog/setup/repair/UID updater is not yet exposed.

Known limits: IPv4 only for actual TPROXY traffic; no Android package/App UID or
HTTPS/HTTP2/WebSocket end-to-end interception acceptance, live network switching,
1000+ TPROXY streams or crash-watchdog verification. Existing eBPF/relay tests
are retained. Full live mark safety remains unresolved; no implicit override.

Next: controlled live-namespace rule planning and ownership journal/rollback,
with explicit mark-risk override before writing live rules; use saved upstream
configuration via integration adapter, verify actual App HTTP/HTTPS/CA and
non-target traffic, then crash fail-open and network-change tests. WebUI remains
gated until those acceptance conditions pass.

Extraction check: all new code remains inside the independently buildable
`ebpf-proxy/` Go module. No parent-relative source paths or KernelSU APIs are
required; copy the directory and run the same build/tests. Fixture UID/IP values
are explicitly test-only, not production policy or upstream configuration.
