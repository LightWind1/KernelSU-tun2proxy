//go:build linux

package tproxy

import (
	"context"
	"ebpf-proxy/internal/config"
	"ebpf-proxy/internal/upstream"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Resource queries are deliberately separate from mutating planners. Neither
// this API nor its CLI exposes an override/setup option.
func preflightCommands(o PreflightOptions) map[string][]string {
	table := strconv.FormatUint(uint64(o.Table), 10)
	return map[string][]string{
		"rules4": {"ip", "rule", "show"}, "rules6": {"ip", "-6", "rule", "show"},
		"mangle4": {"iptables", "-w", "2", "-t", "mangle", "-S"}, "mangle6": {"ip6tables", "-w", "2", "-t", "mangle", "-S"},
		"table4": {"ip", "-4", "route", "show", "table", table}, "table6": {"ip", "-6", "route", "show", "table", table},
		"firewall4": {"iptables-save"}, "firewall6": {"ip6tables-save"},
	}
}

func routingAliases() map[string]uint32 {
	aliases := map[string]uint32{}
	for _, path := range []string{"/data/misc/net/rt_tables", "/etc/iproute2/rt_tables", "/system/etc/iproute2/rt_tables"} {
		b, e := os.ReadFile(path)
		if e != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(strings.SplitN(line, "#", 2)[0])
			if len(f) != 2 {
				continue
			}
			id, e := strconv.ParseUint(f[0], 0, 32)
			if e == nil {
				aliases[f[1]] = uint32(id)
			}
		}
	}
	return aliases
}

func summarizedResult(v Result) Result {
	return Result{Command: v.Command, ExitCode: v.ExitCode, Error: v.Error, Output: fmt.Sprintf("captured %d bytes; contents omitted", len(v.Output)), SHA256: stateDigest([]string{v.Output})}
}

func stableResourceState(e map[string]Result) string {
	var parts []string
	for _, name := range []string{"rules4", "rules6", "mangle4", "mangle6", "table4", "table6"} {
		v := e[name]
		parts = append(parts, fmt.Sprintf("%s:%d:%s:%s", name, v.ExitCode, v.Error, v.Output))
	}
	return stateDigest(parts)
}

func Preflight(ctx context.Context, c config.Config, o PreflightOptions, probeUpstream bool) (PreflightReport, error) {
	if e := o.Validate(); e != nil {
		return PreflightReport{}, e
	}
	if e := c.Validate(); e != nil {
		return PreflightReport{}, e
	}
	commands := preflightCommands(o)
	evidence := map[string]Result{}
	for _, name := range []string{"rules4", "rules6", "mangle4", "mangle6", "table4", "table6", "firewall4", "firewall6"} {
		evidence[name] = query(commands[name])
	}
	before := stableResourceState(evidence)
	var ports []uint16
	portChecks := map[string]Result{}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, e := os.ReadFile(path)
		if e != nil {
			portChecks[path] = Result{ExitCode: -1, Error: e.Error()}
			continue
		}
		parsed, e := listeningPorts(string(b))
		if e != nil {
			portChecks[path] = Result{ExitCode: -1, Error: e.Error()}
			continue
		}
		ports = append(ports, parsed...)
		portChecks[path] = Result{Output: fmt.Sprintf("read %d listening socket entries; addresses/owners omitted", len(parsed))}
	}
	r := evaluatePreflight(c, o, os.Geteuid(), evidence, routingAliases(), ports)
	var namespaceErr error
	r.Namespace, namespaceErr = os.Readlink("/proc/self/ns/net")
	if namespaceErr != nil {
		appendOnce(&r.Blocks, "NETWORK_NAMESPACE_IDENTITY_UNAVAILABLE")
	}
	for name, v := range evidence {
		r.Checks[name] = summarizedResult(v)
	}
	for path, v := range portChecks {
		r.Checks[path] = v
		if v.ExitCode != 0 {
			appendOnce(&r.Blocks, "LISTENER_QUERY_FAILED")
		}
	}
	capability := Probe()
	for _, name := range []string{"kernel", "android", "sdk", "identity", "selinux", "iptables", "ip6tables", "tproxy4", "tproxy6", "owner", "MARK", "mark", "IP_TRANSPARENT", "IPV6_TRANSPARENT"} {
		r.Checks[name] = capability.Checks[name]
	}
	r.Checks["kernel_config"] = capability.Config
	for _, name := range []string{"iptables", "tproxy4", "owner", "MARK", "mark", "IP_TRANSPARENT"} {
		v := capability.Checks[name]
		if v.ExitCode != 0 || v.Error != "" {
			appendOnce(&r.Blocks, "CAPABILITY_QUERY_FAILED")
		}
	}
	targets := capability.Checks["/proc/net/ip_tables_targets"]
	if targets.ExitCode != 0 || !strings.Contains("\n"+targets.Output+"\n", "\nTPROXY\n") {
		appendOnce(&r.Blocks, "KERNEL_TPROXY_TARGET_UNCONFIRMED")
	}
	if capability.Config.ExitCode != 0 {
		appendOnce(&r.Warnings, "KERNEL_CONFIG_UNAVAILABLE_NOT_PROOF_OF_ABSENCE")
	} else {
		for _, key := range []string{"NETFILTER_XT_TARGET_TPROXY", "NF_TPROXY_IPV4", "IP_MULTIPLE_TABLES"} {
			if !strings.Contains(capability.Config.Output, "CONFIG_"+key+"=y") && !strings.Contains(capability.Config.Output, "CONFIG_"+key+"=m") {
				appendOnce(&r.Blocks, "KERNEL_CONFIG_REQUIREMENT_UNCONFIRMED")
			}
		}
	}
	if probeUpstream {
		if !r.DaemonBypass || len(r.Warnings) > 0 && hasCode(r.Warnings, "EXISTING_TPROXY_RULES_PROBE_BYPASS_UNCONFIRMED") {
			r.UpstreamProbe = "skipped_bypass_unconfirmed"
			appendOnce(&r.Blocks, "UPSTREAM_PROBE_BYPASS_UNCONFIRMED")
		} else {
			probeCtx, cancel := context.WithTimeout(ctx, 7*time.Second)
			conn, e := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(probeCtx, "tcp", r.Upstream)
			if e != nil {
				r.UpstreamProbe = "tcp_unreachable"
				r.Checks["upstream_tcp"] = Result{ExitCode: -1, Error: e.Error()}
				appendOnce(&r.Blocks, "UPSTREAM_UNREACHABLE")
			} else {
				remote := conn.RemoteAddr().String()
				conn.Close()
				r.Checks["upstream_tcp"] = Result{Output: "TCP reachable; connected endpoint=" + remote}
				s := upstream.SOCKS5{Address: r.Upstream, Username: c.Upstream.Username, Password: c.Upstream.Password, Timeout: 3 * time.Second}
				if e = s.Probe(probeCtx); e != nil {
					r.UpstreamProbe = "socks5_failed"
					r.Checks["upstream_socks5"] = Result{ExitCode: -1, Error: e.Error()}
					appendOnce(&r.Blocks, "SOCKS5_NEGOTIATION_FAILED")
				} else {
					r.UpstreamProbe = "socks5_ready"
					r.Checks["upstream_socks5"] = Result{Output: "SOCKS5 negotiation/authentication accepted; no CONNECT or payload sent"}
				}
			}
			cancel()
		}
	} else {
		appendOnce(&r.Blocks, "UPSTREAM_CONNECTIVITY_NOT_TESTED")
	}
	after := map[string]Result{}
	for _, name := range []string{"rules4", "rules6", "mangle4", "mangle6", "table4", "table6"} {
		after[name] = query(commands[name])
	}
	r.Stable = before == stableResourceState(after)
	if !r.Stable {
		appendOnce(&r.Blocks, "RESOURCE_STATE_CHANGED_RETRY_REQUIRED")
	}
	r.Checks["snapshot_before"] = Result{SHA256: before}
	r.Checks["snapshot_after"] = Result{SHA256: stableResourceState(after)}
	r.Warnings = append(r.Warnings, "No transparent listener was bound; no interception path or real App/MITM acceptance is established.", "A later setup must freshly recheck resources and separately resolve vendor mark risk; this report never authorizes writes.")
	return r, nil
}

func hasCode(values []string, code string) bool {
	for _, v := range values {
		if v == code {
			return true
		}
	}
	return false
}
