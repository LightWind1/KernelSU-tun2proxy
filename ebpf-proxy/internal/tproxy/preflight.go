package tproxy

import (
	"ebpf-proxy/internal/config"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type PreflightOptions struct {
	Mark     uint32 `json:"mark_value"`
	Mask     uint32 `json:"mark_mask"`
	Table    uint32 `json:"routing_table"`
	Priority uint32 `json:"rule_priority"`
	Prefix   string `json:"prefix"`
}

func DefaultPreflightOptions() PreflightOptions {
	return PreflightOptions{1 << 22, 1 << 22, 38766, 9001, "ATP_LIVE"}
}

func (o PreflightOptions) Validate() error {
	if o.Mark == 0 || o.Mark != o.Mask || o.Mask&(o.Mask-1) != 0 || o.Table < 256 || o.Priority == 0 || o.Priority >= 32766 || !planPrefix.MatchString(o.Prefix) {
		return fmt.Errorf("invalid single-bit mark/mask, dedicated table, priority or prefix")
	}
	return nil
}

type PreflightReport struct {
	Version        int               `json:"version"`
	ReadOnly       bool              `json:"network_rules_read_only"`
	AutomaticSetup bool              `json:"automatic_setup_allowed"`
	Status         string            `json:"status"`
	Options        PreflightOptions  `json:"candidate"`
	Namespace      string            `json:"network_namespace"`
	UID            int               `json:"caller_uid"`
	Upstream       string            `json:"upstream"`
	Listener       string            `json:"configured_listener"`
	PolicyMode     string            `json:"policy_mode"`
	TargetUIDs     []uint32          `json:"target_uids"`
	DaemonBypass   bool              `json:"daemon_uid_in_bypass"`
	Checks         map[string]Result `json:"checks"`
	Blocks         []string          `json:"blocking_reasons"`
	Warnings       []string          `json:"warnings"`
	MarkReferences []MarkReference   `json:"mark_conflict_references"`
	Stable         bool              `json:"snapshot_stable"`
	UpstreamProbe  string            `json:"upstream_probe"`
	RequiredBypass []string          `json:"planned_mandatory_bypass"`
}

type MarkReference struct {
	Source string `json:"source"`
	Kind   string `json:"kind"`
	Value  uint32 `json:"value"`
	Mask   uint32 `json:"mask"`
}

func appendOnce(values *[]string, s string) {
	for _, v := range *values {
		if v == s {
			return
		}
	}
	*values = append(*values, s)
}

func emptyRoutingTable(v Result) bool {
	return strings.TrimSpace(v.Output) == "" && (v.ExitCode == 0 && v.Error == "" || v.ExitCode == 2 && strings.TrimSpace(v.Error) == "Error: ipv4: FIB table does not exist.\nDump terminated" || v.ExitCode == 2 && strings.TrimSpace(v.Error) == "Error: ipv6: FIB table does not exist.\nDump terminated")
}

// No override enables writes in this phase. Even a conflict-free snapshot
// cannot certify vendor fwmark/BPF behavior or deploy the production guardian.
func evaluatePreflight(c config.Config, o PreflightOptions, uid int, evidence map[string]Result, aliases map[string]uint32, ports []uint16) PreflightReport {
	r := PreflightReport{Version: 1, ReadOnly: true, Status: "blocked", Options: o, UID: uid, Upstream: net.JoinHostPort(c.Upstream.Host, strconv.Itoa(c.Upstream.Port)), Listener: c.Listener.String(), PolicyMode: c.Policy.Mode, Checks: map[string]Result{}, TargetUIDs: []uint32{}, UpstreamProbe: "not_requested"}
	r.Blocks = []string{"VENDOR_MARK_SAFETY_UNPROVEN", "LIVE_OWNERSHIP_NOT_IMPLEMENTED", "PRODUCTION_SUPERVISOR_NOT_DEPLOYED"}
	r.RequiredBypass = []string{"daemon UID", "system network UIDs", "loopback", "link-local", "multicast/broadcast", "resolved upstream IP:port"}
	for _, b := range c.Policy.BypassUIDs {
		if b == uint32(uid) && uid >= 0 {
			r.DaemonBypass = true
		}
	}
	if !r.DaemonBypass {
		appendOnce(&r.Blocks, "DAEMON_UID_BYPASS_MISSING")
	}
	if c.Policy.Mode != "uid_allowlist" {
		appendOnce(&r.Blocks, "LIVE_POC_REQUIRES_FINITE_UID_ALLOWLIST")
	}
	seen := map[uint32]bool{}
	for _, u := range c.Policy.UIDs {
		if seen[u] {
			continue
		}
		seen[u] = true
		r.TargetUIDs = append(r.TargetUIDs, u)
		if u < 10000 {
			appendOnce(&r.Blocks, "SYSTEM_UID_SELECTED")
		}
		for _, b := range c.Policy.BypassUIDs {
			if u == b {
				appendOnce(&r.Blocks, "TARGET_BYPASS_OVERLAP")
			}
		}
	}
	if len(r.TargetUIDs) == 0 {
		appendOnce(&r.Blocks, "NO_TARGET_UIDS")
	}
	if len(r.TargetUIDs) > 32 {
		appendOnce(&r.Blocks, "LIVE_POC_UID_LIMIT_EXCEEDED")
	}
	if c.IPv6 {
		appendOnce(&r.Blocks, "LIVE_IPV6_DATA_PATH_NOT_VALIDATED")
	}
	for _, p := range ports {
		if p == uint16(c.Listener.Port) {
			appendOnce(&r.Blocks, "LISTENER_PORT_IN_USE")
		}
	}
	for _, name := range []string{"rules4", "rules6", "mangle4", "mangle6", "table4", "table6", "firewall4", "firewall6"} {
		v, ok := evidence[name]
		if ok && strings.HasPrefix(name, "table") && emptyRoutingTable(v) {
			continue
		}
		if !ok || v.ExitCode != 0 || v.Error != "" {
			appendOnce(&r.Blocks, "RESOURCE_QUERY_FAILED")
			continue
		}
		if strings.HasPrefix(name, "table") && strings.TrimSpace(v.Output) != "" {
			appendOnce(&r.Blocks, "ROUTING_TABLE_IN_USE")
		}
		if strings.HasPrefix(name, "rules") {
			for _, line := range strings.Split(v.Output, "\n") {
				f := strings.Fields(line)
				if len(f) == 0 {
					continue
				}
				priority, e := strconv.ParseUint(strings.TrimSuffix(f[0], ":"), 10, 32)
				if e != nil {
					appendOnce(&r.Blocks, "POLICY_RULE_PARSE_UNKNOWN")
					continue
				}
				if uint32(priority) == o.Priority {
					appendOnce(&r.Blocks, "RULE_PRIORITY_IN_USE")
				}
				for i := 1; i+1 < len(f); i++ {
					if f[i] == "lookup" || f[i] == "table" {
						id, e := strconv.ParseUint(f[i+1], 0, 32)
						if e != nil {
							_, known := aliases[f[i+1]]
							if !known && f[i+1] != "local" && f[i+1] != "main" && f[i+1] != "default" {
								appendOnce(&r.Blocks, "SYMBOLIC_ROUTING_TABLE_UNKNOWN")
							}
						}
						if e == nil && uint32(id) == o.Table || e != nil && aliases[f[i+1]] == o.Table {
							appendOnce(&r.Blocks, "ROUTING_TABLE_REFERENCED")
						}
					}
				}
			}
		}
		if strings.HasPrefix(name, "mangle") {
			for _, token := range strings.Fields(v.Output) {
				if strings.HasPrefix(token, o.Prefix) {
					appendOnce(&r.Blocks, "CHAIN_PREFIX_IN_USE")
				}
			}
			if strings.Contains(v.Output, "-j TPROXY") {
				appendOnce(&r.Warnings, "EXISTING_TPROXY_RULES_PROBE_BYPASS_UNCONFIRMED")
			}
		}
	}
	for _, name := range []string{"rules4", "rules6", "firewall4", "firewall6"} {
		for _, u := range MarkUses(name, evidence[name].Output) {
			if u.Kind == "packet" && u.Mask&o.Mask != 0 {
				r.MarkReferences = append(r.MarkReferences, MarkReference{u.Source, u.Kind, u.Value, u.Mask})
			}
		}
	}
	if len(r.MarkReferences) > 0 {
		appendOnce(&r.Blocks, "MARK_MASK_OVERLAP_OBSERVED")
	}
	if len(aliases) == 0 {
		appendOnce(&r.Warnings, "SYMBOLIC_ROUTING_TABLE_ALIASES_NOT_AVAILABLE")
	}
	return r
}

func listeningPorts(text string) ([]uint16, error) {
	var ports []uint16
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] == "sl" {
			continue
		}
		if len(f) < 4 {
			return nil, fmt.Errorf("invalid TCP socket row")
		}
		if f[3] != "0A" {
			continue
		}
		i := strings.LastIndex(f[1], ":")
		if i < 0 {
			return nil, fmt.Errorf("invalid socket endpoint")
		}
		p, e := strconv.ParseUint(f[1][i+1:], 16, 16)
		if e != nil {
			return nil, e
		}
		ports = append(ports, uint16(p))
	}
	return ports, nil
}
