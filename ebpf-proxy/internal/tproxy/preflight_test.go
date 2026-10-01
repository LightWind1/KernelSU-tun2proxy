package tproxy

import (
	"ebpf-proxy/internal/config"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func preflightFixture() (config.Config, map[string]Result) {
	c := config.Config{Version: 1, Listener: config.Endpoint{Address: "127.0.0.1", Port: 18080}}
	c.Upstream.Type = "socks5"
	c.Upstream.Host = "192.0.2.1"
	c.Upstream.Port = 1080
	c.Upstream.Username = "private-user"
	c.Upstream.Password = "private-password"
	c.Policy.Mode = "uid_allowlist"
	c.Policy.UIDs = []uint32{10001, 10001}
	c.Policy.BypassUIDs = []uint32{0}
	c.UDP.Mode = "pass"
	e := map[string]Result{}
	for _, n := range []string{"rules4", "rules6", "mangle4", "mangle6", "table4", "table6", "firewall4", "firewall6"} {
		e[n] = Result{}
	}
	e["rules4"] = Result{Output: "0: from all lookup local\n10000: from all fwmark 0xc0000/0xd0000 lookup 99"}
	return c, e
}
func containsCode(codes []string, s string) bool {
	for _, c := range codes {
		if c == s {
			return true
		}
	}
	return false
}

func TestPreflightNeverAuthorizesWrites(t *testing.T) {
	c, e := preflightFixture()
	o := DefaultPreflightOptions()
	r := evaluatePreflight(c, o, 0, e, nil, nil)
	if r.AutomaticSetup || !r.ReadOnly || r.Status != "blocked" || len(r.TargetUIDs) != 1 || !r.DaemonBypass || r.Options != o {
		t.Fatal("unsafe report or changed selection")
	}
	for _, code := range []string{"VENDOR_MARK_SAFETY_UNPROVEN", "LIVE_OWNERSHIP_NOT_IMPLEMENTED", "PRODUCTION_SUPERVISOR_NOT_DEPLOYED"} {
		if !containsCode(r.Blocks, code) {
			t.Fatal(code)
		}
	}
	b, _ := json.Marshal(r)
	for _, secret := range []string{c.Upstream.Username, c.Upstream.Password, "Proxy-Authorization"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("credential leak")
		}
	}
}

func TestPreflightConflicts(t *testing.T) {
	for _, tc := range []struct {
		name, field, text, code string
		exit                    int
	}{
		{"priority", "rules6", "9001: from all lookup 99", "RULE_PRIORITY_IN_USE", 0},
		{"numeric table", "rules4", "1: from all lookup 38766", "ROUTING_TABLE_REFERENCED", 0},
		{"symbolic table", "rules4", "1: from all lookup reserved", "ROUTING_TABLE_REFERENCED", 0},
		{"unknown alias", "rules4", "1: from all lookup mystery", "SYMBOLIC_ROUTING_TABLE_UNKNOWN", 0},
		{"occupied table", "table4", "local default dev lo", "ROUTING_TABLE_IN_USE", 0},
		{"chain", "mangle4", "-N ATP_LIVE_OUT", "CHAIN_PREFIX_IN_USE", 0},
		{"vendor mark", "firewall4", "-A INPUT -j MARK --set-xmark 0/0x7fefffff", "MARK_MASK_OVERLAP_OBSERVED", 0},
		{"rule mask", "rules4", "1: from all fwmark 0/0x00400000 lookup 99", "MARK_MASK_OVERLAP_OBSERVED", 0},
		{"query failed", "firewall6", "", "RESOURCE_QUERY_FAILED", 1},
		{"malformed rule", "rules4", "garbled priority", "POLICY_RULE_PARSE_UNKNOWN", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, e := preflightFixture()
			e[tc.field] = Result{Output: tc.text, ExitCode: tc.exit}
			r := evaluatePreflight(c, DefaultPreflightOptions(), 0, e, map[string]uint32{"reserved": 38766}, nil)
			if !containsCode(r.Blocks, tc.code) {
				t.Fatalf("missing %s: %v", tc.code, r.Blocks)
			}
		})
	}
	c, e := preflightFixture()
	delete(e, "firewall4")
	if !containsCode(evaluatePreflight(c, DefaultPreflightOptions(), 0, e, nil, nil).Blocks, "RESOURCE_QUERY_FAILED") {
		t.Fatal("missing evidence accepted")
	}
	c, e = preflightFixture()
	e["firewall4"] = Result{Output: "-A X -j CONNMARK --set-xmark 0/0x00400000"}
	if containsCode(evaluatePreflight(c, DefaultPreflightOptions(), 0, e, nil, nil).Blocks, "MARK_MASK_OVERLAP_OBSERVED") {
		t.Fatal("connection-only mark reported as packet mark")
	}
}

func TestPreflightPolicyLimits(t *testing.T) {
	for _, tc := range []struct {
		code   string
		change func(*config.Config)
	}{
		{"DAEMON_UID_BYPASS_MISSING", func(c *config.Config) { c.Policy.BypassUIDs = nil }},
		{"NO_TARGET_UIDS", func(c *config.Config) { c.Policy.UIDs = nil }},
		{"SYSTEM_UID_SELECTED", func(c *config.Config) { c.Policy.UIDs = []uint32{1000} }},
		{"TARGET_BYPASS_OVERLAP", func(c *config.Config) { c.Policy.BypassUIDs = []uint32{0, 10001} }},
		{"LIVE_POC_REQUIRES_FINITE_UID_ALLOWLIST", func(c *config.Config) { c.Policy.Mode = "all_non_bypass" }},
		{"LIVE_IPV6_DATA_PATH_NOT_VALIDATED", func(c *config.Config) { c.IPv6 = true }},
		{"LIVE_POC_UID_LIMIT_EXCEEDED", func(c *config.Config) {
			c.Policy.UIDs = nil
			for u := uint32(10000); u < 10033; u++ {
				c.Policy.UIDs = append(c.Policy.UIDs, u)
			}
		}},
	} {
		t.Run(tc.code, func(t *testing.T) {
			c, e := preflightFixture()
			tc.change(&c)
			r := evaluatePreflight(c, DefaultPreflightOptions(), 0, e, nil, nil)
			if !containsCode(r.Blocks, tc.code) {
				t.Fatal(r.Blocks)
			}
		})
	}
	c, e := preflightFixture()
	r := evaluatePreflight(c, DefaultPreflightOptions(), 0, e, nil, []uint16{18080})
	if !containsCode(r.Blocks, "LISTENER_PORT_IN_USE") {
		t.Fatal("listener collision ignored")
	}
}

func TestPreflightOptions(t *testing.T) {
	for _, change := range []func(*PreflightOptions){func(o *PreflightOptions) { o.Mark = 0 }, func(o *PreflightOptions) { o.Mask = 3 }, func(o *PreflightOptions) { o.Mark = 2 }, func(o *PreflightOptions) { o.Table = 254 }, func(o *PreflightOptions) { o.Priority = 0 }, func(o *PreflightOptions) { o.Priority = 32766 }, func(o *PreflightOptions) { o.Prefix = "ATP_;cmd" }, func(o *PreflightOptions) { o.Prefix = "../" }} {
		o := DefaultPreflightOptions()
		change(&o)
		if o.Validate() == nil {
			t.Fatal("invalid candidate accepted")
		}
	}
	if DefaultPreflightOptions().Validate() != nil {
		t.Fatal("valid options rejected")
	}
}

func TestListeningPorts(t *testing.T) {
	for _, text := range []string{"sl local_address rem_address st\n0: 0100007F:46A0 00000000:0000 0A", "0: 00000000000000000000000001000000:46A0 00000000000000000000000000000000:0000 0A"} {
		p, e := listeningPorts(text)
		if e != nil || !reflect.DeepEqual(p, []uint16{18080}) {
			t.Fatalf("%v %v", p, e)
		}
	}
	p, e := listeningPorts("0: 0100007F:46A0 00000000:0000 01")
	if e != nil || len(p) != 0 {
		t.Fatal("established socket reported as listener")
	}
	for _, text := range []string{"bad", "0: invalid 0:0 0A", "0: 0100007F:10000 0:0 0A"} {
		if _, e := listeningPorts(text); e == nil {
			t.Fatal("malformed socket accepted")
		}
	}
}

func TestAbsentTableIsNotPermissionFailure(t *testing.T) {
	for _, v := range []Result{{}, {ExitCode: 2, Error: "Error: ipv4: FIB table does not exist.\nDump terminated"}, {ExitCode: 2, Error: "Error: ipv6: FIB table does not exist.\nDump terminated"}} {
		if !emptyRoutingTable(v) {
			t.Fatal("known empty table rejected")
		}
	}
	for _, v := range []Result{{ExitCode: 2, Error: "Permission denied"}, {ExitCode: 1}, {Output: "local default dev lo"}} {
		if emptyRoutingTable(v) {
			t.Fatal("unknown failure treated as absence")
		}
	}
}
