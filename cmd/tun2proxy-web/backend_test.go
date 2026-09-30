package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBackendDefault(t *testing.T) {
	if backendName(Config{}) != "tun" {
		t.Fatal("legacy default changed")
	}
	if e := validateBackend(Config{Backend: "other"}); e == nil {
		t.Fatal("unknown backend accepted")
	}
	if e := validateBackend(Config{Backend: "ebpf", ProxyURL: "http://192.0.2.1:8083"}); e == nil {
		t.Fatal("HTTP silently treated as SOCKS5")
	}
}
func TestEBPFAdapter(t *testing.T) {
	c := Config{Backend: "ebpf", ProxyURL: "socks5h://test:p%40ss@[::1]:1080", RouteMode: "selected", AppPackages: []string{"test.app", "same.uid"}, BypassIPs: []string{"192.0.2.1", "2001:db8::/32"}}
	core, e := ebpfConfig(c, []AppEntry{{Package: "test.app", UID: 10001}, {Package: "same.uid", UID: 10001}})
	if e != nil {
		t.Fatal(e)
	}
	up := core["upstream"].(map[string]any)
	if up["password"] != "p@ss" || up["host"] != "::1" || up["type"] != "socks5" {
		t.Fatal("existing auth/address not reused")
	}
	p := core["policy"].(map[string]any)
	if len(p["uids"].([]uint32)) != 1 {
		t.Fatal("UID dedup failed")
	}
	b, _ := json.Marshal(core)
	if strings.Contains(strings.ToLower(string(b)), "yakit") {
		t.Fatal("product-specific core configuration")
	}
	c.RouteMode = "all"
	core, e = ebpfConfig(c, nil)
	if e != nil || core["policy"].(map[string]any)["mode"] != "all_non_bypass" {
		t.Fatal("all policy")
	}
	c.RouteMode = "off"
	core, e = ebpfConfig(c, nil)
	if e != nil || len(core["policy"].(map[string]any)["uids"].([]uint32)) != 0 {
		t.Fatal("off policy")
	}
	c.RouteMode = "selected"
	if _, e = ebpfConfig(c, nil); e == nil {
		t.Fatal("missing package accepted")
	}
}
