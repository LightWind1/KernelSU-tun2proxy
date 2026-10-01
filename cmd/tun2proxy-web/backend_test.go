package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTPROXYPreflightDoesNotCreateRuntime(t *testing.T) {
	dir := t.TempDir()
	oldConfig, oldRun := configFile, runDir
	defer func() { configFile, runDir = oldConfig, oldRun }()
	configFile = filepath.Join(dir, "config.json")
	runDir = filepath.Join(dir, "must-not-exist")
	b, _ := json.Marshal(Config{ProxyURL: "http://name:private-password@192.0.2.1:8083", RouteMode: "off"})
	if e := os.WriteFile(configFile, b, 0600); e != nil {
		t.Fatal(e)
	}
	out, e := backendAction("tproxy-preflight")
	if e == nil || strings.Contains(out+e.Error(), "private-password") {
		t.Fatal("HTTP converted or credential leaked")
	}
	var report map[string]any
	if json.Unmarshal([]byte(out), &report) != nil || report["status"] != "blocked" || report["automatic_setup_allowed"] != false || report["upstream_type"] != "http" {
		t.Fatal("missing protocol mismatch report")
	}
	if _, e := os.Stat(runDir); !os.IsNotExist(e) {
		t.Fatal("read-only preflight created runtime/lock")
	}
	after, _ := os.ReadFile(configFile)
	if string(after) != string(b) {
		t.Fatal("saved configuration modified")
	}
}

func TestTPROXYPreflightUsesPrivatePipe(t *testing.T) {
	shell := "/bin/sh"
	if _, e := os.Stat(shell); e != nil {
		shell = "/system/bin/sh"
	}
	if _, e := os.Stat(shell); e != nil {
		t.Skip("POSIX shell fixture unavailable")
	}
	dir := t.TempDir()
	oldConfig, oldRun, oldMod := configFile, runDir, modDir
	defer func() { configFile, runDir, modDir = oldConfig, oldRun, oldMod }()
	configFile = filepath.Join(dir, "config.json")
	runDir = filepath.Join(dir, "must-not-exist")
	modDir = filepath.Join(dir, "module")
	b, _ := json.Marshal(Config{ProxyURL: "socks5h://private-user:private-password@192.0.2.1:1080", RouteMode: "off"})
	if e := os.WriteFile(configFile, b, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.MkdirAll(filepath.Dir(ebpfBinary()), 0700); e != nil {
		t.Fatal(e)
	}
	script := "#!" + shell + `
[ "$1" = tproxy ] && [ "$2" = preflight ] && [ "$3" = --config ] && [ "$4" = - ] && [ "$5" = --probe-upstream ] || exit 9
IFS= read -r data
case "$data" in
 *'"password":"private-password"'*'"port":1080'*|*'"port":1080'*'"password":"private-password"'*) ;;
 *) exit 9 ;;
esac
printf '%s\n' 'private-password' >&2
printf '%s\n' '{"status":"blocked","network_rules_read_only":true,"automatic_setup_allowed":false}'
exit 1
`
	if e := os.WriteFile(ebpfBinary(), []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	out, e := backendAction("tproxy-preflight")
	if e == nil || !json.Valid([]byte(out)) || strings.Contains(out+e.Error(), "private-password") {
		t.Fatal("pipe/report/stderr isolation failed")
	}
	if _, e := os.Stat(runDir); !os.IsNotExist(e) {
		t.Fatal("runtime created")
	}
	after, _ := os.ReadFile(configFile)
	if string(after) != string(b) {
		t.Fatal("saved configuration modified")
	}
}

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
