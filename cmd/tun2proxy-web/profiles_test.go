package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"tun2proxy-web/certificate"
)

func TestProfilesMigrateSaveAndSwitch(t *testing.T) {
	old := configFile
	configFile = filepath.Join(t.TempDir(), "config.json")
	defer func() { configFile = old }()
	original := Config{ProxyURL: "http://192.168.30.102:8083", DNSMode: "virtual", TunName: "tun0"}
	if e := saveRuntimeConfig(original); e != nil {
		t.Fatal(e)
	}
	p, e := readProfiles()
	if e != nil || len(p.Profiles) != 1 || p.Profiles[0].Config.ProxyURL != original.ProxyURL {
		t.Fatalf("migration: %+v %v", p, e)
	}
	if e = saveConfig(original); e != nil {
		t.Fatal(e)
	}
	invoke := func(action, id, name string) (ProfileSet, int) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"action": action, "id": id, "name": name})
		w := httptest.NewRecorder()
		apiProfiles(w, httptest.NewRequest("POST", "/api/profiles", bytes.NewReader(body)))
		var result ProfileSet
		_ = json.Unmarshal(w.Body.Bytes(), &result)
		return result, w.Code
	}
	p, status := invoke("create", "", "第二台电脑")
	if status != 200 || len(p.Profiles) != 2 {
		t.Fatalf("create: %d %+v", status, p)
	}
	second := p.Profiles[1].ID
	p, status = invoke("select", second, "")
	if status != 200 || p.ActiveID != second {
		t.Fatalf("select: %d %+v", status, p)
	}
	active, _ := loadConfig()
	if active.ProxyURL != "http://127.0.0.1:8083" {
		t.Fatalf("active config: %+v", active)
	}
	active.ProxyURL = "http://192.168.30.103:8090"
	if e = saveConfig(active); e != nil {
		t.Fatal(e)
	}
	p, e = readProfiles()
	if e != nil || p.Profiles[1].Config.ProxyURL != active.ProxyURL || p.Profiles[0].Config.ProxyURL != original.ProxyURL {
		t.Fatalf("isolation: %+v %v", p, e)
	}
	_, status = invoke("delete", second, "")
	if status != 409 {
		t.Fatalf("active delete: %d", status)
	}
}

func TestYakitEndpointIsolationAndLegacyMigration(t *testing.T) {
	old := configFile
	configFile = filepath.Join(t.TempDir(), "config.json")
	defer func() { configFile = old }()
	if e := saveRuntimeConfig(Config{ProxyURL: "http://192.168.30.102:8083"}); e != nil {
		t.Fatal(e)
	}
	v := certificate.Inventory{Version: 1, Yakit: map[string]certificate.Remote{"normal": {LocalID: "old"}}}
	scopedYakit(&v, "http://192.168.30.103:8090")
	if v.Yakit["http://192.168.30.102:8083|normal"].LocalID != "old" {
		t.Fatalf("legacy assigned to wrong endpoint: %+v", v.Yakit)
	}
	v.Yakit["http://192.168.30.103:8090|normal"] = certificate.Remote{LocalID: "new", History: []string{"new"}}
	if v.Yakit["http://192.168.30.102:8083|normal"].LocalID == "new" {
		t.Fatal("endpoint certificate overwritten")
	}
}
