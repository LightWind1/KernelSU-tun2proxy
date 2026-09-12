package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCertificateHTTPBoundary(t *testing.T) {
	tests := []struct {
		name, remote, host, origin, header string
		allowed                            bool
	}{
		{"local", "127.0.0.1:1234", "127.0.0.1:38765", "", "1", true},
		{"same-origin", "127.0.0.1:1234", "127.0.0.1:38765", "http://127.0.0.1:38765", "1", true},
		{"LAN", "192.168.1.2:123", "127.0.0.1:38765", "", "1", false},
		{"cross-origin", "127.0.0.1:123", "127.0.0.1:38765", "http://evil.test", "1", false},
		{"dns-rebind", "127.0.0.1:123", "evil.test:38765", "", "1", false},
		{"missing-header", "127.0.0.1:123", "127.0.0.1:38765", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "http://"+tt.host+"/api/certificates/action", nil)
			req.RemoteAddr = tt.remote
			req.Host = tt.host
			req.Header.Set("Origin", tt.origin)
			req.Header.Set("X-Tun2proxy-Certificate", tt.header)
			hit := false
			w := httptest.NewRecorder()
			certHTTP(func(w http.ResponseWriter, r *http.Request) { hit = true })(w, req)
			if hit != tt.allowed {
				t.Fatalf("allowed=%v status=%d", hit, w.Code)
			}
		})
	}
}
func TestProxyConfigRoundTrip(t *testing.T) {
	original := configFile
	defer func() { configFile = original }()
	configFile = filepath.Join(t.TempDir(), "config.json")
	input := Config{Version: "1.0", RouteMode: "selected", AppPackages: []string{"app.one"}, Enabled: true, TunName: "tun0", ProxyURL: "http://test:p%40ss@192.168.1.2:8083", DNSMode: "over-tcp", BypassIPs: []string{"10.0.0.0/8"}, TCPTimeout: 45, UDPTimeout: 19, UDPGWServer: "127.0.0.1:7300"}
	if e := saveConfig(input); e != nil {
		t.Fatal(e)
	}
	got, e := loadConfig()
	if e != nil {
		t.Fatal(e)
	}
	a, _ := json.Marshal(input)
	b, _ := json.Marshal(got)
	if string(a) != string(b) {
		t.Fatal("proxy config regression")
	}
	if st, e := os.Stat(configFile); e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("credential file permission")
	}
}
func TestCertificateIDAction(t *testing.T) {
	for _, id := range []string{"../", "/system/etc/security/cacerts/a", "x;id", ""} {
		body := `{"action":"delete","id":"` + id + `"}`
		w := httptest.NewRecorder()
		certAction(w, httptest.NewRequest("POST", "/api/certificates/action", strings.NewReader(body)))
		if w.Code != 400 || !strings.Contains(w.Body.String(), "Invalid certificate ID") {
			t.Fatalf("%s: %d %s", id, w.Code, w.Body.String())
		}
	}
}
