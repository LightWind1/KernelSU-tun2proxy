package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodePrivatePipe(t *testing.T) {
	c := valid()
	c.Upstream.Username = "name"
	c.Upstream.Password = "secret"
	b, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	got, e := Decode(strings.NewReader(string(b)))
	if e != nil || got.Upstream.Password != c.Upstream.Password || got.ConnectTimeoutSeconds != 10 {
		t.Fatal("private pipe changed validation or auth")
	}
	for _, bad := range []string{string(b) + " {}", strings.Replace(string(b), `"version":1`, `"version":1,"unknown":true`, 1)} {
		if _, e := Decode(strings.NewReader(bad)); e == nil {
			t.Fatal("pipe bypasses strict decoder")
		}
	}
	if _, e := Decode(strings.NewReader(string(b) + strings.Repeat(" ", 1<<20))); e == nil {
		t.Fatal("oversize trailing data accepted")
	}
}

func valid() Config {
	c := Config{Version: 1, Listener: Endpoint{"127.0.0.1", 18080}}
	c.Upstream.Type = "socks5"
	c.Upstream.Host = "192.0.2.1"
	c.Upstream.Port = 1080
	c.Policy.Mode = "uid_allowlist"
	c.UDP.Mode = "pass"
	return c
}
func TestValidation(t *testing.T) {
	for _, change := range []func(*Config){func(c *Config) { c.Listener.Address = "0.0.0.0" }, func(c *Config) { c.Upstream.Port = 65536 }, func(c *Config) { c.Upstream.Host = "host;cmd" }, func(c *Config) { c.Upstream.Type = "http" }, func(c *Config) { c.Policy.BypassCIDRs = []string{"../"} }, func(c *Config) { c.UDP.Mode = "proxy" }, func(c *Config) { c.Upstream.Password = "secret" }, func(c *Config) { c.MaxConnections = 20000 }} {
		c := valid()
		change(&c)
		if e := c.Validate(); e == nil {
			t.Errorf("accepted invalid config: %+v", c.Listener)
		}
	}
	c := valid()
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
}
func TestStrictJSON(t *testing.T) {
	for _, data := range []string{`{"version":1,"unknown":1}`, `{} {}`, strings.Repeat("x", 1<<20)} {
		p := filepath.Join(t.TempDir(), "config.json")
		os.WriteFile(p, []byte(data), 0600)
		if _, e := Load(p); e == nil {
			t.Fatal("accepted invalid JSON")
		}
	}
}
