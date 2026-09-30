package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
