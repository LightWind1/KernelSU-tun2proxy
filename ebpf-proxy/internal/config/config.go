package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

type Endpoint struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

func (e Endpoint) String() string { return net.JoinHostPort(e.Address, strconv.Itoa(e.Port)) }

type Config struct {
	Version  int      `json:"version"`
	Listener Endpoint `json:"listener"`
	IPv6     bool     `json:"ipv6"`
	Upstream struct {
		Type     string `json:"type"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username,omitempty"`
		Password string `json:"password,omitempty"`
	} `json:"upstream"`
	Policy struct {
		Mode        string   `json:"mode"`
		UIDs        []uint32 `json:"uids"`
		BypassUIDs  []uint32 `json:"bypass_uids"`
		BypassCIDRs []string `json:"bypass_cidrs,omitempty"`
	} `json:"policy"`
	UDP struct {
		Mode string `json:"mode"`
	} `json:"udp"`
	BPF struct {
		Object string `json:"object"`
		Cgroup string `json:"cgroup"`
	} `json:"bpf"`
	RuntimeDir string `json:"runtime_dir"`
	Logging    struct {
		Level string `json:"level"`
	} `json:"logging"`
	ConnectTimeoutSeconds int `json:"connect_timeout_seconds"`
	IdleTimeoutSeconds    int `json:"idle_timeout_seconds"`
	MaxConnections        int `json:"max_connections"`
}

func Load(path string) (Config, error) {
	var c Config
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("extra configuration data")
	}
	return c, c.Validate()
}
func (c *Config) Validate() error {
	if c.Version != 1 {
		return errors.New("configuration version must be 1")
	}
	ip := net.ParseIP(c.Listener.Address)
	if ip == nil || ip.To4() == nil || !ip.IsLoopback() {
		return errors.New("listener must be IPv4 loopback; IPv6 uses ::1")
	}
	if c.Listener.Port < 1 || c.Listener.Port > 65535 {
		return errors.New("invalid listener port")
	}
	if c.Upstream.Type != "socks5" {
		return errors.New("only socks5 upstream is supported")
	}
	if c.Upstream.Host == "" || c.Upstream.Port < 1 || c.Upstream.Port > 65535 {
		return errors.New("invalid upstream endpoint")
	}
	if strings.ContainsAny(c.Upstream.Host, " /\\;\r\n\t@?#") {
		return errors.New("invalid upstream host")
	}
	if len(c.Upstream.Username) > 255 || len(c.Upstream.Password) > 255 || (c.Upstream.Password != "" && c.Upstream.Username == "") {
		return errors.New("invalid upstream authentication")
	}
	if c.Policy.Mode != "uid_allowlist" && c.Policy.Mode != "all_non_bypass" {
		return errors.New("invalid UID policy mode")
	}
	if c.UDP.Mode != "pass" {
		return errors.New("only UDP pass is supported")
	}
	for _, s := range c.Policy.BypassCIDRs {
		if _, _, e := net.ParseCIDR(s); e != nil {
			return fmt.Errorf("invalid bypass CIDR: %s", s)
		}
	}
	if c.ConnectTimeoutSeconds == 0 {
		c.ConnectTimeoutSeconds = 10
	}
	if c.IdleTimeoutSeconds == 0 {
		c.IdleTimeoutSeconds = 300
	}
	if c.MaxConnections == 0 {
		c.MaxConnections = 4096
	}
	if c.ConnectTimeoutSeconds < 1 || c.IdleTimeoutSeconds < 1 || c.MaxConnections < 1 || c.MaxConnections > 16384 {
		return errors.New("invalid connection limits")
	}
	switch c.Logging.Level {
	case "", "info":
		c.Logging.Level = "info"
	case "error", "warn", "debug", "trace":
	default:
		return errors.New("invalid log level")
	}
	return nil
}
