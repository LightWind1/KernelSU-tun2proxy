//go:build linux

package tproxy

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

type Report struct {
	Version        int               `json:"version"`
	ReadOnly       bool              `json:"read_only"`
	Namespace      string            `json:"network_namespace"`
	Config         Result            `json:"kernel_config"`
	Checks         map[string]Result `json:"checks"`
	Marks          []MarkUse         `json:"mark_uses"`
	Candidate      string            `json:"candidate_mark"`
	Mask           string            `json:"candidate_mask"`
	AutomaticSetup bool              `json:"automatic_setup_allowed"`
	Risks          []string          `json:"collision_risks"`
	Conclusion     string            `json:"conclusion"`
}

// Every command here is a query. No shell, namespace, route, firewall or BPF
// modification is performed. Help probes do not create rules.
var probeCommands = map[string][]string{
	"kernel":       {"uname", "-a"},
	"android":      {"getprop", "ro.build.version.release"},
	"sdk":          {"getprop", "ro.build.version.sdk"},
	"identity":     {"id"},
	"selinux":      {"getenforce"},
	"iptables":     {"iptables", "--version"},
	"ip6tables":    {"ip6tables", "--version"},
	"nft":          {"nft", "--version"},
	"tproxy4":      {"iptables", "-j", "TPROXY", "-h"},
	"tproxy6":      {"ip6tables", "-j", "TPROXY", "-h"},
	"owner":        {"iptables", "-m", "owner", "-h"},
	"MARK":         {"iptables", "-j", "MARK", "-h"},
	"mark":         {"iptables", "-m", "mark", "-h"},
	"socket":       {"iptables", "-m", "socket", "-h"},
	"xtables_wait": {"iptables", "-w", "2", "-t", "mangle", "-S"},
	"rules4":       {"ip", "rule", "show"},
	"rules6":       {"ip", "-6", "rule", "show"},
	"routes4":      {"ip", "route", "show", "table", "all"},
	"routes6":      {"ip", "-6", "route", "show", "table", "all"},
	"firewall4":    {"iptables-save"},
	"firewall6":    {"ip6tables-save"},
	"nft_ruleset":  {"nft", "list", "ruleset"},
}

func query(args []string) Result {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, args[0], args[1:]...)
	var stderr strings.Builder
	c.Stderr = &stderr
	b, err := c.Output()
	r := Result{Command: args, Output: strings.TrimSpace(string(b)), Error: strings.TrimSpace(stderr.String())}
	if err != nil {
		r.ExitCode = -1
		if e, ok := err.(*exec.ExitError); ok {
			r.ExitCode = e.ExitCode()
		}
		if r.Error == "" {
			r.Error = err.Error()
		}
		if ctx.Err() != nil {
			r.Error += ": " + ctx.Err().Error()
		}
	}
	return r
}

func transparentOption(family, level, option int) Result {
	fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err == nil {
		defer unix.Close(fd)
		err = unix.SetsockoptInt(fd, level, option, 1)
		if err == nil {
			var value int
			value, err = unix.GetsockoptInt(fd, level, option)
			if err == nil && value != 1 {
				err = fmt.Errorf("getsockopt returned %d", value)
			}
		}
	}
	if err != nil {
		return Result{ExitCode: -1, Error: fmt.Sprintf("setsockopt/getsockopt: %v", err)}
	}
	return Result{Output: "supported: setsockopt=1, getsockopt=1; socket closed without binding"}
}

func kernelConfig() Result {
	f, err := os.Open("/proc/config.gz")
	if err != nil {
		return Result{ExitCode: -1, Error: err.Error()}
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		return Result{ExitCode: -1, Error: err.Error()}
	}
	defer z.Close()
	b, err := io.ReadAll(io.LimitReader(z, 4<<20))
	if err != nil {
		return Result{ExitCode: -1, Error: err.Error()}
	}
	keys := []string{"NETFILTER", "NETFILTER_XTABLES", "NETFILTER_XT_MARK", "NETFILTER_XT_MATCH_MARK", "NETFILTER_XT_MATCH_OWNER", "NETFILTER_XT_MATCH_SOCKET", "NETFILTER_XT_TARGET_MARK", "NETFILTER_XT_TARGET_TPROXY", "IP_ADVANCED_ROUTER", "IP_MULTIPLE_TABLES", "IPV6", "IPV6_MULTIPLE_TABLES", "NF_TABLES", "NFT_TPROXY", "NFT_SOCKET", "NFT_MARK", "NF_TPROXY_IPV4", "NF_TPROXY_IPV6", "IP_NF_MANGLE", "IP6_NF_MANGLE"}
	var lines []string
	for _, key := range keys {
		found := "CONFIG_" + key + ": not present (not evidence of absence if config is unavailable)"
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "CONFIG_"+key+"=") || line == "# CONFIG_"+key+" is not set" {
				found = line
				break
			}
		}
		lines = append(lines, found)
	}
	return Result{Output: strings.Join(lines, "\n"), SHA256: fmt.Sprintf("%x", sha256.Sum256(b))}
}

func Probe() Report {
	r := Report{Version: 1, ReadOnly: true, Checks: map[string]Result{}, Config: kernelConfig(), Candidate: "0x00400000", Mask: "0x00400000", AutomaticSetup: false}
	r.Namespace, _ = os.Readlink("/proc/self/ns/net")
	names := make([]string, 0, len(probeCommands))
	for name := range probeCommands {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		args := probeCommands[name]
		v := query(args)
		if args[len(args)-1] == "-h" && v.ExitCode == 0 {
			// Keep extension-specific help; omit repetitive general usage.
			if index := strings.LastIndex(v.Output, "\n\n"); index >= 0 {
				v.Output = v.Output[index+2:]
			}
		}
		if name == "firewall4" || name == "firewall6" || name == "rules4" || name == "rules6" || name == "nft_ruleset" {
			r.Marks = append(r.Marks, MarkUses(name, v.Output)...)
		}
		// Do not expose full system firewall dumps in normal diagnostics.
		if strings.HasPrefix(name, "firewall") || name == "nft_ruleset" || name == "xtables_wait" {
			v.SHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(v.Output)))
			v.Output = fmt.Sprintf("captured %d bytes; full firewall omitted", len(v.Output))
		}
		r.Checks[name] = v
	}
	for _, path := range []string{"/proc/net/ip_tables_targets", "/proc/net/ip_tables_matches", "/proc/net/ip6_tables_targets", "/proc/sys/net/ipv4/conf/all/rp_filter", "/proc/sys/net/ipv4/conf/lo/rp_filter", "/proc/sys/net/ipv4/conf/all/route_localnet", "/proc/sys/net/ipv4/conf/lo/route_localnet"} {
		b, err := os.ReadFile(path)
		v := Result{Output: strings.TrimSpace(string(b))}
		if err != nil {
			v.ExitCode = -1
			v.Error = err.Error()
		}
		r.Checks[path] = v
	}
	r.Checks["IP_TRANSPARENT"] = transparentOption(unix.AF_INET, unix.SOL_IP, unix.IP_TRANSPARENT)
	r.Checks["IPV6_TRANSPARENT"] = transparentOption(unix.AF_INET6, unix.SOL_IPV6, unix.IPV6_TRANSPARENT)
	r.Risks = MarkRisk(0x00400000, r.Marks)
	r.Risks = append(r.Risks, "TPROXY mark collision risk: vendor BPF/netd future changes cannot be certified by this snapshot; explicit live-namespace override required")
	r.Conclusion = "Capability evidence only: OUTPUT -> policy route -> PREROUTING requires a real TCP PoC. Automatic live-network setup is disabled."
	return r
}
