package tproxy

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
)

// IPv4DestinationPlan is the narrow destination-only PoC planner. UID policy
// and production preflight will build on this boundary rather than letting
// WebUI construct commands. It is not permission to mutate a host namespace.
type IPv4DestinationPlan struct {
	Destination  netip.AddrPort
	ListenerPort uint16
	Mark         uint32
	Mask         uint32
	Table        uint32
	Priority     uint32
	Prefix       string
}

var planPrefix = regexp.MustCompile(`^ATP_[A-Z0-9_]{1,16}$`)

func (c IPv4DestinationPlan) Steps() ([]Step, error) {
	if !c.Destination.IsValid() || !c.Destination.Addr().Is4() || c.Destination.Port() == 0 || c.Destination.Addr().IsLoopback() || c.Destination.Addr().IsMulticast() || c.Destination.Addr().IsUnspecified() || c.Destination.Addr().IsLinkLocalUnicast() || c.Destination.Addr() == netip.MustParseAddr("255.255.255.255") {
		return nil, fmt.Errorf("invalid IPv4 TCP destination")
	}
	if c.ListenerPort == 0 || c.Mask == 0 || c.Mask&(c.Mask-1) != 0 || c.Mark != c.Mask || c.Table < 256 || c.Priority == 0 || c.Priority >= 32766 || !planPrefix.MatchString(c.Prefix) {
		return nil, fmt.Errorf("invalid listener, single-bit mark, dedicated table, priority or prefix")
	}
	ip := c.Destination.Addr().String()
	port := strconv.Itoa(int(c.Destination.Port()))
	table := strconv.FormatUint(uint64(c.Table), 10)
	priority := strconv.FormatUint(uint64(c.Priority), 10)
	mark := fmt.Sprintf("0x%08x/0x%08x", c.Mark, c.Mask)
	pre, out := c.Prefix+"_PRE", c.Prefix+"_OUT"
	ipt := func(args ...string) []string { return append([]string{"iptables", "-w", "2", "-t", "mangle"}, args...) }
	rule := func(chain string, args ...string) Step {
		return Step{ipt(append([]string{"-A", chain}, args...)...), ipt(append([]string{"-D", chain}, args...)...)}
	}
	return []Step{
		{[]string{"ip", "route", "add", "local", ip + "/32", "dev", "lo", "table", table}, []string{"ip", "route", "del", "local", ip + "/32", "dev", "lo", "table", table}},
		{[]string{"ip", "rule", "add", "priority", priority, "fwmark", mark, "lookup", table}, []string{"ip", "rule", "del", "priority", priority, "fwmark", mark, "lookup", table}},
		{ipt("-N", pre), ipt("-X", pre)},
		rule(pre, "-p", "tcp", "-d", ip, "--dport", port, "-m", "mark", "--mark", mark, "-j", "TPROXY", "--on-port", strconv.Itoa(int(c.ListenerPort)), "--tproxy-mark", mark),
		{ipt("-I", "PREROUTING", "1", "-p", "tcp", "-j", pre), ipt("-D", "PREROUTING", "-p", "tcp", "-j", pre)},
		{ipt("-N", out), ipt("-X", out)},
		rule(out, "-p", "tcp", "-d", ip, "--dport", port, "-j", "MARK", "--set-xmark", mark),
		// The only interception entry is last, hence removed first.
		{ipt("-I", "OUTPUT", "1", "-p", "tcp", "-j", out), ipt("-D", "OUTPUT", "-p", "tcp", "-j", out)},
	}, nil
}
