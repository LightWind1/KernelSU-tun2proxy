//go:build linux

package tproxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

type PoCReport struct {
	Namespace     string            `json:"network_namespace"`
	HostNamespace string            `json:"host_network_namespace"`
	Original      string            `json:"original_destination,omitempty"`
	Client        string            `json:"client,omitempty"`
	Steps         []Result          `json:"steps"`
	Evidence      map[string]Result `json:"evidence"`
	Rollback      []Result          `json:"rollback"`
	RollbackOK    bool              `json:"rollback_ok"`
	Scope         string            `json:"scope"`
}

// PoCIsolated deliberately has no live-network override. Run using unshare -n.
// It refuses the host namespace and any non-empty firewall. No upstream is
// contacted: this proves interception and exact original destination only.
func PoCIsolated() (r PoCReport, err error) {
	return pocIsolated(0)
}

// failAfter is an internal fault-injection seam, not a user-facing rule API.
func pocIsolated(failAfter int) (r PoCReport, err error) {
	r.Scope = "IPv4 TCP destination-only PoC; isolated namespace; no UID policy or upstream acceptance claimed"
	r.Evidence = map[string]Result{}
	r.Namespace, err = os.Readlink("/proc/self/ns/net")
	if err != nil {
		return
	}
	r.HostNamespace, err = os.Readlink("/proc/1/ns/net")
	if err != nil {
		return
	}
	if r.Namespace == r.HostNamespace {
		return r, fmt.Errorf("refusing host network namespace: run unshare -n ebpf-proxy tproxy poc-isolated")
	}
	snapshot := query([]string{"iptables-save"})
	if snapshot.ExitCode != 0 {
		return r, fmt.Errorf("firewall preflight: %s", snapshot.Error)
	}
	for _, line := range strings.Split(snapshot.Output, "\n") {
		if strings.HasPrefix(line, "-A ") || strings.Contains(line, "ATP_") {
			return r, fmt.Errorf("refusing non-empty namespace firewall")
		}
	}
	check := query([]string{"ip", "route", "show", "table", "all"})
	if check.ExitCode != 0 || check.Output != "" {
		return r, fmt.Errorf("requires a fresh namespace without routes")
	}
	rules := query([]string{"ip", "rule", "show"})
	if rules.ExitCode != 0 {
		return r, fmt.Errorf("namespace policy preflight: %s", rules.Error)
	}
	for _, line := range strings.Split(rules.Output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] != "0:" && fields[0] != "32766:" && fields[0] != "32767:" {
			return r, fmt.Errorf("refusing namespace with custom policy rules")
		}
	}
	listener, err := ListenTransparent(context.Background(), "tcp4", "0.0.0.0:18080")
	if err != nil {
		return r, err
	}
	defer listener.Close()
	if tcp, ok := listener.(*net.TCPListener); ok {
		_ = tcp.SetDeadline(time.Now().Add(12 * time.Second))
	}
	var tx *Transaction
	rollingBack := false
	defer func() {
		r.RollbackOK = true
		rollingBack = true
		if tx != nil {
			if e := tx.Teardown(); e != nil {
				r.RollbackOK = false
				if err == nil {
					err = e
				}
			}
		}
		r.Evidence["after_firewall"] = query([]string{"iptables-save"})
		r.Evidence["after_rule"] = query([]string{"ip", "rule", "show"})
		r.Evidence["after_routes"] = query([]string{"ip", "route", "show", "table", "all"})
		for name, v := range r.Evidence {
			// Bringing lo up can leave kernel-generated 127/8 local routes after
			// link-down. They are not owned by this PoC: verify our addresses and
			// table are gone, never delete unrelated kernel routes to force empty.
			if strings.HasPrefix(name, "after_") && (v.ExitCode != 0 || strings.Contains(v.Output, "ATP_POC") || strings.Contains(v.Output, "38766") || name == "after_routes" && (strings.Contains(v.Output, "198.18.0.1") || strings.Contains(v.Output, "192.0.2.2"))) {
				r.RollbackOK = false
			}
		}
		if !r.RollbackOK && err == nil {
			err = fmt.Errorf("isolated rollback failed; namespace destruction still removes all resources")
		}
	}()
	// Fixture-only main route supplies the pre-OUTPUT route lookup. It never
	// modifies Android's main table: namespace and empty-state guards run first.
	steps := []Step{
		{[]string{"ip", "link", "set", "lo", "up"}, []string{"ip", "link", "set", "lo", "down"}},
		{[]string{"ip", "addr", "add", "192.0.2.2/32", "dev", "lo"}, []string{"ip", "addr", "del", "192.0.2.2/32", "dev", "lo"}},
		{[]string{"ip", "route", "add", "198.18.0.1/32", "dev", "lo", "src", "192.0.2.2"}, []string{"ip", "route", "del", "198.18.0.1/32", "dev", "lo"}},
	}
	planned, e := (IPv4DestinationPlan{
		Destination: netip.MustParseAddrPort("198.18.0.1:443"), ListenerPort: 18080,
		Mark: 0x00400000, Mask: 0x00400000, Table: 38766, Priority: 9001, Prefix: "ATP_POC",
	}).Steps()
	if e != nil {
		return r, e
	}
	steps = append(steps, planned...)
	adds := map[string]bool{}
	for _, s := range steps {
		adds[strings.Join(s.Add, "\x00")] = true
	}
	tx = NewTransaction(steps, func(args []string) Result {
		v := query(args)
		if !rollingBack && adds[strings.Join(args, "\x00")] {
			r.Steps = append(r.Steps, v)
		} else {
			r.Rollback = append(r.Rollback, v)
		}
		return v
	})
	if err = tx.setup(failAfter); err != nil {
		return
	}
	clientErr := make(chan error, 1)
	go func() {
		c, e := (&net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.2")}}).Dial("tcp4", "198.18.0.1:443")
		if c != nil {
			c.Close()
		}
		clientErr <- e
	}()
	c, err := listener.Accept()
	if err != nil {
		return r, fmt.Errorf("transparent accept: %w", err)
	}
	r.Client = c.RemoteAddr().String()
	r.Original, err = OriginalDestination(c)
	c.Close()
	if err != nil {
		return
	}
	if err = <-clientErr; err != nil {
		return r, fmt.Errorf("client connect: %w", err)
	}
	if r.Original != "198.18.0.1:443" {
		return r, fmt.Errorf("original destination mismatch: %s", r.Original)
	}
	r.Evidence["counters"] = query([]string{"iptables", "-w", "2", "-t", "mangle", "-L", "-n", "-v", "-x"})
	r.Evidence["rule"] = query([]string{"ip", "rule", "show"})
	r.Evidence["route"] = query([]string{"ip", "route", "show", "table", "38766"})
	return
}
