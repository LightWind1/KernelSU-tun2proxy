//go:build linux

package tproxy

import (
	"bytes"
	"context"
	"ebpf-proxy/internal/relay"
	"ebpf-proxy/internal/testutil"
	"ebpf-proxy/internal/upstream"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type RelayPoCReport struct {
	Namespace         string            `json:"namespace"`
	Cases             map[string]Result `json:"cases"`
	Originals         []string          `json:"original_destinations"`
	UpstreamOriginals []string          `json:"upstream_original_destinations,omitempty"`
	Stats             map[string]any    `json:"relay_stats"`
	Counters          Result            `json:"counters"`
	PolicyDisable     Result            `json:"policy_disable"`
	After             map[string]Result `json:"after"`
	Rollback          []Result          `json:"rollback"`
	RollbackOK        bool              `json:"rollback_ok"`
	Scope             string            `json:"scope"`
}

// RelayPoCIsolated tests real owner UID sockets in a fresh netns, using a local
// original-destination fixture. The previous nonlocal PoC separately proves
// policy rerouting. This fixture proves opaque relay and UID isolation, not an
// Internet path. The workers change UID in a child process, never Go threads.
func RelayPoCIsolated(workerArgs []string) (r RelayPoCReport, err error) {
	return relayPoCIsolated(workerArgs, false)
}

func SOCKS5PoCIsolated(workerArgs []string) (RelayPoCReport, error) {
	return relayPoCIsolated(workerArgs, true)
}

func relayPoCIsolated(workerArgs []string, socks bool) (r RelayPoCReport, err error) {
	r.Cases = map[string]Result{}
	r.Scope = "isolated IPv4 local-destination fixture: direct relay, UID owner, daemon/upstream bypass, half-close; not live Android/App/MITM acceptance"
	if socks {
		r.Scope = "isolated IPv4 fixture: TPROXY -> generic SOCKS5 -> exact original destination; UID/bypass/half-close; not live MITM acceptance"
	}
	r.Namespace, err = os.Readlink("/proc/self/ns/net")
	if err != nil {
		return
	}
	host, e := os.Readlink("/proc/1/ns/net")
	if e != nil {
		return r, e
	}
	if host == r.Namespace {
		return r, fmt.Errorf("refusing host namespace; use unshare -n")
	}
	// Android hides /proc/1 from non-root UIDs. Pass an already verified netns
	// descriptor to workers instead of weakening procfs/SELinux permissions.
	privateNS, e := os.Open("/proc/self/ns/net")
	if e != nil {
		return r, e
	}
	defer privateNS.Close()
	fw := query([]string{"iptables-save"})
	routes := query([]string{"ip", "route", "show", "table", "all"})
	rules := query([]string{"ip", "rule", "show"})
	if fw.ExitCode != 0 || strings.Contains(fw.Output, "-A ") || strings.Contains(fw.Output, "ATP_") || routes.ExitCode != 0 || routes.Output != "" || rules.ExitCode != 0 {
		return r, fmt.Errorf("requires a fresh namespace")
	}
	for _, line := range strings.Split(rules.Output, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && f[0] != "0:" && f[0] != "32766:" && f[0] != "32767:" {
			return r, fmt.Errorf("custom namespace policy")
		}
	}
	var undo [][]string
	defer func() {
		r.RollbackOK = true
		for i := len(undo) - 1; i >= 0; i-- {
			v := query(undo[i])
			r.Rollback = append(r.Rollback, v)
			if v.ExitCode != 0 {
				r.RollbackOK = false
			}
		}
		for _, args := range [][]string{{"iptables-save"}, {"ip", "rule", "show"}, {"ip", "route", "show", "table", "all"}} {
			v := query(args)
			if r.After == nil {
				r.After = map[string]Result{}
			}
			r.After[strings.Join(args, " ")] = v
			if v.ExitCode != 0 || strings.Contains(v.Output, "ATP_UID") || strings.Contains(v.Output, "38766") || strings.Contains(v.Output, "198.18.0.1") {
				r.RollbackOK = false
			}
		}
		if !r.RollbackOK && err == nil {
			err = fmt.Errorf("owned resource rollback failed")
		}
	}()
	step := func(add, del []string) error {
		v := query(add)
		if v.ExitCode != 0 {
			return fmt.Errorf("%v: exit=%d %s", add, v.ExitCode, v.Error)
		}
		undo = append(undo, del)
		return nil
	}
	for _, p := range [][2][]string{
		{{"ip", "link", "set", "lo", "up"}, {"ip", "link", "set", "lo", "down"}},
		{{"ip", "addr", "add", "198.18.0.1/32", "dev", "lo"}, {"ip", "addr", "del", "198.18.0.1/32", "dev", "lo"}},
		{{"ip", "route", "add", "local", "default", "dev", "lo", "table", "38766"}, {"ip", "route", "del", "local", "default", "dev", "lo", "table", "38766"}},
		{{"ip", "rule", "add", "priority", "9001", "fwmark", "0x400000/0x400000", "lookup", "38766"}, {"ip", "rule", "del", "priority", "9001", "fwmark", "0x400000/0x400000", "lookup", "38766"}},
	} {
		if err = step(p[0], p[1]); err != nil {
			return
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var servers []net.Listener
	var mu sync.Mutex
	defer func() {
		for _, s := range servers {
			s.Close()
		}
	}()
	udp, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.18.0.1"), Port: 443})
	if e != nil {
		return r, e
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 8192)
		for {
			n, a, e := udp.ReadFromUDP(b)
			if e != nil {
				return
			}
			_, _ = udp.WriteToUDP(b[:n], a)
		}
	}()
	// Fixture waits for EOF before returning bytes, exercising TCP half-close.
	for _, port := range []int{443, 8443} {
		l, e := net.Listen("tcp4", fmt.Sprintf("198.18.0.1:%d", port))
		if e != nil {
			return r, e
		}
		servers = append(servers, l)
		if socks && port == 8443 {
			go testutil.ServeSOCKS5(ctx, l, "198.18.0.1:443", func(d string) { mu.Lock(); r.UpstreamOriginals = append(r.UpstreamOriginals, d); mu.Unlock() })
			continue
		}
		go func(l net.Listener) {
			for {
				c, e := l.Accept()
				if e != nil {
					return
				}
				go func() {
					defer c.Close()
					c.SetDeadline(time.Now().Add(10 * time.Second))
					b, e := io.ReadAll(io.LimitReader(c, 1<<20))
					if e == nil {
						_, _ = c.Write(b)
					}
				}()
			}
		}(l)
	}
	l, e := ListenTransparent(ctx, "tcp4", "0.0.0.0:18080")
	if e != nil {
		return r, e
	}
	defer l.Close()
	stats := &relay.Stats{}
	var connector upstream.Connector = upstream.Direct{Timeout: 3 * time.Second}
	if socks {
		s := upstream.SOCKS5{Address: "198.18.0.1:8443", Timeout: 3 * time.Second}
		// Do not enable interception until the upstream handshake succeeds.
		if e := s.Probe(ctx); e != nil {
			return r, fmt.Errorf("fixture upstream unavailable: %w", e)
		}
		connector = s
	}
	done := make(chan error, 1)
	go func() {
		done <- relay.Serve(ctx, l, connector, func(c net.Conn) (string, error) {
			d, e := OriginalDestination(c)
			mu.Lock()
			r.Originals = append(r.Originals, d)
			mu.Unlock()
			return d, e
		}, 5*time.Second, 32, stats)
	}()
	ipt := func(a ...string) []string { return append([]string{"iptables", "-w", "2", "-t", "mangle"}, a...) }
	entryIndex := -1
	disable := func() error {
		if entryIndex < 0 {
			return nil
		}
		v := query(undo[entryIndex])
		r.PolicyDisable = v
		if v.ExitCode != 0 {
			return fmt.Errorf("disable interception: %s", v.Error)
		}
		undo = append(undo[:entryIndex], undo[entryIndex+1:]...)
		entryIndex = -1
		return nil
	}
	var stopOnce sync.Once
	var serveErr error
	stopRelay := func() { stopOnce.Do(func() { cancel(); serveErr = <-done }) }
	defer func() {
		if e := disable(); e != nil && err == nil {
			err = e
		}
		stopRelay()
		r.Stats = stats.Snapshot()
	}()
	for _, chain := range []string{"ATP_UID_PRE", "ATP_UID_OUT"} {
		if err = step(ipt("-N", chain), ipt("-X", chain)); err != nil {
			return
		}
	}
	addRule := func(chain string, args ...string) error {
		return step(ipt(append([]string{"-A", chain}, args...)...), ipt(append([]string{"-D", chain}, args...)...))
	}
	if err = addRule("ATP_UID_PRE", "-p", "tcp", "-m", "mark", "--mark", "0x400000/0x400000", "-j", "TPROXY", "--on-port", "18080", "--tproxy-mark", "0x400000/0x400000"); err != nil {
		return
	}
	if err = step(ipt("-I", "PREROUTING", "1", "-p", "tcp", "-j", "ATP_UID_PRE"), ipt("-D", "PREROUTING", "-p", "tcp", "-j", "ATP_UID_PRE")); err != nil {
		return
	}
	// Ordering: processed bit, daemon UID, special networks, upstream tuple,
	// then selected UID. Even a misconfigured target containing root is bypassed.
	for _, a := range [][]string{
		{"-m", "mark", "--mark", "0x400000/0x400000", "-j", "RETURN"},
		{"-m", "owner", "--uid-owner", strconv.Itoa(os.Getuid()), "-j", "RETURN"},
		{"-d", "127.0.0.0/8", "-j", "RETURN"},
		{"-d", "169.254.0.0/16", "-j", "RETURN"},
		{"-d", "224.0.0.0/4", "-j", "RETURN"},
		{"-d", "255.255.255.255", "-j", "RETURN"},
		{"-d", "198.18.0.1", "-p", "tcp", "--dport", "8443", "-j", "RETURN"},
		{"-m", "owner", "--uid-owner", "41001", "-p", "tcp", "-j", "MARK", "--set-xmark", "0x400000/0x400000"},
		{"-m", "owner", "--uid-owner", strconv.Itoa(os.Getuid()), "-p", "tcp", "-j", "MARK", "--set-xmark", "0x400000/0x400000"},
	} {
		if err = addRule("ATP_UID_OUT", a...); err != nil {
			return
		}
	}
	if err = step(ipt("-I", "OUTPUT", "1", "-p", "tcp", "-j", "ATP_UID_OUT"), ipt("-D", "OUTPUT", "-p", "tcp", "-j", "ATP_UID_OUT")); err != nil {
		return
	}
	entryIndex = len(undo) - 1
	worker := func(name string, uid uint32, port int) error {
		// Worker lifetime must not depend on the relay after it has stopped.
		cctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		cmd := exec.CommandContext(cctx, os.Args[0], workerArgs...)
		cmd.ExtraFiles = []*os.File{privateNS}
		cmd.Env = append(os.Environ(), "TP_FIXTURE_NS_FD=3", "TP_FIXTURE_PORT="+strconv.Itoa(port), "TP_FIXTURE_UID="+strconv.Itoa(int(uid)))
		if socks && port == 8443 {
			cmd.Env = append(cmd.Env, "TP_FIXTURE_SOCKS=1")
		}
		if name == "udp_pass" {
			cmd.Env = append(cmd.Env, "TP_FIXTURE_UDP=1")
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
		b, e := cmd.CombinedOutput()
		v := Result{Output: strings.TrimSpace(string(b))}
		if e != nil {
			v.ExitCode = -1
			v.Error = e.Error()
		}
		mu.Lock()
		r.Cases[name] = v
		mu.Unlock()
		return e
	}
	// Simultaneous clients to the same destination must not mix streams.
	var a, b error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a = worker("target", 41001, 443) }()
	go func() { defer wg.Done(); b = worker("non_target", 41002, 443) }()
	wg.Wait()
	if a != nil || b != nil {
		return r, fmt.Errorf("client failures target=%v non_target=%v", a, b)
	}
	if err = worker("upstream_bypass", 41001, 8443); err != nil {
		return
	}
	if err = worker("daemon_bypass", uint32(os.Getuid()), 443); err != nil {
		return
	}
	if err = worker("udp_pass", 41001, 443); err != nil {
		return
	}
	if socks {
		mu.Lock()
		valid := len(r.UpstreamOriginals) == 2
		for _, d := range r.UpstreamOriginals {
			valid = valid && d == "198.18.0.1:443"
		}
		mu.Unlock()
		if !valid {
			return r, fmt.Errorf("SOCKS5 original destination mismatch")
		}
	}
	// Stop interception BEFORE stopping relay; future target connection is direct.
	if err = disable(); err != nil {
		return
	}
	stopRelay()
	if serveErr != nil {
		return r, serveErr
	}
	if err = worker("after_stop_direct", 41001, 443); err != nil {
		return
	}
	r.Counters = query(ipt("-L", "-n", "-v", "-x"))
	if stats.Accepted.Load() != 1 || stats.Failures.Load() != 0 || stats.Sent.Load() != 65536 || stats.Received.Load() != 65536 {
		return r, fmt.Errorf("unexpected relay statistics: %v", stats.Snapshot())
	}
	mu.Lock()
	valid := len(r.Originals) == 1 && r.Originals[0] == "198.18.0.1:443"
	mu.Unlock()
	if !valid {
		return r, fmt.Errorf("original destination mismatch")
	}
	return
}

// FixtureClient is a controlled worker for the isolated PoC, not a proxy API.
func FixtureClient() error {
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return err
	}
	if os.Getenv("TP_FIXTURE_NS_FD") != "3" {
		return fmt.Errorf("fixture worker requires verified inherited namespace descriptor")
	}
	verified, err := os.Readlink("/proc/self/fd/3")
	if err != nil || verified != self {
		return fmt.Errorf("fixture worker namespace mismatch")
	}
	if os.Getuid() == 0 {
		host, err := os.Readlink("/proc/1/ns/net")
		if err != nil {
			return err
		}
		if self == host {
			return fmt.Errorf("fixture worker refuses host namespace")
		}
	}
	port, e := strconv.Atoi(os.Getenv("TP_FIXTURE_PORT"))
	if e != nil || port != 443 && port != 8443 {
		return fmt.Errorf("invalid fixture port")
	}
	uid, e := strconv.Atoi(os.Getenv("TP_FIXTURE_UID"))
	if e != nil || os.Getuid() != uid {
		return fmt.Errorf("fixture UID mismatch")
	}
	var c net.Conn
	udp := os.Getenv("TP_FIXTURE_UDP") == "1"
	if os.Getenv("TP_FIXTURE_SOCKS") == "1" {
		c, e = (upstream.SOCKS5{Address: "198.18.0.1:8443", Timeout: 3 * time.Second}).Connect(context.Background(), "198.18.0.1:443")
	} else {
		proto := "tcp4"
		if udp {
			proto = "udp4"
		}
		c, e = net.DialTimeout(proto, fmt.Sprintf("198.18.0.1:%d", port), 3*time.Second)
	}
	if e != nil {
		return e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	size := 65536
	if udp {
		size = 4096
	}
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i + uid)
	}
	if _, e = c.Write(payload); e != nil {
		return e
	}
	var response []byte
	halfClose := "ok"
	if udp {
		halfClose = "not_applicable"
		response = make([]byte, size)
		_, e = io.ReadFull(c, response)
	} else {
		if e = c.(*net.TCPConn).CloseWrite(); e != nil {
			return e
		}
		response, e = io.ReadAll(c)
	}
	if e != nil {
		return e
	}
	if !bytes.Equal(payload, response) {
		return fmt.Errorf("opaque payload mismatch")
	}
	fmt.Printf("uid=%d destination=198.18.0.1:%d bytes=%d half_close=%s payload_equal=true udp=%v\n", uid, port, len(payload), halfClose, udp)
	return nil
}
