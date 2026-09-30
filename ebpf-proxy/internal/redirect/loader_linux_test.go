//go:build linux

package redirect

import (
	"bytes"
	"context"
	"ebpf-proxy/internal/config"
	"ebpf-proxy/internal/relay"
	"ebpf-proxy/internal/upstream"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestABI(t *testing.T) {
	if unsafe.Sizeof(FlowKey{}) != 48 || unsafe.Sizeof(FlowValue{}) != 48 || unsafe.Sizeof(Policy{}) != 40 || unsafe.Sizeof(Prefix{}) != 20 {
		t.Fatal("shared ABI size mismatch")
	}
}
func TestClientChild(t *testing.T) {
	if os.Getenv("EP_CHILD") == "" {
		t.Skip("private child process")
	}
	if e := os.WriteFile(filepath.Join(os.Getenv("EP_CGROUP"), "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0600); e != nil {
		t.Fatal(e)
	}
	uid, _ := strconv.Atoi(os.Getenv("EP_UID"))
	if e := syscall.Setgid(uid); e != nil {
		t.Fatal(e)
	}
	if e := syscall.Setuid(uid); e != nil {
		t.Fatal(e)
	}
	if os.Getenv("EP_UDP") == "1" {
		c, e := net.DialTimeout("udp", os.Getenv("EP_TARGET"), time.Second)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		c.Write([]byte("udp-pass"))
		b := make([]byte, 64)
		n, e := c.Read(b)
		if e != nil || string(b[:n]) != "udp-pass" {
			t.Fatalf("UDP altered: %v", e)
		}
		return
	}
	count, _ := strconv.Atoi(os.Getenv("EP_COUNT"))
	var wg sync.WaitGroup
	slots := make(chan struct{}, 32)
	for i := 0; i < count; i++ {
		slots <- struct{}{}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-slots }()
			c, e := net.DialTimeout("tcp", os.Getenv("EP_TARGET"), 5*time.Second)
			if e != nil {
				t.Error(e)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			payload := bytes.Repeat([]byte{byte(i)}, 256)
			if _, e = c.Write(payload); e != nil {
				t.Error(e)
				return
			}
			c.(*net.TCPConn).CloseWrite()
			got, e := io.ReadAll(c)
			if e != nil || !bytes.Equal(got, payload) {
				t.Errorf("roundtrip %d: %v bytes=%d", i, e, len(got))
			}
		}(i)
	}
	wg.Wait()
}
func TestPrivilegedRedirect(t *testing.T) {
	if os.Getenv("EP_RUN_PRIVILEGED") != "1" {
		t.Skip("requires root, isolated writable cgroup v2 and EP_BPF_OBJECT")
	}
	group := fmt.Sprintf("/sys/fs/cgroup/ep-test-%d", os.Getpid())
	if e := os.Mkdir(group, 0700); e != nil {
		t.Fatal(e)
	}
	defer os.Remove(group)
	cfg := config.Config{Version: 1, IPv6: true}
	cfg.BPF.Cgroup = group
	cfg.BPF.Object = os.Getenv("EP_BPF_OBJECT")
	cfg.Policy.Mode = "uid_allowlist"
	cfg.Policy.UIDs = []uint32{61000}
	cfg.UDP.Mode = "pass"
	l4, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l4.Close()
	cfg.Listener = config.Endpoint{Address: "127.0.0.1", Port: l4.Addr().(*net.TCPAddr).Port}
	l6, e := net.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(cfg.Listener.Port)))
	if e != nil {
		t.Fatal(e)
	}
	defer l6.Close()
	m, e := Load(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	target4 := echoTarget(t, "tcp4", "127.0.0.2:0")
	defer target4.Close()
	target6 := echoTarget(t, "tcp6", "[::1]:0")
	defer target6.Close()
	socks := socksFixture(t)
	defer socks.Close()
	stats := &relay.Stats{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 2)
	for _, l := range []net.Listener{l4, l6} {
		go func(l net.Listener) {
			done <- relay.Serve(ctx, l, upstream.SOCKS5{Address: socks.Addr().String(), Timeout: 5 * time.Second}, func(c net.Conn) (string, error) { v, e := m.Resolve(c); return v.Address(), e }, 10*time.Second, 64, stats)
		}(l)
	}
	if e = m.SetEnabled(true); e != nil {
		t.Fatal(e)
	}
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = m.Heartbeat()
			}
		}
	}()
	child := func(uid, count int, target string) {
		t.Helper()
		exe, _ := os.Executable()
		cmd := exec.Command(exe, "-test.run=^TestClientChild$", "-test.v")
		cmd.Env = append(os.Environ(), "EP_CHILD=1", "EP_CGROUP="+group, "EP_UID="+strconv.Itoa(uid), "EP_COUNT="+strconv.Itoa(count), "EP_TARGET="+target)
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("UID %d child: %v\n%s", uid, e, out)
		}
	}
	child(61000, 1, target4.Addr().String())
	if stats.Accepted.Load() != 1 {
		t.Fatalf("IPv4 not redirected: %+v", m.Counters())
	}
	child(61000, 1, target6.Addr().String())
	if stats.Accepted.Load() != 2 {
		t.Fatalf("IPv6 not redirected: %+v", m.Counters())
	}
	child(61001, 1, target4.Addr().String())
	if stats.Accepted.Load() != 2 {
		t.Fatal("non-target UID intercepted")
	}
	if e = m.UID("del", 61000); e != nil {
		t.Fatal(e)
	}
	child(61000, 1, target4.Addr().String())
	if stats.Accepted.Load() != 2 {
		t.Fatal("removed UID intercepted")
	}
	if e = m.UID("add", 61000); e != nil {
		t.Fatal(e)
	}
	child(61000, 1000, target4.Addr().String())
	if stats.Accepted.Load() != 1002 || stats.Failures.Load() != 0 {
		t.Fatalf("relay counts: %+v; BPF: %+v", stats.Snapshot(), m.Counters())
	}
	if e = m.UID("add", 0); e != nil {
		t.Fatal(e)
	}
	child(0, 1, target4.Addr().String())
	if stats.Accepted.Load() != 1002 {
		t.Fatal("daemon UID bypass failed")
	}
	prefix := Prefix{Bits: 128, Address: [16]byte{10: 255, 11: 255, 12: 127, 13: 0, 14: 0, 15: 2}}
	if e = m.collection.Maps["bypass_prefix"].Put(prefix, uint32(1)); e != nil {
		t.Fatal(e)
	}
	child(61000, 1, target4.Addr().String())
	if stats.Accepted.Load() != 1002 {
		t.Fatal("CIDR bypass failed")
	}
	m.collection.Maps["bypass_prefix"].Delete(prefix)
	udp, e := net.ListenPacket("udp4", "127.0.0.2:0")
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 64)
		n, a, e := udp.ReadFrom(b)
		if e == nil {
			udp.WriteTo(b[:n], a)
		}
	}()
	exe, _ := os.Executable()
	cmd := exec.Command(exe, "-test.run=^TestClientChild$")
	cmd.Env = append(os.Environ(), "EP_CHILD=1", "EP_UDP=1", "EP_CGROUP="+group, "EP_UID=61000", "EP_TARGET="+udp.LocalAddr().String())
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("UDP: %v %s", e, out)
	}
	if stats.Accepted.Load() != 1002 {
		t.Fatal("UDP intercepted")
	}
	// A stalled daemon's lease expires independently in kernel, retaining direct networking.
	cancel()
	<-heartbeatDone
	<-done
	<-done
	time.Sleep(3100 * time.Millisecond)
	child(61000, 1, target4.Addr().String())
	if stats.Accepted.Load() != 1002 {
		t.Fatal("expired lease still intercepts")
	}
	if len(m.Flows()) != 0 {
		t.Fatal("flow metadata remained after successful accepts")
	}
	if e = m.SetEnabled(false); e != nil {
		t.Fatal(e)
	}
	child(61000, 1, target4.Addr().String())
	if stats.Accepted.Load() != 1002 {
		t.Fatal("disabled policy intercepted")
	}
	t.Logf("IPv4/IPv6, UID add/del/non-target, 1000 connections, disable: relay=%+v BPF=%+v", stats.Snapshot(), m.Counters())
}
func echoTarget(t *testing.T, network, address string) net.Listener {
	t.Helper()
	l, e := net.Listen(network, address)
	if e != nil {
		t.Fatal(e)
	}
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				b, e := io.ReadAll(c)
				if e == nil {
					_, _ = c.Write(b)
				}
			}()
		}
	}()
	return l
}
func socksFixture(t *testing.T) net.Listener {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				g := make([]byte, 3)
				if _, e := io.ReadFull(c, g); e != nil {
					return
				}
				c.Write([]byte{5, 0})
				h := make([]byte, 4)
				if _, e := io.ReadFull(c, h); e != nil {
					return
				}
				n := 4
				if h[3] == 4 {
					n = 16
				}
				b := make([]byte, n+2)
				if _, e := io.ReadFull(c, b); e != nil {
					return
				}
				dst := net.JoinHostPort(net.IP(b[:n]).String(), fmt.Sprint(binary.BigEndian.Uint16(b[n:])))
				r, e := net.DialTimeout("tcp", dst, 5*time.Second)
				if e != nil {
					return
				}
				defer r.Close()
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
				relay.Relay(context.Background(), c, r, 10*time.Second, &relay.Stats{})
			}()
		}
	}()
	return l
}
