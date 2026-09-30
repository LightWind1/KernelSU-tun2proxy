//go:build linux

package daemon

import (
	"ebpf-proxy/internal/config"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPrivilegedDaemonControl(t *testing.T) {
	if os.Getenv("EP_RUN_PRIVILEGED") != "1" {
		t.Skip("requires private cgroup and BPF object")
	}
	group := fmt.Sprintf("/sys/fs/cgroup/ep-daemon-%d", os.Getpid())
	if e := os.Mkdir(group, 0700); e != nil {
		t.Fatal(e)
	}
	defer os.Remove(group)
	socks, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer socks.Close()
	go func() {
		for {
			c, e := socks.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Second))
				g := make([]byte, 3)
				if _, e := io.ReadFull(c, g); e == nil {
					c.Write([]byte{5, 0})
				}
			}()
		}
	}()
	local, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := local.Addr().(*net.TCPAddr).Port
	local.Close()
	cfg := config.Config{Version: 1, IPv6: true, Listener: config.Endpoint{Address: "127.0.0.1", Port: port}, RuntimeDir: filepath.Join(t.TempDir(), "runtime")}
	cfg.BPF.Cgroup = group
	cfg.BPF.Object = os.Getenv("EP_BPF_OBJECT")
	cfg.Upstream.Type = "socks5"
	cfg.Upstream.Host = "127.0.0.1"
	cfg.Upstream.Port = socks.Addr().(*net.TCPAddr).Port
	cfg.Policy.Mode = "uid_allowlist"
	cfg.UDP.Mode = "pass"
	if e = cfg.Validate(); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- Run(cfg) }()
	stopped := false
	defer func() {
		if !stopped {
			Control(cfg.RuntimeDir, Request{Action: "stop"})
			select {
			case <-done:
			case <-time.After(10 * time.Second):
			}
		}
	}()
	ready := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case e := <-done:
			stopped = true
			t.Fatalf("daemon exited: %v", e)
		default:
		}
		b, e := Control(cfg.RuntimeDir, Request{Action: "status"})
		var status struct{ Running bool }
		if e == nil && json.Unmarshal(b, &status) == nil && status.Running {
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("daemon never ready")
	}
	for _, req := range []Request{{Action: "uid-add", UID: 61000}, {Action: "uid-add", UID: 61001}, {Action: "uid-del", UID: 61000}} {
		if _, e = Control(cfg.RuntimeDir, req); e != nil {
			t.Fatal(e)
		}
	}
	b, e := Control(cfg.RuntimeDir, Request{Action: "uid-list"})
	var uids []uint32
	if e != nil || json.Unmarshal(b, &uids) != nil || len(uids) != 1 || uids[0] != 61001 {
		t.Fatalf("dynamic control: %s %v", b, e)
	}
	if _, e = Control(cfg.RuntimeDir, Request{Action: "uid-clear"}); e != nil {
		t.Fatal(e)
	}
	if _, e = Control(cfg.RuntimeDir, Request{Action: "stop"}); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		stopped = true
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stop did not complete")
	}
	if _, e = os.Stat(socketPath(cfg.RuntimeDir)); !os.IsNotExist(e) {
		t.Fatal("control socket retained after stop")
	}
	stopped = false
	go func() { done <- Run(cfg) }()
	ready = false
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, e := Control(cfg.RuntimeDir, Request{Action: "status"})
		var status struct{ Running bool }
		if e == nil && json.Unmarshal(b, &status) == nil && status.Running {
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("restart not ready")
	}
	if _, e = Control(cfg.RuntimeDir, Request{Action: "stop"}); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		stopped = true
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("restart stop timeout")
	}
}

func TestPrivateRuntimeLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	f, e := secureRuntime(dir)
	if e != nil {
		t.Fatal(e)
	}
	if f2, e := secureRuntime(dir); e == nil {
		f2.Close()
		t.Fatal("duplicate daemon lock allowed")
	}
	f.Close()
	f, e = secureRuntime(dir)
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	os.Chmod(dir, 0777)
	if f, e := secureRuntime(dir); e == nil {
		f.Close()
		t.Fatal("public runtime accepted")
	}
	os.Chmod(dir, 0700)
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(dir, link)
	if f, e := secureRuntime(link); e == nil {
		f.Close()
		t.Fatal("symlink runtime accepted")
	}
}
