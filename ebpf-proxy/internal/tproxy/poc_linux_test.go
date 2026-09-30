//go:build linux

package tproxy

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestProbeCommandsReadOnly(t *testing.T) {
	for name, args := range probeCommands {
		for _, arg := range args {
			switch arg {
			case "-A", "-I", "-D", "-F", "-X", "-N", "add", "del", "flush", "set", "attach", "detach":
				t.Fatalf("mutating probe %s: %v", name, args)
			}
		}
	}
}

func TestPrivilegedIsolatedPoC(t *testing.T) {
	if child := os.Getenv("TP_TEST_CHILD"); child != "" {
		failAfter, _ := strconv.Atoi(child)
		r, err := pocIsolated(failAfter)
		if failAfter == 0 && err != nil {
			t.Fatalf("PoC: %v; report=%+v", err, r)
		}
		if failAfter != 0 && (err == nil || !strings.Contains(err.Error(), "injected setup failure")) {
			t.Fatalf("expected injection: %v; report=%+v", err, r)
		}
		if !r.RollbackOK {
			t.Fatalf("rollback failed: %+v", r)
		}
		if failAfter == 0 && r.Original != "198.18.0.1:443" {
			t.Fatal(r.Original)
		}
		t.Logf("original=%s injected_after=%d rollback_steps=%d rollback_ok=%v", r.Original, failAfter, len(r.Rollback), r.RollbackOK)
		return
	}
	if os.Getenv("TP_RUN_PRIVILEGED") != "1" {
		t.Skip("opt-in: TP_RUN_PRIVILEGED=1; requires root and unshare")
	}
	for _, after := range []int{0, 2, 5, 8, 10, 11} {
		t.Run(strconv.Itoa(after), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "unshare", "-n", os.Args[0], "-test.run=^TestPrivilegedIsolatedPoC$", "-test.v")
			cmd.Env = append(os.Environ(), "TP_TEST_CHILD="+strconv.Itoa(after))
			b, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%v: %s", err, b)
			}
			t.Log(string(b))
		})
	}
}

func TestHostNamespaceRejected(t *testing.T) {
	self, e := os.Readlink("/proc/self/ns/net")
	if e != nil {
		t.Skip(e)
	}
	host, e := os.Readlink("/proc/1/ns/net")
	if e != nil {
		t.Skip(e)
	}
	if self != host {
		t.Skip("test is already in a private namespace")
	}
	r, e := PoCIsolated()
	if e == nil || !strings.Contains(e.Error(), "refusing host") || len(r.Steps) != 0 {
		t.Fatalf("must reject without writes: %v %+v", e, r)
	}
}

func TestOriginalDestination(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	d, err := OriginalDestination(s)
	if err != nil || d != l.Addr().String() {
		t.Fatalf("getsockname resolve %s %v", d, err)
	}
	if _, err := ListenTransparent(context.Background(), "udp4", "127.0.0.1:0"); err == nil {
		t.Fatal("must reject non-TCP")
	}
}
