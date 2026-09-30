//go:build linux

package tproxy

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestUIDFixtureClient(t *testing.T) {
	if os.Getenv("TP_FIXTURE_PORT") == "" {
		t.Skip("fixture worker only")
	}
	if err := FixtureClient(); err != nil {
		t.Fatal(err)
	}
}

func TestRelayHostNamespaceRejected(t *testing.T) {
	self, e := os.Readlink("/proc/self/ns/net")
	if e != nil {
		t.Skip(e)
	}
	host, e := os.Readlink("/proc/1/ns/net")
	if e != nil || self != host {
		t.Skip("not host namespace")
	}
	for _, fn := range []func([]string) (RelayPoCReport, error){RelayPoCIsolated, SOCKS5PoCIsolated} {
		r, e := fn(nil)
		if e == nil || len(r.Cases) != 0 || len(r.Rollback) != 0 {
			t.Fatalf("must refuse without writes: %v %+v", e, r)
		}
	}
	if e = FixtureClient(); e == nil {
		t.Fatal("worker must refuse host")
	}
}

func TestPrivilegedUIDRelay(t *testing.T) {
	if os.Getenv("TP_RELAY_CHILD") == "1" {
		fn := RelayPoCIsolated
		if os.Getenv("TP_RELAY_MODE") == "socks" {
			fn = SOCKS5PoCIsolated
		}
		args := []string{"-test.run=^TestUIDFixtureClient$", "-test.v"}
		fault := os.Getenv("TP_RELAY_MODE") == "worker_failure"
		if fault {
			args = []string{"-invalid-fixture-worker-flag"}
		}
		r, e := fn(args)
		if fault {
			if e == nil || !r.RollbackOK || r.PolicyDisable.ExitCode != 0 {
				t.Fatalf("failed-worker cleanup: %v %+v", e, r)
			}
			t.Log("expected worker failure; interception disabled and owned resources rolled back")
			return
		}
		if e != nil || !r.RollbackOK {
			t.Fatalf("relay: %v %+v", e, r)
		}
		t.Logf("cases=%v originals=%v stats=%v rollback=%v", r.Cases, r.Originals, r.Stats, r.RollbackOK)
		return
	}
	if os.Getenv("TP_RUN_PRIVILEGED") != "1" {
		t.Skip("privileged opt-in")
	}
	for _, mode := range []string{"direct", "socks", "worker_failure"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			c := exec.CommandContext(ctx, "unshare", "-n", os.Args[0], "-test.run=^TestPrivilegedUIDRelay$", "-test.v")
			c.Env = append(os.Environ(), "TP_RELAY_CHILD=1", "TP_RELAY_MODE="+mode)
			b, e := c.CombinedOutput()
			if e != nil {
				t.Fatalf("%v: %s", e, b)
			}
			t.Log(string(b))
		})
	}
}
