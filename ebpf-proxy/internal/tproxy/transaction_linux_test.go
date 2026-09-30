//go:build linux

package tproxy

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestPrivilegedTransactions(t *testing.T) {
	if os.Getenv("TP_TRANSACTION_CHILD") != "1" {
		if os.Getenv("TP_RUN_PRIVILEGED") != "1" {
			t.Skip("privileged opt-in")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, "unshare", "-n", os.Args[0], "-test.run=^TestPrivilegedTransactions$", "-test.v")
		c.Env = append(os.Environ(), "TP_TRANSACTION_CHILD=1")
		b, e := c.CombinedOutput()
		if e != nil {
			t.Fatalf("%v: %s", e, b)
		}
		t.Log(string(b))
		return
	}
	self, e := os.Readlink("/proc/self/ns/net")
	if e != nil {
		t.Fatal(e)
	}
	host, e := os.Readlink("/proc/1/ns/net")
	if e != nil || self == host {
		t.Fatal("isolated namespace required", e)
	}
	if r := query([]string{"iptables-save"}); r.ExitCode != 0 || strings.Contains(r.Output, "-A ") {
		t.Fatal("fresh firewall required", r)
	}
	if r := query([]string{"ip", "link", "set", "lo", "up"}); r.ExitCode != 0 {
		t.Fatal(r)
	}
	defer query([]string{"ip", "link", "set", "lo", "down"})
	s := samplePlan(t)
	clean := func() {
		t.Helper()
		for _, args := range [][]string{{"iptables-save"}, {"ip", "rule", "show"}, {"ip", "route", "show", "table", "all"}} {
			r := query(args)
			if r.ExitCode != 0 || strings.Contains(r.Output, "ATP_TEST") || strings.Contains(r.Output, "38766") {
				t.Fatalf("leaked resources: %+v", r)
			}
		}
	}
	tx := NewTransaction(s, query)
	for cycle := 0; cycle < 3; cycle++ {
		if e := tx.Setup(); e != nil {
			t.Fatal(e)
		}
		if e := tx.Setup(); e != nil {
			t.Fatal(e)
		}
		r := query([]string{"iptables", "-w", "2", "-t", "mangle", "-S", "OUTPUT"})
		if r.ExitCode != 0 || strings.Count(r.Output, "-j ATP_TEST_OUT") != 1 {
			t.Fatal("duplicate entry", r)
		}
		if e := tx.Teardown(); e != nil {
			t.Fatal(e)
		}
		if e := tx.Teardown(); e != nil {
			t.Fatal(e)
		}
		clean()
	}
	t.Log("three repeated setup/setup/teardown/teardown cycles: one entry, no owned resource leaks")
	for step := 1; step <= len(s); step++ {
		tx := NewTransaction(s, query)
		if e := tx.setup(step); e == nil {
			t.Fatal("fault missing")
		}
		if tx.OwnedSteps() != 0 {
			t.Fatal("incomplete rollback", step)
		}
		clean()
	}
	t.Log("fault injection after all eight route/rule/chain/entry steps: reverse rollback verified")
	// A failed create must never adopt or flush a pre-existing foreign chain.
	ipt := []string{"iptables", "-w", "2", "-t", "mangle"}
	if r := query(append(append([]string{}, ipt...), "-N", "ATP_TEST_PRE")); r.ExitCode != 0 {
		t.Fatal(r)
	}
	tx = NewTransaction(s, query)
	if tx.Setup() == nil || tx.OwnedSteps() != 0 {
		t.Fatal("collision should fail and rollback")
	}
	if r := query(append(append([]string{}, ipt...), "-S", "ATP_TEST_PRE")); r.ExitCode != 0 {
		t.Fatal("foreign chain removed", r)
	}
	if r := query(append(append([]string{}, ipt...), "-X", "ATP_TEST_PRE")); r.ExitCode != 0 {
		t.Fatal(r)
	}
	clean()
	t.Log("foreign chain collision: rejected, foreign chain preserved, own route/rule rolled back")
}
