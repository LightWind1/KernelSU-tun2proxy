//go:build linux

package tproxy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestScopedHostRejected(t *testing.T) {
	if _, e := OpenScopedIsolated("/nonexistent-scoped-state", journalPlan()); e == nil {
		t.Fatal("host namespace admitted")
	}
	if _, e := WatchScopedIsolatedWorker(nil, "/nonexistent-scoped-state", journalPlan()); e == nil {
		t.Fatal("host guardian admitted")
	}
}

func scopedPrivateChild(t *testing.T, name string) bool {
	t.Helper()
	if os.Getenv("TP_SCOPED_CHILD") != "1" {
		if os.Getenv("TP_RUN_PRIVILEGED") != "1" {
			t.Skip("privileged opt-in")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
		defer cancel()
		c := exec.CommandContext(ctx, "unshare", "-n", os.Args[0], "-test.run=^"+name+"$", "-test.v")
		c.Env = append(os.Environ(), "TP_SCOPED_CHILD=1")
		b, e := c.CombinedOutput()
		if e != nil {
			t.Fatalf("%v: %s", e, b)
		}
		t.Log(string(b))
		return false
	}
	self, e := os.Readlink("/proc/self/ns/net")
	if e != nil {
		t.Fatal(e)
	}
	host, e := os.Readlink("/proc/1/ns/net")
	if e != nil || self == host {
		t.Fatal("private namespace required")
	}
	if e := commandError(query([]string{"ip", "link", "set", "lo", "up"})); e != nil {
		t.Fatal(e)
	}
	return true
}

func scopedForeignFixture(t *testing.T) func(int) {
	t.Helper()
	ipt := []string{"iptables", "-w", "2", "-t", "mangle"}
	chain := func(args ...string) []string { return append(append([]string(nil), ipt...), args...) }
	steps := []Step{
		{chain("-N", "FOREIGN_NETD"), chain("-X", "FOREIGN_NETD")},
		{chain("-A", "OUTPUT", "-j", "FOREIGN_NETD"), chain("-D", "OUTPUT", "-j", "FOREIGN_NETD")},
		{[]string{"ip", "rule", "add", "priority", "20000", "fwmark", "0x10000/0x10000", "table", "12345"}, []string{"ip", "rule", "del", "priority", "20000", "fwmark", "0x10000/0x10000", "table", "12345"}},
		{[]string{"ip", "route", "add", "198.19.0.0/24", "dev", "lo", "table", "12345"}, []string{"ip", "route", "del", "198.19.0.0/24", "dev", "lo", "table", "12345"}},
	}
	tx := NewTransaction(steps, query)
	if e := tx.Setup(); e != nil {
		t.Fatal(e)
	}
	var undo [][]string
	t.Cleanup(func() {
		for i := len(undo) - 1; i >= 0; i-- {
			if e := commandError(query(undo[i])); e != nil {
				t.Error(e)
			}
		}
		if e := tx.Teardown(); e != nil {
			t.Error(e)
		}
	})
	return func(n int) {
		t.Helper()
		args := []string{"FOREIGN_NETD", "-m", "comment", "--comment", fmt.Sprintf("netd-shaped-update-%d", n), "-j", "RETURN"}
		if e := commandError(query(chain(append([]string{"-A"}, args...)...))); e != nil {
			t.Fatal(e)
		}
		undo = append(undo, chain(append([]string{"-D"}, args...)...))
	}
}

func assertForeignPreserved(t *testing.T, p IPv4DestinationPlan, before []string) {
	t.Helper()
	after, e := captureNamespace()
	if e != nil {
		t.Fatal(e)
	}
	b, e := classifyResources(p, before, func(int) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	a, e := classifyResources(p, after, func(int) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	if a.Residual != b.Residual || !countsMatch(a.Counts, 0) {
		t.Fatal("foreign resources changed or own resources leaked")
	}
}

func TestPrivilegedScopedLifecycle(t *testing.T) {
	if !scopedPrivateChild(t, "TestPrivilegedScopedLifecycle") {
		return
	}
	update := scopedForeignFixture(t)
	p := journalPlan()
	dir := privateJournalTestDir(t)
	d, e := OpenScopedIsolated(dir, p)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	for cycle := 0; cycle < 3; cycle++ {
		update(cycle)
		if e = d.Setup(); e != nil {
			t.Fatal(e)
		}
		if e = d.Setup(); e != nil {
			t.Fatal(e)
		}
		update(cycle + 100)
		if e = d.ResolvePending(); e != nil {
			t.Fatal("unrelated change blocked live check", e)
		}
		before, e := captureNamespace()
		if e != nil {
			t.Fatal(e)
		}
		if e = d.Recover(); e != nil {
			t.Fatal(e)
		}
		if e = d.Recover(); e != nil {
			t.Fatal(e)
		}
		assertForeignPreserved(t, p, before)
	}
	t.Log("3 repeated scoped setup/recover cycles: unrelated firewall/rule/route fixture preserved; own resources clean")
	if e = d.Setup(); e != nil {
		t.Fatal(e)
	}
	for _, args := range [][]string{
		{"iptables", "-w", "2", "-t", "mangle", "-A", "FOREIGN_NETD", "-j", p.Prefix + "_OUT"},
		{"ip", "rule", "add", "priority", "21000", "table", "38766"},
		{"ip", "route", "add", "198.19.1.0/24", "dev", "lo", "table", "38766"},
	} {
		if e = commandError(query(args)); e != nil {
			t.Fatal(e)
		}
		before, e := captureNamespace()
		if e != nil {
			t.Fatal(e)
		}
		if d.Recover() == nil {
			t.Fatal("conflicting resource accepted")
		}
		after, e := captureNamespace()
		if e != nil || stateDigest(before) != stateDigest(after) {
			t.Fatal("refusal mutated network", e)
		}
		undo := append([]string(nil), args...)
		for i, a := range undo {
			if a == "add" {
				undo[i] = "del"
			}
			if a == "-A" {
				undo[i] = "-D"
			}
		}
		if e = commandError(query(undo)); e != nil {
			t.Fatal(e)
		}
	}
	before, e := captureNamespace()
	if e != nil {
		t.Fatal(e)
	}
	if e = d.Recover(); e != nil {
		t.Fatal(e)
	}
	assertForeignPreserved(t, p, before)
	t.Log("foreign reserved-chain jump/table reference/route: recovery refused with zero mutations; safe retry after fixture-owner removal")
	d.Close()
	if _, e := OpenDurableIsolated(dir, p); e == nil {
		t.Fatal("strict opener adopted v3")
	}
	// Empty state never adopts a resource merely because its selector matches.
	collide := []string{"iptables", "-w", "2", "-t", "mangle", "-N", p.Prefix + "_PRE"}
	if e = commandError(query(collide)); e != nil {
		t.Fatal(e)
	}
	fresh, e := OpenScopedIsolated(privateJournalTestDir(t), p)
	if e != nil {
		t.Fatal(e)
	}
	before, e = captureNamespace()
	if e != nil {
		t.Fatal(e)
	}
	if fresh.Setup() == nil {
		t.Fatal("pre-existing chain adopted")
	}
	after, e := captureNamespace()
	if e != nil || stateDigest(before) != stateDigest(after) {
		t.Fatal("collision setup mutated resources", e)
	}
	fresh.Close()
	collide[len(collide)-2] = "-X"
	if e = commandError(query(collide)); e != nil {
		t.Fatal(e)
	}
}

func TestPrivilegedScopedPendingRecovery(t *testing.T) {
	if !scopedPrivateChild(t, "TestPrivilegedScopedPendingRecovery") {
		return
	}
	update := scopedForeignFixture(t)
	p := journalPlan()
	caseNumber := 0
	for _, stage := range []string{"intent", "applied"} {
		for _, operation := range []string{"add", "remove"} {
			for i := 0; i < 8; i++ {
				owned := i
				if operation == "remove" {
					owned++
				}
				dir := privateJournalTestDir(t)
				worker, cancel := pendingWorkerMode(t, dir, operation, stage, owned, true)
				update(caseNumber)
				caseNumber++
				before, e := captureNamespace()
				if e != nil {
					cancel()
					t.Fatal(e)
				}
				if e = worker.Process.Kill(); e != nil {
					cancel()
					t.Fatal(e)
				}
				r, e := WatchScopedIsolatedWorker(worker, dir, p)
				cancel()
				expected := owned
				if stage == "applied" {
					if operation == "add" {
						expected++
					} else {
						expected--
					}
				}
				if e != nil || !r.Clean || !r.Reconciled || !r.ExitObserved || r.RecoveredSteps != expected {
					t.Fatalf("%s/%s owned=%d: %+v %v", stage, operation, owned, r, e)
				}
				assertForeignPreserved(t, p, before)
				d, e := OpenScopedIsolated(dir, p)
				if e != nil {
					t.Fatal(e)
				}
				if e = d.Recover(); e != nil {
					t.Fatal(e)
				}
				d.Close()
				t.Logf("scoped pending %s/%s owned=%d: reconciled=%d; concurrent foreign change preserved; repeated recovery clean", stage, operation, owned, expected)
			}
		}
	}
	// No claim of netd running here: these are netd-shaped private fixtures.
	r := query([]string{"iptables", "-w", "2", "-t", "mangle", "-S"})
	if strings.Contains(r.Output, "ATP_JOURNAL") {
		t.Fatal("owned footprint leak")
	}
}
