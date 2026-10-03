//go:build linux

package tproxy

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func pendingWorker(t *testing.T, dir, operation, stage string, owned int) (*exec.Cmd, context.CancelFunc) {
	return pendingWorkerMode(t, dir, operation, stage, owned, false)
}

func pendingWorkerMode(t *testing.T, dir, operation, stage string, owned int, scoped bool) (*exec.Cmd, context.CancelFunc) {
	t.Helper()
	timeout := 15 * time.Second
	if scoped {
		timeout = 45 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	c := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestJournalCrashWorker$", "-test.v")
	c.Env = append(os.Environ(), "TP_JOURNAL_DIR="+dir, "TP_JOURNAL_OPERATION="+operation, "TP_JOURNAL_STAGE="+stage, fmt.Sprintf("TP_JOURNAL_BOUNDARY=%d", owned))
	mode := "0"
	if scoped {
		mode = "1"
	}
	c.Env = append(c.Env, "TP_JOURNAL_SCOPED="+mode)
	pipe, e := c.StdoutPipe()
	if e != nil {
		cancel()
		t.Fatal(e)
	}
	c.Stderr = c.Stdout
	if e = c.Start(); e != nil {
		cancel()
		t.Fatal(e)
	}
	scan := bufio.NewScanner(pipe)
	var lines []string
	for scan.Scan() {
		lines = append(lines, scan.Text())
		if scan.Text() == "COMMITTED_READY" {
			return c, cancel
		}
	}
	c.Wait()
	cancel()
	t.Fatalf("worker failed: %s", strings.Join(lines, "\n"))
	return nil, nil
}

func privateRecoveryChild(t *testing.T, flag, name string) bool {
	t.Helper()
	if os.Getenv(flag) != "1" {
		if os.Getenv("TP_RUN_PRIVILEGED") != "1" {
			t.Skip("privileged opt-in")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, "unshare", "-n", os.Args[0], "-test.run=^"+name+"$", "-test.v")
		c.Env = append(os.Environ(), flag+"=1")
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
		t.Fatal("private namespace required", e)
	}
	if r := query([]string{"ip", "link", "set", "lo", "up"}); r.ExitCode != 0 {
		t.Fatal(r)
	}
	t.Cleanup(func() { query([]string{"ip", "link", "set", "lo", "down"}) })
	return true
}

func TestPrivilegedPendingRecovery(t *testing.T) {
	if !privateRecoveryChild(t, "TP_PENDING_CHILD", "TestPrivilegedPendingRecovery") {
		return
	}
	p := journalPlan()
	for _, stage := range []string{"intent", "applied"} {
		for _, operation := range []string{"add", "remove"} {
			for i := 0; i < 8; i++ {
				owned := i
				if operation == "remove" {
					owned = i + 1
				}
				dir := privateJournalTestDir(t)
				c, cancel := pendingWorker(t, dir, operation, stage, owned)
				if e := c.Process.Kill(); e != nil {
					cancel()
					t.Fatal(e)
				}
				r, e := WatchIsolatedWorker(c, dir, p)
				cancel()
				expected := owned
				if stage == "applied" {
					if operation == "add" {
						expected++
					} else {
						expected--
					}
				}
				if e != nil || !r.Clean || !r.Reconciled || r.RecoveredSteps != expected {
					t.Fatalf("%s %s owned=%d: %+v %v", stage, operation, owned, r, e)
				}
				d, e := OpenDurableIsolated(dir, p)
				if e != nil {
					t.Fatal(e)
				}
				if e = d.Recover(); e != nil {
					t.Fatal(e)
				}
				d.Close()
				t.Logf("pending %s/%s owned=%d: reconciled=%d, cleanup and repeated recovery clean", stage, operation, owned, expected)
			}
		}
	}
	// A foreign resource appearing in the crash window must not be adopted.
	dir := privateJournalTestDir(t)
	c, cancel := pendingWorker(t, dir, "add", "applied", 2)
	foreign := []string{"iptables", "-w", "2", "-t", "mangle", "-N", "FOREIGN_PENDING"}
	if r := query(foreign); r.ExitCode != 0 {
		t.Fatal(r)
	}
	c.Process.Kill()
	c.Wait()
	cancel()
	d, e := OpenDurableIsolated(dir, p)
	if e != nil {
		t.Fatal(e)
	}
	if d.Recover() == nil {
		t.Fatal("foreign pending resource adopted")
	}
	if r := query([]string{"iptables", "-w", "2", "-t", "mangle", "-S", "FOREIGN_PENDING"}); r.ExitCode != 0 {
		t.Fatal("foreign chain deleted")
	}
	if r := query([]string{"iptables", "-w", "2", "-t", "mangle", "-X", "FOREIGN_PENDING"}); r.ExitCode != 0 {
		t.Fatal(r)
	}
	if e = d.Recover(); e != nil {
		t.Fatal(e)
	}
	d.Close()
	t.Log("foreign pending-window chain preserved; recovery refused until external change removed")
}
