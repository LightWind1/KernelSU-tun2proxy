//go:build linux

package tproxy

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func privateJournalTestDir(t *testing.T) string {
	t.Helper()
	dir, e := os.MkdirTemp("", "tproxy-journal-") // atomically creates 0700
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := os.RemoveAll(dir); e != nil {
			t.Error(e)
		}
	})
	return dir
}

func TestDurableHostNamespaceRejected(t *testing.T) {
	self, e := os.Readlink("/proc/self/ns/net")
	if e != nil {
		t.Skip(e)
	}
	host, e := os.Readlink("/proc/1/ns/net")
	if e != nil || self != host {
		t.Skip("host namespace only")
	}
	if d, e := OpenDurableIsolated("/nonexistent-tproxy-state", journalPlan()); e == nil {
		d.Close()
		t.Fatal("host controller admitted")
	}
	if _, e := WatchIsolatedWorker(nil, "/nonexistent-tproxy-state", journalPlan()); e == nil {
		t.Fatal("host guardian admitted")
	}
}

func TestJournalCrashWorker(t *testing.T) {
	dir := os.Getenv("TP_JOURNAL_DIR")
	if dir == "" {
		t.Skip("worker only")
	}
	n, e := strconv.Atoi(os.Getenv("TP_JOURNAL_BOUNDARY"))
	if e != nil {
		t.Fatal(e)
	}
	d, e := OpenDurableIsolated(dir, journalPlan())
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	l, e := ListenTransparent(context.Background(), "tcp4", "0.0.0.0:18080")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	operation := os.Getenv("TP_JOURNAL_OPERATION")
	d.hook = func(intent string, owned int) {
		if intent == operation && owned == n {
			fmt.Println("COMMITTED_READY")
			for {
				time.Sleep(time.Hour)
			}
		}
	}
	if e = d.Setup(); e != nil {
		t.Fatal(e)
	}
	if operation == "remove" {
		if e = d.Recover(); e != nil {
			t.Fatal(e)
		}
	}
	t.Fatal("worker did not reach crash boundary")
}

func TestPrivilegedJournalRecovery(t *testing.T) {
	if os.Getenv("TP_JOURNAL_CHILD") != "1" {
		if os.Getenv("TP_RUN_PRIVILEGED") != "1" {
			t.Skip("privileged opt-in")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, "unshare", "-n", os.Args[0], "-test.run=^TestPrivilegedJournalRecovery$", "-test.v")
		c.Env = append(os.Environ(), "TP_JOURNAL_CHILD=1")
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
		t.Fatal("private namespace required", e)
	}
	if r := query([]string{"ip", "link", "set", "lo", "up"}); r.ExitCode != 0 {
		t.Fatal(r)
	}
	defer query([]string{"ip", "link", "set", "lo", "down"})
	p := journalPlan()
	for _, operation := range []string{"add", "remove"} {
		for index := 0; index < 8; index++ {
			boundary := index + 1
			if operation == "remove" {
				boundary = index
			}
			dir := privateJournalTestDir(t)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			c := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestJournalCrashWorker$", "-test.v")
			c.Env = append(os.Environ(), "TP_JOURNAL_DIR="+dir, "TP_JOURNAL_OPERATION="+operation, fmt.Sprintf("TP_JOURNAL_BOUNDARY=%d", boundary))
			pipe, e := c.StdoutPipe()
			if e != nil {
				t.Fatal(e)
			}
			c.Stderr = c.Stdout
			if e = c.Start(); e != nil {
				t.Fatal(e)
			}
			ready := false
			var workerOutput []string
			scan := bufio.NewScanner(pipe)
			for scan.Scan() {
				workerOutput = append(workerOutput, scan.Text())
				if strings.Contains(scan.Text(), "COMMITTED_READY") {
					ready = true
					break
				}
			}
			if !ready {
				c.Wait()
				cancel()
				t.Fatal("worker not ready", boundary, strings.Join(workerOutput, "\n"))
			}
			// Kernel flock must prevent a second live owner before the worker dies.
			if d, e := OpenDurableIsolated(dir, p); e == nil {
				d.Close()
				c.Process.Kill()
				c.Wait()
				cancel()
				t.Fatal("concurrent owner admitted")
			}
			if e = c.Process.Kill(); e != nil {
				t.Fatal(e)
			}
			guardian, e := WatchIsolatedWorker(c, dir, p)
			cancel()
			if e != nil || !guardian.Clean || guardian.RecoveredSteps != boundary || guardian.ExitCode != -1 || guardian.Signal != "killed" {
				t.Fatalf("guardian recovery: %+v %v", guardian, e)
			}
			// Recovery must remain idempotent after another process/open instance.
			d, e := OpenDurableIsolated(dir, p)
			if e != nil {
				t.Fatal(e)
			}
			if e = d.Recover(); e != nil {
				t.Fatal(e)
			}
			d.Close()
			for _, args := range [][]string{{"iptables", "-w", "2", "-t", "mangle", "-S"}, {"ip", "rule", "show"}, {"ip", "route", "show", "table", "all"}} {
				r := query(args)
				if r.ExitCode != 0 || strings.Contains(r.Output, p.Prefix) || strings.Contains(r.Output, "38766") {
					t.Fatal("recovery leaked resources", r)
				}
			}
			t.Logf("SIGKILL after committed %s, owned=%d: lock released, exact recovery, repeated recovery clean", operation, boundary)
		}
	}
	t.Run("journal_write_failure_before_rules", func(t *testing.T) {
		dir := privateJournalTestDir(t)
		d, e := OpenDurableIsolated(dir, p)
		if e != nil {
			t.Fatal(e)
		}
		defer d.Close()
		before, e := isolatedSnapshot()
		if e != nil {
			t.Fatal(e)
		}
		// A non-empty staging directory forces the atomic writer to fail
		// before the first kernel operation, without relaxing root permissions.
		if e = os.Mkdir(filepath.Join(dir, "journal.next"), 0700); e != nil {
			t.Fatal(e)
		}
		f, e := os.OpenFile(filepath.Join(dir, "journal.next", "blocker"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		f.Close()
		if d.Setup() == nil {
			t.Fatal("journal failure ignored")
		}
		after, e := isolatedSnapshot()
		if e != nil || before != after || d.r.Owned != 0 {
			t.Fatal("mutated kernel without durable journal", e)
		}
	})
	t.Run("security_and_uncertainty", func(t *testing.T) {
		dir := privateJournalTestDir(t)
		d, e := OpenDurableIsolated(dir, p)
		if e != nil {
			t.Fatal(e)
		}
		if e = d.Setup(); e != nil {
			t.Fatal(e)
		}
		// An unexpected external rule blocks deletion rather than being flushed.
		foreign := []string{"iptables", "-w", "2", "-t", "mangle", "-N", "FOREIGN_KEEP"}
		if r := query(foreign); r.ExitCode != 0 {
			t.Fatal(r)
		}
		if d.Recover() == nil {
			t.Fatal("external change not detected")
		}
		if r := query([]string{"iptables", "-w", "2", "-t", "mangle", "-S", "FOREIGN_KEEP"}); r.ExitCode != 0 {
			t.Fatal("foreign chain lost")
		}
		if r := query([]string{"iptables", "-w", "2", "-t", "mangle", "-X", "FOREIGN_KEEP"}); r.ExitCode != 0 {
			t.Fatal(r)
		}
		d.r.Pending = "remove"
		if e = d.save(); e != nil {
			t.Fatal(e)
		}
		d.Close()
		d, e = OpenDurableIsolated(dir, p)
		if e != nil {
			t.Fatal(e)
		}
		if d.Recover() == nil {
			t.Fatal("ambiguous intent adopted")
		}
		// Test-only known pre-command intent: restore the committed checkpoint.
		d.r.Pending = ""
		if e = d.save(); e != nil {
			t.Fatal(e)
		}
		if e = d.Recover(); e != nil {
			t.Fatal(e)
		}
		d.Close()
		if e = os.Chmod(filepath.Join(dir, "journal.json"), 0644); e != nil {
			t.Fatal(e)
		}
		if d, e := OpenDurableIsolated(dir, p); e == nil {
			d.Close()
			t.Fatal("public journal accepted")
		}
		if e = os.Remove(filepath.Join(dir, "journal.json")); e != nil {
			t.Fatal(e)
		}
		if e = os.Symlink("lock", filepath.Join(dir, "journal.json")); e != nil {
			t.Fatal(e)
		}
		if d, e := OpenDurableIsolated(dir, p); e == nil {
			d.Close()
			t.Fatal("symlink journal accepted")
		}
		if e = os.Remove(filepath.Join(dir, "journal.json")); e != nil {
			t.Fatal(e)
		}
		if e = os.Link(filepath.Join(dir, "lock"), filepath.Join(dir, "journal.json")); e != nil {
			t.Fatal(e)
		}
		if d, e := OpenDurableIsolated(dir, p); e == nil {
			d.Close()
			t.Fatal("hard-linked state accepted")
		}
	})
}
