//go:build linux

package tproxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSupervisorReadiness(t *testing.T) {
	if e := readyRecord(strings.NewReader("{\"version\":1,\"ready\":true}\n")); e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"", "{\"version\":2,\"ready\":true}\n", "{\"version\":1,\"ready\":false}\n", "{\"version\":1,\"ready\":true,\"password\":\"private-secret\"}\n", "{\"version\":1,\"ready\":true} {}\n", strings.Repeat("x", 300) + "\n"} {
		if e := readyRecord(strings.NewReader(s)); e == nil || strings.Contains(e.Error(), "private-secret") {
			t.Fatal("invalid/unredacted readiness accepted")
		}
	}
}

func TestSupervisorHostRejected(t *testing.T) {
	called := false
	_, e := SuperviseScopedIsolated(context.Background(), "/nonexistent-supervisor", journalPlan(), supervisorOptions(), func(int) (*exec.Cmd, error) { called = true; return nil, nil })
	if e == nil || called {
		t.Fatal("host supervision admitted")
	}
}

// Trusted native fixture: listener precedes rules; TERM normally removes
// interception/dependencies before exit. No payload or upstream protocol here.
func TestSupervisedWorker(t *testing.T) {
	dir := os.Getenv("TP_SUPERVISOR_DIR")
	if dir == "" {
		t.Skip("fixture worker only")
	}
	mode := os.Getenv("TP_SUPERVISOR_MODE")
	ready := os.NewFile(3, "readiness")
	if ready == nil {
		t.Fatal("ready fd unavailable")
	}
	defer ready.Close()
	if mode == "bad_ready" {
		_, _ = io.WriteString(ready, "{\"version\":1,\"ready\":true,\"password\":\"private-secret\"}\n")
		time.Sleep(10 * time.Second)
		return
	}
	if mode == "startup_failed" {
		t.Fatal("fixture upstream/startup failure before interception")
	}
	term := make(chan os.Signal, 1)
	if mode == "hang" {
		signal.Ignore(syscall.SIGTERM)
	} else {
		signal.Notify(term, syscall.SIGTERM)
		defer signal.Stop(term)
	}
	d, e := OpenScopedIsolated(dir, journalPlan())
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	listener, e := ListenTransparent(context.Background(), "tcp4", "0.0.0.0:18080")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	if e = d.Setup(); e != nil {
		t.Fatal(e)
	}
	if mode != "no_ready" {
		if _, e = io.WriteString(ready, "{\"version\":1,\"ready\":true}\n"); e != nil {
			t.Fatal(e)
		}
		ready.Close()
	}
	switch mode {
	case "crash", "foreign":
		if mode == "foreign" {
			if e = commandError(query([]string{"iptables", "-w", "2", "-t", "mangle", "-A", "FOREIGN_NETD", "-j", "ATP_JOURNAL_OUT"})); e != nil {
				t.Fatal(e)
			}
		}
		time.Sleep(100 * time.Millisecond)
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		t.Fatal("fixture kill did not exit")
	case "hang":
		for {
			time.Sleep(time.Hour)
		}
	case "grace", "no_ready":
		<-term
	case "normal":
		time.Sleep(100 * time.Millisecond)
	default:
		t.Fatal("unknown fixture mode")
	}
	if e = d.Recover(); e != nil {
		t.Fatal(e)
	}
}

func fixtureFactory(dir string, modes []string, calls *int) IsolatedWorkerFactory {
	return func(attempt int) (*exec.Cmd, error) {
		*calls++
		mode := modes[0]
		if attempt < len(modes) {
			mode = modes[attempt]
		}
		c := exec.Command(os.Args[0], "-test.run=^TestSupervisedWorker$")
		c.Env = append(os.Environ(), "TP_SUPERVISOR_DIR="+dir, "TP_SUPERVISOR_MODE="+mode)
		return c, nil
	}
}

func TestPrivilegedBoundedSupervisor(t *testing.T) {
	if !scopedPrivateChild(t, "TestPrivilegedBoundedSupervisor") {
		return
	}
	update := scopedForeignFixture(t)
	update(1)
	for _, tc := range []struct {
		name     string
		modes    []string
		budget   int
		state    string
		attempts int
		cancel   bool
		kill     bool
	}{
		{"crash_then_normal", []string{"crash", "normal"}, 1, "completed", 2, false, false},
		{"crash_budget", []string{"crash"}, 1, "exhausted", 2, false, false},
		{"graceful_stop", []string{"grace"}, 0, "stopped", 1, true, false},
		{"ignored_term", []string{"hang"}, 0, "stopped", 1, true, true},
		{"readiness_timeout", []string{"no_ready"}, 0, "exhausted", 1, false, false},
		{"invalid_readiness", []string{"bad_ready"}, 0, "exhausted", 1, false, false},
		{"startup_failure", []string{"startup_failed"}, 1, "exhausted", 2, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := privateJournalTestDir(t)
			calls := 0
			o := supervisorOptions()
			o.MaxRestarts = tc.budget
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			if tc.cancel {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
			}
			if tc.kill {
				o.StopGrace = 100 * time.Millisecond
			}
			defer cancel()
			before, e := captureNamespace()
			if e != nil {
				t.Fatal(e)
			}
			r, e := SuperviseScopedIsolated(ctx, dir, journalPlan(), o, fixtureFactory(dir, tc.modes, &calls))
			if r.State != tc.state || !r.Clean || calls != tc.attempts || len(r.Attempts) != tc.attempts || (tc.state == "exhausted") != (e != nil) {
				t.Fatalf("%+v calls=%d err=%v", r, calls, e)
			}
			for _, a := range r.Attempts {
				if !a.ExitObserved || !a.Clean {
					t.Fatal("restart before verified exit/cleanup", a)
				}
			}
			if tc.cancel && (!r.Attempts[0].TermRequested || r.Attempts[0].KillRequested != tc.kill) {
				t.Fatal("stop escalation mismatch", r)
			}
			assertForeignPreserved(t, journalPlan(), before)
			t.Logf("state=%s attempts=%d restarts=%d clean=%v term=%v kill=%v", r.State, len(r.Attempts), r.Restarts, r.Clean, r.Attempts[0].TermRequested, r.Attempts[0].KillRequested)
		})
	}
	// Launch errors consume a finite budget and never expose factory secrets.
	calls := 0
	o := supervisorOptions()
	o.MaxRestarts = 2
	r, e := SuperviseScopedIsolated(context.Background(), privateJournalTestDir(t), journalPlan(), o, func(int) (*exec.Cmd, error) { calls++; return nil, errors.New("private-secret") })
	if calls != 3 || r.State != "exhausted" || !r.Clean || e == nil || strings.Contains(e.Error(), "private-secret") {
		t.Fatal(r, calls, e)
	}
	// Foreign references prohibit cleanup/restart; they are not deleted by the
	// supervisor. The fixture owner explicitly removes its own foreign jump.
	dir := privateJournalTestDir(t)
	calls = 0
	o.MaxRestarts = 3
	r, e = SuperviseScopedIsolated(context.Background(), dir, journalPlan(), o, fixtureFactory(dir, []string{"foreign"}, &calls))
	if e == nil || r.State != "blocked" || r.Clean || calls != 1 {
		t.Fatal("unsafe recovery restarted", r, e)
	}
	if e = commandError(query([]string{"iptables", "-w", "2", "-t", "mangle", "-D", "FOREIGN_NETD", "-j", "ATP_JOURNAL_OUT"})); e != nil {
		t.Fatal(e)
	}
	if _, e = scopedCleanup(o, dir, journalPlan()); e != nil {
		t.Fatal(e)
	}
	t.Log("foreign ownership conflict: blocked, one launch only; fixture owner removes reference; explicit cleanup succeeds")
	// A stopped context cannot spend another launch budget. Cleanup deliberately
	// uses its own bounded context rather than an already-cancelled run context.
	dir = privateJournalTestDir(t)
	calls = 0
	ctx, cancel := context.WithCancel(context.Background())
	r, e = SuperviseScopedIsolated(ctx, dir, journalPlan(), o, func(int) (*exec.Cmd, error) { calls++; cancel(); return nil, errors.New("private-secret") })
	if e != nil || r.State != "stopped" || !r.Clean || calls != 1 {
		t.Fatal(r, calls, e)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "private-secret") {
		t.Fatal("supervisor result leaks credentials")
	}
}

func TestPrivilegedSupervisorAdmission(t *testing.T) {
	if !scopedPrivateChild(t, "TestPrivilegedSupervisorAdmission") {
		return
	}
	o := supervisorOptions()
	p := journalPlan()
	// Hold just the session lock: simulate another supervisor between workers,
	// with the journal lock free. No second factory may be called.
	dir := privateJournalTestDir(t)
	d, e := OpenScopedIsolated(dir, p)
	if e != nil {
		t.Fatal(e)
	}
	f, e := d.root.OpenFile("supervisor.lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		t.Fatal(e)
	}
	d.Close()
	called := false
	r, e := SuperviseScopedIsolated(context.Background(), dir, p, o, func(int) (*exec.Cmd, error) { called = true; return nil, nil })
	if e == nil || called || r.State != "blocked" {
		t.Fatal("concurrent session admitted", r, e)
	}
	f.Close()
	// A symlink cannot redirect the session lock outside the private root.
	dir = privateJournalTestDir(t)
	target := privateJournalTestDir(t) + "/target"
	if e = os.WriteFile(target, []byte("keep"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(target, dir+"/supervisor.lock"); e != nil {
		t.Fatal(e)
	}
	called = false
	r, e = SuperviseScopedIsolated(context.Background(), dir, p, o, func(int) (*exec.Cmd, error) { called = true; return nil, nil })
	if e == nil || called {
		t.Fatal("symlink session admitted")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "keep" {
		t.Fatal("foreign target changed")
	}
	// A prestarted process from a faulty factory is not ours to kill or reap.
	dir = privateJournalTestDir(t)
	r, e = SuperviseScopedIsolated(context.Background(), dir, p, o, func(int) (*exec.Cmd, error) { return &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}, nil })
	if e == nil || r.State != "blocked" || len(r.Attempts) != 1 || r.Attempts[0].ExitObserved {
		t.Fatal("unverified process adopted", r, e)
	}
	// Recovery cancellation must reach every observer/query before any removal.
	dir = privateJournalTestDir(t)
	d, e = OpenScopedIsolated(dir, p)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if e = d.Setup(); e != nil {
		t.Fatal(e)
	}
	before, e := captureNamespace()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.run = func(args []string) Result { return queryContext(ctx, args) }
	if d.Recover() == nil {
		t.Fatal("cancelled query recovered")
	}
	after, e := captureNamespace()
	if e != nil || stateDigest(before) != stateDigest(after) {
		t.Fatal("cancelled observer mutated resources", e)
	}
	d.run = query
	if e = d.Recover(); e != nil {
		t.Fatal(e)
	}
	t.Log("session contention/symlink/prestarted process refused; cancelled recovery performed zero mutations; explicit retry clean")
}
