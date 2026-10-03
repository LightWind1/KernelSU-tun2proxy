//go:build linux

package tproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	if code, handled := CommandGuardEntry(os.Args); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

type anchorIdentity struct {
	PID   int             `json:"pid"`
	Start string          `json:"start"`
	Guard *anchorIdentity `json:"guard,omitempty"`
}

func writeAnchorIdentity(t *testing.T, name string, guard bool) {
	t.Helper()
	start, e := fixtureStartTime(os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	i := anchorIdentity{PID: os.Getpid(), Start: start}
	if guard {
		s, e := fixtureStartTime(os.Getppid())
		if e != nil {
			t.Fatal(e)
		}
		i.Guard = &anchorIdentity{PID: os.Getppid(), Start: s}
	}
	b, _ := json.Marshal(i)
	if e = os.WriteFile(os.Getenv("TP_ANCHOR_DIR")+"/"+name, b, 0600); e != nil {
		t.Fatal(e)
	}
}

// Controlled test command: retain inherited lease, announce identities before
// mutation, wait for fixture-owner permission, then execute the exact final
// plan step. It is not a fake firewall or a claim about arbitrary descendants.
func TestAnchorDelayedCommand(t *testing.T) {
	dir := os.Getenv("TP_ANCHOR_DIR")
	if dir == "" {
		t.Skip("fixture command only")
	}
	lease := os.NewFile(3, "command-lease")
	if lease == nil || privateFile(lease) != nil {
		t.Fatal("missing command lease")
	}
	defer lease.Close()
	if os.Getenv("TP_ANCHOR_DISCARD_LEASE") == "1" {
		if e := unix.Prctl(unix.PR_SET_PDEATHSIG, 0, 0, 0, 0); e != nil {
			t.Fatal(e)
		}
		if e := lease.Close(); e != nil {
			t.Fatal(e)
		}
	}
	writeAnchorIdentity(t, "command.json", true)
	deadline := time.NewTimer(6 * time.Second)
	defer deadline.Stop()
	for {
		if _, e := os.Stat(dir + "/release"); e == nil {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("fixture release timeout")
		case <-time.After(10 * time.Millisecond):
		}
	}
	var args []string
	if e := json.Unmarshal([]byte(os.Args[len(os.Args)-1]), &args); e != nil {
		t.Fatal(e)
	}
	if e := commandError(query(args)); e != nil {
		t.Fatal(e)
	}
}

func TestAnchorWorker(t *testing.T) {
	dir := os.Getenv("TP_ANCHOR_DIR")
	if dir == "" {
		t.Skip("fixture worker only")
	}
	writeAnchorIdentity(t, "worker.json", false)
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
	steps, _ := journalPlan().Steps()
	original := d.run
	d.run = func(args []string) Result {
		if !reflect.DeepEqual(args, steps[len(steps)-1].Add) {
			return original(args)
		}
		b, _ := json.Marshal(args)
		return queryLeasedContext(context.Background(), []string{os.Args[0], "-test.run=^TestAnchorDelayedCommand$", "--", string(b)}, d.lock)
	}
	if e = d.Setup(); e != nil {
		t.Fatal(e)
	}
	t.Fatal("fixture owner must kill worker while command is pending")
}

func TestAnchorSupervisor(t *testing.T) {
	dir := os.Getenv("TP_ANCHOR_DIR")
	if dir == "" {
		t.Skip("fixture supervisor only")
	}
	o := supervisorOptions()
	o.MaxRestarts = 0
	o.ReadyTimeout = 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, e := SuperviseScopedIsolated(ctx, dir, journalPlan(), o, func(int) (*exec.Cmd, error) {
		c := exec.Command(os.Args[0], "-test.run=^TestAnchorWorker$")
		c.Env = os.Environ()
		return c, nil
	})
	t.Fatalf("fixture supervisor unexpectedly completed: %v", e)
}

func readAnchorIdentity(t *testing.T, path string) anchorIdentity {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		b, e := os.ReadFile(path)
		var i anchorIdentity
		if e == nil && json.Unmarshal(b, &i) == nil && i.PID > 1 && i.Start != "" {
			return i
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("fixture identity timeout")
	return anchorIdentity{}
}

func pinAnchorIdentity(t *testing.T, i anchorIdentity) int {
	t.Helper()
	start, e := fixtureStartTime(i.PID)
	if e != nil || start != i.Start {
		t.Fatal("fixture identity changed", e)
	}
	fd, e := unix.PidfdOpen(i.PID, 0)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); unix.Close(fd) })
	start, e = fixtureStartTime(i.PID)
	if e != nil || start != i.Start {
		t.Fatal("fixture identity changed during pin", e)
	}
	return fd
}

func anchorExited(t *testing.T, fd int, timeout time.Duration) bool {
	t.Helper()
	p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	_, e := unix.Poll(p, int(timeout.Milliseconds()))
	if e != nil {
		t.Fatal(e)
	}
	return p[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0
}

func TestScopedAnchorHostRejected(t *testing.T) {
	if r, e := WatchScopedIsolatedPIDFD(context.Background(), -1, "/nonexistent", journalPlan()); e == nil || r.Clean {
		t.Fatal("host anchor admitted")
	}
	if code, handled := CommandGuardEntry([]string{"native", commandGuardArgument, "--", "ip", "rule", "show"}); !handled || code == 0 {
		t.Fatal("host guard admitted")
	}
	if _, handled := CommandGuardEntry([]string{"native", "normal"}); handled {
		t.Fatal("ordinary CLI intercepted")
	}
}

func TestPrivilegedScopedSurvivor(t *testing.T) {
	if !scopedPrivateChild(t, "TestPrivilegedScopedSurvivor") {
		return
	}
	update := scopedForeignFixture(t)
	update(1)
	dir := privateJournalTestDir(t)
	before, e := captureNamespace()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAnchorSupervisor$")
	c.Env = append(os.Environ(), "TP_ANCHOR_DIR="+dir)
	if e = c.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = c.Process.Kill(); _ = c.Wait() }()
	supervisorFD, e := unix.PidfdOpen(c.Process.Pid, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(supervisorFD)
	workerFD := pinAnchorIdentity(t, readAnchorIdentity(t, dir+"/worker.json"))
	command := readAnchorIdentity(t, dir+"/command.json")
	commandFD := pinAnchorIdentity(t, command)
	if command.Guard == nil {
		t.Fatal("guard identity absent")
	}
	guardFD := pinAnchorIdentity(t, *command.Guard)
	paused, e := captureNamespace()
	if e != nil {
		t.Fatal(e)
	}
	if e = unix.PidfdSendSignal(supervisorFD, unix.SIGKILL, nil, 0); e != nil {
		t.Fatal(e)
	}
	if e = c.Wait(); e == nil {
		t.Fatal("supervisor not killed")
	}
	probe, stop := context.WithTimeout(context.Background(), 120*time.Millisecond)
	r, e := WatchScopedIsolatedPIDFD(probe, workerFD, dir, journalPlan())
	stop()
	if e == nil || r.Clean || r.ExitObserved {
		t.Fatal("live worker recovered", r, e)
	}
	if e = unix.PidfdSendSignal(workerFD, unix.SIGKILL, nil, 0); e != nil {
		t.Fatal(e)
	}
	probe, stop = context.WithTimeout(context.Background(), time.Second)
	r, e = WatchScopedIsolatedPIDFD(probe, workerFD, dir, journalPlan())
	stop()
	if e == nil || !strings.Contains(e.Error(), "state locked") || !r.ExitObserved || r.Clean {
		t.Fatal("live command lease stolen", r, e)
	}
	if anchorExited(t, commandFD, 0) || anchorExited(t, guardFD, 0) {
		t.Fatal("command guard did not survive launcher loss")
	}
	after, e := captureNamespace()
	if e != nil || stateDigest(after) != stateDigest(paused) {
		t.Fatal("blocked anchor mutated rules", e)
	}
	t.Log("supervisor SIGKILL + worker SIGKILL: command/guard alive; anchor exit_observed=true clean=false state locked; zero rule mutations")
	if e = os.WriteFile(dir+"/release", []byte("fixture-owner-release"), 0600); e != nil {
		t.Fatal(e)
	}
	if !anchorExited(t, commandFD, 3*time.Second) || !anchorExited(t, guardFD, 3*time.Second) {
		t.Fatal("command/guard exit not observed")
	}
	r, e = WatchScopedIsolatedPIDFD(ctx, workerFD, dir, journalPlan())
	if e != nil || !r.ExitObserved || r.ExitCodeKnown || !r.Reconciled || !r.Clean || r.RecoveredSteps != 8 {
		t.Fatalf("replacement scoped anchor: %+v %v", r, e)
	}
	assertForeignPreserved(t, journalPlan(), before)
	t.Logf("command/guard pidfd exit verified; pending add reconciled; recovered=%d clean=%v foreign fixture preserved", r.RecoveredSteps, r.Clean)
	ordinary, e := os.Open("/proc/self/stat")
	if e != nil {
		t.Fatal(e)
	}
	defer ordinary.Close()
	if _, e = WatchScopedIsolatedPIDFD(ctx, int(ordinary.Fd()), dir, journalPlan()); e == nil {
		t.Fatal("ordinary file admitted as pidfd")
	}
}

func TestPrivilegedCommandGuardCancellation(t *testing.T) {
	if !scopedPrivateChild(t, "TestPrivilegedCommandGuardCancellation") {
		return
	}
	dir := privateJournalTestDir(t)
	d, e := OpenScopedIsolated(dir, journalPlan())
	if e != nil {
		t.Fatal(e)
	}
	t.Setenv("TP_ANCHOR_DIR", dir)
	before, e := captureNamespace()
	if e != nil {
		t.Fatal(e)
	}
	args := []string{"iptables", "-w", "2", "-t", "mangle", "-N", "GUARD_CANCEL"}
	b, _ := json.Marshal(args)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan Result, 1)
	go func() {
		done <- queryLeasedContext(ctx, []string{os.Args[0], "-test.run=^TestAnchorDelayedCommand$", "--", string(b)}, d.lock)
	}()
	i := readAnchorIdentity(t, dir+"/command.json")
	commandFD := pinAnchorIdentity(t, i)
	if i.Guard == nil {
		t.Fatal("guard identity absent")
	}
	guardFD := pinAnchorIdentity(t, *i.Guard)
	cancel()
	select {
	case r := <-done:
		if r.ExitCode == 0 {
			t.Fatal("cancelled command succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("guard cancellation did not reap command")
	}
	if !anchorExited(t, commandFD, 0) || !anchorExited(t, guardFD, 0) {
		t.Fatal("query returned before command/guard exit")
	}
	if e = d.Close(); e != nil {
		t.Fatal(e)
	}
	d, e = OpenScopedIsolated(dir, journalPlan())
	if e != nil {
		t.Fatal("lease leaked after cancellation", e)
	}
	d.Close()
	after, e := captureNamespace()
	if e != nil || stateDigest(before) != stateDigest(after) {
		t.Fatal("cancelled command modified rules", e)
	}
	t.Log(fmt.Sprintf("cancelled query: command and guard exited; lock reacquired; zero kernel mutations"))
}
