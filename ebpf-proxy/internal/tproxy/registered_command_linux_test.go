//go:build linux

package tproxy

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRegisteredHostAndZero(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, e := privateWitnessNamespace(); e == nil {
		t.Skip("host-only check")
	}
	if _, e := StartRegisteredScopedCommand(ctx, []string{"true"}, nil, "/nonexistent", journalPlan()); e == nil {
		t.Fatal("host registration admitted")
	}
	if _, e := (*RegisteredCommandSession)(nil).Wait(ctx); e == nil {
		t.Fatal("nil session")
	}
	if _, e := (&RegisteredCommandSession{}).Wait(ctx); e == nil {
		t.Fatal("zero session")
	}
}

func TestRegisteredOutputFixture(t *testing.T) {
	if os.Getenv("TP_REGISTERED_OUTPUT") != "1" {
		t.Skip("output fixture only")
	}
	if _, e := os.Stdout.Write([]byte(strings.Repeat("x", 65537))); e != nil {
		t.Fatal(e)
	}
}

func TestPrivilegedRegisteredBadReport(t *testing.T) {
	if !scopedPrivateChild(t, "TestPrivilegedRegisteredBadReport") {
		return
	}
	dir := privateJournalTestDir(t)
	f, e := os.OpenFile(dir+"/must-not-write", os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if _, e = f.Write([]byte("sentinel")); e != nil {
		t.Fatal(e)
	}
	f.Seek(0, 0)
	workerFD, e := unix.PidfdOpen(os.Getpid(), 0)
	if e != nil {
		t.Fatal(e)
	}
	worker := os.NewFile(uintptr(workerFD), "worker")
	defer worker.Close()
	g := exec.Command("/system/bin/sleep", "15")
	if e = g.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { g.Process.Kill(); g.Wait() }()
	guardFD, e := unix.PidfdOpen(g.Process.Pid, 0)
	if e != nil {
		t.Fatal(e)
	}
	guard := os.NewFile(uintptr(guardFD), "guard")
	defer guard.Close()
	fds, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	parent, child := os.NewFile(uintptr(fds[0]), "parent"), os.NewFile(uintptr(fds[1]), "child")
	defer parent.Close()
	defer child.Close()
	cfg, e := registeredConfigPipe(registeredCommandConfig{1, dir, journalPlan()})
	if e != nil {
		t.Fatal(e)
	}
	defer cfg.Close()
	c := exec.Command(os.Args[0], registeredAnchorArgument)
	c.ExtraFiles = []*os.File{child, worker, guard, cfg, f}
	if e = c.Start(); e != nil {
		t.Fatal(e)
	}
	child.Close()
	parent.Close()
	if e = c.Wait(); e == nil {
		t.Fatal("ordinary file accepted as report pipe")
	}
	b, e := os.ReadFile(dir + "/must-not-write")
	if e != nil || string(b) != "sentinel" {
		t.Fatal("wrong report descriptor overwritten", e)
	}
}

func waitRegisteredBarrier(t *testing.T, path string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if _, e := os.Stat(path); e == nil {
			return
		}
	}
	t.Fatal("registered fixture barrier timeout")
}

func TestRegisteredDelayedCommand(t *testing.T) {
	dir := os.Getenv("TP_REGISTERED_DIR")
	if dir == "" {
		t.Skip("command fixture only")
	}
	lease := os.NewFile(3, "direct-command-lease")
	if privateFile(lease) != nil {
		t.Fatal("missing command lease")
	}
	defer lease.Close()
	// Control descriptors must not leak through guard -> stub -> actual exec.
	entries, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		link, _ := os.Readlink("/proc/self/fd/" + entry.Name())
		if link == "anon_inode:[pidfd]" || strings.HasPrefix(link, "socket:") {
			t.Fatal("control capability leaked into direct command")
		}
	}
	if os.Getenv("TP_REGISTERED_DISCARD") == "1" {
		lease.Close()
		if e := unix.Prctl(unix.PR_SET_PDEATHSIG, 0, 0, 0, 0); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.WriteFile(dir+"/command-ready", []byte("ready"), 0600); e != nil {
		t.Fatal(e)
	}
	for deadline := time.Now().Add(6 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, e = os.Stat(dir + "/release-command"); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture command release timeout")
		}
	}
	var args []string
	if e = json.Unmarshal([]byte(os.Args[len(os.Args)-1]), &args); e != nil {
		t.Fatal(e)
	}
	if e = commandError(query(args)); e != nil {
		t.Fatal(e)
	}
}

func TestRegisteredWorkerFixture(t *testing.T) {
	dir := os.Getenv("TP_REGISTERED_DIR")
	if dir == "" {
		t.Skip("worker fixture only")
	}
	unix.CloseOnExec(3) // fixture notification capability is not a command FD
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
		ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
		defer cancel()
		b, _ := json.Marshal(args)
		s, e := StartRegisteredScopedCommand(ctx, []string{os.Args[0], "-test.run=^TestRegisteredDelayedCommand$", "--", string(b)}, d.lock, dir, journalPlan())
		if e != nil {
			t.Fatal(e)
		}
		workerFD, e := unix.PidfdOpen(os.Getpid(), 0)
		if e != nil {
			t.Fatal(e)
		}
		defer unix.Close(workerFD)
		packet := make([]byte, handoffPacketSize)
		packet[0] = 1
		if e = handoffSend(ctx, 3, packet, []int{workerFD, s.guardFD, s.anchorFD}); e != nil {
			t.Fatal(e)
		}
		result, e := s.Wait(ctx)
		if e != nil {
			t.Fatal(e)
		}
		return result.Command
	}
	if e = d.Setup(); e != nil {
		t.Fatal(e)
	}
	t.Fatal("fixture owner must kill worker during final pending command")
}

func TestPrivilegedRegisteredCommand(t *testing.T) {
	if !scopedPrivateChild(t, "TestPrivilegedRegisteredCommand") {
		return
	}
	for _, mode := range []string{"success", "failure", "overflow", "cancel", "guard-crash", "anchor-crash"} {
		t.Run(mode, func(t *testing.T) {
			dir := privateJournalTestDir(t)
			d, e := OpenScopedIsolated(dir, journalPlan())
			if e != nil {
				t.Fatal(e)
			}
			defer d.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
			defer cancel()
			args := []string{"/system/bin/touch", dir + "/executed"}
			if mode == "failure" {
				args = []string{"/nonexistent-registered-command"}
			}
			if mode == "overflow" {
				t.Setenv("TP_REGISTERED_OUTPUT", "1")
				args = []string{os.Args[0], "-test.run=^TestRegisteredOutputFixture$"}
			}
			if mode == "cancel" || mode == "guard-crash" || mode == "anchor-crash" {
				t.Setenv("TP_REGISTERED_DIR", dir)
				t.Setenv("TP_REGISTERED_DISCARD", "1")
				b, _ := json.Marshal(args)
				args = []string{os.Args[0], "-test.run=^TestRegisteredDelayedCommand$", "--", string(b)}
			}
			s, e := StartRegisteredScopedCommand(ctx, args, d.lock, dir, journalPlan())
			if e != nil {
				t.Fatal(e)
			}
			if mode == "cancel" || mode == "guard-crash" || mode == "anchor-crash" {
				waitRegisteredBarrier(t, dir+"/command-ready")
			}
			if mode == "cancel" {
				cancel()
			}
			if mode == "anchor-crash" {
				if e = unix.PidfdSendSignal(s.anchorFD, unix.SIGKILL, nil, 0); e != nil {
					t.Fatal(e)
				}
				cancel()
			}
			if mode == "guard-crash" {
				if e = unix.PidfdSendSignal(s.guardFD, unix.SIGKILL, nil, 0); e != nil {
					t.Fatal(e)
				}
			}
			var result RegisteredCommandResult
			if mode == "guard-crash" {
				type outcome struct {
					r   RegisteredCommandResult
					err error
				}
				done := make(chan outcome, 1)
				go func() { r, err := s.Wait(ctx); done <- outcome{r, err} }()
				select {
				case <-done:
					t.Fatal("reported quiescent while command alive")
				case <-time.After(150 * time.Millisecond):
				}
				if e = os.WriteFile(dir+"/release-command", []byte("go"), 0600); e != nil {
					t.Fatal(e)
				}
				finished := <-done
				result, e = finished.r, finished.err
			} else {
				result, e = s.Wait(ctx)
			}
			if !result.GuardExitObserved || !result.AnchorExitObserved {
				t.Fatal(result, e)
			}
			if mode == "anchor-crash" {
				if e == nil || result.Quiescent {
					t.Fatal("lost anchor admitted", result, e)
				}
			} else if !result.Quiescent {
				t.Fatal("quiescence not verified", result, e)
			}
			if mode == "success" {
				if e != nil || result.Command.ExitCode != 0 {
					t.Fatal(result, e)
				}
			} else if e == nil {
				t.Fatal("failed command reported success", result)
			}
			if mode == "overflow" && (!result.OutputTruncated || result.Command.ExitCode != -1) {
				t.Fatal("truncated observation admitted")
			}
			if mode == "cancel" || mode == "anchor-crash" {
				if _, e = os.Stat(dir + "/executed"); !os.IsNotExist(e) {
					t.Fatal("cancelled fixture mutated")
				}
			}
			if _, e = s.Wait(ctx); e == nil {
				t.Fatal("session reused")
			}
			t.Logf("mode=%s guard_exit=%v anchor_exit=%v quiescent=%v exit=%d", mode, result.GuardExitObserved, result.AnchorExitObserved, result.Quiescent, result.Command.ExitCode)
		})
	}
}

func TestPrivilegedRegisteredWorkerLoss(t *testing.T) {
	if !scopedPrivateChild(t, "TestPrivilegedRegisteredWorkerLoss") {
		return
	}
	for _, mode := range []string{"worker-loss", "guard-and-worker-loss-retained", "guard-and-worker-loss-discarded"} {
		t.Run(mode, func(t *testing.T) {
			dir := privateJournalTestDir(t)
			scopedForeignFixture(t)
			before, e := captureNamespace()
			if e != nil {
				t.Fatal(e)
			}
			fds, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
			if e != nil {
				t.Fatal(e)
			}
			parent, child := os.NewFile(uintptr(fds[0]), "fixture-parent"), os.NewFile(uintptr(fds[1]), "fixture-worker")
			defer parent.Close()
			c := exec.Command(os.Args[0], "-test.run=^TestRegisteredWorkerFixture$")
			discard := "0"
			if mode == "guard-and-worker-loss-discarded" {
				discard = "1"
			}
			c.Env = append(os.Environ(), "TP_REGISTERED_DIR="+dir, "TP_REGISTERED_DISCARD="+discard)
			c.ExtraFiles = []*os.File{child}
			if e = c.Start(); e != nil {
				t.Fatal(e)
			}
			child.Close()
			defer func() { c.Process.Kill(); c.Wait() }()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			_, pinned, e := handoffReceive(ctx, int(parent.Fd()), 3)
			if e != nil {
				t.Fatal(e)
			}
			defer closeHandoffFDs(pinned)
			for _, fd := range pinned {
				if _, e = liveHandoffPID(fd); e != nil {
					t.Fatal(e)
				}
			}
			waitRegisteredBarrier(t, dir+"/command-ready")
			paused, e := captureNamespace()
			if e != nil {
				t.Fatal(e)
			}
			if e = unix.PidfdSendSignal(pinned[0], unix.SIGKILL, nil, 0); e != nil {
				t.Fatal(e)
			}
			if mode != "worker-loss" {
				if e = unix.PidfdSendSignal(pinned[1], unix.SIGKILL, nil, 0); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "guard-and-worker-loss-discarded" {
				for deadline := time.Now().Add(time.Second); ; time.Sleep(10 * time.Millisecond) {
					d, e := OpenScopedIsolated(dir, journalPlan())
					if e == nil {
						d.Close()
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("discarded lease remained locked", e)
					}
				}
			}
			time.Sleep(150 * time.Millisecond)
			dead, e := witnessPoll([]int{pinned[2]}, 0)
			if e != nil || dead {
				t.Fatal("anchor lost while command pending", e)
			}
			after, e := captureNamespace()
			if e != nil || stateDigest(after) != stateDigest(paused) {
				t.Fatal("premature recovery mutation", e)
			}
			if e = os.WriteFile(dir+"/release-command", []byte("go"), 0600); e != nil {
				t.Fatal(e)
			}
			for {
				dead, e = witnessPoll([]int{pinned[2]}, 100)
				if e != nil {
					t.Fatal(e)
				}
				if dead {
					break
				}
				if ctx.Err() != nil {
					t.Fatal("anchor recovery timeout")
				}
			}
			assertForeignPreserved(t, journalPlan(), before)
			d, e := OpenScopedIsolated(dir, journalPlan())
			if e != nil {
				t.Fatal(e)
			}
			if d.r.Owned != 0 || d.r.Pending != "" {
				t.Fatal("anchor did not finish recovery", d.r)
			}
			d.Close()
			t.Log("actual registered guard/worker loss: survivor waited for command; pending reconciled; eight owned steps removed; foreign fixture preserved")
		})
	}
}
