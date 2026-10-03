//go:build linux

package tproxy

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCommandWitnessHostRejected(t *testing.T) {
	if w, e := AcquireScopedCommandWitness(-1, -1, -1); e == nil || w != nil {
		t.Fatal("host handoff admitted")
	}
	var zero ScopedCommandWitness
	if r, e := zero.Recover(context.Background(), "/nonexistent", journalPlan()); e == nil || r.AllExitsObserved || r.Recovery.Clean {
		t.Fatal("zero witness admitted")
	}
	var empty *ScopedCommandWitness
	if empty.Close() != nil {
		t.Fatal("nil close failed")
	}
	if _, e := empty.Recover(context.Background(), "/nonexistent", journalPlan()); e == nil {
		t.Fatal("nil witness admitted")
	}
}

func TestPrivilegedGuardLossWitness(t *testing.T) {
	if !scopedPrivateChild(t, "TestPrivilegedGuardLossWitness") {
		return
	}
	update := scopedForeignFixture(t)
	update(1)
	for _, discard := range []bool{false, true} {
		name := "inherited_lease_and_pdeathsig"
		if discard {
			name = "discarded_lease_and_pdeathsig"
		}
		t.Run(name, func(t *testing.T) {
			dir := privateJournalTestDir(t)
			before, e := captureNamespace()
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			c := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAnchorSupervisor$")
			mode := "0"
			if discard {
				mode = "1"
			}
			c.Env = append(os.Environ(), "TP_ANCHOR_DIR="+dir, "TP_ANCHOR_DISCARD_LEASE="+mode)
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
			if command.Guard == nil {
				t.Fatal("guard identity absent")
			}
			commandFD := pinAnchorIdentity(t, command)
			guardFD := pinAnchorIdentity(t, *command.Guard)
			w, e := AcquireScopedCommandWitness(workerFD, guardFD, commandFD)
			if e != nil {
				t.Fatal("live witness handoff failed", e)
			}
			defer w.Close()
			// A second descriptor for the same identity is not a distinct role.
			if bad, e := AcquireScopedCommandWitness(workerFD, guardFD, guardFD); e == nil {
				bad.Close()
				t.Fatal("duplicate identity admitted")
			}
			ordinary, e := os.Open("/proc/self/stat")
			if e != nil {
				t.Fatal(e)
			}
			if bad, e := AcquireScopedCommandWitness(workerFD, guardFD, int(ordinary.Fd())); e == nil {
				bad.Close()
				t.Fatal("ordinary descriptor admitted")
			}
			ordinary.Close()
			if bad, e := AcquireScopedCommandWitness(workerFD, guardFD, -1); e == nil {
				bad.Close()
				t.Fatal("missing command witness admitted")
			}
			hostFD, e := unix.PidfdOpen(1, 0)
			if e != nil {
				t.Fatal("host identity probe unavailable", e)
			}
			bad, mismatch := AcquireScopedCommandWitness(workerFD, guardFD, hostFD)
			unix.Close(hostFD)
			if mismatch == nil {
				bad.Close()
				t.Fatal("foreign namespace identity admitted")
			}
			// Original descriptor closure/reuse must not invalidate owned pins.
			duplicate, e := unix.FcntlInt(uintptr(commandFD), unix.F_DUPFD_CLOEXEC, 0)
			if e != nil {
				t.Fatal(e)
			}
			temporary, e := AcquireScopedCommandWitness(workerFD, guardFD, duplicate)
			unix.Close(duplicate)
			if e != nil {
				t.Fatal(e)
			}
			probe, stop := context.WithTimeout(ctx, 120*time.Millisecond)
			r, e := temporary.Recover(probe, dir, journalPlan())
			stop()
			if e == nil || r.AllExitsObserved || r.Recovery.Clean {
				t.Fatal("live worker recovered", r, e)
			}
			temporary.Close()
			if _, e = temporary.Recover(ctx, dir, journalPlan()); e == nil {
				t.Fatal("closed witness reused")
			}
			if _, e = w.Recover(context.Background(), dir, journalPlan()); e == nil {
				t.Fatal("unbounded recovery admitted")
			}
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
			if e = unix.PidfdSendSignal(workerFD, unix.SIGKILL, nil, 0); e != nil {
				t.Fatal(e)
			}
			if !anchorExited(t, workerFD, time.Second) {
				t.Fatal("worker exit unverified")
			}
			if e = unix.PidfdSendSignal(guardFD, unix.SIGKILL, nil, 0); e != nil {
				t.Fatal(e)
			}
			if !anchorExited(t, guardFD, time.Second) {
				t.Fatal("guard exit unverified")
			}
			expected := 7
			if discard {
				if anchorExited(t, commandFD, 0) {
					t.Fatal("adversarial command unexpectedly exited")
				}
				// Lock is obtainable but command is demonstrably alive. DO NOT
				// run the old worker-only recovery in this unsafe state.
				d, e := OpenScopedIsolated(dir, journalPlan())
				if e != nil {
					t.Fatal("discarded lease should allow lock acquisition", e)
				}
				d.Close()
				probe, stop := context.WithTimeout(ctx, 120*time.Millisecond)
				r, e := w.Recover(probe, dir, journalPlan())
				stop()
				if e == nil || r.AllExitsObserved || r.Recovery.Clean {
					t.Fatal("running unleased command recovered", r, e)
				}
				after, e := captureNamespace()
				if e != nil || stateDigest(paused) != stateDigest(after) {
					t.Fatal("blocked witness mutated rules", e)
				}
				t.Log("guard SIGKILL with discarded lease/PDEATHSIG: lock available but command alive; witness blocks recovery; zero mutations")
				if e = os.WriteFile(dir+"/release", []byte("fixture-owner-release"), 0600); e != nil {
					t.Fatal(e)
				}
				if !anchorExited(t, commandFD, 3*time.Second) {
					t.Fatal("released command did not exit")
				}
				expected = 8
			} else {
				if !anchorExited(t, commandFD, 3*time.Second) {
					t.Fatal("PDEATHSIG did not stop direct command")
				}
				after, e := captureNamespace()
				if e != nil || stateDigest(paused) != stateDigest(after) {
					t.Fatal("killed pending command modified rules", e)
				}
				t.Log("guard SIGKILL: inherited-lease direct command exits via PDEATHSIG; pending final add not applied")
			}
			if late, e := AcquireScopedCommandWitness(workerFD, guardFD, commandFD); e == nil {
				late.Close()
				t.Fatal("post-exit handoff adopted")
			}
			r, e = w.Recover(ctx, dir, journalPlan())
			if e != nil || !r.AllExitsObserved || r.Witnesses != 3 || !r.Recovery.Clean || !r.Recovery.Reconciled || r.Recovery.RecoveredSteps != expected {
				t.Fatalf("exit witness recovery: %+v %v", r, e)
			}
			assertForeignPreserved(t, journalPlan(), before)
			t.Logf("three pinned exits observed; recovered=%d clean=%v foreign fixture preserved", r.Recovery.RecoveredSteps, r.Recovery.Clean)
		})
	}
}
