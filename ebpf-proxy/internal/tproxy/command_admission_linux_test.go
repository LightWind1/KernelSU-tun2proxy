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

func TestCommandAdmissionHostRejected(t *testing.T) {
	if _, e := privateWitnessNamespace(); e == nil {
		t.Skip("host namespace check only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, e := StartPausedScopedCommand(ctx, []string{"true"}, nil); e == nil {
		t.Fatal("host admission allowed")
	}
}

func TestCommandAdmissionUninitialized(t *testing.T) {
	p := &PausedScopedCommand{}
	if _, e := p.Admit(-1, -1); e == nil {
		t.Fatal("zero admission accepted")
	}
	if e := p.Wait(); e == nil {
		t.Fatal("zero Wait accepted")
	}
	if e := p.Abort(); e == nil {
		t.Fatal("zero Abort accepted")
	}
	var absent *PausedScopedCommand
	if _, e := absent.Admit(-1, -1); e == nil {
		t.Fatal("nil admission accepted")
	}
	if e := absent.Wait(); e == nil {
		t.Fatal("nil Wait accepted")
	}
	if e := absent.Abort(); e != nil {
		t.Fatal(e)
	}
}

func TestPrivilegedCommandAdmission(t *testing.T) {
	if !scopedPrivateChild(t, "TestPrivilegedCommandAdmission") {
		return
	}
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	d, e := OpenScopedIsolated(dir, journalPlan())
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	guard, e := unix.PidfdOpen(os.Getpid(), 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(guard)
	worker := exec.Command("/system/bin/sleep", "30")
	if e = worker.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { worker.Process.Kill(); worker.Wait() }()
	workerFD, e := unix.PidfdOpen(worker.Process.Pid, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(workerFD)
	for _, tc := range []string{"admit", "invalid-witness", "duplicate", "missing-ack", "bad-version", "trailing-data", "ancillary", "timeout", "cancel", "cancel-before-admit"} {
		t.Run(tc, func(t *testing.T) {
			path := dir + "/" + tc
			limit := 3 * time.Second
			if tc == "timeout" {
				limit = 300 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), limit)
			defer cancel()
			p, e := StartPausedScopedCommand(ctx, []string{"/system/bin/touch", path}, d.lock)
			if e != nil {
				t.Fatal(e)
			}
			defer p.Abort()
			time.Sleep(50 * time.Millisecond)
			if _, e = os.Stat(path); !os.IsNotExist(e) {
				t.Fatal("executed before admission")
			}
			switch tc {
			case "admit":
				w, e := p.Admit(workerFD, guard)
				if e != nil {
					t.Fatal(e)
				}
				defer w.Close()
				if _, e = p.Admit(workerFD, guard); e == nil {
					t.Fatal("replay accepted")
				}
				if e = p.Wait(); e != nil {
					t.Fatal(e)
				}
				if _, e = os.Stat(path); e != nil {
					t.Fatal("admitted exec missing", e)
				}
				return
			case "invalid-witness":
				if _, e = p.Admit(-1, guard); e == nil {
					t.Fatal("invalid descriptor accepted")
				}
			case "duplicate":
				if _, e = p.Admit(guard, guard); e == nil {
					t.Fatal("duplicate identities accepted")
				}
			case "missing-ack":
				p.gate.Close()
				p.mu.Lock()
				e = p.finish(false)
				p.mu.Unlock()
				if e == nil {
					t.Fatal("EOF admitted command")
				}
			case "bad-version", "trailing-data":
				b := []byte{2}
				if tc == "trailing-data" {
					b = []byte{1, 1}
				}
				if e = unix.Sendmsg(int(p.gate.Fd()), b, nil, nil, unix.MSG_NOSIGNAL); e != nil {
					t.Fatal(e)
				}
				p.mu.Lock()
				e = p.finish(false)
				p.mu.Unlock()
				if e == nil {
					t.Fatal("malformed acknowledgement admitted command")
				}
			case "cancel":
				cancel()
				p.mu.Lock()
				e = p.finish(false)
				p.mu.Unlock()
				if e == nil {
					t.Fatal("cancelled stub succeeded")
				}
			case "cancel-before-admit":
				cancel()
				if _, e = p.Admit(workerFD, guard); e == nil {
					t.Fatal("cancelled admission succeeded")
				}
			case "timeout":
				<-ctx.Done()
				p.mu.Lock()
				e = p.finish(false)
				p.mu.Unlock()
				if e == nil {
					t.Fatal("timeout admitted command")
				}
			case "ancillary":
				if e = unix.Sendmsg(int(p.gate.Fd()), []byte{1}, unix.UnixRights(workerFD), nil, unix.MSG_NOSIGNAL); e != nil {
					t.Fatal(e)
				}
				p.mu.Lock()
				e = p.finish(false)
				p.mu.Unlock()
				if e == nil {
					t.Fatal("ancillary descriptor admitted command")
				}
			}
			if _, e = os.Stat(path); !os.IsNotExist(e) {
				t.Fatal("refused command executed")
			}
		})
	}
	t.Run("real-private-rule", func(t *testing.T) {
		args := []string{"iptables", "-w", "2", "-t", "mangle", "-N", "ATP_ADMISSION"}
		check := []string{"iptables", "-t", "mangle", "-S", "ATP_ADMISSION"}
		remove := []string{"iptables", "-w", "2", "-t", "mangle", "-X", "ATP_ADMISSION"}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		p, e := StartPausedScopedCommand(ctx, args, d.lock)
		if e != nil {
			t.Fatal(e)
		}
		defer p.Abort()
		if query(check).ExitCode == 0 {
			t.Fatal("rule executed before admission")
		}
		w, e := p.Admit(workerFD, guard)
		if e != nil {
			t.Fatal(e)
		}
		defer w.Close()
		if e = p.Wait(); e != nil {
			t.Fatal(e)
		}
		defer query(remove)
		if e = commandError(query(check)); e != nil {
			t.Fatal(e)
		}
		if e = commandError(query(remove)); e != nil {
			t.Fatal(e)
		}
		if query(check).ExitCode == 0 {
			t.Fatal("private chain remains")
		}
	})
}
