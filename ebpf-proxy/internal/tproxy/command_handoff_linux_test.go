//go:build linux

package tproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCommandHandoffHostAndZero(t *testing.T) {
	if _, e := privateWitnessNamespace(); e == nil {
		t.Skip("host-only check")
	}
	if _, e := ScopedCommandBinding("/nonexistent", journalPlan()); e == nil {
		t.Fatal("host binding admitted")
	}
	if _, e := NewScopedCommandAnchor(-1, -1, -1, "/nonexistent", journalPlan()); e == nil {
		t.Fatal("host anchor admitted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var a *ScopedCommandAnchor
	if _, e := a.Accept(ctx); e == nil {
		t.Fatal("nil anchor")
	}
	a.Close()
	a = &ScopedCommandAnchor{}
	if _, e := a.Accept(ctx); e == nil {
		t.Fatal("zero anchor")
	}
	a.Close()
	var r *RegisteredScopedCommand
	if _, e := r.Recover(ctx); e == nil {
		t.Fatal("nil registration")
	}
	r.Close()
	if e := (*PausedScopedCommand)(nil).HandoffScoped(ctx, -1, -1, -1, "", journalPlan()); e == nil {
		t.Fatal("nil sender")
	}
}

func TestPrivilegedCommandHandoffBinding(t *testing.T) {
	if !scopedPrivateChild(t, "TestPrivilegedCommandHandoffBinding") {
		return
	}
	base := privateJournalTestDir(t)
	dir := base + "/state"
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	p := journalPlan()
	b, e := ScopedCommandBinding(dir, p)
	if e != nil {
		t.Fatal(e)
	}
	if other, e := ScopedCommandBinding(dir+"/.", p); e != nil || b != other {
		t.Fatal("canonical binding unstable", e)
	}
	changed := p
	changed.ListenerPort++
	if other, e := ScopedCommandBinding(dir, changed); e != nil || b == other {
		t.Fatal("plan not bound", e)
	}
	if e = os.Symlink(dir, base+"/link"); e != nil {
		t.Fatal(e)
	}
	if _, e = ScopedCommandBinding(base+"/link", p); e == nil {
		t.Fatal("symlink state accepted")
	}
	if e = os.Chmod(dir, 0755); e != nil {
		t.Fatal(e)
	}
	if _, e = ScopedCommandBinding(dir, p); e == nil {
		t.Fatal("public state accepted")
	}
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	before, e := captureNamespace()
	if e != nil {
		t.Fatal(e)
	}
	// Exercise binding refusal before any witness polling/journal open.
	r := &RegisteredScopedCommand{w: &ScopedCommandWitness{}, dir: dir, plan: changed, binding: b}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, e = r.Recover(ctx); e == nil || !strings.Contains(e.Error(), "binding changed") {
		t.Fatal("changed plan not refused", e)
	}
	r.plan = p
	if e = os.Rename(dir, base+"/old"); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = r.Recover(ctx); e == nil || !strings.Contains(e.Error(), "binding changed") {
		t.Fatal("replaced directory not refused", e)
	}
	after, e := captureNamespace()
	if e != nil {
		t.Fatal(e)
	}
	if stateDigest(before) != stateDigest(after) {
		t.Fatal("binding refusal changed namespace")
	}
}

// Independent surviving anchor: capabilities/expected roles arrive only as
// inherited descriptors. Files below are fixture barriers/results, never PID
// identity input or production IPC endpoints.
func TestCommandHandoffAnchorFixture(t *testing.T) {
	dir, mode := os.Getenv("TP_HANDOFF_DIR"), os.Getenv("TP_HANDOFF_MODE")
	if dir == "" {
		t.Skip("anchor fixture only")
	}
	if mode == "die-before-read" {
		unix.Kill(os.Getpid(), unix.SIGKILL)
		select {}
	}
	channel := os.NewFile(3, "anchor-channel")
	defer channel.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	if mode == "die-after-receive" || mode == "wrong-ack" || mode == "missing-ack" || mode == "launcher-cancel" {
		b, fds, e := handoffReceive(ctx, 3, 4)
		if e != nil {
			t.Fatal(e)
		}
		defer closeHandoffFDs(fds)
		switch mode {
		case "die-after-receive":
			unix.Kill(os.Getpid(), unix.SIGKILL)
			select {}
		case "wrong-ack":
			b[1] ^= 1
			if e = handoffSend(ctx, 3, b, nil); e != nil {
				t.Fatal(e)
			}
		case "missing-ack", "launcher-cancel":
			<-ctx.Done()
		}
		return
	}
	plan := journalPlan()
	w, g := 4, 5
	if mode == "wrong-plan" {
		plan.ListenerPort++
	}
	if mode == "wrong-role" {
		w, g = g, w
	}
	a, e := NewScopedCommandAnchor(3, w, g, dir, plan)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	if mode == "die-before-ack" || mode == "die-after-ack" || mode == "die-after-confirm" {
		a.boundaryHook = func(point string) {
			if (mode == "die-before-ack" && point == "owned-before-ack") || (mode == "die-after-ack" && point == "ack-before-release") || (mode == "die-after-confirm" && point == "confirmed-before-release") {
				unix.Kill(os.Getpid(), unix.SIGKILL)
				select {}
			}
		}
	}
	r, e := a.Accept(ctx)
	if mode == "wrong-plan" || mode == "wrong-role" || mode == "reject-packet" || mode == "reject-confirm" {
		if e == nil || r != nil {
			if r != nil {
				r.Close()
			}
			t.Fatal("bad registration admitted")
		}
		t.Log("registration refused before release")
		return
	}
	if r != nil {
		defer r.Close()
	}
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Accept(ctx); e == nil {
		t.Fatal("anchor accepted replay")
	}
	// Source capabilities may all be closed: r owns its pidfd copies.
	a.Close()
	unix.Close(4)
	unix.Close(5)
	if mode == "recover" {
		probe, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
		blocked, e := r.Recover(probe)
		stop()
		if e == nil || blocked.AllExitsObserved || blocked.Recovery.Clean {
			t.Fatal("live process admitted recovery")
		}
		deadline, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		result, e := r.Recover(deadline)
		if e != nil {
			t.Fatal(e)
		}
		if !result.AllExitsObserved || !result.Recovery.Clean || result.Recovery.RecoveredSteps != 8 {
			t.Fatal(result)
		}
		b, _ := json.Marshal(result)
		if e = os.WriteFile(dir+"/recovered.json", b, 0600); e != nil {
			t.Fatal(e)
		}
		t.Log("anchor owns transferred witnesses after source FD closure; all exits observed; recovered=8 clean=true")
		return
	}
	for {
		if _, e = os.Stat(dir + "/release-anchor"); e == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("fixture barrier timeout")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestPrivilegedCommandHandoff(t *testing.T) {
	if !scopedPrivateChild(t, "TestPrivilegedCommandHandoff") {
		return
	}
	for _, mode := range []string{"admit", "die-before-read", "die-after-receive", "die-before-ack", "die-after-ack", "die-after-confirm", "wrong-ack", "missing-ack", "launcher-cancel", "missing-confirm", "bad-confirm", "extra-confirm-fd", "cancel-after-ack", "wrong-plan", "wrong-role", "bad-version", "short-packet", "extra-data", "missing-fd", "extra-fd", "ordinary-fd", "duplicate-fd", "foreign-fd", "wrong-binding", "recover"} {
		t.Run(mode, func(t *testing.T) {
			dir := privateJournalTestDir(t)
			d, e := OpenScopedIsolated(dir, journalPlan())
			if e != nil {
				t.Fatal(e)
			}
			defer d.Close()
			var processes []*exec.Cmd
			var roles []*os.File
			for i := 0; i < 2; i++ {
				c := exec.Command("/system/bin/sleep", "40")
				if e = c.Start(); e != nil {
					t.Fatal(e)
				}
				processes = append(processes, c)
				fd, e := unix.PidfdOpen(c.Process.Pid, 0)
				if e != nil {
					t.Fatal(e)
				}
				roles = append(roles, os.NewFile(uintptr(fd), "pinned-role"))
			}
			defer func() {
				for _, c := range processes {
					c.Process.Kill()
					c.Wait()
				}
				for _, f := range roles {
					f.Close()
				}
			}()
			var before []string
			if mode == "recover" {
				scopedForeignFixture(t)
				before, e = captureNamespace()
				if e != nil {
					t.Fatal(e)
				}
				listener, e := ListenTransparent(context.Background(), "tcp4", "0.0.0.0:18080")
				if e != nil {
					t.Fatal(e)
				}
				defer listener.Close()
				if e = d.Setup(); e != nil {
					t.Fatal(e)
				}
			}
			fds, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
			if e != nil {
				t.Fatal(e)
			}
			parent, child := os.NewFile(uintptr(fds[0]), "handoff-parent"), os.NewFile(uintptr(fds[1]), "handoff-anchor")
			defer parent.Close()
			anchorMode := mode
			malformed := mode == "bad-version" || mode == "short-packet" || mode == "extra-data" || mode == "missing-fd" || mode == "extra-fd" || mode == "ordinary-fd" || mode == "duplicate-fd" || mode == "foreign-fd" || mode == "wrong-binding"
			confirmationFailure := mode == "missing-confirm" || mode == "bad-confirm" || mode == "extra-confirm-fd" || mode == "cancel-after-ack"
			if malformed {
				anchorMode = "reject-packet"
			}
			if confirmationFailure {
				anchorMode = "reject-confirm"
			}
			anchor := exec.Command(os.Args[0], "-test.run=^TestCommandHandoffAnchorFixture$", "-test.v")
			anchor.Env = append(os.Environ(), "TP_HANDOFF_DIR="+dir, "TP_HANDOFF_MODE="+anchorMode)
			anchor.ExtraFiles = []*os.File{child, roles[0], roles[1]}
			anchor.Stdout, anchor.Stderr = os.Stdout, os.Stderr
			if e = anchor.Start(); e != nil {
				t.Fatal(e)
			}
			child.Close()
			waited := false
			defer func() {
				if !waited {
					anchor.Process.Kill()
					anchor.Wait()
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
			defer cancel()
			path := dir + "/executed"
			args := []string{"/system/bin/touch", path}
			if mode == "recover" {
				args = []string{"/system/bin/sleep", "0.5"}
			}
			p, e := StartPausedScopedCommand(ctx, args, d.lock)
			if e != nil {
				t.Fatal(e)
			}
			defer p.Abort()
			if malformed || confirmationFailure {
				binding, e := ScopedCommandBinding(dir, journalPlan())
				if e != nil {
					t.Fatal(e)
				}
				b := make([]byte, handoffPacketSize)
				b[0] = 1
				b[1] = 99
				copy(b[33:], binding[:])
				sendFDs := []int{int(roles[0].Fd()), int(roles[1].Fd()), p.pidfd, int(p.gate.Fd())}
				switch mode {
				case "bad-version":
					b[0] = 2
				case "short-packet":
					b = b[:10]
				case "extra-data":
					b = append(b, 0)
				case "missing-fd":
					sendFDs = sendFDs[:3]
				case "extra-fd":
					sendFDs = append(sendFDs, int(p.gate.Fd()))
				case "ordinary-fd":
					sendFDs[2] = int(d.lock.Fd())
				case "duplicate-fd":
					sendFDs[2] = sendFDs[0]
				case "foreign-fd":
					fd, e := unix.PidfdOpen(1, 0)
					if e != nil {
						t.Fatal(e)
					}
					defer unix.Close(fd)
					sendFDs[2] = fd
				case "wrong-binding":
					b[33] ^= 1
				}
				if e = handoffSend(ctx, int(parent.Fd()), b, sendFDs); e != nil {
					t.Fatal(e)
				}
				p.gate.Close()
				if confirmationFailure {
					ack, _, e := handoffReceive(ctx, int(parent.Fd()), 0)
					if e != nil || !bytes.Equal(ack, b) {
						t.Fatal("registration ACK missing", e)
					}
					switch mode {
					case "missing-confirm":
						parent.Close()
					case "cancel-after-ack":
						cancel()
						parent.Close()
					case "bad-confirm":
						b[1] ^= 1
						if e = handoffSend(ctx, int(parent.Fd()), b, nil); e != nil {
							t.Fatal(e)
						}
					case "extra-confirm-fd":
						if e = handoffSend(ctx, int(parent.Fd()), b, []int{int(roles[0].Fd())}); e != nil {
							t.Fatal(e)
						}
					}
				}
				e = anchor.Wait()
				waited = true
				if e != nil {
					t.Fatal(e)
				}
				p.Abort()
			} else {
				hctx, stop := context.WithTimeout(ctx, 4*time.Second)
				if mode == "missing-ack" {
					stop()
					hctx, stop = context.WithTimeout(ctx, 200*time.Millisecond)
				}
				if mode == "launcher-cancel" {
					time.AfterFunc(150*time.Millisecond, cancel)
				}
				e = p.HandoffScoped(hctx, int(parent.Fd()), int(roles[0].Fd()), int(roles[1].Fd()), dir, journalPlan())
				stop()
				if mode == "admit" || mode == "recover" {
					if e != nil {
						t.Fatal(e)
					}
					if e = p.Wait(); e != nil {
						t.Fatal(e)
					}
					if mode == "admit" {
						if _, e = os.Stat(path); e != nil {
							t.Fatal("admitted command missing", e)
						}
						if e = p.HandoffScoped(ctx, int(parent.Fd()), int(roles[0].Fd()), int(roles[1].Fd()), dir, journalPlan()); e == nil {
							t.Fatal("sender replay admitted")
						}
						os.WriteFile(dir+"/release-anchor", []byte("done"), 0600)
					} else {
						for _, role := range roles {
							if e = unix.PidfdSendSignal(int(role.Fd()), unix.SIGKILL, nil, 0); e != nil {
								t.Fatal(e)
							}
						}
						for _, role := range roles {
							role.Close()
						}
						d.Close()
					}
					e = anchor.Wait()
					waited = true
					if e != nil {
						t.Fatal(e)
					}
					if mode == "recover" {
						assertForeignPreserved(t, journalPlan(), before)
					}
					return
				}
				if (mode == "die-after-ack" || mode == "die-after-confirm") && e == nil {
					e = p.Wait()
				}
				if e == nil {
					t.Fatal("failed anchor admitted execution")
				}
				if mode == "missing-ack" || mode == "launcher-cancel" {
					anchor.Process.Kill()
				}
				e = anchor.Wait()
				waited = true
				if mode == "wrong-plan" || mode == "wrong-role" || mode == "wrong-ack" {
					if e != nil {
						t.Fatal(e)
					}
				}
			}
			if _, e = os.Stat(path); !os.IsNotExist(e) {
				t.Fatal("refused command executed")
			}
			t.Log("no execution on refused/lost handoff")
		})
	}
}
