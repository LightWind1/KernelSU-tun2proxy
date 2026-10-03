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

func TestWorkerRegistry(t *testing.T) {
	r := WorkerCommandRegistry{Version: 1}
	if r.cleanGate() {
		t.Fatal("unsealed registry")
	}
	if e := r.reserve(1); e != nil {
		t.Fatal(e)
	}
	r.finish(true)
	if e := r.reserve(2); e != nil {
		t.Fatal(e)
	}
	r.finish(true)
	r.Sealed = true
	if !r.cleanGate() || r.Completed != 2 {
		t.Fatal(r)
	}
	for _, mode := range []string{"overlap", "sequence", "uncertain", "late", "zero-finish"} {
		r := WorkerCommandRegistry{Version: 1}
		switch mode {
		case "overlap":
			r.reserve(1)
			r.reserve(2)
		case "sequence":
			r.reserve(2)
		case "uncertain":
			r.reserve(1)
			r.finish(false)
		case "late":
			r.Sealed = true
			r.reserve(1)
		case "zero-finish":
			r.finish(true)
		}
		r.Sealed = true
		if r.cleanGate() || !r.Blocked {
			t.Fatal(mode, r)
		}
	}
}

func TestBrokerCommandBoundary(t *testing.T) {
	p := journalPlan()
	steps, _ := p.Steps()
	for _, s := range steps {
		if !brokerAllowed(p, s.Add) || !brokerAllowed(p, s.Remove) {
			t.Fatal("planned command refused")
		}
	}
	for _, a := range [][]string{{"sh", "-c", "true"}, {"iptables", "-F"}, {"ip", "rule", "flush"}, {"ip", "route", "flush", "table", "main"}, {"/system/bin/ip", "rule", "show"}, {"ip", "rule", "show", ";reboot"}} {
		if brokerAllowed(p, a) {
			t.Fatal("unplanned command allowed", a)
		}
	}
	var req brokerRequest
	for _, text := range []string{`{"version":1,"password":"secret"}`, `{} {}`, "invalid"} {
		if e := brokerDecode([]byte(text), &req); e == nil || strings.Contains(e.Error(), "secret") {
			t.Fatal("invalid/unredacted protocol")
		}
	}
}

func TestBrokerHostRefused(t *testing.T) {
	if _, e := privateWitnessNamespace(); e == nil {
		t.Skip("host-only")
	}
	called := false
	_, e := SuperviseBrokeredScopedIsolated(context.Background(), "/nonexistent", journalPlan(), supervisorOptions(), func(int) (*exec.Cmd, error) { called = true; return nil, nil })
	if e == nil || called {
		t.Fatal("host admission")
	}
}

func TestBrokerWorkerFixture(t *testing.T) {
	dir := os.Getenv("TP_BROKER_DIR")
	if dir == "" {
		t.Skip("native broker worker only")
	}
	mode := os.Getenv("TP_BROKER_MODE")
	unix.CloseOnExec(3)
	unix.CloseOnExec(4)
	ready := os.NewFile(3, "broker-ready")
	defer ready.Close()
	if mode == "startup-failed" {
		os.Exit(1)
	}
	d, e := OpenBrokeredScopedIsolated(context.Background(), 4, dir, journalPlan())
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if mode == "bad-protocol" || mode == "wrong-lease" || mode == "extra-fd" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		binding, e := ScopedCommandBinding(dir, journalPlan())
		if e != nil {
			t.Fatal(e)
		}
		req := brokerRequest{Version: 1, ID: 1, Binding: binding, Args: []string{"ip", "rule", "show"}}
		fds := []int{int(d.lock.Fd())}
		if mode == "bad-protocol" {
			req.ID = 2
		}
		if mode == "extra-fd" {
			fds = append(fds, int(d.lock.Fd()))
		}
		if mode == "wrong-lease" {
			f, e := os.OpenFile(dir+"/not-the-journal-lock", os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			fds = []int{int(f.Fd())}
		}
		if e := brokerSend(ctx, 4, req, fds); e != nil {
			t.Fatal(e)
		}
		time.Sleep(500 * time.Millisecond)
		return
	}
	listener, e := ListenTransparent(context.Background(), "tcp4", "0.0.0.0:18080")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	if mode == "commit-gap" {
		d.boundaryHook = func(stage, operation string, step int) {
			if stage == "applied" && operation == "add" && step == 7 {
				unix.Kill(os.Getpid(), unix.SIGKILL)
			}
		}
	}
	if mode == "concurrent" {
		errors := make(chan error, 2)
		go func() { errors <- d.Setup() }()
		go func() { errors <- d.Setup() }()
		for i := 0; i < 2; i++ {
			if e := <-errors; e != nil {
				t.Fatal(e)
			}
		}
	} else if e = d.Setup(); e != nil {
		t.Fatal(e)
	}
	if _, e = ready.Write([]byte("{\"version\":1,\"ready\":true}\n")); e != nil {
		t.Fatal(e)
	}
	ready.Close()
	if mode == "steady-crash" {
		unix.Kill(os.Getpid(), unix.SIGKILL)
	}
	if e = d.Recover(); e != nil {
		t.Fatal(e)
	}
}

func brokerFixtureFactory(dir string, modes []string, calls *int) IsolatedWorkerFactory {
	return func(attempt int) (*exec.Cmd, error) {
		*calls++
		mode := modes[0]
		if attempt < len(modes) {
			mode = modes[attempt]
		}
		c := exec.Command(os.Args[0], "-test.run=^TestBrokerWorkerFixture$")
		c.Env = append(os.Environ(), "TP_BROKER_DIR="+dir, "TP_BROKER_MODE="+mode)
		return c, nil
	}
}

func TestPrivilegedWorkerBroker(t *testing.T) {
	if !scopedPrivateChild(t, "TestPrivilegedWorkerBroker") {
		return
	}
	update := scopedForeignFixture(t)
	update(1)
	base, e := captureNamespace()
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"normal", "concurrent", "commit-gap", "steady-crash", "pending-command", "guard-and-worker", "cancel-pending", "command-failure", "bad-protocol", "wrong-lease", "extra-fd", "startup-failed", "launch-failure", "restart", "stale-marker", "lost-anchor"} {
		t.Run(mode, func(t *testing.T) {
			dir := privateJournalTestDir(t)
			o := supervisorOptions()
			o.ReadyTimeout = 30 * time.Second
			o.RecoveryTimeout = 120 * time.Second
			o.MaxRestarts = 0
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
			defer cancel()
			calls := 0
			modes := []string{mode}
			if mode == "restart" {
				modes = []string{"commit-gap", "normal"}
				o.MaxRestarts = 1
			}
			factory := brokerFixtureFactory(dir, modes, &calls)
			if mode == "launch-failure" {
				factory = func(int) (*exec.Cmd, error) { calls++; return exec.Command("/nonexistent-broker-worker"), nil }
			}
			if mode == "stale-marker" {
				if e := os.WriteFile(dir+"/"+brokerMarker, []byte("unresolved"), 0600); e != nil {
					t.Fatal(e)
				}
				before, _ := captureNamespace()
				r, e := SuperviseBrokeredScopedIsolated(ctx, dir, journalPlan(), o, factory)
				after, _ := captureNamespace()
				if e == nil || calls != 0 || r.Clean || !reflect.DeepEqual(before, after) {
					t.Fatal("stale adoption", r, e)
				}
				return
			}
			var bptr *workerBroker
			wrapped := false
			hook := func(b *workerBroker) {
				bptr = b
				if mode == "command-failure" {
					steps, _ := journalPlan().Steps()
					b.argsHook = func(args []string) []string {
						if reflect.DeepEqual(args, steps[0].Add) {
							return []string{"/nonexistent-broker-command"}
						}
						return args
					}
					return
				}
				if mode != "pending-command" && mode != "guard-and-worker" && mode != "cancel-pending" && mode != "lost-anchor" {
					return
				}
				steps, _ := journalPlan().Steps()
				b.argsHook = func(args []string) []string {
					if !reflect.DeepEqual(args, steps[7].Add) {
						return args
					}
					wrapped = true
					data, _ := json.Marshal(args)
					return []string{os.Args[0], "-test.run=^TestRegisteredDelayedCommand$", "--", string(data)}
				}
				b.commandHook = func(s *RegisteredCommandSession, args []string) {
					if !reflect.DeepEqual(args, steps[7].Add) {
						return
					}
					waitRegisteredBarrier(t, dir+"/command-ready")
					if mode == "cancel-pending" {
						cancel()
					} else if mode == "lost-anchor" {
						unix.PidfdSendSignal(s.anchorFD, unix.SIGKILL, nil, 0)
					} else {
						unix.PidfdSendSignal(int(b.worker.Fd()), unix.SIGKILL, nil, 0)
						if mode == "guard-and-worker" {
							unix.PidfdSendSignal(s.guardFD, unix.SIGKILL, nil, 0)
						}
					}
					before, _ := captureNamespace()
					time.Sleep(150 * time.Millisecond)
					after, _ := captureNamespace()
					if !reflect.DeepEqual(before, after) {
						t.Error("premature pending cleanup")
					}
					if e := os.WriteFile(dir+"/release-command", []byte("release"), 0600); e != nil {
						t.Error(e)
					}
				}
			}
			// Guard subprocess inherits only this parent's controlled fixture env.
			if mode == "pending-command" || mode == "guard-and-worker" || mode == "cancel-pending" || mode == "lost-anchor" {
				t.Setenv("TP_REGISTERED_DIR", dir)
				t.Setenv("TP_REGISTERED_DISCARD", "1")
			}
			r, e := superviseBrokeredScoped(ctx, dir, journalPlan(), o, factory, hook)
			if mode == "bad-protocol" || mode == "wrong-lease" || mode == "extra-fd" {
				if e == nil || r.Clean || calls != 1 || !r.Registries[0].Blocked {
					t.Fatal("malformed membership accepted", r, e)
				}
				assertForeignPreserved(t, journalPlan(), base)
				t.Logf("%s: blocked, no command execution, no cleanup/restart", mode)
				return
			}
			if mode == "lost-anchor" {
				if e == nil || r.Clean || calls != 1 || !wrapped || !r.Registries[0].Blocked {
					t.Fatal("lost anchor authorized recovery", r, e)
				}
				if _, e := os.Stat(dir + "/" + brokerMarker); e != nil {
					t.Fatal("lost blocking marker", e)
				}
				// Same attempt cannot be re-adopted even though flock is now free.
				_, e = SuperviseBrokeredScopedIsolated(ctx, dir, journalPlan(), o, factory)
				if e == nil || calls != 1 {
					t.Fatal("uncertain restart")
				}
				// No cleanup authority from a lost witness. Only private namespace
				// destruction can remove this fixture; run this case last elsewhere.
				t.Logf("lost anchor blocked: requested=%d completed=%d marker retained; no retry", bptr.registry.Requested, bptr.registry.Completed)
				return
			}
			if !r.Clean || len(r.Registries) == 0 || !r.Registries[0].cleanGate() {
				t.Fatal("registry not drained", r, e)
			}
			if (mode == "normal" || mode == "concurrent" || mode == "restart") && (e != nil || r.State != "completed") {
				t.Fatal(r, e)
			}
			if mode == "cancel-pending" && (e != nil || r.State != "stopped" || r.Restarts != 0) {
				t.Fatal("cancel not drained", r, e)
			}
			if mode == "restart" && (calls != 2 || r.Restarts != 1) {
				t.Fatal("no safe restart", r)
			}
			if _, e := os.Stat(dir + "/" + brokerMarker); !os.IsNotExist(e) {
				t.Fatal("clean marker retained", e)
			}
			assertForeignPreserved(t, journalPlan(), base)
			t.Logf("%s: state=%s clean=%v attempts=%d registered=%d verified=%d", mode, r.State, r.Clean, calls, r.Registries[0].Requested, r.Registries[0].Completed)
		})
		// Lost-anchor deliberately leaves owned state. Stop this namespace here;
		// execute other modes before it so we never manually override the gate.
		if mode == "lost-anchor" {
			break
		}
	}
}

func TestPrivilegedBrokerLaunchWindow(t *testing.T) {
	if !scopedPrivateChild(t, "TestPrivilegedBrokerLaunchWindow") {
		return
	}
	scopedForeignFixture(t)
	dir := privateJournalTestDir(t)
	o := supervisorOptions()
	o.ReadyTimeout = 30 * time.Second
	o.MaxRestarts = 2
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	calls := 0
	steps, _ := journalPlan().Steps()
	r, e := superviseBrokeredScoped(ctx, dir, journalPlan(), o, brokerFixtureFactory(dir, []string{"normal"}, &calls), func(b *workerBroker) {
		b.argsHook = func(args []string) []string {
			if reflect.DeepEqual(args, steps[7].Add) {
				unix.PidfdSendSignal(int(b.worker.Fd()), unix.SIGKILL, nil, 0)
				for {
					dead, e := witnessPoll([]int{int(b.worker.Fd())}, 20)
					if e != nil || dead {
						break
					}
				}
			}
			return args
		}
	})
	if e == nil || r.Clean || calls != 1 || len(r.Registries) != 1 || !r.Registries[0].Blocked {
		t.Fatal("prelaunch loss admitted", r, e)
	}
	if _, e := os.Stat(dir + "/" + brokerMarker); e != nil {
		t.Fatal("missing persistent block", e)
	}
	before, _ := captureNamespace()
	_, e = SuperviseBrokeredScopedIsolated(ctx, dir, journalPlan(), o, brokerFixtureFactory(dir, []string{"normal"}, &calls))
	after, _ := captureNamespace()
	if e == nil || calls != 1 || !reflect.DeepEqual(before, after) {
		t.Fatal("unproved launch retried/adopted")
	}
	t.Logf("pre-exec worker loss: blocked requested=%d verified=%d; marker retained; no cleanup/restart", r.Registries[0].Requested, r.Registries[0].Completed)
}

func TestBrokerLauncherFixture(t *testing.T) {
	dir := os.Getenv("TP_BROKER_LAUNCHER_DIR")
	if dir == "" {
		t.Skip("launcher-loss native fixture only")
	}
	unix.CloseOnExec(3)
	o := supervisorOptions()
	o.ReadyTimeout = 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	calls := 0
	steps, _ := journalPlan().Steps()
	_, e := superviseBrokeredScoped(ctx, dir, journalPlan(), o, brokerFixtureFactory(dir, []string{"normal"}, &calls), func(b *workerBroker) {
		b.argsHook = func(args []string) []string {
			if !reflect.DeepEqual(args, steps[7].Add) {
				return args
			}
			data, _ := json.Marshal(args)
			return []string{os.Args[0], "-test.run=^TestRegisteredDelayedCommand$", "--", string(data)}
		}
		b.commandHook = func(s *RegisteredCommandSession, args []string) {
			if !reflect.DeepEqual(args, steps[7].Add) {
				return
			}
			waitRegisteredBarrier(t, dir+"/command-ready")
			launcher, e := unix.PidfdOpen(os.Getpid(), 0)
			if e != nil {
				t.Error(e)
				return
			}
			defer unix.Close(launcher)
			packet := make([]byte, handoffPacketSize)
			packet[0] = 1
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if e := handoffSend(ctx, 3, packet, []int{launcher, int(b.worker.Fd()), s.guardFD, s.anchorFD}); e != nil {
				t.Error(e)
			}
		}
	})
	t.Fatalf("fixture launcher must be killed by pinned capability: %v", e)
}

func TestPrivilegedBrokerLauncherLoss(t *testing.T) {
	if !scopedPrivateChild(t, "TestPrivilegedBrokerLauncherLoss") {
		return
	}
	scopedForeignFixture(t)
	base, e := captureNamespace()
	if e != nil {
		t.Fatal(e)
	}
	dir := privateJournalTestDir(t)
	fds, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	parent, child := os.NewFile(uintptr(fds[0]), "fixture-parent"), os.NewFile(uintptr(fds[1]), "fixture-launcher")
	defer parent.Close()
	defer child.Close()
	c := exec.Command(os.Args[0], "-test.run=^TestBrokerLauncherFixture$")
	c.ExtraFiles = []*os.File{child}
	c.Env = append(os.Environ(), "TP_BROKER_LAUNCHER_DIR="+dir, "TP_REGISTERED_DIR="+dir, "TP_REGISTERED_DISCARD=1")
	if e := c.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		if c.ProcessState == nil {
			c.Process.Kill()
			c.Wait()
		}
	}()
	child.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	_, roles, e := handoffReceive(ctx, int(parent.Fd()), 4)
	if e != nil {
		t.Fatal(e)
	}
	defer closeHandoffFDs(roles)
	for _, fd := range roles {
		if _, e := liveHandoffPID(fd); e != nil {
			t.Fatal(e)
		}
	}
	if e := unix.PidfdSendSignal(roles[0], unix.SIGKILL, nil, 0); e != nil {
		t.Fatal(e)
	}
	c.Wait()
	for deadline := time.Now().Add(3 * time.Second); ; {
		dead, e := witnessPoll([]int{roles[1]}, 20)
		if e != nil {
			t.Fatal(e)
		}
		if dead {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker survived launcher SIGKILL")
		}
	}
	before, _ := captureNamespace()
	time.Sleep(150 * time.Millisecond)
	after, _ := captureNamespace()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("launcher loss cleaned before direct command exit")
	}
	if e := os.WriteFile(dir+"/release-command", []byte("release"), 0600); e != nil {
		t.Fatal(e)
	}
	for deadline := time.Now().Add(50 * time.Second); ; {
		dead, e := witnessPoll(roles[2:], 20)
		if e != nil {
			t.Fatal(e)
		}
		if dead {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("guard/anchor drain timeout")
		}
	}
	assertForeignPreserved(t, journalPlan(), base)
	if _, e := os.Stat(dir + "/" + brokerMarker); e != nil {
		t.Fatal("lost launcher marker removed without proof owner", e)
	}
	calls := 0
	_, e = SuperviseBrokeredScopedIsolated(ctx, dir, journalPlan(), supervisorOptions(), brokerFixtureFactory(dir, []string{"normal"}, &calls))
	if e == nil || calls != 0 {
		t.Fatal("replacement silently adopted stale cohort")
	}
	t.Log("launcher SIGKILL: pinned worker exited; anchor waited for direct command; eight owned steps recovered; foreign state preserved; replacement blocked by durable marker")
}
