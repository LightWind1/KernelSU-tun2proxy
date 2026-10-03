//go:build linux

package tproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const registeredGuardArgument = "__tproxy-registered-guard-v1"
const registeredAnchorArgument = "__tproxy-registered-anchor-v1"

type registeredCommandConfig struct {
	Version   int                 `json:"version"`
	Directory string              `json:"directory"`
	Plan      IPv4DestinationPlan `json:"plan"`
}

type RegisteredCommandReport struct {
	Version   int                  `json:"version"`
	State     string               `json:"state"`
	Quiescent bool                 `json:"quiescent"`
	Recovery  CommandWitnessResult `json:"recovery"`
}

func readRegisteredConfig() (registeredCommandConfig, error) {
	var cfg registeredCommandConfig
	f := os.NewFile(6, "trusted-config-pipe")
	defer f.Close()
	i, e := f.Stat()
	if e != nil || i.Mode()&os.ModeNamedPipe == 0 {
		return cfg, fmt.Errorf("inherited configuration pipe required")
	}
	d := json.NewDecoder(io.LimitReader(f, 4097))
	d.DisallowUnknownFields()
	if e = d.Decode(&cfg); e != nil || cfg.Version != 1 {
		return cfg, fmt.Errorf("invalid inherited configuration")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return cfg, fmt.Errorf("trailing inherited configuration")
	}
	_, e = ScopedCommandBinding(cfg.Directory, cfg.Plan)
	return cfg, e
}

func registeredGuardEntry(args []string) int {
	if len(args) < 4 || args[2] != "--" {
		return 1
	}
	for fd := 4; fd <= 6; fd++ {
		unix.CloseOnExec(fd)
	}
	cfg, e := readRegisteredConfig()
	if e != nil {
		return 1
	}
	lease := os.NewFile(3, "registered-journal-lease")
	defer lease.Close()
	if privateFile(lease) != nil || unix.Flock(3, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return 1
	}
	stop, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	ctx, cancel := context.WithTimeout(stop, 8*time.Second)
	defer cancel()
	guardFD, e := unix.PidfdOpen(os.Getpid(), 0)
	if e != nil {
		return 1
	}
	defer unix.Close(guardFD)
	p, e := StartPausedScopedCommand(ctx, args[3:], lease)
	if e != nil {
		return 1
	}
	defer p.Abort()
	if e = p.HandoffScoped(ctx, 4, 5, guardFD, cfg.Directory, cfg.Plan); e != nil {
		return 1
	}
	e = p.Wait()
	if e == nil {
		return 0
	}
	if p.c.ProcessState != nil {
		if s, ok := p.c.ProcessState.Sys().(syscall.WaitStatus); ok && s.Signaled() {
			return 128 + int(s.Signal())
		}
		return p.c.ProcessState.ExitCode()
	}
	return 1
}

func registeredAnchorEntry(args []string) int {
	if len(args) != 2 {
		return 1
	}
	for fd := 3; fd <= 7; fd++ {
		unix.CloseOnExec(fd)
	}
	report := os.NewFile(7, "anchor-report")
	defer report.Close()
	i, statErr := report.Stat()
	if statErr != nil || i.Mode()&os.ModeNamedPipe == 0 {
		return 1
	}
	emit := func(r RegisteredCommandReport) error { return json.NewEncoder(report).Encode(r) }
	cfg, e := readRegisteredConfig()
	if e != nil {
		return 1
	}
	a, e := NewScopedCommandAnchor(3, 4, 5, cfg.Directory, cfg.Plan)
	if e != nil {
		return 1
	}
	defer a.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	r, e := a.Accept(ctx)
	cancel()
	if r != nil {
		defer r.Close()
	}
	if e != nil {
		emit(RegisteredCommandReport{Version: 1, State: "blocked"})
		return 1
	}
	a.Close() // witness owns its copies; no journal lease is held by the anchor
	for fd := 3; fd <= 5; fd++ {
		unix.Close(fd)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		workerDead, e := witnessPoll([]int{r.w.fds[0]}, 0)
		if e != nil {
			return 1
		}
		if workerDead {
			result, e := r.Recover(ctx)
			state := "blocked"
			if e == nil && result.Recovery.Clean {
				state = "recovered"
			}
			emit(RegisteredCommandReport{Version: 1, State: state, Recovery: result})
			if e != nil {
				return 1
			}
			return 0
		}
		quiet, e := witnessPoll(r.w.fds[1:], 20)
		if e != nil {
			return 1
		}
		if quiet {
			if e = emit(RegisteredCommandReport{Version: 1, State: "quiescent", Quiescent: true}); e == nil {
				return 0
			}
			// Pipe loss is not itself authorization to clean a still-live worker.
			dead, _ := witnessPoll([]int{r.w.fds[0]}, 0)
			if dead {
				continue
			}
			return 1
		}
		// Avoid a busy loop if one of guard/command has exited but not the other.
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Millisecond):
		}
	}
	emit(RegisteredCommandReport{Version: 1, State: "blocked"})
	return 1
}

type registeredOutput struct {
	b        bytes.Buffer
	overflow bool
}

func (w *registeredOutput) Write(b []byte) (int, error) {
	n := len(b)
	available := 65536 - w.b.Len()
	if len(b) > available {
		w.overflow = true
	}
	if available > len(b) {
		available = len(b)
	}
	if available > 0 {
		w.b.Write(b[:available])
	}
	return n, nil
}

// RegisteredCommandSession supervises ONE actual guard/command/anchor set.
// No retries or worker-wide cleanup authority. The anchor survives worker or
// guard loss and requires all pinned exits before journal recovery.
type RegisteredCommandSession struct {
	mu                sync.Mutex
	guard, anchor     *exec.Cmd
	guardFD, anchorFD int
	report            *os.File
	out, stderr       registeredOutput
	args              []string
	waited            bool
}

type RegisteredCommandResult struct {
	Version            int    `json:"version"`
	Command            Result `json:"command"`
	GuardExitObserved  bool   `json:"guard_exit_observed"`
	AnchorExitObserved bool   `json:"anchor_exit_observed"`
	Quiescent          bool   `json:"quiescent"`
	OutputTruncated    bool   `json:"output_truncated"`
}

func registeredConfigPipe(cfg registeredCommandConfig) (*os.File, error) {
	b, e := json.Marshal(cfg)
	if e != nil || len(b) > 4096 {
		return nil, fmt.Errorf("configuration too large")
	}
	r, w, e := os.Pipe()
	if e != nil {
		return nil, e
	}
	_, e = w.Write(b)
	w.Close()
	if e != nil {
		r.Close()
		return nil, e
	}
	return r, nil
}

func StartRegisteredScopedCommand(ctx context.Context, args []string, lease *os.File, dir string, plan IPv4DestinationPlan) (*RegisteredCommandSession, error) {
	if e := handoffDeadline(ctx); e != nil {
		return nil, e
	}
	if _, e := ScopedCommandBinding(dir, plan); e != nil {
		return nil, e
	}
	if len(args) == 0 || lease == nil || privateFile(lease) != nil {
		return nil, fmt.Errorf("private lease and command required")
	}
	exe, e := os.Executable()
	if e != nil {
		return nil, e
	}
	workerFD, e := unix.PidfdOpen(os.Getpid(), 0)
	if e != nil {
		return nil, e
	}
	worker := os.NewFile(uintptr(workerFD), "pinned-worker")
	defer worker.Close()
	channels, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	gch, ach := os.NewFile(uintptr(channels[0]), "guard-channel"), os.NewFile(uintptr(channels[1]), "anchor-channel")
	defer gch.Close()
	defer ach.Close()
	cfg := registeredCommandConfig{1, dir, plan}
	gcfg, e := registeredConfigPipe(cfg)
	if e != nil {
		return nil, e
	}
	defer gcfg.Close()
	acfg, e := registeredConfigPipe(cfg)
	if e != nil {
		return nil, e
	}
	defer acfg.Close()
	read, write, e := os.Pipe()
	if e != nil {
		return nil, e
	}
	defer write.Close()
	s := &RegisteredCommandSession{args: append([]string(nil), args...), report: read, guardFD: -1, anchorFD: -1}
	s.guard = exec.Command(exe, append([]string{registeredGuardArgument, "--"}, args...)...)
	s.guard.ExtraFiles = []*os.File{lease, gch, worker, gcfg}
	s.guard.Stdout, s.guard.Stderr = &s.out, &s.stderr
	if e = s.guard.Start(); e != nil {
		read.Close()
		return nil, e
	}
	// Pin before any Wait: even an exited child is unreaped and cannot be reused.
	s.guardFD, e = unix.PidfdOpen(s.guard.Process.Pid, 0)
	if e != nil {
		s.guard.Process.Kill()
		s.guard.Wait()
		read.Close()
		return nil, e
	}
	guardCopyFD, e := unix.FcntlInt(uintptr(s.guardFD), unix.F_DUPFD_CLOEXEC, 0)
	if e != nil {
		unix.PidfdSendSignal(s.guardFD, unix.SIGTERM, nil, 0)
		s.guard.Wait()
		unix.Close(s.guardFD)
		read.Close()
		return nil, e
	}
	guardCopy := os.NewFile(uintptr(guardCopyFD), "pinned-guard")
	defer guardCopy.Close()
	s.anchor = exec.Command(exe, registeredAnchorArgument)
	s.anchor.ExtraFiles = []*os.File{ach, worker, guardCopy, acfg, write}
	if e = s.anchor.Start(); e != nil {
		ach.Close()
		gch.Close()
		unix.PidfdSendSignal(s.guardFD, unix.SIGTERM, nil, 0)
		s.guard.Wait()
		unix.Close(s.guardFD)
		read.Close()
		return nil, e
	}
	s.anchorFD, e = unix.PidfdOpen(s.anchor.Process.Pid, 0)
	if e != nil {
		// Command may already be admitted: never destroy the sole anchor witness.
		unix.PidfdSendSignal(s.guardFD, unix.SIGTERM, nil, 0)
		s.guard.Wait()
		s.anchor.Wait()
		unix.Close(s.guardFD)
		read.Close()
		return nil, e
	}
	return s, nil
}

// Wait serializes ownership/reaping. Cancel ctx to request guard termination;
// an independently bounded observer still requires both actual process exits
// and the anchor's quiescence report. It never kills the sole surviving anchor.
func (s *RegisteredCommandSession) Wait(ctx context.Context) (RegisteredCommandResult, error) {
	r := RegisteredCommandResult{Version: 1, Command: Result{ExitCode: -1}}
	if s == nil || ctx == nil {
		return r, fmt.Errorf("registered session required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.waited || s.guard == nil || s.anchor == nil || s.report == nil {
		return r, fmt.Errorf("registered session uninitialized or already waited")
	}
	s.waited = true
	defer s.report.Close()
	defer unix.Close(s.guardFD)
	defer unix.Close(s.anchorFD)
	gdone, adone := make(chan struct{}), make(chan struct{})
	go func() { s.guard.Wait(); close(gdone) }()
	go func() { s.anchor.Wait(); close(adone) }()
	timeout := time.NewTimer(50 * time.Second)
	defer timeout.Stop()
	stop := ctx.Done()
	for gdone != nil || adone != nil {
		select {
		case <-gdone:
			r.GuardExitObserved = s.guard.ProcessState != nil
			gdone = nil
		case <-adone:
			r.AnchorExitObserved = s.anchor.ProcessState != nil
			adone = nil
		case <-stop:
			unix.PidfdSendSignal(s.guardFD, unix.SIGTERM, nil, 0)
			stop = nil
		case <-timeout.C:
			return r, fmt.Errorf("registered exits unverified; no cleanup/retry")
		}
	}
	r.Command = Result{Command: s.args, ExitCode: s.guard.ProcessState.ExitCode(), Output: strings.TrimSpace(s.out.b.String()), Error: strings.TrimSpace(s.stderr.b.String())}
	d := json.NewDecoder(io.LimitReader(s.report, 1025))
	d.DisallowUnknownFields()
	var record RegisteredCommandReport
	var extra any
	if e := d.Decode(&record); e != nil || record.Version != 1 || d.Decode(&extra) != io.EOF || record.State != "quiescent" || !record.Quiescent || s.anchor.ProcessState.ExitCode() != 0 {
		return r, fmt.Errorf("registered quiescence unverified; no cleanup/retry")
	}
	r.Quiescent = true
	if s.out.overflow || s.stderr.overflow {
		r.OutputTruncated = true
		r.Command.ExitCode = -1
		r.Command.Error = "registered command output exceeds capture limit"
		return r, fmt.Errorf("truncated output cannot authorize an observation")
	}
	if ctx.Err() != nil {
		return r, ctx.Err()
	}
	if r.Command.ExitCode != 0 {
		return r, fmt.Errorf("registered command failed")
	}
	return r, nil
}

func SuperviseRegisteredScopedCommand(ctx context.Context, args []string, lease *os.File, dir string, plan IPv4DestinationPlan) (RegisteredCommandResult, error) {
	s, e := StartRegisteredScopedCommand(ctx, args, lease, dir, plan)
	if e != nil {
		return RegisteredCommandResult{Version: 1, Command: Result{ExitCode: -1}}, e
	}
	return s.Wait(ctx)
}
