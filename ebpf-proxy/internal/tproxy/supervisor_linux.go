//go:build linux

package tproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"golang.org/x/sys/unix"
)

// The trusted consumer builds argv/configuration; no shell, module path or
// upstream product is interpreted here. Command MUST be unstarted, without
// ExtraFiles. FD 3 is the readiness pipe; the worker owns graceful policy
// disable/drain before exit. Child stdout/stderr are not readiness channels.
type IsolatedWorkerFactory func(attempt int) (*exec.Cmd, error)

func readyRecord(reader io.Reader) error {
	line, e := bufio.NewReader(io.LimitReader(reader, 257)).ReadBytes('\n')
	if e != nil || len(line) > 256 {
		return fmt.Errorf("invalid or incomplete readiness record")
	}
	var message struct {
		Version int  `json:"version"`
		Ready   bool `json:"ready"`
	}
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if e = d.Decode(&message); e != nil || message.Version != 1 || !message.Ready {
		return fmt.Errorf("invalid readiness record")
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return fmt.Errorf("trailing readiness data")
	}
	return nil
}

func scopedCleanup(o SupervisorOptions, dir string, p IPv4DestinationPlan) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), o.RecoveryTimeout)
	defer cancel()
	d, e := OpenScopedIsolated(dir, p)
	if e != nil {
		return 0, e
	}
	defer d.Close()
	d.run = func(args []string) Result { return queryLeasedContext(ctx, args, d.lock) }
	if e = d.ResolvePending(); e != nil {
		return 0, e
	}
	n := d.r.Owned
	if e = d.Recover(); e != nil {
		return n, e
	}
	if ctx.Err() != nil {
		return n, ctx.Err()
	}
	return n, nil
}

// SuperviseScopedIsolated bounds launch count, readiness, stop escalation and
// command recovery deadlines. It always refuses the host namespace. Recovery
// errors stop the run; never restart into uncertain ownership. File I/O/fsync
// is not a hard-real-time guarantee; loss of this supervisor is not solved by
// this API. A separate surviving anchor/deployment is still required.
func SuperviseScopedIsolated(ctx context.Context, dir string, p IPv4DestinationPlan, o SupervisorOptions, factory IsolatedWorkerFactory) (SupervisorResult, error) {
	r := SupervisorResult{Version: 1, State: "blocked", Attempts: []SupervisedAttempt{}}
	if e := o.Validate(); e != nil {
		return r, e
	}
	if _, e := p.Steps(); e != nil {
		return r, e
	}
	self, e := os.Readlink("/proc/self/ns/net")
	if e != nil {
		return r, e
	}
	host, e := os.Readlink("/proc/1/ns/net")
	if e != nil || host == self {
		return r, fmt.Errorf("supervisor requires private network namespace")
	}
	if factory == nil {
		return r, fmt.Errorf("worker factory required")
	}
	// Probe before launching a child; unsupported signaling never leaves an
	// abandoned worker. Signal 0 does not terminate the supervisor.
	fd, e := unix.PidfdOpen(os.Getpid(), 0)
	if e != nil {
		return r, e
	}
	e = unix.PidfdSendSignal(fd, 0, nil, 0)
	unix.Close(fd)
	if e != nil {
		return r, e
	}
	if ctx.Err() != nil {
		r.State = "stopped"
		return r, ctx.Err()
	}
	// A session lock spans recovery, backoff and worker lifetime; the worker's
	// journal lock alone cannot exclude another launcher between child exits.
	d, e := OpenScopedIsolated(dir, p)
	if e != nil {
		return r, e
	}
	session, e := d.root.OpenFile("supervisor.lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if e != nil {
		d.Close()
		return r, e
	}
	if e = privateFile(session); e == nil {
		e = unix.Flock(int(session.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	}
	d.Close()
	if e != nil {
		session.Close()
		return r, fmt.Errorf("supervisor session unavailable: %w", e)
	}
	defer session.Close()
	if _, e = scopedCleanup(o, dir, p); e != nil {
		return r, fmt.Errorf("initial recovery refused: %w", e)
	}
	r.Clean = true
	for number := 0; number <= o.MaxRestarts; number++ {
		if ctx.Err() != nil {
			r.State = "stopped"
			return r, nil
		}
		if number > 0 {
			timer := time.NewTimer(o.Backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				r.State = "stopped"
				return r, nil
			case <-timer.C:
			}
		}
		a, runErr := superviseAttempt(ctx, o, number, factory)
		r.Attempts = append(r.Attempts, a)
		if number > 0 {
			r.Restarts++
		}
		r.Clean = false
		if !a.ExitObserved && a.Reason != "launch_failed" {
			return r, fmt.Errorf("worker exit unverified; no cleanup/restart: %w", runErr)
		}
		n, cleanupErr := scopedCleanup(o, dir, p)
		r.Attempts[len(r.Attempts)-1].RecoveredSteps = n
		if cleanupErr != nil {
			return r, fmt.Errorf("recovery refused; no restart: %w", cleanupErr)
		}
		r.Attempts[len(r.Attempts)-1].Clean = true
		r.Clean = true
		if ctx.Err() != nil {
			r.State = "stopped"
			return r, nil
		}
		if a.Ready && a.ExitObserved && a.ExitCode == 0 {
			r.State = "completed"
			return r, nil
		}
		if number == o.MaxRestarts {
			r.State = "exhausted"
			return r, fmt.Errorf("restart budget exhausted after verified cleanup")
		}
	}
	return r, fmt.Errorf("unreachable supervisor state")
}

func superviseAttempt(ctx context.Context, o SupervisorOptions, number int, factory IsolatedWorkerFactory) (a SupervisedAttempt, resultErr error) {
	a = SupervisedAttempt{Number: number, ExitCode: -1, Reason: "launch_failed"}
	cmd, e := factory(number)
	if e != nil {
		return a, fmt.Errorf("worker factory failed")
	}
	if cmd != nil && cmd.Process != nil {
		a.Reason = "factory_returned_started_worker"
		return a, fmt.Errorf("factory must not start the worker")
	}
	if cmd == nil || len(cmd.ExtraFiles) != 0 {
		return a, fmt.Errorf("invalid unstarted worker")
	}
	read, write, e := os.Pipe()
	if e != nil {
		return a, e
	}
	defer read.Close()
	cmd.ExtraFiles = []*os.File{write}
	if e = cmd.Start(); e != nil {
		write.Close()
		return a, fmt.Errorf("worker launch failed")
	}
	write.Close()
	// No concurrent Wait before pidfd_open: an already-exited child is still
	// unreaped and its numeric PID cannot be reused in this acquisition window.
	fd, e := unix.PidfdOpen(cmd.Process.Pid, 0)
	if e != nil {
		// Still unreaped: this exact child's PID cannot be reused before Kill.
		_ = cmd.Process.Kill()
		exited := make(chan struct{})
		go func() { _ = cmd.Wait(); close(exited) }()
		timer := time.NewTimer(o.KillWait)
		select {
		case <-exited:
			timer.Stop()
			a.ExitObserved = cmd.ProcessState != nil
		case <-timer.C:
		}
		a.Reason = "identity_acquisition_failed"
		return a, fmt.Errorf("child pidfd acquisition failed")
	}
	defer unix.Close(fd)
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	ready := make(chan error, 1)
	go func() { ready <- readyRecord(read) }()
	timer := time.NewTimer(o.ReadyTimeout)
	select {
	case <-ctx.Done():
		a.Reason = "stop_requested"
	case <-done:
		a.Reason = "exit_before_ready"
	case e = <-ready:
		if e != nil {
			a.Reason = "readiness_invalid"
		} else {
			a.Ready = true
			select {
			case <-ctx.Done():
				a.Reason = "stop_requested"
			case <-done:
				a.Reason = "worker_exited"
			}
		}
	case <-timer.C:
		a.Reason = "readiness_timeout"
	}
	timer.Stop()
	select {
	case <-done:
	default:
		a.TermRequested = true
		e = unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0)
		if e != nil && e != unix.ESRCH {
			return a, fmt.Errorf("verified worker termination failed")
		}
		grace := time.NewTimer(o.StopGrace)
		select {
		case <-done:
			grace.Stop()
		case <-grace.C:
			a.KillRequested = true
			e = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
			if e != nil && e != unix.ESRCH {
				return a, fmt.Errorf("verified worker kill failed")
			}
			wait := time.NewTimer(o.KillWait)
			select {
			case <-done:
				wait.Stop()
			case <-wait.C:
				return a, fmt.Errorf("verified worker did not exit within kill wait")
			}
		}
	}
	a.ExitObserved = cmd.ProcessState != nil
	if a.ExitObserved {
		a.ExitCode = cmd.ProcessState.ExitCode()
	}
	return a, nil
}
