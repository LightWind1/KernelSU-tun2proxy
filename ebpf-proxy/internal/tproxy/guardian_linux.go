//go:build linux

package tproxy

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"syscall"
)

type GuardianResult struct {
	ExitCode       int    `json:"worker_exit_code"`
	Signal         string `json:"worker_signal,omitempty"`
	RecoveredSteps int    `json:"recovered_steps"`
	Clean          bool   `json:"clean"`
	Reconciled     bool   `json:"pending_reconciled"`
	ExitObserved   bool   `json:"exit_observed"`
	ExitCodeKnown  bool   `json:"exit_code_known"`
}

// WatchIsolatedWorker belongs to a surviving parent, not the worker. Wait
// proves the actual child has exited and released its flock; no stale PID or
// process-name matching is used. Call only with a started, trusted exec.Cmd.
// The caller controls cancellation/termination of that worker. A killed
// guardian can be replaced by a surviving trusted pidfd anchor. Unverifiable
// journals still need investigation; this is not a deployed production watchdog
// or a guarantee of fail-open after loss of all supervisors.
func WatchIsolatedWorker(worker *exec.Cmd, dir string, plan IPv4DestinationPlan) (GuardianResult, error) {
	var result GuardianResult
	ns, e := os.Readlink("/proc/self/ns/net")
	if e != nil {
		return result, e
	}
	host, e := os.Readlink("/proc/1/ns/net")
	if e != nil || host == ns {
		return result, fmt.Errorf("guardian requires private network namespace")
	}
	if worker == nil || worker.Process == nil {
		return result, fmt.Errorf("worker not started")
	}
	waitErr := worker.Wait()
	if worker.ProcessState == nil {
		return result, fmt.Errorf("cannot verify child exit: %w", waitErr)
	}
	result.ExitCode = worker.ProcessState.ExitCode()
	result.ExitObserved = true
	result.ExitCodeKnown = true
	if s, ok := worker.ProcessState.Sys().(syscall.WaitStatus); ok && s.Signaled() {
		result.Signal = s.Signal().String()
	}
	e = recoverIsolatedExit(&result, dir, plan)
	return result, e
}

func recoverIsolatedExit(result *GuardianResult, dir string, plan IPv4DestinationPlan) error {
	d, e := OpenDurableIsolated(dir, plan)
	if e != nil {
		return e
	}
	defer d.Close()
	result.Reconciled = d.r.Pending != ""
	if e = d.ResolvePending(); e != nil {
		return e
	}
	result.RecoveredSteps = d.r.Owned
	if e = d.Recover(); e != nil {
		return e
	}
	result.Clean = d.r.Owned == 0
	return nil
}

// WatchIsolatedPIDFD lets a surviving anchor replace a lost guardian. The fd
// must come from a trusted launcher that verified the process identity. This
// function never accepts a PID to kill and never terminates a process. It waits
// for the pinned process identity to exit before trying to acquire ownership.
// Deployment/restart of that anchor remains the integrator's responsibility.
func WatchIsolatedPIDFD(ctx context.Context, fd int, dir string, plan IPv4DestinationPlan) (GuardianResult, error) {
	r := GuardianResult{ExitCode: -1}
	ns, e := os.Readlink("/proc/self/ns/net")
	if e != nil {
		return r, e
	}
	host, e := os.Readlink("/proc/1/ns/net")
	if e != nil || ns == host {
		return r, fmt.Errorf("pidfd guardian requires private namespace")
	}
	// Hold our own descriptor so caller closure cannot cause fd-number reuse
	// while we poll. The caller must supply a trusted live descriptor initially.
	ownedFD, e := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if e != nil {
		return r, e
	}
	defer unix.Close(ownedFD)
	link, e := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", ownedFD))
	if e != nil || link != "anon_inode:[pidfd]" {
		return r, fmt.Errorf("not a pidfd: %s %v", link, e)
	}
	for {
		if e = ctx.Err(); e != nil {
			return r, e
		}
		p := []unix.PollFd{{Fd: int32(ownedFD), Events: unix.POLLIN}}
		_, e = unix.Poll(p, 100)
		if e == unix.EINTR {
			continue
		}
		if e != nil {
			return r, e
		}
		if p[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return r, fmt.Errorf("invalid pidfd poll")
		}
		if p[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0 {
			break
		}
	}
	r.ExitObserved = true
	e = recoverIsolatedExit(&r, dir, plan)
	return r, e
}
