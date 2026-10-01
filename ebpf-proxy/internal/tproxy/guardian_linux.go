//go:build linux

package tproxy

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

type GuardianResult struct {
	ExitCode       int    `json:"worker_exit_code"`
	Signal         string `json:"worker_signal,omitempty"`
	RecoveredSteps int    `json:"recovered_steps"`
	Clean          bool   `json:"clean"`
}

// WatchIsolatedWorker belongs to a surviving parent, not the worker. Wait
// proves the actual child has exited and released its flock; no stale PID or
// process-name matching is used. Call only with a started, trusted exec.Cmd.
// The caller controls cancellation/termination of that worker. A killed
// guardian or uncertain journal still needs investigation; this is not a
// production watchdog or a guarantee of fail-open at every crash boundary.
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
	if s, ok := worker.ProcessState.Sys().(syscall.WaitStatus); ok && s.Signaled() {
		result.Signal = s.Signal().String()
	}
	d, e := OpenDurableIsolated(dir, plan)
	if e != nil {
		return result, e
	}
	defer d.Close()
	result.RecoveredSteps = d.r.Owned
	if e = d.Recover(); e != nil {
		return result, e
	}
	result.Clean = d.r.Owned == 0
	return result, nil
}
