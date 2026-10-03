//go:build linux

package tproxy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const commandGuardArgument = "__tproxy-command-guard-v1"

// CommandGuardEntry is dispatched by the standalone executable (and native
// test executable) before ordinary CLI parsing. Only a trusted scoped controller
// supplies argv and the inherited owned journal lease on FD 3. No shell, saved
// module config or upstream protocol is interpreted here.
func CommandGuardEntry(args []string) (int, bool) {
	if len(args) > 1 && args[1] == commandAdmissionArgument {
		return commandAdmissionEntry(args), true
	}
	if len(args) < 2 || args[1] != commandGuardArgument {
		return 0, false
	}
	if len(args) < 4 || args[2] != "--" {
		return 1, true
	}
	self, e := os.Readlink("/proc/self/ns/net")
	host, he := os.Readlink("/proc/1/ns/net")
	if e != nil || he != nil || self == host {
		return 1, true
	}
	lease := os.NewFile(3, "inherited-journal-lease")
	if lease == nil {
		return 1, true
	}
	defer lease.Close()
	if e = privateFile(lease); e != nil {
		return 1, true
	}
	// This is the inherited open file description, not a newly opened path.
	// Reasserting its lock does not release it or unlock another controller.
	if e = unix.Flock(int(lease.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return 1, true
	}
	stop, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	ctx, deadline := context.WithTimeout(stop, 8*time.Second)
	defer deadline()
	// Linux PDEATHSIG is tied to the creating thread. Keep that thread alive
	// through Wait. The guard deliberately survives death of its own launcher.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	c := exec.CommandContext(ctx, args[3], args[4:]...)
	c.ExtraFiles = []*os.File{lease}
	c.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	if e = c.Run(); e == nil {
		return 0, true
	}
	if c.ProcessState != nil {
		if s, ok := c.ProcessState.Sys().(syscall.WaitStatus); ok && s.Signaled() {
			return 128 + int(s.Signal()), true
		}
		return c.ProcessState.ExitCode(), true
	}
	// Do not print argv, environment or file contents on launch failure.
	fmt.Fprintln(os.Stderr, "scoped command launch failed")
	return 1, true
}

func queryLeasedContext(parent context.Context, args []string, lease *os.File) Result {
	if lease == nil || len(args) == 0 {
		return Result{Command: args, ExitCode: -1, Error: "scoped command lease required"}
	}
	exe, e := os.Executable()
	if e != nil {
		return Result{Command: args, ExitCode: -1, Error: "command guard executable unavailable"}
	}
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, exe, append([]string{commandGuardArgument, "--"}, args...)...)
	c.ExtraFiles = []*os.File{lease}
	// Cancellation asks the guard to kill/reap its command while retaining the
	// lease. Killing just the guard could release ownership before command exit.
	c.Cancel = func() error { return c.Process.Signal(syscall.SIGTERM) }
	return queryResult(ctx, args, c)
}
