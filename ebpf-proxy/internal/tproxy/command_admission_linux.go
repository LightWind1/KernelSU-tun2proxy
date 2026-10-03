//go:build linux

package tproxy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const commandAdmissionArgument = "__tproxy-command-admission-v1"

// PausedScopedCommand owns one native exec stub and its private admission socket.
// The trusted caller must retain the returned witness in a surviving anchor.
// This primitive is deliberately NOT installed as the default journal runner.
type PausedScopedCommand struct {
	mu       sync.Mutex
	c        *exec.Cmd
	gate     *os.File
	pidfd    int
	admitted bool
	closed   bool
	ctx      context.Context
}

func commandAdmissionEntry(args []string) int {
	if len(args) < 4 || args[2] != "--" {
		return 1
	}
	if _, e := privateWitnessNamespace(); e != nil {
		return 1
	}
	lease := os.NewFile(3, "admission-lease")
	if lease == nil {
		return 1
	}
	defer lease.Close()
	if privateFile(lease) != nil || unix.Flock(3, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return 1
	}
	// SOCK_SEQPACKET preserves the single versioned acknowledgement boundary.
	// An inherited socketpair is the capability: no pathname, public listener,
	// PID file or shell text is accepted. No ancillary descriptors are allowed.
	if kind, e := unix.GetsockoptInt(4, unix.SOL_SOCKET, unix.SO_TYPE); e != nil || kind != unix.SOCK_SEQPACKET {
		return 1
	}
	if e := unix.SetsockoptTimeval(4, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 8}); e != nil {
		return 1
	}
	b, oob := make([]byte, 2), make([]byte, 128)
	n, on, flags, _, e := unix.Recvmsg(4, b, oob, unix.MSG_CMSG_CLOEXEC)
	if on > 0 {
		messages, _ := unix.ParseSocketControlMessage(oob[:on])
		for _, m := range messages {
			fds, _ := unix.ParseUnixRights(&m)
			for _, fd := range fds {
				unix.Close(fd)
			}
		}
	}
	unix.Close(4)
	if e != nil || n != 1 || on != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || b[0] != 1 {
		return 1
	}
	path, e := exec.LookPath(args[3])
	if e != nil {
		return 1
	}
	// Exec preserves the identity pinned before admission; the actual command
	// may drop the lease, so recovery must still observe all witness exits.
	if e = unix.Exec(path, args[3:], os.Environ()); e != nil {
		return 1
	}
	return 1
}

func StartPausedScopedCommand(ctx context.Context, args []string, lease *os.File) (*PausedScopedCommand, error) {
	if _, e := privateWitnessNamespace(); e != nil {
		return nil, e
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 8*time.Second {
		return nil, fmt.Errorf("admission requires a live deadline within eight seconds")
	}
	if len(args) == 0 || lease == nil || privateFile(lease) != nil {
		return nil, fmt.Errorf("private lease and command required")
	}
	exe, e := os.Executable()
	if e != nil {
		return nil, e
	}
	fds, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	gate, child := os.NewFile(uintptr(fds[0]), "admission-parent"), os.NewFile(uintptr(fds[1]), "admission-child")
	defer child.Close()
	c := exec.CommandContext(ctx, exe, append([]string{commandAdmissionArgument, "--"}, args...)...)
	c.ExtraFiles = []*os.File{lease, child}
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	if e = c.Start(); e != nil {
		gate.Close()
		return nil, e
	}
	fd, e := unix.PidfdOpen(c.Process.Pid, 0)
	if e != nil {
		gate.Close()
		c.Process.Kill()
		c.Wait()
		return nil, e
	}
	return &PausedScopedCommand{c: c, gate: gate, pidfd: fd, ctx: ctx}, nil
}

// Admit duplicates all three live identities BEFORE allowing exec. Caller owns
// the witness on success. Source FD closure is harmless. Failure is terminal.
// workerFD/guardFD must originate in the trusted launcher, not user input.
func (p *PausedScopedCommand) Admit(workerFD, guardFD int) (*ScopedCommandWitness, error) {
	if p == nil {
		return nil, fmt.Errorf("paused command required")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.admitted {
		return nil, fmt.Errorf("admission is single use")
	}
	if p.ctx == nil || p.c == nil || p.gate == nil {
		return nil, fmt.Errorf("paused command uninitialized")
	}
	if e := p.ctx.Err(); e != nil {
		p.finish(true)
		return nil, e
	}
	w, e := AcquireScopedCommandWitness(workerFD, guardFD, p.pidfd)
	if e == nil {
		e = p.ctx.Err()
	}
	if e == nil {
		e = unix.Sendmsg(int(p.gate.Fd()), []byte{1}, nil, nil, unix.MSG_NOSIGNAL)
	}
	if e != nil {
		if w != nil {
			w.Close()
		}
		p.finish(true)
		return nil, e
	}
	p.admitted = true
	p.gate.Close()
	return w, nil
}

func (p *PausedScopedCommand) finish(kill bool) error {
	if p.closed {
		return nil
	}
	if p.ctx == nil || p.c == nil || p.gate == nil {
		return fmt.Errorf("paused command uninitialized")
	}
	p.closed = true
	p.gate.Close()
	if kill {
		p.c.Process.Kill()
	}
	e := p.c.Wait()
	unix.Close(p.pidfd)
	return e
}

// Wait is bounded by the launch context. Abort kills/reaps the owned direct
// command only. Do not concurrently call Abort to interrupt Wait; cancel its
// launch context instead. Arbitrary descendants are outside this closed set.
func (p *PausedScopedCommand) Wait() error {
	if p == nil {
		return fmt.Errorf("paused command required")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.admitted || p.closed {
		return fmt.Errorf("command not admitted or already reaped")
	}
	return p.finish(false)
}

func (p *PausedScopedCommand) Abort() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.finish(true)
}
