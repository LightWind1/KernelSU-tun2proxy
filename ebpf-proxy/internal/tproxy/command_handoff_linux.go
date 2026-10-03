//go:build linux

package tproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const handoffPacketSize = 65 // version, 32-byte nonce, 32-byte state/plan binding

// ScopedCommandBinding is a read-only identity for a trusted state/plan. No
// state path or executable command is accepted from the IPC packet.
func ScopedCommandBinding(dir string, plan IPv4DestinationPlan) ([32]byte, error) {
	var zero [32]byte
	ns, e := privateWitnessNamespace()
	if e != nil {
		return zero, e
	}
	if _, e = plan.Steps(); e != nil {
		return zero, e
	}
	i, e := os.Lstat(dir)
	if e != nil {
		return zero, e
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || !i.IsDir() || i.Mode().Perm() != 0700 || s.Uid != uint32(os.Geteuid()) {
		return zero, fmt.Errorf("handoff state must be private owned directory")
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		return zero, e
	}
	defer root.Close()
	f, e := root.Open(".")
	if e != nil {
		return zero, e
	}
	opened, e := f.Stat()
	f.Close()
	if e != nil || !os.SameFile(i, opened) {
		return zero, fmt.Errorf("handoff state identity changed")
	}
	abs, e := filepath.Abs(dir)
	if e != nil {
		return zero, e
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return zero, e
	}
	b, e := json.Marshal(struct {
		Version                    int
		Directory, Namespace, Boot string
		Device, Inode              uint64
		Plan                       IPv4DestinationPlan
	}{1, abs, ns, strings.TrimSpace(string(boot)), uint64(s.Dev), s.Ino, plan})
	if e != nil {
		return zero, e
	}
	return sha256.Sum256(b), nil
}

func handoffDeadline(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("handoff context required")
	}
	d, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil || time.Until(d) <= 0 || time.Until(d) > 8*time.Second {
		return fmt.Errorf("handoff requires live deadline within eight seconds")
	}
	return nil
}

func handoffSocket(fd int) error {
	kind, e := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if e != nil || kind != unix.SOCK_SEQPACKET {
		return fmt.Errorf("handoff needs connected Unix seqpacket capability")
	}
	a, e := unix.Getpeername(fd)
	if _, ok := a.(*unix.SockaddrUnix); e != nil || !ok {
		return fmt.Errorf("handoff socket is not connected Unix socket")
	}
	return nil
}

func handoffPoll(ctx context.Context, fd int, event int16) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	p := []unix.PollFd{{Fd: int32(fd), Events: event}}
	_, e := unix.Poll(p, 20)
	if e == unix.EINTR {
		return nil
	}
	if e != nil {
		return e
	}
	if p[0].Revents&(unix.POLLNVAL|unix.POLLERR) != 0 {
		return fmt.Errorf("handoff channel failed")
	}
	return ctx.Err()
}

func handoffSend(ctx context.Context, fd int, b []byte, fds []int) error {
	var oob []byte
	if len(fds) > 0 {
		oob = unix.UnixRights(fds...)
	}
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		e := unix.Sendmsg(fd, b, oob, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
		if e != unix.EAGAIN && e != unix.EINTR {
			return e
		}
		if e = handoffPoll(ctx, fd, unix.POLLOUT); e != nil {
			return e
		}
	}
}

func closeHandoffFDs(fds []int) {
	for _, fd := range fds {
		unix.Close(fd)
	}
}

func handoffReceive(ctx context.Context, fd, wantFDs int) ([]byte, []int, error) {
	for {
		if e := ctx.Err(); e != nil {
			return nil, nil, e
		}
		b, oob := make([]byte, handoffPacketSize+1), make([]byte, unix.CmsgSpace(4*4))
		n, on, flags, _, e := unix.Recvmsg(fd, b, oob, unix.MSG_DONTWAIT|unix.MSG_CMSG_CLOEXEC)
		if e == unix.EAGAIN || e == unix.EINTR {
			if e = handoffPoll(ctx, fd, unix.POLLIN); e != nil {
				return nil, nil, e
			}
			continue
		}
		if e != nil {
			return nil, nil, e
		}
		var fds []int
		messages, parseErr := unix.ParseSocketControlMessage(oob[:on])
		for _, m := range messages {
			got, re := unix.ParseUnixRights(&m)
			fds = append(fds, got...)
			if re != nil {
				parseErr = re
			}
		}
		if n != handoffPacketSize || b[0] != 1 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || parseErr != nil || len(fds) != wantFDs || (wantFDs > 0 && len(messages) != 1) || (wantFDs == 0 && on != 0) {
			closeHandoffFDs(fds)
			return nil, nil, fmt.Errorf("invalid handoff packet or descriptor set")
		}
		return b[:n], fds, nil
	}
}

// liveHandoffPID reads metadata only; no numeric-PID signaling/adoption. Both
// expected and received pidfds must remain live across the role comparison.
func liveHandoffPID(fd int) (int, error) {
	ns, e := privateWitnessNamespace()
	if e != nil {
		return 0, e
	}
	link, e := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if e != nil || link != "anon_inode:[pidfd]" {
		return 0, fmt.Errorf("handoff identity must be pidfd")
	}
	dead, e := witnessPoll([]int{fd}, 0)
	if e != nil || dead {
		return 0, fmt.Errorf("handoff identity exited")
	}
	b, e := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	if e != nil {
		return 0, e
	}
	pid := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Pid:") {
			pid, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Pid:")))
		}
	}
	if pid <= 0 {
		return 0, fmt.Errorf("handoff live identity missing")
	}
	other, e := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
	if e != nil || other != ns {
		return 0, fmt.Errorf("handoff identity namespace differs")
	}
	dead, e = witnessPoll([]int{fd}, 0)
	if e != nil || dead {
		return 0, fmt.Errorf("handoff identity raced exit")
	}
	return pid, nil
}

// ScopedCommandAnchor is one-shot, created by a trusted launcher. Authentication
// is an inherited socket capability plus pre-pinned expected roles, not a
// public pathname or SO_PEERCRED (socketpair credentials identify its creator).
type ScopedCommandAnchor struct {
	mu           sync.Mutex
	fds          []int // channel, expected worker, expected guard
	dir          string
	plan         IPv4DestinationPlan
	binding      [32]byte
	used         bool
	boundaryHook func(string) // unexported crash seam, native tests only
}

func NewScopedCommandAnchor(channelFD, workerFD, guardFD int, dir string, plan IPv4DestinationPlan) (*ScopedCommandAnchor, error) {
	binding, e := ScopedCommandBinding(dir, plan)
	if e != nil {
		return nil, e
	}
	a := &ScopedCommandAnchor{dir: dir, plan: plan, binding: binding}
	fail := func(e error) (*ScopedCommandAnchor, error) { a.Close(); return nil, e }
	for _, source := range []int{channelFD, workerFD, guardFD} {
		fd, e := unix.FcntlInt(uintptr(source), unix.F_DUPFD_CLOEXEC, 0)
		if e != nil {
			return fail(e)
		}
		a.fds = append(a.fds, fd)
	}
	if e = handoffSocket(a.fds[0]); e != nil {
		return fail(e)
	}
	w, e := liveHandoffPID(a.fds[1])
	if e != nil {
		return fail(e)
	}
	g, e := liveHandoffPID(a.fds[2])
	if e != nil || w == g {
		return fail(fmt.Errorf("expected handoff roles invalid"))
	}
	return a, nil
}

// RegisteredScopedCommand binds recovery to the exact local state/plan; callers
// cannot substitute a path supplied by the sender. Keep this pointer alive.
type RegisteredScopedCommand struct {
	w       *ScopedCommandWitness
	dir     string
	plan    IPv4DestinationPlan
	binding [32]byte
}

func (r *RegisteredScopedCommand) Close() error {
	if r == nil {
		return nil
	}
	return r.w.Close()
}
func (r *RegisteredScopedCommand) Recover(ctx context.Context) (CommandWitnessResult, error) {
	if r == nil || r.w == nil {
		return CommandWitnessResult{}, fmt.Errorf("registered witness required")
	}
	b, e := ScopedCommandBinding(r.dir, r.plan)
	if e != nil || b != r.binding {
		return CommandWitnessResult{}, fmt.Errorf("registered state/plan binding changed")
	}
	return r.w.Recover(ctx, r.dir, r.plan)
}

func (a *ScopedCommandAnchor) Accept(ctx context.Context) (*RegisteredScopedCommand, error) {
	if a == nil {
		return nil, fmt.Errorf("anchor required")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.used || len(a.fds) != 3 {
		return nil, fmt.Errorf("anchor closed or already used")
	}
	a.used = true
	if e := handoffDeadline(ctx); e != nil {
		return nil, e
	}
	b, fds, e := handoffReceive(ctx, a.fds[0], 4)
	if e != nil {
		return nil, e
	}
	defer closeHandoffFDs(fds)
	if !bytes.Equal(b[33:], a.binding[:]) {
		return nil, fmt.Errorf("handoff state/plan mismatch")
	}
	for i := 0; i < 2; i++ {
		expected, e := liveHandoffPID(a.fds[i+1])
		if e != nil {
			return nil, e
		}
		got, e := liveHandoffPID(fds[i])
		if e != nil || got != expected {
			return nil, fmt.Errorf("handoff role identity mismatch")
		}
		if _, e = liveHandoffPID(a.fds[i+1]); e != nil {
			return nil, e
		}
	}
	if e = handoffSocket(fds[3]); e != nil {
		return nil, e
	}
	current, e := ScopedCommandBinding(a.dir, a.plan)
	if e != nil || current != a.binding {
		return nil, fmt.Errorf("anchor state identity changed")
	}
	w, e := AcquireScopedCommandWitness(fds[0], fds[1], fds[2])
	if e != nil {
		return nil, e
	}
	r := &RegisteredScopedCommand{w: w, dir: a.dir, plan: a.plan, binding: a.binding}
	// The anchor owns the witness BEFORE ACK. Only the anchor owns the gate after
	// transfer. If it dies before releasing it, the stub receives EOF and refuses.
	if a.boundaryHook != nil {
		a.boundaryHook("owned-before-ack")
	}
	if e = handoffSend(ctx, a.fds[0], b, nil); e != nil {
		r.Close()
		return nil, e
	}
	if a.boundaryHook != nil {
		a.boundaryHook("ack-before-release")
	}
	// ACK transmission is not proof the sender consumed/validated it. Require
	// its nonce-bound confirmation before release; lost ACK cannot execute.
	confirmation, _, e := handoffReceive(ctx, a.fds[0], 0)
	if e != nil || !bytes.Equal(confirmation, b) {
		r.Close()
		return nil, fmt.Errorf("sender confirmation missing or mismatched")
	}
	if a.boundaryHook != nil {
		a.boundaryHook("confirmed-before-release")
	}
	if e = handoffSend(ctx, fds[3], []byte{1}, nil); e != nil {
		return r, e
	}
	return r, nil
}

func (a *ScopedCommandAnchor) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	closeHandoffFDs(a.fds)
	a.fds = nil
	return nil
}

// HandoffScoped transfers the release gate and three pinned identities to an
// independently surviving anchor. No ACK or a mismatched ACK is terminal:
// kill/reap the owned command, never fall back to local/worker-only admission.
func (p *PausedScopedCommand) HandoffScoped(ctx context.Context, channelFD, workerFD, guardFD int, dir string, plan IPv4DestinationPlan) error {
	if p == nil {
		return fmt.Errorf("paused command required")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.admitted || p.c == nil || p.gate == nil || p.ctx == nil {
		return fmt.Errorf("paused command unavailable")
	}
	fail := func(e error) error { p.finish(true); return e }
	if e := handoffDeadline(ctx); e != nil {
		return fail(e)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(p.ctx, cancel)
	defer stop()
	if e := p.ctx.Err(); e != nil {
		return fail(e)
	}
	binding, e := ScopedCommandBinding(dir, plan)
	if e != nil {
		return fail(e)
	}
	fd, e := unix.FcntlInt(uintptr(channelFD), unix.F_DUPFD_CLOEXEC, 0)
	if e != nil {
		return fail(e)
	}
	defer unix.Close(fd)
	if e = handoffSocket(fd); e != nil {
		return fail(e)
	}
	w, e := AcquireScopedCommandWitness(workerFD, guardFD, p.pidfd)
	if e != nil {
		return fail(e)
	}
	defer w.Close()
	b := make([]byte, handoffPacketSize)
	b[0] = 1
	if _, e = rand.Read(b[1:33]); e != nil {
		return fail(e)
	}
	copy(b[33:], binding[:])
	if e = handoffSend(ctx, fd, b, append(append([]int(nil), w.fds...), int(p.gate.Fd()))); e != nil {
		return fail(e)
	}
	p.gate.Close() // do not retain another write capability after transfer
	ack, _, e := handoffReceive(ctx, fd, 0)
	if e != nil || !bytes.Equal(b, ack) {
		return fail(fmt.Errorf("anchor acknowledgement missing or mismatched"))
	}
	if e = p.ctx.Err(); e != nil {
		return fail(e)
	}
	// Successful confirmation send is the execution commit point. Cancellation
	// after this point can terminate a command but cannot undo its side effects.
	if e = handoffSend(ctx, fd, b, nil); e != nil {
		return fail(e)
	}
	p.admitted = true
	return nil
}
