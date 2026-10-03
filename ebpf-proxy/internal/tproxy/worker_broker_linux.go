//go:build linux

package tproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const brokerLimit = 150000 // two capped 64 KiB streams plus JSON escaping overhead
const brokerMarker = "broker-session.json"

type brokerRequest struct {
	Version int      `json:"version"`
	ID      uint64   `json:"id"`
	Binding [32]byte `json:"binding"`
	Args    []string `json:"args"`
}
type brokerResponse struct {
	Version int    `json:"version"`
	ID      uint64 `json:"id"`
	Quiet   bool   `json:"quiet"`
	Command Result `json:"command"`
}

// Registry counts reserved commands, not just successful executions. A missing
// proof is sticky for the entire worker attempt. Execution is serial: no second
// command may be admitted until the previous guard AND anchor have exited.
type WorkerCommandRegistry struct {
	Version   int    `json:"version"`
	Requested uint64 `json:"requested"`
	Completed uint64 `json:"completed"`
	Active    bool   `json:"active"`
	Blocked   bool   `json:"blocked"`
	Sealed    bool   `json:"sealed"`
}

func (r *WorkerCommandRegistry) reserve(id uint64) error {
	if r.Blocked || r.Sealed || r.Active || id != r.Requested+1 {
		r.Blocked = true
		return fmt.Errorf("worker command membership refused")
	}
	r.Requested = id
	r.Active = true
	return nil
}
func (r *WorkerCommandRegistry) finish(quiet bool) {
	if !r.Active || !quiet {
		r.Blocked = true
	}
	if quiet && r.Active {
		r.Completed++
	}
	r.Active = false
}
func (r WorkerCommandRegistry) cleanGate() bool {
	return r.Sealed && !r.Blocked && !r.Active && r.Requested == r.Completed
}

func brokerDecode(b []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(value); e != nil {
		return fmt.Errorf("invalid broker record")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return fmt.Errorf("trailing broker record")
	}
	return nil
}
func brokerReceive(ctx context.Context, fd, want int) ([]byte, []int, error) {
	for {
		if e := ctx.Err(); e != nil {
			return nil, nil, e
		}
		b, oob := make([]byte, brokerLimit+1), make([]byte, unix.CmsgSpace(8))
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
		messages, pe := unix.ParseSocketControlMessage(oob[:on])
		for _, m := range messages {
			got, re := unix.ParseUnixRights(&m)
			fds = append(fds, got...)
			if re != nil {
				pe = re
			}
		}
		if n == 0 && on == 0 {
			return nil, nil, io.EOF
		}
		if n > brokerLimit || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || pe != nil || len(fds) != want || (want == 0 && on != 0) || (want > 0 && len(messages) != 1) {
			closeHandoffFDs(fds)
			return nil, nil, fmt.Errorf("invalid broker packet/descriptors")
		}
		return b[:n], fds, nil
	}
}
func brokerSend(ctx context.Context, fd int, value any, fds []int) error {
	b, e := json.Marshal(value)
	if e != nil || len(b) > brokerLimit {
		return fmt.Errorf("broker record too large")
	}
	return handoffSend(ctx, fd, b, fds)
}

func brokerAllowed(p IPv4DestinationPlan, args []string) bool {
	for _, a := range [][]string{{"iptables", "-w", "2", "-t", "mangle", "-S"}, {"ip", "rule", "show"}, {"ip", "route", "show", "table", "all"}} {
		if reflect.DeepEqual(args, a) {
			return true
		}
	}
	steps, e := p.Steps()
	if e != nil {
		return false
	}
	for _, s := range steps {
		if reflect.DeepEqual(args, s.Add) || reflect.DeepEqual(args, s.Remove) {
			return true
		}
		check := append([]string(nil), s.Remove...)
		for i, a := range check {
			if a == "-D" {
				check[i] = "-C"
				break
			}
		}
		if reflect.DeepEqual(args, check) {
			return true
		}
	}
	return false
}

// OpenBrokeredScopedIsolated is explicitly opt-in. Every journal observation,
// add, remove and pending proof uses the inherited private broker capability.
// No local command fallback. Trusted workers must not perform out-of-band
// network writes or spawn arbitrary descendants.
func OpenBrokeredScopedIsolated(ctx context.Context, channelFD int, dir string, p IPv4DestinationPlan) (*DurableIsolated, error) {
	if ctx == nil || handoffSocket(channelFD) != nil {
		return nil, fmt.Errorf("broker context/channel required")
	}
	binding, e := ScopedCommandBinding(dir, p)
	if e != nil {
		return nil, e
	}
	fd, e := unix.FcntlInt(uintptr(channelFD), unix.F_DUPFD_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	d, e := OpenScopedIsolated(dir, p)
	if e != nil {
		unix.Close(fd)
		return nil, e
	}
	var mu sync.Mutex
	var id uint64
	blocked := false
	d.commandClose = func() { unix.Close(fd) }
	d.run = func(args []string) Result {
		mu.Lock()
		defer mu.Unlock()
		fail := func() Result {
			blocked = true
			return Result{Command: args, ExitCode: -1, Error: "worker broker proof unavailable"}
		}
		if blocked || !brokerAllowed(p, args) {
			return fail()
		}
		id++
		call, cancel := context.WithTimeout(ctx, 55*time.Second)
		defer cancel()
		if e := brokerSend(call, fd, brokerRequest{1, id, binding, args}, []int{int(d.lock.Fd())}); e != nil {
			return fail()
		}
		b, _, e := brokerReceive(call, fd, 0)
		if e != nil {
			return fail()
		}
		var r brokerResponse
		if brokerDecode(b, &r) != nil || r.Version != 1 || r.ID != id || !r.Quiet || !reflect.DeepEqual(r.Command.Command, args) {
			return fail()
		}
		return r.Command
	}
	return d, nil
}

type BrokeredSupervisorResult struct {
	SupervisorResult
	Registries []WorkerCommandRegistry `json:"registries"`
}

type workerBroker struct {
	dir      string
	plan     IPv4DestinationPlan
	binding  [32]byte
	channel  *os.File
	worker   *os.File
	registry WorkerCommandRegistry
	// Trusted deterministic test seams, never supplied by IPC or module config.
	commandHook func(*RegisteredCommandSession, []string)
	argsHook    func([]string) []string
}

func (b *workerBroker) run(ctx context.Context, stopWorker context.CancelFunc) {
	defer func() { b.registry.Sealed = true }()
	for {
		packet, fds, e := brokerReceive(ctx, int(b.channel.Fd()), 1)
		if e == io.EOF || e == context.Canceled {
			return
		}
		if e != nil {
			b.registry.Blocked = true
			stopWorker()
			return
		}
		lease := os.NewFile(uintptr(fds[0]), "broker-command-lease")
		var req brokerRequest
		valid := brokerDecode(packet, &req) == nil && req.Version == 1 && req.Binding == b.binding && brokerAllowed(b.plan, req.Args)
		// A received regular file is not enough: it must be this exact journal
		// lock inode, not another private file selected by the worker.
		root, re := os.OpenRoot(b.dir)
		if re == nil {
			lock, le := root.OpenFile("lock", os.O_RDONLY|unix.O_NOFOLLOW, 0)
			if le == nil {
				i, ie := lock.Stat()
				j, je := lease.Stat()
				valid = valid && ie == nil && je == nil && os.SameFile(i, j) && privateFile(lease) == nil
				lock.Close()
			} else {
				valid = false
			}
			root.Close()
		} else {
			valid = false
		}
		binding, be := ScopedCommandBinding(b.dir, b.plan)
		valid = valid && be == nil && binding == b.binding
		if !valid || b.registry.reserve(req.ID) != nil {
			lease.Close()
			b.registry.Blocked = true
			stopWorker()
			return
		}
		args := req.Args
		if b.argsHook != nil {
			args = b.argsHook(args)
		}
		launch, cancel := context.WithTimeout(context.Background(), 7*time.Second)
		s, e := startRegisteredScopedCommand(launch, args, lease, b.dir, b.plan, b.worker)
		// Never hold the command's journal lease while waiting for the anchor's
		// worker-death recovery; guard/direct command own the inherited copies.
		lease.Close()
		var result RegisteredCommandResult
		if e == nil {
			if b.commandHook != nil {
				b.commandHook(s, req.Args)
			}
			result, _ = s.wait(context.Background(), true)
		}
		cancel()
		b.registry.finish(e == nil && result.Quiescent)
		if b.registry.Blocked {
			stopWorker()
			return
		}
		// Execution errors remain command errors, but verified exits still close
		// membership. Preserve requested argv when a test wraps execution.
		result.Command.Command = req.Args
		sendCtx, sendCancel := context.WithTimeout(context.Background(), time.Second)
		e = brokerSend(sendCtx, int(b.channel.Fd()), brokerResponse{1, req.ID, true, result.Command}, nil)
		sendCancel()
		if e != nil {
			// Reply loss cannot authorize new execution. All known commands have
			// nevertheless exited; stop/reap worker before the cleanup gate.
			stopWorker()
			return
		}
	}
}

// SuperviseBrokeredScopedIsolated is a new, explicit worker-wide mode, not an
// upgrade of the legacy supervisor. FD3 readiness; FD4 inherited broker. One
// command at a time provides a closed command set even during worker SIGKILL.
// A durable marker blocks re-adoption after launcher loss/uncertain membership.
func SuperviseBrokeredScopedIsolated(ctx context.Context, dir string, p IPv4DestinationPlan, o SupervisorOptions, factory IsolatedWorkerFactory) (BrokeredSupervisorResult, error) {
	return superviseBrokeredScoped(ctx, dir, p, o, factory, nil)
}
func superviseBrokeredScoped(ctx context.Context, dir string, p IPv4DestinationPlan, o SupervisorOptions, factory IsolatedWorkerFactory, hook func(*workerBroker)) (r BrokeredSupervisorResult, err error) {
	r.SupervisorResult = SupervisorResult{Version: 1, State: "blocked"}
	if ctx == nil || factory == nil {
		return r, fmt.Errorf("broker supervisor context/factory required")
	}
	if e := o.Validate(); e != nil {
		return r, e
	}
	binding, e := ScopedCommandBinding(dir, p)
	if e != nil {
		return r, e
	}
	d, e := OpenScopedIsolated(dir, p)
	if e != nil {
		return r, e
	}
	if d.r.Owned != 0 || d.r.Pending != "" {
		d.Close()
		return r, fmt.Errorf("prior worker state has no broker membership proof; no adoption")
	}
	session, e := d.root.OpenFile("supervisor.lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if e == nil {
		e = privateFile(session)
	}
	if e == nil {
		e = unix.Flock(int(session.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	}
	if e != nil {
		if session != nil {
			session.Close()
		}
		d.Close()
		return r, fmt.Errorf("broker session unavailable")
	}
	defer session.Close()
	root, e := os.OpenRoot(dir)
	d.Close()
	if e != nil {
		return r, e
	}
	defer root.Close()
	// Do not interpret stale PID files or available flock as recovery authority.
	marker, e := root.OpenFile(brokerMarker, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return r, fmt.Errorf("unresolved broker session; no cleanup/restart")
	}
	data, _ := json.Marshal(struct {
		Version int
		Binding [32]byte
	}{1, binding})
	_, e = marker.Write(data)
	if e == nil {
		e = marker.Sync()
	}
	ce := marker.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = syncBrokerRoot(root)
	}
	if e != nil {
		return r, fmt.Errorf("broker admission durability failed")
	}
	defer func() {
		if r.Clean {
			if e := root.Remove(brokerMarker); e != nil {
				r.Clean = false
				r.State = "blocked"
				err = e
			} else if e := syncBrokerRoot(root); e != nil {
				r.Clean = false
				r.State = "blocked"
				err = e
			}
		}
	}()
	if _, e = scopedCleanup(o, dir, p); e != nil {
		return r, e
	}
	r.Clean = true
	for number := 0; number <= o.MaxRestarts; number++ {
		if ctx.Err() != nil {
			r.State = "stopped"
			return r, nil
		}
		if number > 0 {
			select {
			case <-ctx.Done():
				r.State = "stopped"
				return r, nil
			case <-time.After(o.Backoff):
			}
		}
		fds, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if e != nil {
			return r, e
		}
		parent, child := os.NewFile(uintptr(fds[0]), "broker-parent"), os.NewFile(uintptr(fds[1]), "broker-worker")
		b := &workerBroker{dir: dir, plan: p, binding: binding, channel: parent, registry: WorkerCommandRegistry{Version: 1}}
		if hook != nil {
			hook(b)
		}
		attemptCtx, stop := context.WithCancel(ctx)
		observeCtx, endObserve := context.WithCancel(context.Background())
		done := make(chan struct{})
		started := false
		r.Clean = false
		runtime.LockOSThread()
		a, runErr := superviseAttemptWithBroker(attemptCtx, o, number, factory, child, func(fd int) error {
			copyFD, e := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
			if e != nil {
				return e
			}
			b.worker = os.NewFile(uintptr(copyFD), "broker-pinned-worker")
			started = true
			go func() { b.run(observeCtx, stop); close(done) }()
			return nil
		})
		runtime.UnlockOSThread()
		child.Close() // parent must not keep the worker endpoint alive after exit
		endObserve()
		if started {
			select {
			case <-done:
			case <-time.After(55 * time.Second):
				stop()
				parent.Close()
				r.Attempts = append(r.Attempts, a)
				return r, fmt.Errorf("worker command registry drain unverified")
			}
			b.worker.Close()
		} else {
			b.registry.Sealed = true
		}
		stop()
		parent.Close()
		r.Attempts = append(r.Attempts, a)
		r.Registries = append(r.Registries, b.registry)
		if number > 0 {
			r.Restarts++
		}
		if (!a.ExitObserved && a.Reason != "launch_failed") || !b.registry.cleanGate() {
			return r, fmt.Errorf("worker membership/exit unverified; no cleanup/restart")
		}
		current, bindingErr := ScopedCommandBinding(dir, p)
		if bindingErr != nil || current != binding {
			return r, fmt.Errorf("broker state binding changed; no cleanup/restart")
		}
		n, e := scopedCleanup(o, dir, p)
		r.Attempts[len(r.Attempts)-1].RecoveredSteps = n
		if e != nil {
			return r, fmt.Errorf("broker recovery refused")
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
			return r, fmt.Errorf("broker restart budget exhausted after verified cleanup: %v", runErr)
		}
	}
	return r, fmt.Errorf("unreachable broker state")
}
func syncBrokerRoot(root *os.Root) error {
	f, e := root.Open(".")
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
