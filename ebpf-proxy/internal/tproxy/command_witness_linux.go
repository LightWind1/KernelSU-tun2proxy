//go:build linux

package tproxy

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// ScopedCommandWitness is acquired by a trusted surviving launcher BEFORE any
// of the three processes exits. It is a closed set for ONE direct command, not
// a process-tree registry. The consumer must bind this set to its state/plan.
// No WebUI/PID input, signaling or automatic adoption is provided.
type ScopedCommandWitness struct {
	mu        sync.Mutex
	fds       []int
	namespace string
}

type CommandWitnessResult struct {
	Version          int            `json:"version"`
	Witnesses        int            `json:"witnesses"`
	AllExitsObserved bool           `json:"all_exits_observed"`
	Recovery         GuardianResult `json:"recovery"`
}

func privateWitnessNamespace() (string, error) {
	self, e := os.Readlink("/proc/self/ns/net")
	host, he := os.Readlink("/proc/1/ns/net")
	if e != nil || he != nil || self == host {
		return "", fmt.Errorf("command witness requires private network namespace")
	}
	return self, nil
}

func witnessPoll(fds []int, timeout int) (bool, error) {
	p := make([]unix.PollFd, len(fds))
	for i, fd := range fds {
		p[i] = unix.PollFd{Fd: int32(fd), Events: unix.POLLIN}
	}
	_, e := unix.Poll(p, timeout)
	if e == unix.EINTR {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	all := true
	for _, fd := range p {
		if fd.Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return false, fmt.Errorf("invalid witness descriptor")
		}
		if fd.Revents&(unix.POLLIN|unix.POLLHUP) == 0 {
			all = false
		}
	}
	return all, nil
}

// AcquireScopedCommandWitness duplicates each trusted pidfd, checks live PID
// metadata and distinct identities in this private namespace, then rechecks
// liveness. Numeric PIDs are used ONLY to read namespace metadata, never signal.
// A failed/racing handoff is refused, not reconstructed from a stale journal.
func AcquireScopedCommandWitness(workerFD, guardFD, commandFD int) (*ScopedCommandWitness, error) {
	ns, e := privateWitnessNamespace()
	if e != nil {
		return nil, e
	}
	w := &ScopedCommandWitness{namespace: ns}
	fail := func(e error) (*ScopedCommandWitness, error) { w.Close(); return nil, e }
	seen := map[int]bool{}
	for _, source := range []int{workerFD, guardFD, commandFD} {
		fd, e := unix.FcntlInt(uintptr(source), unix.F_DUPFD_CLOEXEC, 0)
		if e != nil {
			return fail(fmt.Errorf("witness duplication failed: %w", e))
		}
		w.fds = append(w.fds, fd)
		link, e := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
		if e != nil || link != "anon_inode:[pidfd]" {
			return fail(fmt.Errorf("witness is not a pidfd"))
		}
		info, e := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
		if e != nil {
			return fail(e)
		}
		pid := 0
		for _, line := range strings.Split(string(info), "\n") {
			if strings.HasPrefix(line, "Pid:") {
				pid, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Pid:")))
			}
		}
		if pid <= 0 || seen[pid] {
			return fail(fmt.Errorf("witness identities must be distinct and live"))
		}
		seen[pid] = true
		processNS, e := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
		if e != nil || processNS != ns {
			return fail(fmt.Errorf("witness namespace differs"))
		}
	}
	for _, fd := range w.fds {
		exited, e := witnessPoll([]int{fd}, 0)
		if e != nil || exited {
			return fail(fmt.Errorf("witness exited during handoff"))
		}
	}
	return w, nil
}

// Close is serialized with Recover. Cancel the recovery context to interrupt
// an observer before closing. Caller closure/reuse of original FDs is harmless.
func (w *ScopedCommandWitness) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	var err error
	for _, fd := range w.fds {
		if e := unix.Close(fd); e != nil {
			err = e
		}
	}
	w.fds = nil
	return err
}

// Recover requires an explicit deadline and observes ALL pinned identities
// before even opening the journal. An available flock alone is not proof that
// the direct command is quiescent. Conflicts still block the existing v3 proof.
func (w *ScopedCommandWitness) Recover(ctx context.Context, dir string, p IPv4DestinationPlan) (CommandWitnessResult, error) {
	r := CommandWitnessResult{Version: 1, Recovery: GuardianResult{ExitCode: -1}}
	if w == nil {
		return r, fmt.Errorf("command witness required")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.fds) != 3 {
		return r, fmt.Errorf("command witness closed or incomplete")
	}
	r.Witnesses = len(w.fds)
	ns, e := privateWitnessNamespace()
	if e != nil || ns != w.namespace {
		return r, fmt.Errorf("command witness namespace changed")
	}
	if _, ok := ctx.Deadline(); !ok {
		return r, fmt.Errorf("command witness recovery deadline required")
	}
	if _, e = p.Steps(); e != nil {
		return r, e
	}
	// Poll only an outstanding identity: an already-readable dead pidfd would
	// otherwise make a multi-fd poll spin while another command remains alive.
	for _, fd := range w.fds {
		for {
			if e = ctx.Err(); e != nil {
				return r, e
			}
			all, e := witnessPoll([]int{fd}, 100)
			if e != nil {
				return r, e
			}
			if all {
				break
			}
		}
	}
	if e = ctx.Err(); e != nil {
		return r, e
	}
	r.AllExitsObserved = true
	r.Recovery, e = WatchScopedIsolatedPIDFD(ctx, w.fds[0], dir, p)
	return r, e
}
