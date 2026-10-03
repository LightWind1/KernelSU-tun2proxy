//go:build linux

package tproxy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// DurableIsolated is intentionally NOT a host-network setup API. A private
// namespace and exclusive cooperative writer are required. Version-2 pending
// intents admit only an individually verified single-operation outcome with
// unchanged residual state. Explicit version-3 mode witnesses the reserved
// footprint instead. Legacy/unverifiable intents and interfering changes
// still require investigation; journals never contain executable commands.
type DurableIsolated struct {
	mu           sync.Mutex
	root         *os.Root
	lock         *os.File
	r            journalRecord
	steps        []Step
	hook         func(string, int)         // committed-boundary crash seam, tests only
	boundaryHook func(string, string, int) // intent/applied crash seam, tests only
	closed       bool
	scoped       bool // explicit v3 mode; never silently reinterpret v1/v2 state
}

func privateFile(f *os.File) error {
	i, e := f.Stat()
	if e != nil {
		return e
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || !i.Mode().IsRegular() || i.Mode().Perm() != 0600 || s.Uid != uint32(os.Geteuid()) || s.Nlink != 1 {
		return fmt.Errorf("unsafe journal/lock file")
	}
	return nil
}

func OpenDurableIsolated(dir string, plan IPv4DestinationPlan) (*DurableIsolated, error) {
	return openDurableIsolated(dir, plan, false)
}

// OpenScopedIsolated validates only the reserved footprint. It still rejects
// the host namespace and does not expose a live setup/override mechanism.
func OpenScopedIsolated(dir string, plan IPv4DestinationPlan) (*DurableIsolated, error) {
	return openDurableIsolated(dir, plan, true)
}

func openDurableIsolated(dir string, plan IPv4DestinationPlan, scoped bool) (*DurableIsolated, error) {
	ns, e := os.Readlink("/proc/self/ns/net")
	if e != nil {
		return nil, e
	}
	host, e := os.Readlink("/proc/1/ns/net")
	if e != nil || host == ns {
		return nil, fmt.Errorf("durable controller requires private network namespace")
	}
	steps, e := plan.Steps()
	if e != nil {
		return nil, e
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return nil, e
	}
	i, e := os.Lstat(dir)
	if e != nil {
		return nil, e
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || !i.IsDir() || i.Mode().Perm() != 0700 || s.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("state directory must be private, owned, non-symlink 0700")
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		return nil, e
	}
	df, e := root.Open(".")
	if e != nil {
		root.Close()
		return nil, e
	}
	di, e := df.Stat()
	df.Close()
	if e != nil || !os.SameFile(i, di) {
		root.Close()
		return nil, fmt.Errorf("state directory changed while opening")
	}
	lock, e := root.OpenFile("lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if e != nil {
		root.Close()
		return nil, e
	}
	fail := func(e error) (*DurableIsolated, error) { lock.Close(); root.Close(); return nil, e }
	if e = privateFile(lock); e != nil {
		return fail(e)
	}
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return fail(fmt.Errorf("state locked: %w", e))
	}
	d := &DurableIsolated{root: root, lock: lock, steps: steps, r: journalRecord{Version: 2, Namespace: ns, Boot: strings.TrimSpace(string(boot)), Plan: plan}}
	d.scoped = scoped
	if scoped {
		d.r.Version = 3
	}
	f, e := root.OpenFile("journal.json", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if os.IsNotExist(e) {
		return d, nil
	}
	if e != nil {
		return fail(e)
	}
	defer f.Close()
	if e = privateFile(f); e != nil {
		return fail(e)
	}
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil {
		return fail(e)
	}
	d.r, e = decodeJournalMode(b, plan, ns, d.r.Boot, scoped)
	if e != nil {
		return fail(e)
	}
	return d, nil
}

func (d *DurableIsolated) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	e := d.lock.Close()
	re := d.root.Close()
	if e != nil {
		return e
	}
	return re
}

func isolatedSnapshot() (string, error) {
	outputs, e := captureNamespace()
	if e != nil {
		return "", e
	}
	return stateDigest(outputs), nil
}

func (d *DurableIsolated) save() error {
	b, e := json.Marshal(d.r)
	if e != nil {
		return e
	}
	// A crash may leave this private staging file. Only this exact, owned
	// staging name is replaced; it is never interpreted or followed.
	if e = d.root.Remove("journal.next"); e != nil && !os.IsNotExist(e) {
		return e
	}
	f, e := d.root.OpenFile("journal.next", os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = d.root.Rename("journal.next", "journal.json"); e != nil {
		return e
	}
	dir, e := d.root.Open(".")
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}

func (d *DurableIsolated) check() error {
	if d.closed {
		return fmt.Errorf("controller closed")
	}
	if d.r.Pending != "" {
		return fmt.Errorf("uncertain %s intent: refusing automatic recovery", d.r.Pending)
	}
	s, e := d.snapshot()
	if e != nil {
		return e
	}
	if d.r.Snapshot != "" && s != d.r.Snapshot {
		return fmt.Errorf("external resource change: refusing recovery")
	}
	return nil
}

func (d *DurableIsolated) snapshot() (string, error) {
	if !d.scoped {
		return isolatedSnapshot()
	}
	w, e := observeScoped(d.r.Plan)
	if e == nil && !countsMatch(w.Counts, d.r.Owned) {
		return "", fmt.Errorf("scoped owned-resource profile differs")
	}
	return w.Digest, e
}

func (d *DurableIsolated) witness(index int) (resourceWitness, error) {
	if !d.scoped {
		return observeResources(d.r.Plan)
	}
	w, e := observeScoped(d.r.Plan)
	return resourceWitness{Counts: w.Counts, Whole: w.Digest, Residual: w.excluding(index)}, e
}

func (d *DurableIsolated) Setup() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if e := d.check(); e != nil {
		return e
	}
	if d.r.Owned == len(d.steps) {
		return nil
	}
	if d.r.Owned != 0 {
		return fmt.Errorf("recover partial setup before starting")
	}
	if d.scoped {
		w, e := observeScoped(d.r.Plan)
		if e != nil {
			return e
		}
		if !countsMatch(w.Counts, 0) {
			return fmt.Errorf("pre-existing reserved resources cannot be adopted")
		}
		d.r.Snapshot = w.Digest
		if e = d.save(); e != nil {
			return e
		}
		for d.r.Owned < len(d.steps) {
			if e = d.change("add"); e != nil {
				return e
			}
		}
		return nil
	}
	// Only fresh private namespaces are admitted. This is conservative and
	// deliberately unsuitable for adoption of Android's live firewall.
	fw := query([]string{"iptables", "-w", "2", "-t", "mangle", "-S"})
	if e := commandError(fw); e != nil {
		return e
	}
	if strings.Contains(fw.Output, "-A ") || strings.Contains(fw.Output, "-N ") {
		return fmt.Errorf("nonempty private firewall")
	}
	rules := query([]string{"ip", "rule", "show"})
	if e := commandError(rules); e != nil {
		return e
	}
	for _, line := range strings.Split(rules.Output, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && f[0] != "0:" && f[0] != "32766:" && f[0] != "32767:" {
			return fmt.Errorf("nondefault private policy")
		}
	}
	routes := query([]string{"ip", "route", "show", "table", "all"})
	if e := commandError(routes); e != nil {
		return e
	}
	for _, line := range strings.Split(routes.Output, "\n") {
		loopback := strings.Contains(line, "dev lo") && (strings.Contains(line, "127.") || strings.HasPrefix(line, "local ::1 dev lo "))
		if line != "" && !loopback {
			return fmt.Errorf("nondefault private route: %s", line)
		}
	}
	var e error
	d.r.Snapshot, e = isolatedSnapshot()
	if e != nil {
		return e
	}
	if e = d.save(); e != nil {
		return e
	}
	for d.r.Owned < len(d.steps) {
		if e = d.change("add"); e != nil {
			return e
		}
	}
	return nil
}

func (d *DurableIsolated) change(intent string) error {
	if e := d.check(); e != nil {
		return e
	}
	index := d.r.Owned
	if intent == "remove" {
		index--
	}
	w, e := d.witness(index)
	if e != nil {
		return e
	}
	if w.Whole != d.r.Snapshot || !countsMatch(w.Counts, d.r.Owned) {
		return fmt.Errorf("owned resources differ before intent")
	}
	before := d.r
	d.r.Version = 2
	if d.scoped {
		d.r.Version = 3
	}
	d.r.Pending = intent
	d.r.PendingProof = w.Residual
	if e := d.save(); e != nil {
		return e
	} // write intent before mutating the kernel
	if d.boundaryHook != nil {
		d.boundaryHook("intent", intent, d.r.Owned)
	}
	var args []string
	if intent == "add" {
		args = d.steps[index].Add
	} else {
		args = d.steps[index].Remove
	}
	if e := commandError(query(args)); e != nil {
		return e
	} // completion may be ambiguous
	if d.boundaryHook != nil {
		d.boundaryHook("applied", intent, d.r.Owned)
	}
	if intent == "add" {
		d.r.Owned++
	} else {
		d.r.Owned--
	}
	s, e := d.snapshot()
	if e != nil {
		d.r.Owned = before.Owned
		return e
	}
	d.r.Snapshot = s
	d.r.Pending = ""
	d.r.PendingProof = ""
	if e = d.save(); e != nil {
		d.r.Owned = before.Owned
		d.r.Snapshot = before.Snapshot
		d.r.Pending = intent
		d.r.PendingProof = w.Residual
		return e
	}
	if d.hook != nil {
		d.hook(intent, d.r.Owned)
	}
	return nil
}

// Recover disables the entrance first, then removes exact owned dependencies.
// Committed and precisely witnessed version-2/explicit-v3 pending boundaries
// are supported; neither mode is admitted on the host network namespace.
func (d *DurableIsolated) Recover() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return fmt.Errorf("controller closed")
	}
	if d.r.Pending != "" {
		if e := d.reconcile(); e != nil {
			return e
		}
	}
	if e := d.check(); e != nil {
		return e
	}
	for d.r.Owned > 0 {
		if e := d.change("remove"); e != nil {
			return e
		}
	}
	return nil
}

// reconcile admits only the two precisely witnessed outcomes: no operation,
// or exactly one planned resource addition/removal. Strict mode requires an
// unchanged residual; scoped mode requires the other seven resources unchanged.
func (d *DurableIsolated) reconcile() error {
	if (d.r.Version != 2 && d.r.Version != 3) || d.r.PendingProof == "" {
		return fmt.Errorf("unwitnessed legacy intent: refusing recovery")
	}
	index := d.r.Owned
	if d.r.Pending == "remove" {
		index--
	}
	w, e := d.witness(index)
	if e != nil {
		return e
	}
	if w.Residual != d.r.PendingProof {
		return fmt.Errorf("foreign change during pending intent")
	}
	owned := d.r.Owned
	after := owned + 1
	if d.r.Pending == "remove" {
		after = owned - 1
	}
	if countsMatch(w.Counts, after) {
		owned = after
	} else if !countsMatch(w.Counts, owned) {
		return fmt.Errorf("pending outcome not a single planned operation")
	}
	old := d.r
	d.r.Owned = owned
	d.r.Snapshot = w.Whole
	d.r.Pending = ""
	d.r.PendingProof = ""
	if e = d.save(); e != nil {
		d.r = old
		return e
	}
	return nil
}

func (d *DurableIsolated) ResolvePending() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return fmt.Errorf("controller closed")
	}
	if d.r.Pending != "" {
		return d.reconcile()
	}
	return d.check()
}
