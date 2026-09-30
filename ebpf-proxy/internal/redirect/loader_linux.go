//go:build linux

package redirect

import (
	"ebpf-proxy/internal/config"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"
	"unsafe"
)

type Manager struct {
	collection *ebpf.Collection
	links      []*link.RawLink
	policy     Policy
	mu         sync.Mutex
}

func MonotonicNS() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Nano())
}
func QueryCgroup(fd int, attach ebpf.AttachType) (uint32, []uint32, error) {
	var q struct {
		Target, Attach, QueryFlags, Flags uint32
		IDs                               uint64
		Count, Pad                        uint32
		PerProgramFlags                   uint64
	}
	ids := make([]uint32, 64)
	q.Target = uint32(fd)
	q.Attach = uint32(attach)
	q.IDs = uint64(uintptr(unsafe.Pointer(&ids[0])))
	q.Count = uint32(len(ids))
	_, _, errno := unix.Syscall(unix.SYS_BPF, 16, uintptr(unsafe.Pointer(&q)), unsafe.Sizeof(q))
	runtime.KeepAlive(ids)
	if errno != 0 {
		return 0, nil, errno
	}
	if int(q.Count) > len(ids) {
		return 0, nil, errors.New("too many existing cgroup programs")
	}
	return q.Flags, ids[:q.Count], nil
}

// Do not replace, detach, or override the effective programs of another owner.
func CheckCgroup(path string, ipv6 bool) error {
	path, e := filepath.EvalSymlinks(path)
	if e != nil {
		return e
	}
	var initial unix.Statfs_t
	if e = unix.Statfs(path, &initial); e != nil {
		return e
	}
	if initial.Type != unix.CGROUP2_SUPER_MAGIC {
		return errors.New("target is not a cgroup v2 directory")
	}
	for {
		var fs unix.Statfs_t
		if e = unix.Statfs(path, &fs); e != nil {
			return e
		}
		if fs.Type != unix.CGROUP2_SUPER_MAGIC {
			break
		}
		f, e := os.Open(path)
		if e != nil {
			return e
		}
		types := []ebpf.AttachType{ebpf.AttachCGroupInet4Connect, ebpf.AttachCGroupSockOps}
		if ipv6 {
			types = append(types, ebpf.AttachCGroupInet6Connect)
		}
		for _, typ := range types {
			flags, ids, e := QueryCgroup(int(f.Fd()), typ)
			if e != nil {
				f.Close()
				return fmt.Errorf("cgroup query %s: %w", path, e)
			}
			if len(ids) > 0 && flags != 2 {
				f.Close()
				return fmt.Errorf("cgroup %s hook %s has exclusive/overriding programs %v flags=%d; preserve existing programs: backend unavailable", path, typ, ids, flags)
			}
		}
		f.Close()
		parent := filepath.Dir(path)
		if parent == path {
			break
		}
		path = parent
	}
	return nil
}
func Load(cfg config.Config) (*Manager, error) {
	if cfg.BPF.Object == "" || cfg.BPF.Cgroup == "" {
		return nil, errors.New("BPF object and cgroup are required")
	}
	if e := CheckCgroup(cfg.BPF.Cgroup, cfg.IPv6); e != nil {
		return nil, e
	}
	_ = rlimit.RemoveMemlock()
	spec, e := ebpf.LoadCollectionSpec(cfg.BPF.Object)
	if e != nil {
		return nil, e
	}
	for name, sizes := range map[string][2]uint32{"target_uid_map": {4, 4}, "bypass_uid_map": {4, 4}, "config_map": {4, 40}, "socket_store": {4, 48}, "flow_map": {48, 48}, "bypass_prefix": {20, 4}, "bypass_prefix6": {20, 4}, "stats_map": {4, 8}} {
		s := spec.Maps[name]
		if s == nil || s.KeySize != sizes[0] || s.ValueSize != sizes[1] {
			return nil, fmt.Errorf("BPF map %s missing or ABI mismatch", name)
		}
	}
	coll, e := ebpf.NewCollection(spec)
	if e != nil {
		return nil, fmt.Errorf("load BPF (verifier): %w", e)
	}
	m := &Manager{collection: coll}
	success := false
	defer func() {
		if !success {
			m.Close()
		}
	}()
	m.policy = Policy{Version: ABIVersion, Port: uint16(cfg.Listener.Port), LeaseNS: uint64(3 * time.Second)}
	copy(m.policy.IPv4[:], net.ParseIP(cfg.Listener.Address).To4())
	if cfg.IPv6 {
		m.policy.IPv6 = 1
	}
	if cfg.Policy.Mode == "all_non_bypass" {
		m.policy.AllNonBypass = 1
	}
	for _, uid := range cfg.Policy.UIDs {
		if e = m.UID("add", uid); e != nil {
			return nil, e
		}
	}
	bypass := append(append([]uint32{}, cfg.Policy.BypassUIDs...), uint32(os.Geteuid()))
	for _, uid := range bypass {
		if e = coll.Maps["bypass_uid_map"].Put(uid, uint32(1)); e != nil {
			return nil, e
		}
	}
	for _, cidr := range cfg.Policy.BypassCIDRs {
		p, e := netip.ParsePrefix(cidr)
		if e != nil {
			return nil, e
		}
		key := Prefix{Bits: uint32(p.Bits()), Address: p.Masked().Addr().As16()}
		if p.Addr().Is4() {
			key.Bits += 96
		}
		name := "bypass_prefix6"
		if p.Addr().Is4() {
			name = "bypass_prefix"
		}
		if e = coll.Maps[name].Put(key, uint32(1)); e != nil {
			return nil, e
		}
	}
	if e = m.SetEnabled(false); e != nil {
		return nil, e
	}
	f, e := os.Open(cfg.BPF.Cgroup)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	names := []string{"ep_sockops", "ep_connect4"}
	if cfg.IPv6 {
		names = append(names, "ep_connect6")
	}
	types := map[string]ebpf.AttachType{"ep_sockops": ebpf.AttachCGroupSockOps, "ep_connect4": ebpf.AttachCGroupInet4Connect, "ep_connect6": ebpf.AttachCGroupInet6Connect}
	for _, name := range names {
		p := coll.Programs[name]
		if p == nil {
			return nil, fmt.Errorf("BPF object missing %s", name)
		}
		l, e := link.AttachRawLink(link.RawLinkOptions{Target: int(f.Fd()), Program: p, Attach: types[name]})
		if e != nil {
			return nil, fmt.Errorf("native cgroup link %s: %w", name, e)
		}
		m.links = append(m.links, l)
	}
	success = true
	return m, nil
}
func (m *Manager) SetEnabled(enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if enabled {
		m.policy.Enabled = 1
	} else {
		m.policy.Enabled = 0
	}
	m.policy.HeartbeatNS = MonotonicNS()
	return m.collection.Maps["config_map"].Put(uint32(0), m.policy)
}
func (m *Manager) Heartbeat() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policy.HeartbeatNS = MonotonicNS()
	return m.collection.Maps["config_map"].Put(uint32(0), m.policy)
}
func (m *Manager) Close() {
	if m.collection == nil {
		return
	}
	_ = m.SetEnabled(false)
	m.Detach()
	m.collection.Close()
	m.collection = nil
}
func (m *Manager) Detach() {
	for i := len(m.links) - 1; i >= 0; i-- {
		m.links[i].Close()
	}
	m.links = nil
}
func (m *Manager) UID(action string, uid uint32) error {
	table := m.collection.Maps["target_uid_map"]
	switch action {
	case "add":
		return table.Put(uid, uint32(1))
	case "del":
		e := table.Delete(uid)
		if errors.Is(e, ebpf.ErrKeyNotExist) {
			return nil
		}
		return e
	case "clear":
		for _, id := range m.UIDs() {
			if e := table.Delete(id); e != nil {
				return e
			}
		}
		return nil
	}
	return errors.New("invalid UID action")
}
func (m *Manager) UIDs() []uint32 {
	result := []uint32{}
	var key, value uint32
	it := m.collection.Maps["target_uid_map"].Iterate()
	for it.Next(&key, &value) {
		result = append(result, key)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}
func (m *Manager) Resolve(c net.Conn) (FlowValue, error) {
	remote, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return FlowValue{}, errors.New("invalid client address")
	}
	local, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok {
		return FlowValue{}, errors.New("invalid listener address")
	}
	key := FlowKey{Version: ABIVersion, Protocol: 6, ClientPort: uint16(remote.Port), ListenerPort: uint16(local.Port)}
	if remote.IP.To4() != nil && local.IP.To4() != nil {
		key.Family = 2
		copy(key.Client[:4], remote.IP.To4())
		copy(key.Listener[:4], local.IP.To4())
	} else {
		key.Family = 10
		copy(key.Client[:], remote.IP.To16())
		copy(key.Listener[:], local.IP.To16())
	}
	var v FlowValue
	table := m.collection.Maps["flow_map"]
	for i := 0; i < 10; i++ {
		e := table.Lookup(key, &v)
		if e == nil {
			if v.Version != ABIVersion || v.Cookie == 0 || v.Family != key.Family || MonotonicNS()-v.CreatedNS > uint64(30*time.Second) {
				return v, errors.New("invalid/stale flow metadata")
			}
			_ = table.Delete(key)
			return v, nil
		}
		if !errors.Is(e, ebpf.ErrKeyNotExist) {
			return v, e
		}
		time.Sleep(5 * time.Millisecond)
	}
	return v, errors.New("original destination unavailable")
}
func (v FlowValue) Address() string {
	ip := net.IP(v.Destination[:])
	if v.Family == 2 {
		ip = net.IP(v.Destination[:4])
	}
	return net.JoinHostPort(ip.String(), fmt.Sprint(v.Port))
}
func (m *Manager) Flows() []map[string]any {
	out := []map[string]any{}
	var k FlowKey
	var v FlowValue
	it := m.collection.Maps["flow_map"].Iterate()
	for it.Next(&k, &v) {
		out = append(out, map[string]any{"uid": v.UID, "cookie": v.Cookie, "original": v.Address(), "age_ms": (MonotonicNS() - v.CreatedNS) / 1000000})
	}
	return out
}
func (m *Manager) Sweep() {
	var k FlowKey
	var v FlowValue
	table := m.collection.Maps["flow_map"]
	it := table.Iterate()
	for it.Next(&k, &v) {
		if MonotonicNS()-v.CreatedNS > uint64(60*time.Second) {
			var current FlowValue
			if table.Lookup(k, &current) == nil && current.Cookie == v.Cookie {
				_ = table.Delete(k)
			}
		}
	}
}
func (m *Manager) Counters() map[string]uint64 {
	out := map[string]uint64{}
	names := []string{"redirect", "policy_pass", "bypass", "metadata_failures", "flow_published"}
	for i, name := range names {
		var values []uint64
		if m.collection.Maps["stats_map"].Lookup(uint32(i), &values) == nil {
			for _, v := range values {
				out[name] += v
			}
		}
	}
	return out
}
