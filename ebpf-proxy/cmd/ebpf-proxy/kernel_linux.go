//go:build linux

package main

import (
	"ebpf-proxy/internal/config"
	"ebpf-proxy/internal/daemon"
	"encoding/json"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"unsafe"
)

func runNative(c config.Config) error { return daemon.Run(c) }
func verifyObject(path string) error {
	spec, e := ebpf.LoadCollectionSpec(path)
	if e != nil {
		return e
	}
	_ = rlimit.RemoveMemlock()
	c, e := ebpf.NewCollection(spec)
	if e != nil {
		return fmt.Errorf("BPF verifier: %+v", e)
	}
	defer c.Close()
	fmt.Printf("verified %d programs and %d maps (not attached)\n", len(c.Programs), len(c.Maps))
	return nil
}
func controlNative(dir, command string, args []string) error {
	req := daemon.Request{Action: command}
	if command == "uid" {
		if len(args) < 1 {
			return fmt.Errorf("uid requires add|del|clear|list")
		}
		req.Action = "uid-" + args[0]
		if args[0] == "add" || args[0] == "del" {
			if len(args) != 2 {
				return fmt.Errorf("uid add/del requires numeric UID")
			}
			v, e := strconv.ParseUint(args[1], 10, 32)
			if e != nil {
				return e
			}
			req.UID = uint32(v)
		}
	}
	if command == "debug" {
		if len(args) != 1 || args[0] != "flows" {
			return fmt.Errorf("debug requires flows")
		}
		req.Action = "flows"
	}
	b, e := daemon.Control(dir, req)
	if e != nil {
		return e
	}
	fmt.Println(string(b))
	return nil
}

func probeKernel() error {
	result := map[string]string{}
	record := func(name string, e error) {
		if e == nil {
			result[name] = "supported"
		} else {
			result[name] = e.Error()
		}
	}
	record("memlock", rlimit.RemoveMemlock())
	if root, e := os.Open("/sys/fs/cgroup"); e == nil {
		for name, attach := range map[string]ebpf.AttachType{"connect4": ebpf.AttachCGroupInet4Connect, "connect6": ebpf.AttachCGroupInet6Connect, "sockops": ebpf.AttachCGroupSockOps} {
			var query struct {
				Target, Attach, QueryFlags, AttachFlags uint32
				IDs                                     uint64
				Count, Pad                              uint32
				PerProgramFlags                         uint64
			}
			ids := make([]uint32, 64)
			query.Target = uint32(root.Fd())
			query.Attach = uint32(attach)
			query.IDs = uint64(uintptr(unsafe.Pointer(&ids[0])))
			query.Count = 64
			_, _, errno := unix.Syscall(unix.SYS_BPF, 16, uintptr(unsafe.Pointer(&query)), unsafe.Sizeof(query))
			runtime.KeepAlive(ids)
			if errno != 0 {
				record("root_"+name+"_query", errno)
			} else {
				count := int(query.Count)
				if count > len(ids) {
					count = len(ids)
				}
				result["root_"+name+"_query"] = fmt.Sprintf("flags=%d program_ids=%v", query.AttachFlags, ids[:count])
				for _, id := range ids[:count] {
					if p, e := ebpf.NewProgramFromID(ebpf.ProgramID(id)); e == nil {
						if info, e := p.Info(); e == nil {
							result[fmt.Sprintf("program_%d", id)] = info.Name
						}
						p.Close()
					}
				}
			}
		}
		root.Close()
	}
	for name, typ := range map[string]ebpf.MapType{"hash": ebpf.Hash, "lru_hash": ebpf.LRUHash, "sk_storage": ebpf.SkStorage, "ringbuf": ebpf.RingBuf} {
		record("map_"+name, features.HaveMapType(typ))
	}
	record("cgroup_sock_addr", features.HaveProgramType(ebpf.CGroupSockAddr))
	record("sockops", features.HaveProgramType(ebpf.SockOps))
	record("connect_cookie", features.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnGetSocketCookie))
	record("sockops_cookie", features.HaveProgramHelper(ebpf.SockOps, asm.FnGetSocketCookie))
	record("connect_sk_storage", features.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnSkStorageGet))
	record("sockops_sk_storage", features.HaveProgramHelper(ebpf.SockOps, asm.FnSkStorageGet))
	_, btfErr := os.Stat("/sys/kernel/btf/vmlinux")
	record("kernel_btf_file", btfErr)
	cg := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("ebpf-probe-%d", os.Getpid()))
	e := os.Mkdir(cg, 0700)
	record("private_cgroup_create", e)
	if e == nil {
		defer os.Remove(cg)
		f, e := os.Open(cg)
		if e == nil {
			defer f.Close()
			for name, attach := range map[string]ebpf.AttachType{"connect4": ebpf.AttachCGroupInet4Connect, "connect6": ebpf.AttachCGroupInet6Connect, "sockops": ebpf.AttachCGroupSockOps} {
				typ := ebpf.CGroupSockAddr
				if name == "sockops" {
					typ = ebpf.SockOps
				}
				p, e := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "probe_" + name, Type: typ, AttachType: attach, License: "Dual MIT/GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()}})
				record(name+"_load", e)
				if e != nil {
					continue
				}
				l, e := link.AttachRawLink(link.RawLinkOptions{Target: int(f.Fd()), Program: p, Attach: attach})
				record(name+"_native_link", e)
				if e == nil {
					l.Close()
				}
				p.Close()
			}
		} else {
			record("private_cgroup_open", e)
		}
	}
	b, e := json.MarshalIndent(result, "", "  ")
	if e != nil {
		return e
	}
	fmt.Println(string(b))
	return nil
}
