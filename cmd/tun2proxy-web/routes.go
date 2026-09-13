package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const routeTable = "38765"
const routePriority = "9000"
const routeChain = "T2P_CAPTURE"

type AppEntry struct {
	Package string `json:"package"`
	UID     int    `json:"uid"`
}
type RouteState struct {
	Boot     string     `json:"boot,omitempty"`
	Mode     string     `json:"mode"`
	UIDs     []int      `json:"uids"`
	PID      int        `json:"pid"`
	Identity string     `json:"identity"`
	Undo     [][]string `json:"undo"`
}

func appsList() ([]AppEntry, error) {
	out, err := exec.Command("pm", "list", "packages", "-U", "--user", "0").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("list apps: %v: %s", err, out)
	}
	apps := []AppEntry{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		uid, e := strconv.Atoi(strings.TrimPrefix(fields[1], "uid:"))
		if e == nil && uid >= 10000 && uid < 100000 {
			apps = append(apps, AppEntry{strings.TrimPrefix(fields[0], "package:"), uid})
		}
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i].Package < apps[j].Package })
	return apps, nil
}
func apiApps(w http.ResponseWriter, r *http.Request) {
	apps, err := appsList()
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, apps)
}
func routeStatePath() string { return filepath.Join(runDir, "routes.json") }
func readRoutes() RouteState {
	var s RouteState
	b, _ := os.ReadFile(routeStatePath())
	_ = json.Unmarshal(b, &s)
	return s
}
func withRouteLock(fn func() error) error {
	if err := os.MkdirAll(runDir, 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(runDir, "routes.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}
func routeCmd(args ...string) (string, error) {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, out)
	}
	return string(out), nil
}
func writeRoutes(s RouteState) error {
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	tmp := routeStatePath() + ".tmp"
	if e = os.WriteFile(tmp, b, 0600); e != nil {
		return e
	}
	return os.Rename(tmp, routeStatePath())
}
func cleanupRoutes() error {
	s := readRoutes()
	if s.Boot != "" && s.Boot != bootID() {
		return os.Remove(routeStatePath())
	}
	// Only commands journaled by this module are eligible for cleanup.
	failures := []string{}
	for i := len(s.Undo) - 1; i >= 0; i-- {
		out, err := routeCmd(s.Undo[i]...)
		if err != nil && !routeAlreadyAbsent(out) {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("routing cleanup incomplete (journal retained): %s", strings.Join(failures, "; "))
	}
	return os.Remove(routeStatePath())
}
func routeAlreadyAbsent(out string) bool {
	for _, message := range []string{"No such", "Bad rule", "Cannot find device", "does not exist", "No chain/target/match", "Couldn't find target `" + routeChain + "'"} {
		if strings.Contains(out, message) {
			return true
		}
	}
	return false
}
func engineIdentity(pid int) string {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil || exe != binary {
		return ""
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ""
	}
	parts := strings.Fields(string(b))
	if len(parts) < 22 {
		return ""
	}
	return parts[21]
}
func startRoutes() (err error) {
	return withRouteLock(func() (err error) {
		if e := cleanupRoutes(); e != nil && !os.IsNotExist(e) {
			return e
		}
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		mode := cfg.RouteMode
		if mode == "" || mode == "off" {
			fmt.Println("Routing disabled")
			return nil
		}
		if mode != "selected" && mode != "all" {
			return fmt.Errorf("invalid route mode")
		}
		proxy, err := url.Parse(cfg.ProxyURL)
		if err != nil {
			return err
		}
		ip := net.ParseIP(proxy.Hostname())
		if ip == nil || ip.To4() == nil || ip.IsUnspecified() {
			return fmt.Errorf("routing requires a valid IPv4 proxy address")
		}
		if cfg.DNSMode != "virtual" {
			return fmt.Errorf("capture mode requires virtual DNS")
		}
		if cfg.TunName == "" {
			cfg.TunName = "tun0"
		}
		iface, err := net.InterfaceByName(cfg.TunName)
		if err != nil || iface.Flags&net.FlagUp == 0 {
			return fmt.Errorf("TUN interface not ready")
		}
		ps := getProcessStatus()
		ident := engineIdentity(ps.PID)
		if !ps.Running || ident == "" {
			return fmt.Errorf("engine is not running")
		}
		apps, err := appsList()
		if err != nil {
			return err
		}
		known := map[string]int{}
		for _, app := range apps {
			known[app.Package] = app.UID
		}
		uids := []int{}
		seen := map[int]bool{}
		if mode == "selected" {
			for _, pkg := range cfg.AppPackages {
				uid, ok := known[pkg]
				if !ok {
					return fmt.Errorf("app unavailable in primary user: %s", pkg)
				}
				if !seen[uid] {
					uids = append(uids, uid)
					seen[uid] = true
				}
			}
			if len(uids) == 0 {
				return fmt.Errorf("select at least one app")
			}
		}
		sort.Ints(uids)
		// Refuse to take over a table/chain owned by another service.
		out, _ := routeCmd("ip", "route", "show", "table", routeTable)
		if strings.TrimSpace(out) != "" {
			return fmt.Errorf("routing table %s is already in use", routeTable)
		}
		for _, tool := range []string{"iptables", "ip6tables"} {
			if _, e := routeCmd(tool, "-w", "5", "-S", routeChain); e == nil {
				return fmt.Errorf("%s chain already exists", tool)
			}
		}
		state := RouteState{Boot: bootID(), Mode: mode, UIDs: uids, PID: ps.PID, Identity: ident}
		if err = writeRoutes(state); err != nil {
			return err
		}
		defer func() {
			if err != nil {
				_ = cleanupRoutes()
			}
		}()
		add := func(do, undo []string) error {
			state.Undo = append(state.Undo, undo)
			if e := writeRoutes(state); e != nil {
				return e
			}
			_, e := routeCmd(do...)
			return e
		}
		for _, tool := range []string{"iptables", "ip6tables"} {
			if err = add([]string{tool, "-w", "5", "-N", routeChain}, []string{tool, "-w", "5", "-X", routeChain}); err != nil {
				return err
			}
			// Flush only our dedicated chain before deleting it.
			state.Undo = append(state.Undo, []string{tool, "-w", "5", "-F", routeChain})
			if err = writeRoutes(state); err != nil {
				return err
			}
			if tool == "iptables" {
				_, err = routeCmd(tool, "-w", "5", "-A", routeChain, "-p", "udp", "!", "--dport", "53", "-j", "REJECT", "--reject-with", "icmp-port-unreachable")
			} else {
				// Keep local IPC unaffected; reject external IPv6 to avoid uncaptured traffic.
				_, err = routeCmd(tool, "-w", "5", "-A", routeChain, "-d", "::1/128", "-j", "RETURN")
				if err == nil {
					_, err = routeCmd(tool, "-w", "5", "-A", routeChain, "-j", "REJECT", "--reject-with", "icmp6-adm-prohibited")
				}
			}
			if err != nil {
				return err
			}
		}
		if err = add([]string{"ip", "route", "add", "default", "dev", cfg.TunName, "table", routeTable}, []string{"ip", "route", "del", "default", "dev", cfg.TunName, "table", routeTable}); err != nil {
			return err
		}
		bypass := append([]string{ip.String() + "/32", "127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32"}, cfg.BypassIPs...)
		seenCIDR := map[string]bool{}
		for _, cidr := range bypass {
			if !strings.Contains(cidr, "/") {
				cidr += "/32"
			}
			addr, network, e := net.ParseCIDR(cidr)
			if e != nil || addr.To4() == nil {
				return fmt.Errorf("invalid IPv4 bypass: %s", cidr)
			}
			cidr = network.String()
			if seenCIDR[cidr] {
				continue
			}
			seenCIDR[cidr] = true
			// Bypassed destinations retain their UDP behavior too (including localhost).
			if _, err = routeCmd("iptables", "-w", "5", "-I", routeChain, "1", "-d", cidr, "-j", "RETURN"); err != nil {
				return err
			}
			if err = add([]string{"ip", "route", "add", "throw", cidr, "table", routeTable}, []string{"ip", "route", "del", "throw", cidr, "table", routeTable}); err != nil {
				return err
			}
		}
		ranges := []string{}
		if mode == "all" {
			ranges = []string{"1-4294967294"}
		} else {
			for _, uid := range uids {
				ranges = append(ranges, fmt.Sprintf("%d-%d", uid, uid))
			}
		}
		for _, r := range ranges {
			for _, tool := range []string{"iptables", "ip6tables"} {
				owner := strings.ReplaceAll(r, "-", ":")
				if err = add([]string{tool, "-w", "5", "-I", "OUTPUT", "1", "-m", "owner", "--uid-owner", owner, "-j", routeChain}, []string{tool, "-w", "5", "-D", "OUTPUT", "-m", "owner", "--uid-owner", owner, "-j", routeChain}); err != nil {
					return err
				}
			}
			if err = add([]string{"ip", "rule", "add", "priority", routePriority, "uidrange", r, "lookup", routeTable}, []string{"ip", "rule", "del", "priority", routePriority, "uidrange", r, "lookup", routeTable}); err != nil {
				return err
			}
		}
		// Independent watchdog survives Web UI restarts and removes rules on engine death.
		logFile, e := os.OpenFile(filepath.Join(logDir, "routing.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		defer logFile.Close()
		watcher := exec.Command(os.Args[0], "--routes-watch", strconv.Itoa(ps.PID), ident)
		watcher.Stdout = logFile
		watcher.Stderr = logFile
		watcher.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err = watcher.Start(); err != nil {
			return err
		}
		_ = watcher.Process.Release()
		fmt.Printf("Routing active: mode=%s uids=%v; IPv6 and non-DNS UDP blocked; root excluded\n", mode, uids)
		return nil
	})
}
func routeCLI() bool {
	if len(os.Args) < 2 || !strings.HasPrefix(os.Args[1], "--routes-") {
		return false
	}
	var err error
	switch os.Args[1] {
	case "--routes-start":
		err = startRoutes()
	case "--routes-stop":
		err = withRouteLock(func() error {
			e := cleanupRoutes()
			if os.IsNotExist(e) {
				return nil
			}
			return e
		})
	case "--routes-watch":
		if len(os.Args) != 4 {
			os.Exit(2)
		}
		pid, _ := strconv.Atoi(os.Args[2])
		identity := os.Args[3]
		for {
			finished := false
			err = withRouteLock(func() error {
				s := readRoutes()
				if s.PID != pid || s.Identity != identity {
					finished = true
					return nil
				}
				if engineIdentity(pid) != identity {
					finished = true
					return cleanupRoutes()
				}
				return nil
			})
			if finished || err != nil {
				break
			}
			time.Sleep(2 * time.Second)
		}
	default:
		err = fmt.Errorf("unknown routing command")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return true
}
