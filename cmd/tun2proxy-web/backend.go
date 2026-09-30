package main

// Integration only: the independently buildable core never reads module config.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func backendName(c Config) string {
	if c.Backend == "ebpf" {
		return "ebpf"
	}
	return "tun"
}
func validateBackend(c Config) error {
	if c.Backend != "" && c.Backend != "tun" && c.Backend != "ebpf" {
		return errors.New("unknown proxy backend")
	}
	if c.EBPFPort < 0 || c.EBPFPort > 65535 {
		return errors.New("invalid eBPF listener port")
	}
	if backendName(c) == "ebpf" {
		u, e := url.Parse(c.ProxyURL)
		if e != nil || (u.Scheme != "socks5" && u.Scheme != "socks5h") {
			return errors.New("eBPF requires a real SOCKS5 upstream; HTTP CONNECT is not converted automatically")
		}
	}
	return nil
}
func ebpfBinary() string  { return filepath.Join(modDir, "system", "bin", "ebpf-proxy") }
func ebpfRuntime() string { return filepath.Join(runDir, "ebpf") }
func ebpfCommand(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, ebpfBinary(), args...).CombinedOutput()
}
func ebpfStatus() map[string]any {
	s := map[string]any{"running": false, "programs_loaded": false}
	if _, e := os.Stat(filepath.Join(ebpfRuntime(), "control.sock")); e != nil {
		return s
	}
	b, e := ebpfCommand("status", "--runtime-dir", ebpfRuntime())
	if e == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}
func getProcessStatus() ProcessStatus {
	ps := getTunProcessStatus()
	if ps.Running {
		return ps
	}
	s := ebpfStatus()
	if running, _ := s["running"].(bool); running {
		ps = ProcessStatus{Running: true}
		if pid, ok := s["pid"].(float64); ok {
			ps.PID = int(pid)
		}
	}
	return ps
}
func ebpfConfig(c Config, apps []AppEntry) (map[string]any, error) {
	if e := validateBackend(c); e != nil {
		return nil, e
	}
	u, e := url.Parse(c.ProxyURL)
	if e != nil || u.Hostname() == "" {
		return nil, errors.New("invalid upstream")
	}
	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return nil, errors.New("choose SOCKS5 before testing eBPF upstream")
	}
	port, e := strconv.Atoi(u.Port())
	if e != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid upstream port")
	}
	upstream := map[string]any{"type": "socks5", "host": u.Hostname(), "port": port}
	if u.User != nil {
		upstream["username"] = u.User.Username()
		password, _ := u.User.Password()
		upstream["password"] = password
	}
	mode := "uid_allowlist"
	uids := []uint32{}
	known := map[string]int{}
	seen := map[int]bool{}
	for _, a := range apps {
		known[a.Package] = a.UID
	}
	switch c.RouteMode {
	case "", "off":
	case "all":
		mode = "all_non_bypass"
	case "selected":
		for _, pkg := range c.AppPackages {
			uid, ok := known[pkg]
			if !ok || uid < 10000 {
				return nil, fmt.Errorf("app unavailable: %s", pkg)
			}
			if !seen[uid] {
				uids = append(uids, uint32(uid))
				seen[uid] = true
			}
		}
		if len(uids) == 0 {
			return nil, errors.New("select at least one app")
		}
	default:
		return nil, errors.New("invalid route mode")
	}
	bypass := []string{}
	for _, v := range c.BypassIPs {
		if ip := net.ParseIP(v); ip != nil {
			if ip.To4() != nil {
				v += "/32"
			} else {
				v += "/128"
			}
		}
		if _, _, e := net.ParseCIDR(v); e != nil {
			return nil, errors.New("invalid bypass IP/CIDR")
		}
		bypass = append(bypass, v)
	}
	lp := c.EBPFPort
	if lp == 0 {
		lp = 18080
	}
	return map[string]any{"version": 1, "listener": map[string]any{"address": "127.0.0.1", "port": lp}, "ipv6": true, "upstream": upstream, "policy": map[string]any{"mode": mode, "uids": uids, "bypass_uids": []uint32{0}, "bypass_cidrs": bypass}, "udp": map[string]string{"mode": "pass"}, "bpf": map[string]string{"object": filepath.Join(modDir, "system", "bpf", "redirect.bpf.o"), "cgroup": "/sys/fs/cgroup"}, "runtime_dir": ebpfRuntime(), "logging": map[string]string{"level": "info"}, "connect_timeout_seconds": 5, "idle_timeout_seconds": 300, "max_connections": 4096}, nil
}
func writeEBPFConfig(c Config) (string, error) {
	var apps []AppEntry
	var e error
	if c.RouteMode == "selected" {
		apps, e = appsList()
		if e != nil {
			return "", e
		}
	}
	core, e := ebpfConfig(c, apps)
	if e != nil {
		return "", e
	}
	dir := ebpfRuntime()
	if e = os.MkdirAll(dir, 0700); e != nil {
		return "", e
	}
	if e = os.Chmod(dir, 0700); e != nil {
		return "", e
	}
	path := filepath.Join(dir, "config.json")
	b, _ := json.MarshalIndent(core, "", "  ")
	f, e := os.CreateTemp(dir, ".config-")
	if e != nil {
		return "", e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(b); e != nil {
		f.Close()
		return "", e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return "", e
	}
	f.Close()
	return path, os.Rename(f.Name(), path)
}
func legacyCtl(action string) (string, error) {
	cmd := exec.Command("sh", ctlScript, action)
	cmd.Env = append(os.Environ(), "TUN2PROXY_LEGACY_CTL=1", "TUN2PROXY_MODDIR="+modDir, "TUN2PROXY_CONFIG="+configFile, "TUN2PROXY_RUN_DIR="+runDir, "TUN2PROXY_DATA="+filepath.Dir(runDir), "TUN2PROXY_LOG="+filepath.Join(filepath.Dir(runDir), "logs", "tun2proxy.log"))
	b, e := cmd.CombinedOutput()
	return string(b), e
}
func backendAction(action string) (string, error) {
	if e := os.MkdirAll(runDir, 0755); e != nil {
		return "", e
	}
	lock, e := os.OpenFile(filepath.Join(runDir, "backend.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return "", e
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); e != nil {
		return "", e
	}
	c, e := loadConfig()
	if e != nil {
		return "", e
	}
	stop := func() (string, error) {
		s := ebpfStatus()
		if loaded, _ := s["programs_loaded"].(bool); loaded {
			pid, _ := s["pid"].(float64)
			b, e := ebpfCommand("stop", "--runtime-dir", ebpfRuntime())
			if e != nil {
				return string(b), e
			}
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", int(pid)))
				if !strings.HasPrefix(string(cmdline), ebpfBinary()+"\x00") {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", int(pid)))
			if strings.HasPrefix(string(cmdline), ebpfBinary()+"\x00") {
				return "", errors.New("eBPF daemon has not finished stopping")
			}
		}
		return legacyCtl("stop")
	}
	if action == "stop" {
		return stop()
	}
	if action == "restart" {
		if _, e = stop(); e != nil {
			return "", e
		}
		action = "start"
	}
	if action == "auto-start" {
		if !c.Enabled {
			return "auto-start disabled", nil
		}
		action = "start"
	}
	if action != "start" {
		return "", errors.New("unsupported backend action")
	}
	if e = validateBackend(c); e != nil {
		return "", e
	}
	if getProcessStatus().Running {
		erunning, _ := ebpfStatus()["running"].(bool)
		if (erunning && backendName(c) == "ebpf") || (!erunning && backendName(c) == "tun") {
			return "proxy already running", nil
		}
		return "", errors.New("stop running backend before switching")
	}
	if backendName(c) == "tun" {
		return legacyCtl("start")
	}
	// Never take over a still-installed TUN routing journal or create any routes.
	if len(readRoutes().Undo) > 0 {
		return "", errors.New("stop TUN routing before eBPF start")
	}
	path, e := writeEBPFConfig(c)
	if e != nil {
		return "", e
	}
	b, e := ebpfCommand("check", "--config", path)
	if e != nil {
		return string(b), fmt.Errorf("eBPF preflight failed: %s", b)
	}
	if e = os.MkdirAll(logDir, 0755); e != nil {
		return "", e
	}
	logPath := filepath.Join(logDir, "ebpf.log")
	f, e := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return "", e
	}
	defer f.Close()
	cmd := exec.Command(ebpfBinary(), "run", "--config", path)
	cmd.Stdout = f
	cmd.Stderr = f
	if e = cmd.Start(); e != nil {
		return "", e
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case e := <-done:
			data, _ := os.ReadFile(logPath)
			if len(data) > 4096 {
				data = data[len(data)-4096:]
			}
			return string(data), fmt.Errorf("eBPF exited before ready: %v", e)
		default:
		}
		if running, _ := ebpfStatus()["running"].(bool); running {
			return "eBPF backend ready", nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	<-done
	return "", errors.New("eBPF readiness timeout; native links detached")
}
func backendCLI() bool {
	if len(os.Args) != 3 || os.Args[1] != "--backend-action" {
		return false
	}
	out, e := backendAction(os.Args[2])
	fmt.Println(out)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	return true
}
func apiEBPF(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		writeJSON(w, 200, ebpfStatus())
		return
	}
	if r.Method != "POST" {
		writeError(w, 405, "Use GET/POST")
		return
	}
	var req struct {
		Action string `json:"action"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req) != nil {
		writeError(w, 400, "invalid request")
		return
	}
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	if req.Action == "check" {
		b, e := ebpfCommand("check-cgroup", "--object", filepath.Join(modDir, "system", "bpf", "redirect.bpf.o"), "--cgroup", "/sys/fs/cgroup")
		if e != nil {
			msg := strings.TrimSpace(string(b))
			if msg == "" {
				msg = "eBPF binary unavailable or preflight timed out"
			}
			writeError(w, 400, msg)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "output": strings.TrimSpace(string(b))})
		return
	}
	c, e := loadConfig()
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	path, e := writeEBPFConfig(c)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	command := "check"
	if req.Action == "upstream" {
		command = "probe-upstream"
	} else if req.Action != "check" {
		writeError(w, 400, "unknown action")
		return
	}
	b, e := ebpfCommand(command, "--config", path)
	if e != nil {
		msg := strings.TrimSpace(string(b))
		if msg == "" {
			msg = "eBPF binary unavailable or check timed out"
		}
		writeError(w, 400, msg)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "output": strings.TrimSpace(string(b))})
}
