// tun2proxy-web — HTTP API server for managing tun2proxy on Android (KernelSU module)
// Serves a REST API and a web control panel. Manages tun2proxy process lifecycle.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ========== Module Paths ==========

var (
	modDir     string
	binary     string
	ctlScript  string
	configFile string
	logDir     string
	runDir     string
	webrootDir string
)

func init() {
	// Module directory: env var or derive from executable path
	if d := os.Getenv("TUN2PROXY_MODDIR"); d != "" {
		modDir = d
	} else {
		exe, _ := os.Executable()
		// exe is at system/bin/tun2proxy-web, modDir is 3 levels up
		modDir = filepath.Dir(filepath.Dir(filepath.Dir(exe)))
	}

	binary = filepath.Join(modDir, "system", "bin", "tun2proxy")
	ctlScript = filepath.Join(modDir, "system", "bin", "tun2proxyctl")
	webrootDir = filepath.Join(modDir, "webroot")

	// Runtime data outside module (read-write)
	configFile = "/data/adb/tun2proxy/config.json"
	logDir = "/data/adb/tun2proxy/logs"
	runDir = "/data/adb/tun2proxy/run"

	// Override from env if set
	if d := os.Getenv("TUN2PROXY_CONFIG"); d != "" {
		configFile = d
	}
	if d := os.Getenv("TUN2PROXY_RUN_DIR"); d != "" {
		runDir = d
	}
}

// ========== Config Schema ==========

type Config struct {
	RouteMode   string   `json:"route_mode"`
	AppPackages []string `json:"app_packages"`
	Version     string   `json:"version"`
	Enabled     bool     `json:"enabled"`
	TunName     string   `json:"tun_name"`
	ProxyURL    string   `json:"proxy_url"`
	DNSMode     string   `json:"dns_mode"`
	BypassIPs   []string `json:"bypass_ips"`
	TCPTimeout  int      `json:"tcp_timeout"`
	UDPTimeout  int      `json:"udp_timeout"`
	UDPGWServer string   `json:"udpgw_server"`
}

var configMu sync.Mutex
var lifecycleMu sync.Mutex

func loadConfig() (Config, error) {
	configMu.Lock()
	defer configMu.Unlock()

	var cfg Config
	data, err := os.ReadFile(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			// Return defaults
			return Config{
				Version:    "1.0",
				TunName:    "tun0",
				DNSMode:    "virtual",
				TCPTimeout: 30,
				UDPTimeout: 30,
			}, nil
		}
		return cfg, err
	}
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		return cfg, fmt.Errorf("invalid config JSON: %w", err)
	}
	return cfg, nil
}

func saveConfig(cfg Config) error {
	profileMu.Lock()
	defer profileMu.Unlock()
	p, e := readProfiles()
	if e != nil {
		return e
	}
	old, e := loadConfig()
	if e != nil {
		return e
	}
	if e = saveRuntimeConfig(cfg); e != nil {
		return e
	}
	for i := range p.Profiles {
		if p.Profiles[i].ID == p.ActiveID {
			p.Profiles[i].Config = cfg
		}
	}
	if e = writeProfiles(p); e != nil {
		_ = saveRuntimeConfig(old)
		return e
	}
	return nil
}

func saveRuntimeConfig(cfg Config) error {
	configMu.Lock()
	defer configMu.Unlock()

	os.MkdirAll(filepath.Dir(configFile), 0755)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	f, e := os.CreateTemp(filepath.Dir(configFile), ".config-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(data); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(name, configFile)
}

// ========== Process Status ==========

type ProcessStatus struct {
	Running bool   `json:"running"`
	PID     int    `json:"pid"`
	Crashed bool   `json:"crashed"`
	Uptime  string `json:"uptime"`
}

func getProcessStatus() ProcessStatus {
	ps := ProcessStatus{}
	pidFile := filepath.Join(runDir, "tun2proxy.pid")

	data, err := os.ReadFile(pidFile)
	if err != nil {
		return ps
	}

	var pid int
	fmt.Sscanf(string(data), "%d", &pid)
	if pid <= 0 {
		return ps
	}

	// Check if process is alive
	statFile := fmt.Sprintf("/proc/%d/stat", pid)
	statData, err := os.ReadFile(statFile)
	if err != nil {
		ps.Crashed = true
		ps.PID = pid
		return ps
	}
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	cmdlineText := strings.ReplaceAll(string(cmdline), "\x00", " ")
	if err != nil || !strings.Contains(cmdlineText, "tun2proxy --tun-fd") {
		// A PID file can survive a reboot or a forced stop. It is not evidence
		// that the current boot crashed, so report a clean STOPPED state.
		_ = os.Remove(pidFile)
		return ps
	}

	ps.Running = true
	ps.PID = pid

	// Parse process start time for uptime calculation
	// /proc/[pid]/stat format: pid comm state ... starttime (field 22)
	var starttime uint64
	fields := strings.Fields(string(statData))
	if len(fields) >= 22 {
		fmt.Sscanf(fields[21], "%d", &starttime)
	}

	// Get system uptime and calculate process uptime
	uptimeData, err := os.ReadFile("/proc/uptime")
	if err == nil {
		var uptimeSec float64
		fmt.Sscanf(string(uptimeData), "%f", &uptimeSec)

		// Clock ticks per second (usually 100 on Linux/Android)
		clkTck := float64(100)
		runtime := uptimeSec - float64(starttime)/clkTck
		if runtime > 0 {
			mins := int(runtime) / 60
			secs := int(runtime) % 60
			if mins > 0 {
				ps.Uptime = fmt.Sprintf("%dm %ds", mins, secs)
			} else {
				ps.Uptime = fmt.Sprintf("%ds", secs)
			}
		}
	}

	return ps
}

// ========== Shell Execution Helpers ==========

func runCtl(args ...string) (string, error) {
	os.MkdirAll(runDir, 0755)
	os.MkdirAll(logDir, 0755)

	cmd := exec.Command("sh", append([]string{ctlScript}, args...)...)
	cmd.Env = append(os.Environ(),
		"TUN2PROXY_MODDIR="+modDir,
		"TUN2PROXY_CONFIG="+configFile,
		"TUN2PROXY_DATA=/data/adb/tun2proxy",
		"TUN2PROXY_LOG="+filepath.Join(logDir, "tun2proxy.log"),
		"TUN2PROXY_RUN_DIR="+runDir,
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ========== CORS Middleware ==========

func cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next(w, r)
	}
}

// ========== JSON Helpers ==========

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ========== API Handlers ==========

// GET /api/status
func apiStatus(w http.ResponseWriter, r *http.Request) {
	cfg, err := loadConfig()
	if err != nil {
		writeError(w, 500, "Failed to load config: "+err.Error())
		return
	}

	ps := getProcessStatus()

	// Get web backend uptime (simple approach)
	webRunning := true // we're handling the request

	writeJSON(w, 200, map[string]interface{}{
		"running":       ps.Running,
		"crashed":       ps.Crashed,
		"pid":           ps.PID,
		"uptime":        ps.Uptime,
		"web_running":   webRunning,
		"config":        cfg,
		"tun_available": tunAvailable(),
		"routing":       readRoutes(),
	})
}

// GET /api/config
func apiConfigGet(w http.ResponseWriter, r *http.Request) {
	cfg, err := loadConfig()
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, cfg)
}

// PUT /api/config
func apiConfigPut(w http.ResponseWriter, r *http.Request) {
	var cfg Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, 400, "Invalid JSON: "+err.Error())
		return
	}

	// Validate required fields
	if cfg.ProxyURL == "" {
		writeError(w, 400, "proxy_url is required")
		return
	}
	if cfg.DNSMode == "" {
		cfg.DNSMode = "virtual"
	}
	if cfg.TunName == "" {
		cfg.TunName = "tun0"
	}
	if cfg.TCPTimeout <= 0 {
		cfg.TCPTimeout = 30
	}
	if cfg.UDPTimeout <= 0 {
		cfg.UDPTimeout = 30
	}
	cfg.Version = "1.0"

	if err := saveConfig(cfg); err != nil {
		writeError(w, 500, "Failed to save config: "+err.Error())
		return
	}

	writeJSON(w, 200, map[string]interface{}{
		"ok":     true,
		"config": cfg,
	})
}

// POST /api/start
func apiStart(w http.ResponseWriter, r *http.Request) {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()

	// First save config if body is provided
	if r.Body != nil && r.ContentLength > 0 {
		var cfg Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil || cfg.ProxyURL == "" {
			writeError(w, 400, "Invalid proxy configuration")
			return
		}
		if err := saveConfig(cfg); err != nil {
			writeError(w, 500, "Cannot save configuration: "+err.Error())
			return
		}
	}

	// Check binary exists
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		writeError(w, 500, "tun2proxy binary not found. Build it from the tun2proxy/ submodule.")
		return
	}

	output, err := runCtl("start")
	if err != nil {
		writeJSON(w, 500, map[string]interface{}{
			"ok":     false,
			"error":  "Failed to start tun2proxy",
			"output": output,
		})
		return
	}

	// Wait briefly and check status
	time.Sleep(500 * time.Millisecond)
	ps := getProcessStatus()

	writeJSON(w, 200, map[string]interface{}{
		"ok":      ps.Running,
		"pid":     ps.PID,
		"running": ps.Running,
		"output":  output,
	})
}

// POST /api/stop
func apiStop(w http.ResponseWriter, r *http.Request) {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()

	output, err := runCtl("stop")
	if err != nil {
		writeJSON(w, 500, map[string]interface{}{
			"ok":     false,
			"error":  "Failed to stop tun2proxy",
			"output": output,
		})
		return
	}

	writeJSON(w, 200, map[string]interface{}{
		"ok":     true,
		"output": output,
	})
}

// POST /api/restart
func apiRestart(w http.ResponseWriter, r *http.Request) {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()

	output, err := runCtl("restart")
	if err != nil {
		writeJSON(w, 500, map[string]interface{}{
			"ok":     false,
			"error":  "Failed to restart tun2proxy",
			"output": output,
		})
		return
	}

	time.Sleep(500 * time.Millisecond)
	ps := getProcessStatus()

	writeJSON(w, 200, map[string]interface{}{
		"ok":      ps.Running,
		"pid":     ps.PID,
		"running": ps.Running,
		"output":  output,
	})
}

// GET /api/logs
func apiLogs(w http.ResponseWriter, r *http.Request) {
	lines := r.URL.Query().Get("lines")
	if lines == "" {
		lines = "200"
	}

	logFile := filepath.Join(logDir, "tun2proxy.log")
	if r.URL.Query().Get("category") == "certificate" {
		logFile = filepath.Join(logDir, "certificate.log")
	}

	// Use tail to get recent lines
	cmd := exec.Command("tail", "-n", lines, logFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// If tail fails (e.g., file doesn't exist), return empty
		if os.IsNotExist(err) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("(no log file yet — start tun2proxy to generate logs)"))
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(fmt.Sprintf("(error reading log: %v)", err)))
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(output)
}

// GET /api/check
func apiCheck(w http.ResponseWriter, r *http.Request) {
	output, _ := runCtl("check")
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(output))
}

// ========== Helpers ==========

func tunAvailable() bool {
	if _, err := os.Stat("/dev/tun"); err == nil {
		return true
	}
	if _, err := os.Stat("/dev/net/tun"); err == nil {
		return true
	}
	return false
}

// ========== Main ==========

func main() {
	if certBootCLI() {
		return
	}
	if routeCLI() {
		return
	}
	port := os.Getenv("TUN2PROXY_WEB_PORT")
	if port == "" {
		port = "8080"
	}

	// Create required directories at startup
	os.MkdirAll(logDir, 0755)
	os.MkdirAll(runDir, 0755)

	// Log startup
	log.Printf("tun2proxy-web starting on :%s", port)
	log.Printf("  modDir:      %s", modDir)
	log.Printf("  binary:      %s", binary)
	log.Printf("  ctlScript:   %s", ctlScript)
	log.Printf("  configFile:  %s", configFile)
	log.Printf("  webrootDir:  %s", webrootDir)

	mux := http.NewServeMux()
	registerCertificates(mux)
	mux.HandleFunc("/api/apps", cors(apiApps))
	mux.HandleFunc("/api/profiles", cors(apiProfiles))

	// API routes (CORS-enabled)
	mux.HandleFunc("/api/status", cors(apiStatus))
	mux.HandleFunc("/api/config", cors(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			apiConfigGet(w, r)
		case "PUT":
			apiConfigPut(w, r)
		default:
			writeError(w, 405, "Method not allowed")
		}
	}))
	mux.HandleFunc("/api/start", cors(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			writeError(w, 405, "Use POST")
			return
		}
		apiStart(w, r)
	}))
	mux.HandleFunc("/api/stop", cors(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			writeError(w, 405, "Use POST")
			return
		}
		apiStop(w, r)
	}))
	mux.HandleFunc("/api/restart", cors(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			writeError(w, 405, "Use POST")
			return
		}
		apiRestart(w, r)
	}))
	mux.HandleFunc("/api/logs", cors(apiLogs))
	mux.HandleFunc("/api/check", cors(apiCheck))

	// Health check
	mux.HandleFunc("/api/health", cors(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]interface{}{
			"status": "ok",
			"time":   time.Now().Format(time.RFC3339),
		})
	}))

	// Serve webroot static files
	fs := http.FileServer(http.Dir(webrootDir))
	mux.Handle("/", cors(func(w http.ResponseWriter, r *http.Request) {
		// Don't let FileServer handle /api/ routes
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		// Serve index.html for root
		if r.URL.Path == "/" {
			http.ServeFile(w, r, filepath.Join(webrootDir, "index.html"))
			return
		}
		fs.ServeHTTP(w, r)
	}))

	server := &http.Server{
		Addr:         "0.0.0.0:" + port,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("Listening on http://0.0.0.0:%s", port)
	log.Printf("Web UI:   http://<phone-ip>:%s", port)
	log.Printf("Status:   http://127.0.0.1:%s/api/status", port)

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
