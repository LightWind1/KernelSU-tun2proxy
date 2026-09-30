//go:build linux

package daemon

import (
	"bytes"
	"context"
	"ebpf-proxy/internal/config"
	"ebpf-proxy/internal/redirect"
	"ebpf-proxy/internal/relay"
	"ebpf-proxy/internal/upstream"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Request struct {
	Action string `json:"action"`
	UID    uint32 `json:"uid,omitempty"`
}

func socketPath(dir string) string { return filepath.Join(dir, "control.sock") }
func secureRuntime(dir string) (*os.File, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("runtime_dir must be an absolute private directory")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	st, e := os.Lstat(dir)
	if e != nil {
		return nil, e
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("runtime_dir must be private non-symlink directory (0700)")
	}
	fd, e := unix.Open(filepath.Join(dir, "daemon.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "daemon.lock")
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("daemon already running or lock unavailable")
	}
	return f, nil
}
func Run(cfg config.Config) error {
	if e := redirect.CheckCgroup(cfg.BPF.Cgroup, cfg.IPv6); e != nil {
		return e
	}
	lock, e := secureRuntime(cfg.RuntimeDir)
	if e != nil {
		return e
	}
	defer lock.Close()
	var level slog.Level
	switch cfg.Logging.Level {
	case "error":
		level = slog.LevelError
	case "warn":
		level = slog.LevelWarn
	case "debug":
		level = slog.LevelDebug
	case "trace":
		level = slog.Level(-8)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, e := net.Listen("tcp4", cfg.Listener.String())
	if e != nil {
		return e
	}
	listeners := []net.Listener{listener}
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()
	if cfg.IPv6 {
		l, e := net.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(cfg.Listener.Port)))
		if e != nil {
			return e
		}
		listeners = append(listeners, l)
	}
	connector := upstream.SOCKS5{Address: net.JoinHostPort(cfg.Upstream.Host, strconv.Itoa(cfg.Upstream.Port)), Username: cfg.Upstream.Username, Password: cfg.Upstream.Password, Timeout: time.Duration(cfg.ConnectTimeoutSeconds) * time.Second}
	if e = connector.Probe(ctx); e != nil {
		return e
	}
	manager, e := redirect.Load(cfg)
	if e != nil {
		return e
	}
	defer manager.Close()
	path := socketPath(cfg.RuntimeDir)
	if st, e := os.Lstat(path); e == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return errors.New("control path is not a socket")
		}
		if e = os.Remove(path); e != nil {
			return e
		}
	}
	control, e := net.Listen("unix", path)
	if e != nil {
		return e
	}
	defer os.Remove(path)
	if e = os.Chmod(path, 0600); e != nil {
		control.Close()
		return e
	}
	stats := &relay.Stats{}
	var ready atomic.Bool
	stop := make(chan struct{})
	var once sync.Once
	var controlMu sync.RWMutex
	controlClosed := false
	mux := http.NewServeMux()
	mux.HandleFunc("/command", func(w http.ResponseWriter, r *http.Request) {
		controlMu.RLock()
		defer controlMu.RUnlock()
		if controlClosed {
			http.Error(w, "daemon stopping", 503)
			return
		}
		var req Request
		if r.Method != "POST" || json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req) != nil {
			http.Error(w, "invalid command", 400)
			return
		}
		var result any = map[string]bool{"ok": true}
		var err error
		switch req.Action {
		case "status":
			result = map[string]any{"running": ready.Load(), "pid": os.Getpid(), "programs_loaded": true, "native_links": true, "listener": cfg.Listener.String(), "ipv6": cfg.IPv6, "upstream": connector.Address, "target_uids": manager.UIDs(), "policy_mode": cfg.Policy.Mode, "udp_policy": "pass", "counters": manager.Counters(), "relay": stats.Snapshot(), "flow_map_entries": len(manager.Flows())}
		case "flows":
			result = manager.Flows()
		case "uid-add":
			err = manager.UID("add", req.UID)
		case "uid-del":
			err = manager.UID("del", req.UID)
		case "uid-clear":
			err = manager.UID("clear", 0)
		case "uid-list":
			result = manager.UIDs()
		case "stop":
			defer once.Do(func() { close(stop) })
		default:
			err = errors.New("unknown command")
		}
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(400)
			result = map[string]string{"error": err.Error()}
		}
		json.NewEncoder(w).Encode(result)
	})
	server := &http.Server{Handler: mux, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	defer server.Close()
	controlErrors := make(chan error, 1)
	go func() { controlErrors <- server.Serve(control) }()
	serveErrors := make(chan error, len(listeners))
	for _, l := range listeners {
		go func(l net.Listener) {
			serveErrors <- relay.Serve(ctx, l, connector, func(c net.Conn) (string, error) {
				v, e := manager.Resolve(c)
				if e != nil {
					logger.Warn("original destination lookup failed", "error", e)
					return "", e
				}
				logger.Debug("redirected TCP", "uid", v.UID, "cookie", v.Cookie, "client", c.RemoteAddr().String(), "original", v.Address())
				return v.Address(), nil
			}, time.Duration(cfg.IdleTimeoutSeconds)*time.Second, cfg.MaxConnections, stats)
		}(l)
	}
	if e = manager.SetEnabled(true); e != nil {
		cancel()
		for _, l := range listeners {
			l.Close()
		}
		for range listeners {
			<-serveErrors
		}
		return e
	}
	logger.Info("redirect ready", "listener", cfg.Listener.String(), "upstream", connector.Address, "udp", "pass")
	ready.Store(true)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	ticks := 0
	var cause error
	completed := 0
running:
	for {
		select {
		case <-sig:
			break running
		case <-stop:
			break running
		case cause = <-serveErrors:
			completed++
			break running
		case cause = <-controlErrors:
			break running
		case <-ticker.C:
			if _, e = os.Lstat(path); e != nil {
				cause = errors.New("private control socket disappeared")
				break running
			}
			if e = manager.Heartbeat(); e != nil {
				cause = e
				break running
			}
			ticks++
			if ticks%20 == 0 {
				manager.Sweep()
			}
		}
	}
	_ = manager.SetEnabled(false)
	ready.Store(false)
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
	_ = server.Shutdown(shutdownCtx)
	shutdownCancel()
	_ = server.Close()
	controlMu.Lock()
	controlClosed = true
	controlMu.Unlock()
	// Detach connect hooks while listeners still exist; then drain accepted TCP.
	// Collection maps stay alive until all resolving handlers have exited.
	manager.Detach()
	for _, l := range listeners {
		l.Close()
	}
	deadline := time.Now().Add(3 * time.Second)
	for stats.Active.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	for completed < len(listeners) {
		<-serveErrors
		completed++
	}
	logger.Info("redirect stopped", "relay", stats.Snapshot())
	return cause
}
func Control(dir string, request Request) (json.RawMessage, error) {
	client := &http.Client{Timeout: 6 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socketPath(dir))
	}}}
	defer client.CloseIdleConnections()
	b, _ := json.Marshal(request)
	response, e := client.Post("http://localhost/command", "application/json", bytes.NewReader(b))
	if e != nil {
		return nil, errors.New("daemon control socket unavailable")
	}
	defer response.Body.Close()
	data, e := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if e != nil {
		return nil, e
	}
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("daemon command failed: %s", data)
	}
	return data, nil
}
