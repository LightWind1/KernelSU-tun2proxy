package main

import (
	"context"
	"ebpf-proxy/internal/config"
	"ebpf-proxy/internal/relay"
	"ebpf-proxy/internal/upstream"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if e := execute(); e != nil {
		log.Print(e)
		os.Exit(1)
	}
}
func execute() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: ebpf-proxy poc|probe-upstream --config FILE [--destination IP:PORT]")
	}
	command := os.Args[1]
	if command == "probe-kernel" {
		return probeKernel()
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	path := flags.String("config", "", "generic config JSON")
	destination := flags.String("destination", "", "fixed destination (poc only)")
	object := flags.String("object", "", "BPF object for verifier check")
	runtimeDir := flags.String("runtime-dir", "", "private daemon runtime directory")
	if e := flags.Parse(os.Args[2:]); e != nil {
		return e
	}
	if command == "verify-object" {
		return verifyObject(*object)
	}
	if command == "status" || command == "stop" || command == "uid" || command == "debug" {
		return controlNative(*runtimeDir, command, flags.Args())
	}
	cfg, e := config.Load(*path)
	if e != nil {
		return e
	}
	if command == "run" {
		return runNative(cfg)
	}
	connector := upstream.SOCKS5{Address: net.JoinHostPort(cfg.Upstream.Host, fmt.Sprint(cfg.Upstream.Port)), Username: cfg.Upstream.Username, Password: cfg.Upstream.Password, Timeout: time.Duration(cfg.ConnectTimeoutSeconds) * time.Second}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if command == "probe-upstream" {
		if e = connector.Probe(ctx); e != nil {
			return e
		}
		fmt.Println("SOCKS5 upstream reachable")
		return nil
	}
	if command != "poc" {
		return fmt.Errorf("unknown command")
	}
	if _, _, e = net.SplitHostPort(*destination); e != nil {
		return fmt.Errorf("poc requires --destination IP:PORT")
	}
	if e = connector.Probe(ctx); e != nil {
		return e
	}
	listener, e := net.Listen("tcp4", cfg.Listener.String())
	if e != nil {
		return e
	}
	defer listener.Close()
	log.Printf("TCP relay listening on %s", listener.Addr())
	stats := &relay.Stats{}
	e = relay.Serve(ctx, listener, connector, func(net.Conn) (string, error) { return *destination, nil }, time.Duration(cfg.IdleTimeoutSeconds)*time.Second, cfg.MaxConnections, stats)
	b, _ := json.Marshal(stats.Snapshot())
	log.Print(string(b))
	return e
}
