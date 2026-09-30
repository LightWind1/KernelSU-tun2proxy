package testutil

import (
	"context"
	"ebpf-proxy/internal/upstream"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestSOCKS5FixtureAllowlist(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var records atomic.Int64
	go ServeSOCKS5(ctx, l, "198.18.0.1:443", func(string) { records.Add(1) })
	s := upstream.SOCKS5{Address: l.Addr().String(), Timeout: time.Second}
	if e = s.Probe(ctx); e != nil {
		t.Fatal(e)
	}
	if c, e := s.Connect(ctx, "198.18.0.2:443"); e == nil {
		c.Close()
		t.Fatal("fixture forwarded disallowed destination")
	}
	if records.Load() != 0 {
		t.Fatal("unexpected forwarding")
	}
}
