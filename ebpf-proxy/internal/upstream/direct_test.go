package upstream

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDirectConnector(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	c, e := (Direct{Timeout: time.Second}).Connect(context.Background(), l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = (Direct{Timeout: time.Second}).Connect(ctx, l.Addr().String()); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func TestSOCKS5DialFailureRetainsCause(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := (SOCKS5{Address: "127.0.0.1:1", Username: "secret-user", Password: "secret-password", Timeout: time.Second}).Probe(ctx)
	if !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if strings.Contains(e.Error(), "secret-") {
		t.Fatal("credentials leaked")
	}
}
