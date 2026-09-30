package relay

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); accepted <- c }()
	c, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	a := <-accepted
	if a == nil {
		t.Fatal("accept failed")
	}
	return c, a
}
func TestRelayFailureLifecycle(t *testing.T) {
	for _, mode := range []string{"idle", "cancel", "rst"} {
		t.Run(mode, func(t *testing.T) {
			client, a := tcpPair(t)
			b, server := tcpPair(t)
			defer client.Close()
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() { Relay(ctx, a, b, 100*time.Millisecond, &Stats{}); close(done) }()
			switch mode {
			case "cancel":
				cancel()
			case "rst":
				client.(*net.TCPConn).SetLinger(0)
				client.Close()
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("relay did not terminate after " + mode)
			}
		})
	}
}

type failingConnector struct{}

func (failingConnector) Connect(context.Context, string) (net.Conn, error) {
	return nil, errors.New("fixture upstream offline")
}
func TestServeUpstreamFailure(t *testing.T) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stats := &Stats{}
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, l, failingConnector{}, func(net.Conn) (string, error) { return "192.0.2.1:443", nil }, time.Second, 2, stats)
	}()
	c, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 1)
	if _, e = c.Read(b); e == nil {
		t.Fatal("unexpected payload")
	}
	cancel()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if stats.Failures.Load() != 1 || stats.Active.Load() != 0 {
		t.Fatal(stats.Snapshot())
	}
}
