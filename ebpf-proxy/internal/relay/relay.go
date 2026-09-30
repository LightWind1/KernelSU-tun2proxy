package relay

import (
	"context"
	"ebpf-proxy/internal/upstream"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Stats struct {
	Accepted atomic.Uint64
	Active   atomic.Int64
	Failures atomic.Uint64
	Sent     atomic.Uint64
	Received atomic.Uint64
}

func (s *Stats) Snapshot() map[string]any {
	return map[string]any{"accepted": s.Accepted.Load(), "active": s.Active.Load(), "upstream_failures": s.Failures.Load(), "sent_bytes": s.Sent.Load(), "received_bytes": s.Received.Load()}
}

type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (c idleConn) Read(b []byte) (int, error) {
	_ = c.SetReadDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(b)
}
func (c idleConn) Write(b []byte) (int, error) {
	_ = c.SetWriteDeadline(time.Now().Add(c.timeout))
	return c.Conn.Write(b)
}

// Relay preserves native TCP half-close: a client FIN still permits a response.
// Each direction has bounded buffers and independent idle deadlines.
func Relay(ctx context.Context, a, b net.Conn, idle time.Duration, stats *Stats) {
	defer a.Close()
	defer b.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			a.Close()
			b.Close()
		case <-done:
		}
	}()
	var wg sync.WaitGroup
	copyDirection := func(dst, src net.Conn, counter *atomic.Uint64) {
		defer wg.Done()
		n, e := io.Copy(idleConn{dst, idle}, idleConn{src, idle})
		counter.Add(uint64(n))
		if e != nil {
			a.Close()
			b.Close()
			return
		}
		if tcp, ok := dst.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		} else {
			dst.Close()
		}
	}
	wg.Add(2)
	go copyDirection(b, a, &stats.Sent)
	go copyDirection(a, b, &stats.Received)
	wg.Wait()
}

type Resolve func(net.Conn) (string, error)

func Serve(ctx context.Context, l net.Listener, connector upstream.Connector, resolve Resolve, idle time.Duration, max int, stats *Stats) error {
	go func() { <-ctx.Done(); l.Close() }()
	slots := make(chan struct{}, max)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, e := l.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		select {
		case slots <- struct{}{}:
		default:
			c.Close()
			stats.Failures.Add(1)
			continue
		}
		stats.Accepted.Add(1)
		stats.Active.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots; stats.Active.Add(-1) }()
			dst, e := resolve(c)
			if e != nil {
				stats.Failures.Add(1)
				c.Close()
				return
			}
			remote, e := connector.Connect(ctx, dst)
			if e != nil {
				stats.Failures.Add(1)
				c.Close()
				return
			}
			Relay(ctx, c, remote, idle, stats)
		}()
	}
}
