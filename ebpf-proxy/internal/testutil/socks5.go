// Package testutil contains bounded fixtures, not production proxy backends.
package testutil

import (
	"context"
	"ebpf-proxy/internal/relay"
	"ebpf-proxy/internal/upstream"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// ServeSOCKS5 is a no-auth fixture with an exact destination allowlist. It never
// forwards arbitrary destinations and is only used in an isolated namespace.
func ServeSOCKS5(ctx context.Context, l net.Listener, destination string, record func(string)) {
	for {
		c, e := l.Accept()
		if e != nil {
			return
		}
		go func() {
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			var greeting [3]byte
			if _, e := io.ReadFull(c, greeting[:]); e != nil || greeting != [3]byte{5, 1, 0} {
				return
			}
			if _, e := c.Write([]byte{5, 0}); e != nil {
				return
			}
			var head [4]byte
			if _, e := io.ReadFull(c, head[:]); e != nil || head[0] != 5 || head[1] != 1 || head[2] != 0 {
				return
			}
			n := 0
			switch head[3] {
			case 1:
				n = 4
			case 4:
				n = 16
			default:
				return
			}
			b := make([]byte, n+2)
			if _, e := io.ReadFull(c, b); e != nil {
				return
			}
			d := net.JoinHostPort(net.IP(b[:n]).String(), fmt.Sprint(binary.BigEndian.Uint16(b[n:])))
			if d != destination {
				c.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
				return
			}
			remote, e := (upstream.Direct{Timeout: time.Second}).Connect(ctx, d)
			if e != nil {
				return
			}
			defer remote.Close()
			record(d)
			if _, e = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); e != nil {
				return
			}
			c.SetDeadline(time.Time{})
			relay.Relay(ctx, c, remote, 5*time.Second, &relay.Stats{})
		}()
	}
}
