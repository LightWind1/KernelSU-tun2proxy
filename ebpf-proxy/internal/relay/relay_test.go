package relay

import (
	"bytes"
	"context"
	"ebpf-proxy/internal/upstream"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestSOCKSRelayHalfCloseAndBackpressure(t *testing.T) { testRelay(t, 1, 2<<20) }
func TestSOCKSRelayThousandConnections(t *testing.T)      { testRelay(t, 1000, 64) }
func testRelay(t *testing.T, count, size int) {
	t.Helper()
	target, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer target.Close()
	go func() {
		for {
			c, e := target.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(20 * time.Second))
				b, e := io.ReadAll(c)
				if e == nil {
					c.Write(b)
				}
			}()
		}
	}()
	socks, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer socks.Close()
	go func() {
		for {
			c, e := socks.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(20 * time.Second))
				var g [3]byte
				if _, e = io.ReadFull(c, g[:]); e != nil {
					return
				}
				c.Write([]byte{5, 0})
				var h [4]byte
				if _, e = io.ReadFull(c, h[:]); e != nil {
					return
				}
				n := 4
				if h[3] == 4 {
					n = 16
				}
				b := make([]byte, n+2)
				if _, e = io.ReadFull(c, b); e != nil {
					return
				}
				dst := net.JoinHostPort(net.IP(b[:n]).String(), fmt.Sprint(binary.BigEndian.Uint16(b[n:])))
				remote, e := net.Dial("tcp", dst)
				if e != nil {
					return
				}
				defer remote.Close()
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
				Relay(context.Background(), c, remote, 20*time.Second, &Stats{})
			}()
		}
	}()
	listener, _ := net.Listen("tcp4", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stats := &Stats{}
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, listener, upstream.SOCKS5{Address: socks.Addr().String(), Timeout: 5 * time.Second}, func(net.Conn) (string, error) { return target.Addr().String(), nil }, 20*time.Second, 64, stats)
	}()
	slots := make(chan struct{}, 32)
	var wg sync.WaitGroup
	failures := make(chan error, count)
	for i := 0; i < count; i++ {
		slots <- struct{}{}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-slots }()
			c, e := net.Dial("tcp", listener.Addr().String())
			if e != nil {
				failures <- e
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(20 * time.Second))
			payload := bytes.Repeat([]byte{byte(i)}, size)
			if _, e = c.Write(payload); e != nil {
				failures <- e
				return
			}
			c.(*net.TCPConn).CloseWrite()
			if size > 1024 {
				time.Sleep(30 * time.Millisecond)
			}
			response, e := io.ReadAll(c)
			if e != nil || !bytes.Equal(payload, response) {
				failures <- fmt.Errorf("response mismatch: %v", e)
			}
		}(i)
	}
	wg.Wait()
	close(failures)
	for e := range failures {
		t.Error(e)
	}
	cancel()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if stats.Failures.Load() != 0 || stats.Accepted.Load() != uint64(count) {
		t.Fatalf("stats: %+v", stats.Snapshot())
	}
}
