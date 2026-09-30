package upstream

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

type Connector interface {
	Connect(context.Context, string) (net.Conn, error)
}
type SOCKS5 struct {
	Address, Username, Password string
	Timeout                     time.Duration
}

func (s SOCKS5) negotiate(ctx context.Context) (net.Conn, error) {
	c, e := (&net.Dialer{Timeout: s.Timeout}).DialContext(ctx, "tcp", s.Address)
	if e != nil {
		return nil, errors.New("upstream TCP connection failed")
	}
	success := false
	defer func() {
		if !success {
			c.Close()
		}
	}()
	_ = c.SetDeadline(time.Now().Add(s.Timeout))
	method := byte(0)
	if s.Username != "" {
		method = 2
	}
	if e = writeAll(c, []byte{5, 1, method}); e != nil {
		return nil, e
	}
	var response [2]byte
	if _, e = io.ReadFull(c, response[:]); e != nil {
		return nil, errors.New("upstream SOCKS5 greeting failed")
	}
	if response[0] != 5 || response[1] != method {
		return nil, errors.New("upstream rejected SOCKS5 authentication method")
	}
	if method == 2 {
		if len(s.Username) > 255 || len(s.Password) > 255 {
			return nil, errors.New("authentication too long")
		}
		auth := append([]byte{1, byte(len(s.Username))}, []byte(s.Username)...)
		auth = append(auth, byte(len(s.Password)))
		auth = append(auth, []byte(s.Password)...)
		if e = writeAll(c, auth); e != nil {
			return nil, e
		}
		if _, e = io.ReadFull(c, response[:]); e != nil || response[0] != 1 || response[1] != 0 {
			return nil, errors.New("upstream authentication failed")
		}
	}
	success = true
	return c, nil
}
func (s SOCKS5) Probe(ctx context.Context) error {
	c, e := s.negotiate(ctx)
	if e == nil {
		c.Close()
	}
	return e
}
func (s SOCKS5) Connect(ctx context.Context, destination string) (net.Conn, error) {
	host, ps, e := net.SplitHostPort(destination)
	if e != nil {
		return nil, errors.New("invalid destination")
	}
	port, e := strconv.Atoi(ps)
	if e != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid destination port")
	}
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 1)
			req = append(req, v4...)
		} else {
			req = append(req, 4)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) < 1 || len(host) > 255 {
			return nil, errors.New("invalid destination host")
		}
		req = append(req, 3, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	c, e := s.negotiate(ctx)
	if e != nil {
		return nil, e
	}
	success := false
	defer func() {
		if !success {
			c.Close()
		}
	}()
	if e = writeAll(c, req); e != nil {
		return nil, e
	}
	var head [4]byte
	if _, e = io.ReadFull(c, head[:]); e != nil {
		return nil, errors.New("upstream CONNECT response incomplete")
	}
	if head[0] != 5 || head[2] != 0 {
		return nil, errors.New("invalid upstream CONNECT response")
	}
	if head[1] != 0 {
		return nil, fmt.Errorf("upstream CONNECT rejected: code %d", head[1])
	}
	size := 0
	switch head[3] {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		var b [1]byte
		if _, e = io.ReadFull(c, b[:]); e != nil {
			return nil, e
		}
		size = int(b[0])
	default:
		return nil, errors.New("invalid bound address")
	}
	if _, e = io.CopyN(io.Discard, c, int64(size+2)); e != nil {
		return nil, errors.New("upstream bound address incomplete")
	}
	_ = c.SetDeadline(time.Time{})
	success = true
	return c, nil
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
