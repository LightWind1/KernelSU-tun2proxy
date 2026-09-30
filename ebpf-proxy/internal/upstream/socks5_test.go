package upstream

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestSOCKS5AddressAndAuthentication(t *testing.T) {
	for _, dst := range []string{"192.0.2.1:443", "[2001:db8::1]:8443", "example.test:80"} {
		t.Run(dst, func(t *testing.T) {
			l, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			result := make(chan string, 1)
			go func() {
				c, e := l.Accept()
				if e != nil {
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				var greeting [3]byte
				io.ReadFull(c, greeting[:])
				c.Write([]byte{5})
				c.Write([]byte{2})
				var ah [2]byte
				io.ReadFull(c, ah[:])
				u := make([]byte, int(ah[1]))
				io.ReadFull(c, u)
				var n [1]byte
				io.ReadFull(c, n[:])
				p := make([]byte, int(n[0]))
				io.ReadFull(c, p)
				if string(u) != "user" || string(p) != "secret" {
					result <- "invalid auth"
					return
				}
				c.Write([]byte{1, 0})
				var h [4]byte
				io.ReadFull(c, h[:])
				size := 0
				switch h[3] {
				case 1:
					size = 4
				case 4:
					size = 16
				case 3:
					io.ReadFull(c, n[:])
					size = int(n[0])
				}
				address := make([]byte, size)
				io.ReadFull(c, address)
				var port [2]byte
				io.ReadFull(c, port[:])
				host := string(address)
				if h[3] != 3 {
					host = net.IP(address).String()
				}
				// Deliberately fragment the reply to exercise exact reads.
				for _, b := range []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1} {
					c.Write([]byte{b})
				}
				result <- net.JoinHostPort(host, fmtPort(binary.BigEndian.Uint16(port[:])))
			}()
			s := SOCKS5{Address: l.Addr().String(), Username: "user", Password: "secret", Timeout: 3 * time.Second}
			c, e := s.Connect(context.Background(), dst)
			if e != nil {
				t.Fatal(e)
			}
			c.Close()
			if got := <-result; got != dst {
				t.Fatalf("destination: %s", got)
			}
		})
	}
}
func fmtPort(p uint16) string { return fmt.Sprint(p) }
