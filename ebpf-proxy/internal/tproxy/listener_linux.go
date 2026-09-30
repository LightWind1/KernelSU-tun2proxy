//go:build linux

package tproxy

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"syscall"
)

// ListenTransparent preserves the original destination without NAT or BPF
// correlation. Transparent sockets must be configured before bind.
func ListenTransparent(ctx context.Context, network, address string) (net.Listener, error) {
	if network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("transparent listener requires tcp4 or tcp6")
	}
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var optionErr error
		err := c.Control(func(fd uintptr) {
			level, option := unix.SOL_IP, unix.IP_TRANSPARENT
			if network == "tcp6" {
				level, option = unix.SOL_IPV6, unix.IPV6_TRANSPARENT
			}
			optionErr = unix.SetsockoptInt(int(fd), level, option, 1)
		})
		if err != nil {
			return err
		}
		if optionErr != nil {
			return fmt.Errorf("transparent setsockopt: %w", optionErr)
		}
		return nil
	}}
	return lc.Listen(ctx, network, address)
}

// OriginalDestination is suitable as the existing generic relay.Resolve.
// For a TPROXY accepted socket, Go LocalAddr is backed by getsockname.
func OriginalDestination(c net.Conn) (string, error) {
	a, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok || a.IP.IsUnspecified() || a.Port == 0 {
		return "", fmt.Errorf("invalid accepted original destination")
	}
	return a.String(), nil
}
