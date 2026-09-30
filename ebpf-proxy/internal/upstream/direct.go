package upstream

import (
	"context"
	"net"
	"time"
)

// Direct implements the same opaque-stream connector as SOCKS5. Routing and
// daemon bypass remain the redirect backend's responsibility.
type Direct struct{ Timeout time.Duration }

func (d Direct) Connect(ctx context.Context, destination string) (net.Conn, error) {
	return (&net.Dialer{Timeout: d.Timeout}).DialContext(ctx, "tcp", destination)
}
