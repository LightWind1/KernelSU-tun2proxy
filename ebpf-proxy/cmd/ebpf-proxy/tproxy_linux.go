//go:build linux

package main

import (
	"bufio"
	"context"
	"ebpf-proxy/internal/tproxy"
	"ebpf-proxy/internal/upstream"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func tproxyCommand(args []string) error {
	if len(args) > 0 && args[0] == "test-upstream" {
		f := flag.NewFlagSet("test-upstream", flag.ContinueOnError)
		address := f.String("address", "", "SOCKS5 host:port (no credentials)")
		destination := f.String("http-destination", "", "optional benign HTTP diagnostic destination host:port")
		httpHost := f.String("http-host", "", "HTTP Host for diagnostic only; never parsed by relay")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		h, p, e := net.SplitHostPort(*address)
		port, pe := strconv.Atoi(p)
		if e != nil || pe != nil || h == "" || strings.ContainsAny(h, "/@\\ \t\r\n") || port < 1 || port > 65535 {
			return fmt.Errorf("invalid upstream host:port")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result := map[string]any{"address": *address, "network_rules_changed": false, "authentication": "no-auth probe; use existing probe-upstream --config for credentials"}
		c, e := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", *address)
		result["tcp_reachable"] = e == nil
		if e == nil {
			c.Close()
			e = (upstream.SOCKS5{Address: *address, Timeout: 2 * time.Second}).Probe(ctx)
			result["socks5_ready"] = e == nil
		}
		if e == nil && *destination != "" {
			if *httpHost == "" || strings.ContainsAny(*httpHost, "/\r\n @") {
				return fmt.Errorf("invalid diagnostic HTTP Host")
			}
			conn, ce := (upstream.SOCKS5{Address: *address, Timeout: 2 * time.Second}).Connect(ctx, *destination)
			e = ce
			if e == nil {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				req, re := http.NewRequest("GET", "http://"+*httpHost+"/", nil)
				e = re
				if e == nil {
					req.Close = true
					req.Header.Set("X-Transparent-Proxy-Probe", "direct-uid-phase")
					e = req.Write(conn)
				}
				if e == nil {
					response, re := http.ReadResponse(bufio.NewReader(conn), req)
					e = re
					if e == nil {
						n, re := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
						response.Body.Close()
						e = re
						result["http_status"] = response.StatusCode
						result["response_bytes"] = n
						result["path"] = "root diagnostic -> SOCKS5 (no TPROXY)"
					}
				}
			}
		}
		if e != nil {
			result["error"] = e.Error()
			var ne net.Error
			result["timeout"] = errors.As(e, &ne) && ne.Timeout()
		}
		b, je := json.MarshalIndent(result, "", "  ")
		if je != nil {
			return je
		}
		fmt.Println(string(b))
		return e
	}
	if len(args) == 1 && args[0] == "fixture-client" {
		return tproxy.FixtureClient()
	}
	if len(args) == 1 && (args[0] == "relay-isolated" || args[0] == "socks5-isolated") {
		fn := tproxy.RelayPoCIsolated
		if args[0] == "socks5-isolated" {
			fn = tproxy.SOCKS5PoCIsolated
		}
		r, err := fn([]string{"tproxy", "fixture-client"})
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		if encodeErr := e.Encode(r); encodeErr != nil {
			return encodeErr
		}
		return err
	}
	if len(args) == 1 && args[0] == "poc-isolated" {
		r, err := tproxy.PoCIsolated()
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		if encodeErr := e.Encode(r); encodeErr != nil {
			return encodeErr
		}
		return err
	}
	if len(args) != 1 || args[0] != "probe" {
		return fmt.Errorf("usage: ebpf-proxy tproxy probe | test-upstream --address HOST:PORT | poc-isolated | relay-isolated | socks5-isolated (isolated PoCs require unshare -n)")
	}
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	return e.Encode(tproxy.Probe())
}
