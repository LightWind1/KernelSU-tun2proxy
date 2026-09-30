//go:build linux

package main

import (
	"ebpf-proxy/internal/tproxy"
	"encoding/json"
	"fmt"
	"os"
)

func tproxyCommand(args []string) error {
	if len(args) != 1 || args[0] != "probe" {
		return fmt.Errorf("usage: ebpf-proxy tproxy probe (read-only)")
	}
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	return e.Encode(tproxy.Probe())
}
