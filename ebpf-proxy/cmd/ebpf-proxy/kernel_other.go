//go:build !linux

package main

import (
	"ebpf-proxy/internal/config"
	"fmt"
)

func probeKernel() error            { return fmt.Errorf("kernel probe requires Linux/Android") }
func runNative(config.Config) error { return fmt.Errorf("native redirect requires Linux/Android") }
func verifyObject(string) error     { return fmt.Errorf("BPF verification requires Linux/Android") }
func controlNative(string, string, []string) error {
	return fmt.Errorf("daemon control requires Linux/Android")
}
