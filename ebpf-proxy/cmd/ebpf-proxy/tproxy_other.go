//go:build !linux

package main

import "fmt"

func tproxyCommand([]string) error { return fmt.Errorf("TPROXY requires Linux/Android") }
