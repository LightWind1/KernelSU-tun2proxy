//go:build !linux

package main

import "fmt"

func commandGuardEntry() (int, bool) { return 0, false }
func tproxyCommand([]string) error   { return fmt.Errorf("TPROXY requires Linux/Android") }
