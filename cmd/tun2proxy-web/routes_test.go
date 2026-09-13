package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAbsentRouteErrors(t *testing.T) {
	for _, message := range []string{"RTNETLINK answers: No such file or directory", "No chain/target/match by that name", "Couldn't find target `T2P_CAPTURE'"} {
		if !routeAlreadyAbsent(message) {
			t.Fatal(message)
		}
	}
	for _, message := range []string{"Permission denied", "xtables lock timeout", "Couldn't find target `ANOTHER_CHAIN'"} {
		if routeAlreadyAbsent(message) {
			t.Fatal("unsafe suppression", message)
		}
	}
}
func TestOldBootJournal(t *testing.T) {
	saved := runDir
	defer func() { runDir = saved }()
	runDir = t.TempDir()
	// Would fail if the cleanup mistakenly executed previous-boot commands.
	if e := writeRoutes(RouteState{Boot: "previous-boot", Undo: [][]string{{"/must-not-execute"}}}); e != nil {
		t.Fatal(e)
	}
	if e := cleanupRoutes(); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(runDir, "routes.json")); !os.IsNotExist(e) {
		t.Fatal(e)
	}
}
