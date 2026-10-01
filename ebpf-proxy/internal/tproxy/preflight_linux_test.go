//go:build linux

package tproxy

import (
	"reflect"
	"strings"
	"testing"
)

func TestPreflightCommandsOnlyRead(t *testing.T) {
	commands := preflightCommands(DefaultPreflightOptions())
	if len(commands) != 8 {
		t.Fatal("query inventory changed")
	}
	for _, args := range commands {
		for _, arg := range args {
			switch arg {
			case "add", "del", "delete", "flush", "replace", "-A", "-D", "-F", "-N", "-I", "setup", "teardown":
				t.Fatal("mutation in preflight", args)
			}
		}
	}
	if !reflect.DeepEqual(commands["table4"], []string{"ip", "-4", "route", "show", "table", "38766"}) {
		t.Fatal("candidate table altered")
	}
}
func TestPreflightSnapshotAndRedaction(t *testing.T) {
	_, e := preflightFixture()
	before := stableResourceState(e)
	e["firewall4"] = Result{Output: "counter change omitted from structural snapshot"}
	if stableResourceState(e) != before {
		t.Fatal("unrelated dump affects structural snapshot")
	}
	e["mangle4"] = Result{Output: "-N OTHER_CHAIN"}
	if stableResourceState(e) == before {
		t.Fatal("structural change not detected")
	}
	raw := Result{Command: []string{"iptables-save"}, Output: "unwanted full firewall", ExitCode: 1, Error: "permission denied"}
	r := summarizedResult(raw)
	if strings.Contains(r.Output, raw.Output) || r.SHA256 == "" || r.ExitCode != 1 || r.Error != raw.Error {
		t.Fatal("bad summarized evidence")
	}
}
