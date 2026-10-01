//go:build linux

package tproxy

import (
	"fmt"
	"strings"
	"testing"
)

func TestResourceWitnessClassification(t *testing.T) {
	p := journalPlan()
	base := []string{"-P PREROUTING ACCEPT\n-P OUTPUT ACCEPT", "0: from all lookup local\n32766: from all lookup main\n32767: from all lookup default", "local 127.0.0.1 dev lo table local scope host"}
	full := append([]string(nil), base...)
	full[0] += "\n-N ATP_JOURNAL_PRE\n-N ATP_JOURNAL_OUT\n-A ATP_JOURNAL_PRE -p tcp -m tcp --dport 443 -j TPROXY\n-A PREROUTING -p tcp -j ATP_JOURNAL_PRE\n-A ATP_JOURNAL_OUT -p tcp -j MARK\n-A OUTPUT -p tcp -j ATP_JOURNAL_OUT"
	full[1] += "\n9001: from all fwmark 0x400000/0x400000 lookup 38766"
	full[2] += "\nlocal 198.18.0.1 dev lo table 38766 scope host"
	check := func(int) error { return nil }
	b, e := classifyResources(p, base, check)
	if e != nil {
		t.Fatal(e)
	}
	w, e := classifyResources(p, full, check)
	if e != nil || !countsMatch(w.Counts, 8) || w.Residual != b.Residual {
		t.Fatal(w, e)
	}
	for _, tc := range []struct {
		name   string
		bucket int
		extra  string
	}{
		{"duplicate", 0, "\n-N ATP_JOURNAL_PRE"},
		{"duplicate_rule", 0, "\n-A OUTPUT -p tcp -j ATP_JOURNAL_OUT"},
		{"route_selector", 2, "\nlocal 198.18.0.1 dev lo table 38766 src 192.0.2.2"},
		{"rule_selector", 1, "\n9001: from all fwmark 0x400000/0x400000 lookup 38766 uidrange 0-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := append([]string(nil), full...)
			v[tc.bucket] += tc.extra
			if _, e := classifyResources(p, v, check); e == nil {
				t.Fatal("unsafe witness accepted")
			}
		})
	}
	if _, e := classifyResources(p, full, func(int) error { return fmt.Errorf("rule mismatch") }); e == nil {
		t.Fatal("unverified rule accepted")
	}
	foreign := append([]string(nil), full...)
	foreign[0] += "\n-N FOREIGN_KEEP"
	f, e := classifyResources(p, foreign, check)
	if e != nil || f.Residual == w.Residual {
		t.Fatal("foreign content ignored", e)
	}
	bad := append([]string(nil), full...)
	bad[1] = strings.ReplaceAll(bad[1], "0x400000/0x400000", "0x1/0x1")
	if _, e := classifyResources(p, bad, check); e == nil {
		t.Fatal("foreign mark accepted")
	}
}
