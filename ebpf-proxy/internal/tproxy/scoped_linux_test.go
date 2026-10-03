//go:build linux

package tproxy

import (
	"fmt"
	"strings"
	"testing"
)

func scopedFixture() []string {
	return []string{
		"-P PREROUTING ACCEPT\n-P OUTPUT ACCEPT\n-N ATP_JOURNAL_PRE\n-N ATP_JOURNAL_OUT\n-A ATP_JOURNAL_PRE -p tcp -j TPROXY\n-A PREROUTING -p tcp -j ATP_JOURNAL_PRE\n-A ATP_JOURNAL_OUT -p tcp -j MARK\n-A OUTPUT -p tcp -j ATP_JOURNAL_OUT",
		"0: from all lookup local\n9001: from all fwmark 0x400000/0x400000 lookup 38766",
		"local 127.0.0.1 dev lo table local scope host\nlocal 198.18.0.1 dev lo table 38766 scope host",
	}
}

func TestScopedUnrelatedChanges(t *testing.T) {
	p := journalPlan()
	base := scopedFixture()
	check := func(int) error { return nil }
	before, e := classifyScoped(p, base, nil, check)
	if e != nil || !countsMatch(before.Counts, 8) {
		t.Fatal(before, e)
	}
	changed := append([]string(nil), base...)
	changed[0] += "\n-N fw_NETD_FIXTURE\n-A fw_NETD_FIXTURE -j RETURN\n-A OUTPUT -j fw_NETD_FIXTURE"
	changed[1] += "\n20000: from all fwmark 0x10000/0x10000 lookup network"
	changed[2] += "\n192.0.2.0/24 dev lo table 12345 scope link"
	after, e := classifyScoped(p, changed, map[string]uint32{"network": 12345}, check)
	if e != nil || before.Digest != after.Digest || before.excluding(0) != after.excluding(0) {
		t.Fatal("unrelated netd-shaped changes blocked", e)
	}
	connectionOnly := append([]string(nil), changed...)
	connectionOnly[0] += "\n-A fw_NETD_FIXTURE -j CONNMARK --set-xmark 0/0x400000"
	if _, e := classifyScoped(p, connectionOnly, map[string]uint32{"network": 12345}, check); e != nil {
		t.Fatal("connection-only mark mistaken for packet mark", e)
	}
	changed[0] = strings.Replace(changed[0], "-A OUTPUT -p tcp -j ATP_JOURNAL_OUT", "-A OUTPUT -p tcp -m comment --comment changed -j ATP_JOURNAL_OUT", 1)
	modified, e := classifyScoped(p, changed, map[string]uint32{"network": 12345}, check)
	if e != nil || modified.Digest == before.Digest {
		t.Fatal("owned footprint changed unnoticed", e)
	}
}

func TestScopedForeignInterference(t *testing.T) {
	for _, tc := range []struct {
		name   string
		bucket int
		line   string
	}{
		{"foreign jump", 0, "-A OTHER -j ATP_JOURNAL_PRE"},
		{"foreign goto", 0, "-A OUTPUT -g ATP_JOURNAL_OUT"},
		{"foreign packet mark", 0, "-A OTHER -j MARK --set-xmark 0/0x400000"},
		{"foreign tproxy mark", 0, "-A OTHER -j TPROXY --on-port 20000 --tproxy-mark 0x400000/0x400000"},
		{"extra reserved chain", 0, "-N ATP_JOURNAL_OTHER"},
		{"foreign table rule", 1, "21000: from all lookup 38766"},
		{"alias table rule", 1, "21000: from all lookup reserved"},
		{"priority collision", 1, "9001: from all lookup 12345"},
		{"mark overlap", 1, "21000: from all fwmark 0/0x400000 lookup 12345"},
		{"unresolved alias", 1, "21000: from all lookup unknown"},
		{"foreign route", 2, "192.0.2.0/24 dev lo table 38766 scope link"},
		{"foreign alias route", 2, "192.0.2.0/24 dev lo table reserved scope link"},
		{"duplicate", 0, "-A OUTPUT -p tcp -j ATP_JOURNAL_OUT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := scopedFixture()
			v[tc.bucket] += "\n" + tc.line
			if _, e := classifyScoped(journalPlan(), v, map[string]uint32{"reserved": 38766}, func(int) error { return nil }); e == nil {
				t.Fatal("foreign interference admitted")
			}
		})
	}
	if _, e := classifyScoped(journalPlan(), scopedFixture(), nil, func(int) error { return fmt.Errorf("exact -C mismatch") }); e == nil {
		t.Fatal("unverified rule admitted")
	}
}

func TestScopedPendingProofExcludesOneResourceOnly(t *testing.T) {
	p := journalPlan()
	v := scopedFixture()
	before, e := classifyScoped(p, v, nil, func(int) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	v[0] = strings.Replace(v[0], "\n-A OUTPUT -p tcp -j ATP_JOURNAL_OUT", "", 1)
	after, e := classifyScoped(p, v, nil, func(int) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	if !countsMatch(after.Counts, 7) || before.Digest == after.Digest || before.excluding(7) != after.excluding(7) {
		t.Fatal("single-step proof invalid")
	}
	v[0] = strings.Replace(v[0], "\n-A ATP_JOURNAL_OUT -p tcp -j MARK", "", 1)
	extra, e := classifyScoped(p, v, nil, func(int) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	if before.excluding(7) == extra.excluding(7) {
		t.Fatal("second operation hidden by witness")
	}
}
