package tproxy

import "testing"

func TestMarkUsesAndRisk(t *testing.T) {
	text := "10000: from all fwmark 0xc0000/0xd0000 lookup legacy_system\n-A INPUT -j MARK --set-xmark 0x30065/0x7fefffff\n-A OUTPUT -j CONNMARK --set-xmark 0x20000000/0x30000000\n-A INPUT -m mark --mark 0xdeadc1a7 -j DROP"
	u := MarkUses("fixture", text)
	if len(u) != 4 || u[2].Kind != "connection" || u[3].Mask != 0xffffffff {
		t.Fatalf("wrong parsing: %+v", u)
	}
	if got := len(MarkRisk(0x00400000, u)); got != 2 {
		t.Fatalf("expected conservative mask and full-width match risks, got %d", got)
	}
}

func TestMalformedMarks(t *testing.T) {
	if u := MarkUses("fixture", "--set-mark 0x100000000\nfwmark potato\n--mark 1/0x100000000"); len(u) != 0 {
		t.Fatal(u)
	}
	if u := MarkUses("fixture", "fwmark 4194304/4194304"); len(u) != 1 || u[0].Mask != 4194304 {
		t.Fatal(u)
	}
}

func TestMarkOperationMasks(t *testing.T) {
	u := MarkUses("fixture", "-A OUTPUT -j CONNMARK --save-mark --nfmask 0xfffff --ctmask 0xfffff\n-A OUTPUT -j MARK --or-mark 0x400000\n-A OUTPUT -j MARK --and-mark 0xffbfffff")
	if len(u) != 4 || u[0].Kind != "packet" || u[0].Mask != 0xfffff || u[1].Kind != "connection" || u[1].Mask != 0xfffff || u[2].Mask != 0x400000 || u[3].Mask != 0x400000 {
		t.Fatalf("mask operation semantics: %+v", u)
	}
}
