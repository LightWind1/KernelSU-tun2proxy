package tproxy

import "testing"

func TestTPROXYMarkUse(t *testing.T) {
	uses := MarkUses("firewall", "-A FOREIGN -j TPROXY --on-port 18080 --tproxy-mark 0x400000/0x400000")
	if len(uses) != 1 || uses[0].Kind != "packet" || uses[0].Value != 1<<22 || uses[0].Mask != 1<<22 {
		t.Fatal("TPROXY mark not classified", uses)
	}
}
