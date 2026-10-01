package tproxy

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func journalPlan() IPv4DestinationPlan {
	return IPv4DestinationPlan{Destination: netip.MustParseAddrPort("198.18.0.1:443"), ListenerPort: 18080, Mark: 1 << 22, Mask: 1 << 22, Table: 38766, Priority: 9001, Prefix: "ATP_JOURNAL"}
}

func TestJournalIdentityAndSchema(t *testing.T) {
	p := journalPlan()
	r := journalRecord{Version: 1, Namespace: "net:[123]", Boot: "boot", Plan: p, Owned: 8, Snapshot: strings.Repeat("a", 64)}
	b, _ := json.Marshal(r)
	if _, e := decodeJournal(b, p, r.Namespace, r.Boot); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*journalRecord){
		func(r *journalRecord) { r.Version = 3 }, func(r *journalRecord) { r.Namespace = "net:[456]" },
		func(r *journalRecord) { r.Boot = "other" }, func(r *journalRecord) { r.Plan.Prefix = "../" },
		func(r *journalRecord) { r.Owned = -1 }, func(r *journalRecord) { r.Owned = 9 },
		func(r *journalRecord) { r.Pending = "rm -rf /" }, func(r *journalRecord) { r.Pending = "add" },
		func(r *journalRecord) { r.Owned = 0; r.Pending = "remove" }, func(r *journalRecord) { r.Snapshot = "bad" },
	} {
		rr := r
		change(&rr)
		b, _ := json.Marshal(rr)
		if _, e := decodeJournal(b, p, r.Namespace, r.Boot); e == nil {
			t.Fatalf("accepted %+v", rr)
		}
	}
	for _, bad := range []string{`{"command":["rm","/" ]}`, string(b) + `{}`, strings.Repeat(" ", 65537), `{"version":`} {
		if _, e := decodeJournal([]byte(bad), p, r.Namespace, r.Boot); e == nil {
			t.Fatal("accepted malformed journal")
		}
	}
	// Version 1 stays readable but has no automatically reconcilable witness.
	v2 := r
	v2.Version = 2
	v2.Owned = 0
	v2.Pending = "add"
	v2.PendingProof = strings.Repeat("b", 64)
	b, _ = json.Marshal(v2)
	if _, e := decodeJournal(b, p, r.Namespace, r.Boot); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*journalRecord){func(r *journalRecord) { r.Version = 1 }, func(r *journalRecord) { r.PendingProof = "bad" }, func(r *journalRecord) { r.Pending = "" }} {
		rr := v2
		change(&rr)
		b, _ := json.Marshal(rr)
		if _, e := decodeJournal(b, p, r.Namespace, r.Boot); e == nil {
			t.Fatal("invalid witness accepted", rr)
		}
	}
}
