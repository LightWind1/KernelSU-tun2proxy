package tproxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

// Records contain typed configuration, never executable argv. Recovery also
// requires the independently supplied expected plan, namespace and boot ID.
type journalRecord struct {
	Version   int                 `json:"version"`
	Namespace string              `json:"namespace"`
	Boot      string              `json:"boot"`
	Plan      IPv4DestinationPlan `json:"plan"`
	Owned     int                 `json:"owned"`
	Pending   string              `json:"pending,omitempty"`
	Snapshot  string              `json:"snapshot"`
}

func decodeJournal(b []byte, plan IPv4DestinationPlan, namespace, boot string) (journalRecord, error) {
	var r journalRecord
	if len(b) > 65536 {
		return r, fmt.Errorf("journal too large")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(&r); e != nil {
		return r, e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return r, fmt.Errorf("trailing journal data")
	}
	steps, e := plan.Steps()
	if e != nil {
		return r, e
	}
	if r.Version != 1 || r.Namespace != namespace || r.Boot != boot || r.Plan != plan || r.Owned < 0 || r.Owned > len(steps) {
		return r, fmt.Errorf("journal identity/configuration mismatch")
	}
	if r.Pending != "" && r.Pending != "add" && r.Pending != "remove" {
		return r, fmt.Errorf("invalid journal intent")
	}
	if r.Pending == "add" && r.Owned == len(steps) || r.Pending == "remove" && r.Owned == 0 {
		return r, fmt.Errorf("intent outside plan bounds")
	}
	if digest, e := hex.DecodeString(r.Snapshot); e != nil || len(digest) != sha256.Size {
		return r, fmt.Errorf("invalid snapshot digest")
	}
	return r, nil
}
