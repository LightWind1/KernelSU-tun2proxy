//go:build linux

package tproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type resourceWitness struct {
	Counts   [8]int
	Residual string
	Whole    string
}

func captureNamespace() ([]string, error) {
	var outputs []string
	for _, args := range [][]string{{"iptables", "-w", "2", "-t", "mangle", "-S"}, {"ip", "rule", "show"}, {"ip", "route", "show", "table", "all"}} {
		r := query(args)
		if e := commandError(r); e != nil {
			return nil, e
		}
		outputs = append(outputs, r.Output)
	}
	return outputs, nil
}

func stateDigest(outputs []string) string {
	b, _ := json.Marshal(outputs)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Observe removes ONLY individually validated planned resources from the
// residual digest. Foreign content is never silently ignored. This requires
// an exclusive cooperative writer in a private namespace; an external root
// that recreates an identical resource cannot be distinguished from us.
func observeResources(p IPv4DestinationPlan) (resourceWitness, error) {
	outputs, e := captureNamespace()
	if e != nil {
		return resourceWitness{}, e
	}
	w, e := classifyResources(p, outputs, func(index int) error {
		steps, e := p.Steps()
		if e != nil {
			return e
		}
		args := append([]string(nil), steps[index].Remove...)
		for i, a := range args {
			if a == "-D" {
				args[i] = "-C"
				break
			}
		}
		return commandError(query(args))
	})
	if e != nil {
		return w, e
	}
	// Detect changes during the individual -C checks rather than committing
	// a mixed observation. Counters are absent from -S output.
	after, e := captureNamespace()
	if e != nil {
		return w, e
	}
	if stateDigest(after) != w.Whole {
		return w, fmt.Errorf("resource observation changed")
	}
	return w, nil
}

func classifyResources(p IPv4DestinationPlan, outputs []string, check func(int) error) (resourceWitness, error) {
	var w resourceWitness
	if _, e := p.Steps(); e != nil {
		return w, e
	}
	if len(outputs) != 3 {
		return w, fmt.Errorf("invalid observation")
	}
	w.Whole = stateDigest(outputs)
	pre, out := p.Prefix+"_PRE", p.Prefix+"_OUT"
	residual := make([]string, 3)
	for bucket, text := range outputs {
		var retained []string
		for _, line := range strings.Split(text, "\n") {
			f := strings.Fields(line)
			index := -1
			if bucket == 0 && len(f) >= 2 {
				if len(f) == 2 && f[0] == "-N" && f[1] == pre {
					index = 2
				}
				if len(f) == 2 && f[0] == "-N" && f[1] == out {
					index = 5
				}
				if f[0] == "-A" {
					if f[1] == pre {
						index = 3
					}
					if f[1] == out {
						index = 6
					}
					for i := 2; i+1 < len(f); i++ {
						if f[i] == "-j" && f[i+1] == pre && f[1] == "PREROUTING" {
							index = 4
						}
						if f[i] == "-j" && f[i+1] == out && f[1] == "OUTPUT" {
							index = 7
						}
					}
					if index >= 0 {
						if e := check(index); e != nil {
							return w, fmt.Errorf("planned rule mismatch: %w", e)
						}
					}
				}
			}
			if bucket == 1 && len(f) > 0 && f[0] == strconv.FormatUint(uint64(p.Priority), 10)+":" {
				if len(f) != 7 || f[1] != "from" || f[2] != "all" || f[3] != "fwmark" || f[5] != "lookup" || f[6] != strconv.FormatUint(uint64(p.Table), 10) {
					return w, fmt.Errorf("policy resource mismatch")
				}
				uses := MarkUses("rule", line)
				if len(uses) != 1 || uses[0].Value != p.Mark || uses[0].Mask != p.Mask {
					return w, fmt.Errorf("policy mark mismatch")
				}
				index = 1
			}
			if bucket == 2 && len(f) >= 4 && f[0] == "local" && (f[1] == p.Destination.Addr().String() || f[1] == p.Destination.Addr().String()+"/32") && f[2] == "dev" && f[3] == "lo" {
				found := false
				valid := true
				for i := 4; i < len(f); i += 2 {
					if i+1 >= len(f) {
						valid = false
						break
					}
					switch f[i] {
					case "table":
						found = f[i+1] == strconv.FormatUint(uint64(p.Table), 10)
					case "scope":
						valid = valid && f[i+1] == "host"
					case "proto":
						valid = valid && (f[i+1] == "boot" || f[i+1] == "static")
					default:
						valid = false
					}
				}
				if found {
					if !valid {
						return w, fmt.Errorf("route resource mismatch")
					}
					index = 0
				}
			}
			if index >= 0 {
				w.Counts[index]++
				if w.Counts[index] > 1 {
					return w, fmt.Errorf("duplicate planned resource %d", index)
				}
			} else {
				retained = append(retained, line)
			}
		}
		residual[bucket] = strings.Join(retained, "\n")
	}
	w.Residual = stateDigest(residual)
	return w, nil
}

func countsMatch(counts [8]int, owned int) bool {
	for i, n := range counts {
		expected := 0
		if i < owned {
			expected = 1
		}
		if n != expected {
			return false
		}
	}
	return true
}
