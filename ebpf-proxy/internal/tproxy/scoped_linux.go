//go:build linux

package tproxy

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// scopedWitness ignores changes outside the reserved resource footprint, not
// changes inside it. It is an observation, never permission to adopt resources.
// An identical replacement by another privileged writer is indistinguishable.
type scopedWitness struct {
	Counts    [8]int
	Resources [8][]string
	Digest    string
}

func (w scopedWitness) excluding(index int) string {
	resources := w.Resources
	if index >= 0 && index < len(resources) {
		resources[index] = nil
	}
	b, _ := json.Marshal(resources)
	return stateDigest([]string{"scoped-witness-v3", string(b)})
}

func classifyScoped(p IPv4DestinationPlan, outputs []string, aliases map[string]uint32, check func(int) error) (scopedWitness, error) {
	var s scopedWitness
	// Retain the existing exact-rule/route/priority/duplicate checks.
	w, e := classifyResources(p, outputs, check)
	if e != nil {
		return s, e
	}
	s.Counts = w.Counts
	pre, out := p.Prefix+"_PRE", p.Prefix+"_OUT"
	table := strconv.FormatUint(uint64(p.Table), 10)
	for bucket, text := range outputs {
		for _, line := range strings.Split(text, "\n") {
			f := strings.Fields(line)
			if len(f) == 0 {
				continue
			}
			index := -1
			switch bucket {
			case 0:
				if len(f) < 2 {
					return s, fmt.Errorf("unrecognized firewall observation")
				}
				if f[0] == "-N" && (f[1] == pre || f[1] == out) {
					if f[1] == pre {
						index = 2
					} else {
						index = 5
					}
				}
				if f[0] == "-A" && (f[1] == pre || f[1] == out) {
					if f[1] == pre {
						index = 3
					} else {
						index = 6
					}
				}
				for i := 2; i+1 < len(f); i++ {
					if f[i] == "-j" || f[i] == "-g" {
						target := f[i+1]
						if target == pre || target == out {
							if f[0] != "-A" || f[i] != "-j" || (target == pre && f[1] != "PREROUTING") || (target == out && f[1] != "OUTPUT") {
								return s, fmt.Errorf("foreign reference to reserved chain")
							}
							if target == pre {
								index = 4
							} else {
								index = 7
							}
						} else if strings.HasPrefix(target, p.Prefix) {
							return s, fmt.Errorf("reserved chain prefix collision")
						}
					}
				}
				if strings.HasPrefix(f[1], p.Prefix) && f[1] != pre && f[1] != out {
					return s, fmt.Errorf("reserved chain prefix collision")
				}
				if index < 0 {
					for _, use := range MarkUses("firewall", line) {
						if use.Kind == "packet" && use.Mask&p.Mask != 0 {
							return s, fmt.Errorf("foreign firewall overlaps reserved mark")
						}
					}
				}
			case 1:
				priority, e := strconv.ParseUint(strings.TrimSuffix(f[0], ":"), 10, 32)
				if e != nil {
					return s, fmt.Errorf("unrecognized policy priority")
				}
				if uint32(priority) == p.Priority {
					index = 1
				}
				for i := 1; i+1 < len(f); i++ {
					if f[i] == "lookup" || f[i] == "table" {
						id, e := strconv.ParseUint(f[i+1], 10, 32)
						if e != nil {
							var known bool
							var v uint32
							v, known = aliases[f[i+1]]
							if !known {
								switch f[i+1] {
								case "local":
									v = 255
								case "main":
									v = 254
								case "default":
									v = 253
								default:
									return s, fmt.Errorf("unresolved policy table alias")
								}
							}
							id = uint64(v)
						}
						if uint32(id) == p.Table && index != 1 {
							return s, fmt.Errorf("foreign reference to reserved table")
						}
					}
				}
				if index != 1 {
					for _, use := range MarkUses("rule", line) {
						if use.Mask&p.Mask != 0 {
							return s, fmt.Errorf("foreign policy overlaps reserved mark")
						}
					}
				}
			case 2:
				reserved := false
				for i := 0; i+1 < len(f); i++ {
					if f[i] == "table" {
						if f[i+1] == table || aliases[f[i+1]] == p.Table {
							reserved = true
						}
					}
				}
				if reserved {
					// classifyResources already validates the only permitted route. Any
					// other route in our dedicated table is an ownership conflict.
					if len(f) < 4 || f[0] != "local" || (f[1] != p.Destination.Addr().String() && f[1] != p.Destination.Addr().String()+"/32") || f[2] != "dev" || f[3] != "lo" {
						return s, fmt.Errorf("foreign route in reserved table")
					}
					// Symbolic aliases cannot bypass the existing exact numeric classifier.
					if s.Counts[0] != 1 {
						return s, fmt.Errorf("reserved route not exactly verified")
					}
					index = 0
				}
			}
			if index >= 0 {
				s.Resources[index] = append(s.Resources[index], strings.Join(f, " "))
			}
		}
	}
	for i, n := range s.Counts {
		if len(s.Resources[i]) != n {
			return s, fmt.Errorf("mixed scoped observation")
		}
	}
	s.Digest = s.excluding(-1)
	return s, nil
}

func observeScoped(p IPv4DestinationPlan) (scopedWitness, error) {
	return observeScopedWith(p, query)
}

func observeScopedWith(p IPv4DestinationPlan, run func([]string) Result) (scopedWitness, error) {
	steps, e := p.Steps()
	if e != nil {
		return scopedWitness{}, e
	}
	check := func(index int) error {
		args := append([]string(nil), steps[index].Remove...)
		for i, a := range args {
			if a == "-D" {
				args[i] = "-C"
				break
			}
		}
		return commandError(run(args))
	}
	aliases := routingAliases()
	var previous scopedWitness
	// Two complete observations of the reserved footprint must agree. Outside
	// netd changes are ignored; relevant changes never become a mixed witness.
	for pass := 0; pass < 2; pass++ {
		outputs, e := captureNamespaceWith(run)
		if e != nil {
			return previous, e
		}
		current, e := classifyScoped(p, outputs, aliases, check)
		if e != nil {
			return current, e
		}
		if pass == 1 && previous.Digest != current.Digest {
			return current, fmt.Errorf("scoped resources changed during observation")
		}
		previous = current
	}
	return previous, nil
}
