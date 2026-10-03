// Package tproxy contains generic transparent-socket and routing diagnostics.
// It does not depend on a module, UI, upstream product, or BPF flow map.
package tproxy

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type Result struct {
	Command  []string `json:"command,omitempty"`
	ExitCode int      `json:"exit_code"`
	Output   string   `json:"output,omitempty"`
	Error    string   `json:"error,omitempty"`
	SHA256   string   `json:"sha256,omitempty"`
}

type MarkUse struct {
	Source string `json:"source"`
	Kind   string `json:"kind"`
	Value  uint32 `json:"value"`
	Mask   uint32 `json:"mask"`
	Rule   string `json:"rule"`
}

var markPattern = regexp.MustCompile(`(fwmark|--set-xmark|--set-mark|--tproxy-mark|--mark|--nfmask|--ctmask|--and-mark|--or-mark|--xor-mark)\s+(0x[0-9a-fA-F]+|[0-9]+)(?:/(0x[0-9a-fA-F]+|[0-9]+))?`)

func MarkUses(source, text string) []MarkUse {
	var uses []MarkUse
	for _, line := range strings.Split(text, "\n") {
		for _, m := range markPattern.FindAllStringSubmatch(line, -1) {
			v, err := strconv.ParseUint(m[2], 0, 32)
			if err != nil {
				continue
			}
			mask := uint64(0xffffffff)
			if m[3] != "" {
				mask, err = strconv.ParseUint(m[3], 0, 32)
			}
			if err != nil {
				continue
			}
			kind := "packet"
			if strings.Contains(line, "CONNMARK") || strings.Contains(line, "-m connmark") {
				kind = "connection"
			}
			if m[1] == "--nfmask" {
				kind = "packet"
				mask = v
			}
			if m[1] == "--ctmask" {
				kind = "connection"
				mask = v
			}
			if m[1] == "--or-mark" || m[1] == "--xor-mark" {
				mask = v
			}
			if m[1] == "--and-mark" {
				mask = uint64(^uint32(v))
			}
			uses = append(uses, MarkUse{source, kind, uint32(v), uint32(mask), line})
		}
	}
	return uses
}

// Conservatively reject masks even on ingress-only rules. A snapshot cannot
// prove that vendor BPF code or later netd updates leave a reserved bit alone.
func MarkRisk(bit uint32, uses []MarkUse) []string {
	var risks []string
	for _, u := range uses {
		if u.Kind == "packet" && u.Mask&bit != 0 {
			risks = append(risks, fmt.Sprintf("%s: %s", u.Source, u.Rule))
		}
	}
	return risks
}
