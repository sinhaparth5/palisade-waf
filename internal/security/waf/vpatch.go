package waf

import (
	"embed"
	"fmt"
	"path"
	"slices"
	"strings"
)

// Virtual patches (issue #189): one rule per exploited CVE, embedded and
// loaded into every engine ahead of CRS, so an exploit is denied by its own
// rule id before anomaly scoring. Each file in vpatch/ opens with
// "# CVE:", "# Product:", "# Reference:" and "# Added:" lines. A patch is
// switched off like any rule: a global or per-service rule exception for
// its id (SecRuleRemoveById runs after it is loaded).
const (
	VPatchIDMin = 2000000
	VPatchIDMax = 2099999
)

//go:embed vpatch/*.conf
var vpatchFS embed.FS

// VPatch is one shipped virtual patch.
type VPatch struct {
	CVE, Product, Reference, Added string
	RuleID                         int
	Rule                           string
}

// VPatches lists the shipped patches, newest first. A malformed file fails
// TestVPatchPack, so loading it here never errors in a released binary.
var VPatches = mustLoadVPatches()

func mustLoadVPatches() []VPatch {
	ps, err := loadVPatches()
	if err != nil {
		panic(err)
	}
	return ps
}

func loadVPatches() ([]VPatch, error) {
	entries, err := vpatchFS.ReadDir("vpatch")
	if err != nil {
		return nil, err
	}
	var out []VPatch
	for _, e := range entries {
		b, err := vpatchFS.ReadFile(path.Join("vpatch", e.Name()))
		if err != nil {
			return nil, err
		}
		p := VPatch{Rule: string(b)}
		for _, line := range strings.Split(p.Rule, "\n") {
			k, v, ok := strings.Cut(strings.TrimPrefix(line, "# "), ": ")
			if !ok || !strings.HasPrefix(line, "# ") {
				continue
			}
			switch k {
			case "CVE":
				p.CVE = v
			case "Product":
				p.Product = v
			case "Reference":
				p.Reference = v
			case "Added":
				p.Added = v
			}
		}
		if p.CVE == "" || p.Product == "" || p.Reference == "" || p.Added == "" {
			return nil, fmt.Errorf("%s: needs # CVE:, # Product:, # Reference: and # Added: lines", e.Name())
		}
		ids, err := validateRules(p.Rule, "virtual patch", VPatchIDMin, VPatchIDMax)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if len(ids) != 1 {
			return nil, fmt.Errorf("%s: a patch is exactly one rule id, got %v", e.Name(), ids)
		}
		p.RuleID = ids[0]
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b VPatch) int {
		if c := strings.Compare(b.Added, a.Added); c != 0 {
			return c
		}
		return strings.Compare(a.CVE, b.CVE)
	})
	return out, nil
}

// vpatchDirectives is every patch, in load order.
func vpatchDirectives() string {
	var sb strings.Builder
	for _, p := range VPatches {
		sb.WriteString(p.Rule)
		sb.WriteString("\n")
	}
	return sb.String()
}
