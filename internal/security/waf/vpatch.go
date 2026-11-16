package waf

import (
	"embed"
	"fmt"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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

// shipped lists the embedded patches. A malformed file fails
// TestVPatchPack, so loading it never errors in a released binary. Loaded on
// first use, not at package init: compiling a rule makes Coraza test-write
// to TMPDIR, and at init that panics before main can explain an unwritable
// data dir (issue #274).
var shipped = sync.OnceValue(func() []VPatch {
	ps, err := loadVPatches()
	if err != nil {
		panic(err)
	}
	return ps
})

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
		p, err := ParseVPatch(e.Name(), string(b))
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	sortVPatches(out)
	return out, nil
}

func sortVPatches(ps []VPatch) {
	slices.SortFunc(ps, func(a, b VPatch) int {
		if c := strings.Compare(b.Added, a.Added); c != 0 {
			return c
		}
		return strings.Compare(a.CVE, b.CVE)
	})
}

// ParseVPatch checks one patch file (named name, for errors) the way the
// shipped ones are checked: header lines, one rule id in the patch range,
// and that it compiles.
func ParseVPatch(name, text string) (VPatch, error) {
	p := VPatch{Rule: text}
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
		return VPatch{}, fmt.Errorf("%s: needs # CVE:, # Product:, # Reference: and # Added: lines", name)
	}
	ids, err := validateRules(p.Rule, "virtual patch", VPatchIDMin, VPatchIDMax)
	if err != nil {
		return VPatch{}, fmt.Errorf("%s: %w", name, err)
	}
	if len(ids) != 1 {
		return VPatch{}, fmt.Errorf("%s: a patch is exactly one rule id, got %v", name, ids)
	}
	p.RuleID = ids[0]
	return p, nil
}

var extra atomic.Pointer[[]VPatch]

// SetExtraVPatches adds patches from outside the binary (an add-on's feed,
// each checked with ParseVPatch) to the shipped ones; it replaces the last
// set. A patch whose rule id is already loaded is skipped, so a release that
// ships the same patch wins. Engines built afterwards load them.
func SetExtraVPatches(ps []VPatch) { extra.Store(&ps) }

// VPatches lists the shipped and extra patches, newest first.
func VPatches() []VPatch {
	out := slices.Clone(shipped())
	if e := extra.Load(); e != nil {
		for _, p := range *e {
			if !slices.ContainsFunc(out, func(q VPatch) bool { return q.RuleID == p.RuleID }) {
				out = append(out, p)
			}
		}
	}
	sortVPatches(out)
	return out
}

// vpatchDirectives is every patch, in load order.
func vpatchDirectives() string {
	var sb strings.Builder
	for _, p := range VPatches() {
		sb.WriteString(p.Rule)
		sb.WriteString("\n")
	}
	return sb.String()
}
