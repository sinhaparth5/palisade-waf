package bot

import (
	"maps"
	"slices"
	"testing"
)

// FuzzAIPolicy checks ParseAIPolicy (issue #308): only known categories with
// valid actions survive, and String parses back to the same policy.
func FuzzAIPolicy(f *testing.F) {
	for _, s := range []string{"training=block,user=allow", "search=challenge,search=allow", "training=", "x=block,,=", "user=block=block"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p := ParseAIPolicy(s)
		for k, v := range p {
			if !slices.Contains(AICategories, k) || !ValidAIAction(v) {
				t.Fatalf("%q kept %q=%q", s, k, v)
			}
		}
		if q := ParseAIPolicy(p.String()); !maps.Equal(p, q) {
			t.Fatalf("round trip of %q: %v -> %q -> %v", s, p, p.String(), q)
		}
	})
}
