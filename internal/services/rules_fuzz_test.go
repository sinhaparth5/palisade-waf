package services

import (
	"slices"
	"strings"
	"testing"
)

// FuzzCacheRules checks ParseCacheRules (issue #308): a failure returns no
// rules, every rule is a "/" prefix without "*", and the rules written back
// as text parse to the same rules.
func FuzzCacheRules(f *testing.F) {
	for _, s := range []string{
		"cache /static/\nbypass /api*", "# c\n\n  cache /*", "cache /a*b", "purge /x",
		"cache /a b", strings.Repeat("cache /a\n", maxCacheRules+1),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		rules, err := ParseCacheRules(text)
		if err != nil {
			if rules != nil {
				t.Fatalf("error %v with rules %v", err, rules)
			}
			return
		}
		if len(rules) > maxCacheRules {
			t.Fatalf("%d rules", len(rules))
		}
		var b strings.Builder
		for _, r := range rules {
			if !strings.HasPrefix(r.prefix, "/") || strings.Contains(r.prefix, "*") {
				t.Fatalf("prefix %q", r.prefix)
			}
			verb := "bypass"
			if r.cache {
				verb = "cache"
			}
			b.WriteString(verb + " " + r.prefix + "\n")
		}
		if again, err := ParseCacheRules(b.String()); err != nil || !slices.Equal(again, rules) {
			t.Fatalf("round trip of %q: %v, %v", b.String(), again, err)
		}
	})
}

// FuzzRateRules checks ParseRateRules (issue #308): a failure returns no
// rules, every rule is in range (a finite rate), and each rule's Text
// parses back to the same rule.
func FuzzRateRules(f *testing.F) {
	for _, s := range []string{
		"POST /reset 5/m 5\n* /api* 10 20", "# c\nget / 1/h 1", "POST /x NaN 5", "POST /x 1/d 5",
		"POST /x 5 0", "P0ST /x 5 5", "POST /a*b 5 5", "POST /x +1e6 +100000",
		strings.Repeat("GET /a 1 1\n", maxRateRules+1),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		rules, err := ParseRateRules(text)
		if err != nil {
			if rules != nil {
				t.Fatalf("error %v with rules %v", err, rules)
			}
			return
		}
		if len(rules) > maxRateRules {
			t.Fatalf("%d rules", len(rules))
		}
		texts := make([]string, len(rules))
		for i, r := range rules {
			if r.Method != "*" && (r.Method == "" || strings.Trim(r.Method, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "") {
				t.Fatalf("method %q", r.Method)
			}
			if !strings.HasPrefix(r.Prefix, "/") || strings.Contains(r.Prefix, "*") || len(r.Prefix) > 256 {
				t.Fatalf("prefix %q", r.Prefix)
			}
			if !(r.RPS > 0 && r.RPS <= 1e6) || r.Burst < 1 || r.Burst > 100000 {
				t.Fatalf("rule %q: rps %v burst %d", r.Text, r.RPS, r.Burst)
			}
			texts[i] = r.Text
		}
		if again, err := ParseRateRules(strings.Join(texts, "\n")); err != nil || !slices.Equal(again, rules) {
			t.Fatalf("round trip of %q: %v, %v", texts, again, err)
		}
	})
}
