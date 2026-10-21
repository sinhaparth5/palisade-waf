package waf

import (
	"strings"
	"testing"
)

// FuzzValidateCustomRule checks the validator never panics and that anything
// it accepts holds up its promises: only SecRule/SecAction directives, and at
// least one id, all inside the custom range.
func FuzzValidateCustomRule(f *testing.F) {
	for _, s := range []string{
		`SecRule REQUEST_URI "@contains /x" "id:1000001,phase:1,deny,status:403"`,
		"SecAction \\\n  \"id:1000002,phase:1,pass,nolog\"",
		`SecRuleEngine Off`,
		`Include /etc/passwd`,
		`SecRule ARGS "@rx a" "id:5,deny"`,
		"# comment\nSecRule ARGS \"@rx a\" \"id:'1999999',deny\"",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, rule string) {
		ids, err := ValidateCustomRule(rule)
		if err != nil {
			return
		}
		if len(ids) == 0 {
			t.Fatalf("accepted %q with no ids", rule)
		}
		for _, id := range ids {
			if id < CustomRuleIDMin || id > CustomRuleIDMax {
				t.Fatalf("accepted %q with out-of-range id %d", rule, id)
			}
		}
		joined := strings.NewReplacer("\\\r\n", " ", "\\\n", " ").Replace(rule)
		for _, line := range strings.Split(joined, "\n") {
			f := strings.Fields(line)
			if len(f) == 0 || strings.HasPrefix(f[0], "#") {
				continue
			}
			if !strings.EqualFold(f[0], "SecRule") && !strings.EqualFold(f[0], "SecAction") {
				t.Fatalf("accepted %q with directive %q", rule, f[0])
			}
		}
	})
}
