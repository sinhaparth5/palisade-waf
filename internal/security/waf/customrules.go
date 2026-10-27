package waf

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
)

// Custom rules (issue #112) must use IDs in this range: clear of CRS
// (900000-999999) and of the ModSecurity local-use range a --waf-rules
// directory would normally use (1-99999).
const (
	CustomRuleIDMin = 1000000
	CustomRuleIDMax = 1999999
)

var ruleIDPattern = regexp.MustCompile(`(?i)\bid\s*:\s*'?(\d+)`)

// CustomRuleIDs returns the rule IDs a rule text declares, in order.
func CustomRuleIDs(rule string) []int {
	var ids []int
	for _, m := range ruleIDPattern.FindAllStringSubmatch(rule, -1) {
		id, _ := strconv.Atoi(m[1]) // ponytail: an id too long for int reads as 0, which fails the range check
		ids = append(ids, id)
	}
	return ids
}

// ValidateCustomRule checks an admin-written rule before it is saved and
// returns the IDs it declares. Only SecRule and SecAction are allowed, so a
// custom rule can't Include files or flip engine-wide settings such as
// SecRuleEngine or SecRuleRemoveById. It is compiled on its own, which is
// cheap, rather than with the whole CRS.
func ValidateCustomRule(rule string) ([]int, error) {
	return validateRules(rule, "custom", CustomRuleIDMin, CustomRuleIDMax)
}

// validateRules is ValidateCustomRule for any id range; kind names the
// range in errors.
func validateRules(rule, kind string, idMin, idMax int) ([]int, error) {
	joined := strings.NewReplacer("\\\r\n", " ", "\\\n", " ").Replace(rule)
	for _, line := range strings.Split(joined, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if !strings.EqualFold(f[0], "SecRule") && !strings.EqualFold(f[0], "SecAction") {
			return nil, fmt.Errorf("only SecRule and SecAction are allowed, found %q", f[0])
		}
	}
	ids := CustomRuleIDs(rule)
	for _, id := range ids {
		if id < idMin || id > idMax {
			return nil, fmt.Errorf("rule id %d is outside the %s range %d-%d", id, kind, idMin, idMax)
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("the rule needs an id in the range %d-%d", idMin, idMax)
	}
	if _, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(rule)); err != nil {
		return nil, err
	}
	return ids, nil
}
