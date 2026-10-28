package services

import (
	"fmt"
	"strings"
)

// maxCacheRules caps a service's per-path cache rules; matching is a linear
// scan per request.
const maxCacheRules = 100

// CacheRule is one per-path Varnish override (issue #212).
type CacheRule struct {
	prefix string
	cache  bool // false = bypass
}

// ParseCacheRules parses a service's cache rules: one "cache /path" or
// "bypass /path" per line, the path a prefix (a trailing "*" is allowed and
// ignored). "cache" caches matching GET/HEADs like static assets, ignoring
// cookies; "bypass" skips Varnish entirely. The longest matching prefix wins;
// a path no rule matches keeps the VCL's default behavior. Blank lines and
// "#" comments are skipped.
func ParseCacheRules(text string) ([]CacheRule, error) {
	var out []CacheRule
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 || (f[0] != "cache" && f[0] != "bypass") {
			return nil, fmt.Errorf("line %d: want \"cache /path\" or \"bypass /path\"", i+1)
		}
		p := strings.TrimSuffix(f[1], "*")
		if !strings.HasPrefix(p, "/") || strings.Contains(p, "*") {
			return nil, fmt.Errorf("line %d: the path must start with / and may only end in *", i+1)
		}
		out = append(out, CacheRule{prefix: p, cache: f[0] == "cache"})
	}
	if len(out) > maxCacheRules {
		return nil, fmt.Errorf("at most %d cache rules", maxCacheRules)
	}
	return out, nil
}

// matchCacheRule returns the rule with the longest prefix of path, or nil.
func matchCacheRule(rules []CacheRule, path string) *CacheRule {
	var best *CacheRule
	for i := range rules {
		r := &rules[i]
		if strings.HasPrefix(path, r.prefix) && (best == nil || len(r.prefix) > len(best.prefix)) {
			best = r
		}
	}
	return best
}
