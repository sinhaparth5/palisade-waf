package services

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"palisade/internal/security/ratelimit"
	"palisade/internal/storage"
)

// maxRateRules caps a service's per-path rate limits; matching is a linear
// scan per request and each rule owns a limiter.
const maxRateRules = 50

// RateRule is one per-path rate limit (issue #280).
type RateRule struct {
	Method string // upper case, "*" = any
	Prefix string
	RPS    float64
	Burst  int
	Text   string // the rule as written, for the log row
	lim    *ratelimit.Limiter
}

// ParseRateRules parses a service's per-path rate limits: one
// "METHOD /prefix rate burst" per line. METHOD is an HTTP method or "*";
// the path is a prefix of the service path (a trailing "*" is ignored); rate
// is N, N/s, N/m or N/h requests. The longest matching prefix wins, and a
// rule naming the method beats "*" on the same prefix. Blank lines and "#"
// comments are skipped.
func ParseRateRules(text string) ([]RateRule, error) {
	var out []RateRule
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 4 {
			return nil, fmt.Errorf("line %d: want \"METHOD /path rate burst\", e.g. \"POST /reset 5/m 5\"", i+1)
		}
		m := strings.ToUpper(f[0])
		if m != "*" && strings.Trim(m, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
			return nil, fmt.Errorf("line %d: method must be a word like POST, or *", i+1)
		}
		p := strings.TrimSuffix(f[1], "*")
		if !strings.HasPrefix(p, "/") || strings.Contains(p, "*") || len(p) > 256 {
			return nil, fmt.Errorf("line %d: the path must start with / and may only end in *", i+1)
		}
		rps, err := parseRate(f[2])
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		burst, err := strconv.Atoi(f[3])
		if err != nil || burst < 1 || burst > 100000 {
			return nil, fmt.Errorf("line %d: burst must be a whole number from 1", i+1)
		}
		out = append(out, RateRule{Method: m, Prefix: p, RPS: rps, Burst: burst, Text: strings.Join([]string{m, p, f[2], f[3]}, " ")})
	}
	if len(out) > maxRateRules {
		return nil, fmt.Errorf("at most %d path rate limits", maxRateRules)
	}
	return out, nil
}

func parseRate(s string) (float64, error) {
	n, unit, _ := strings.Cut(s, "/")
	per := map[string]float64{"": 1, "s": 1, "m": 60, "h": 3600}[unit]
	v, err := strconv.ParseFloat(n, 64)
	if per == 0 || err != nil || !(v > 0 && v <= 1e6) { // NaN fails both
		return 0, fmt.Errorf("rate %q: want a positive N, N/s, N/m or N/h", s)
	}
	return v / per, nil
}

// buildRateRules parses each service's stored rules and gives every rule its
// own limiter, so counters are per client and per rule. The admin UI
// validates rules on save; a stored row that no longer parses is skipped.
func buildRateRules(stored map[int]string, list []storage.Service) map[string][]RateRule {
	out := map[string][]RateRule{}
	for _, s := range list {
		rules, err := ParseRateRules(stored[s.ID])
		if err != nil {
			log.Printf("path rate limits for service %q: %v", s.Name, err)
			continue
		}
		for i := range rules {
			rules[i].lim = ratelimit.NewWithParams(rules[i].RPS, rules[i].Burst)
		}
		if len(rules) > 0 {
			out[s.Name] = rules
		}
	}
	return out
}

func stopRateRules(m map[string][]RateRule) {
	for _, rules := range m {
		for _, r := range rules {
			r.lim.Stop()
		}
	}
}

// AllowPath checks the service's per-path rate limit for method and path
// (service prefix stripped). It returns the matching rule's text, "" when
// no rule matches (the result is then Allowed).
func (r *Registry) AllowPath(name, method, path, key string) (ratelimit.Result, string) {
	r.mu.RLock()
	rules := r.rateRules[name]
	r.mu.RUnlock()
	var best *RateRule
	for i := range rules {
		x := &rules[i]
		if (x.Method != "*" && x.Method != method) || !strings.HasPrefix(path, x.Prefix) {
			continue
		}
		if best == nil || len(x.Prefix) > len(best.Prefix) || (len(x.Prefix) == len(best.Prefix) && best.Method == "*") {
			best = x
		}
	}
	if best == nil {
		return ratelimit.Result{Allowed: true}, ""
	}
	return best.lim.Allow(key), best.Text
}
