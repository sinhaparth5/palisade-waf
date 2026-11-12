package csp

import (
	"strings"
	"testing"
)

// FuzzParse reads arbitrary report bodies (issue #265). Only script
// directives are kept, and a recorded source never carries a path or query.
func FuzzParse(f *testing.F) {
	f.Add(`{"csp-report":{"document-uri":"https://a.test/p?q=1","blocked-uri":"https://cdn.test/x.js","effective-directive":"script-src-elem"}}`)
	f.Add(`[{"type":"csp-violation","body":{"documentURL":"https://a.test/","blockedURL":"inline","effectiveDirective":"script-src"}}]`)
	f.Add(`{"csp-report":{"violated-directive":"script-src 'self'","blocked-uri":"data:text/javascript,1"}}`)
	f.Add(`[{"type":"csp-violation","body":null}, 1, "x"]`)
	f.Fuzz(func(t *testing.T, body string) {
		for _, v := range parse([]byte(body)) {
			if v.source == "" || strings.ContainsAny(v.source, "?#") || strings.Count(v.source, "/") > 2 {
				t.Fatalf("source %q", v.source)
			}
			if strings.Contains(v.page, "?") {
				t.Fatalf("page kept a query: %q", v.page)
			}
		}
	})
}
