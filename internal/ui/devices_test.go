package ui

import (
	"strings"
	"testing"
)

// TestBrowserOS pins the ordering traps: every Chromium browser also says
// "Chrome", and Chrome/Edge both say "Safari", so the specific brand has to
// win over the generic one.
func TestBrowserOS(t *testing.T) {
	cases := []struct {
		ua, want string
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36", "Chrome on Windows"},
		{"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/131.0 Safari/537.36 Edg/131.0", "Edge on Windows"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15", "Safari on macOS"},
		{"Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0", "Firefox on Linux"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile Safari/604.1", "Safari on iPhone"},
		{"curl/8.5.0", "curl on Unknown OS"},
		{"", "Unknown device"},
	}
	for _, c := range cases {
		if got := browserOS(c.ua); got != c.want {
			t.Errorf("browserOS(%.40q) = %q, want %q", c.ua, got, c.want)
		}
	}
}

// TestCurrentFirst pins the current device to the top even when another
// live row (a pre-single-session leftover) sorts above it, and leaves the
// order of everything else alone.
func TestCurrentFirst(t *testing.T) {
	tokens := func(rows []deviceRow) string {
		var out []string
		for _, r := range rows {
			out = append(out, r.Token)
		}
		return strings.Join(out, ",")
	}
	cases := []struct {
		name string
		in   []deviceRow
		want string
	}{
		{"current already first", []deviceRow{{Token: "mine", Current: true}, {Token: "a"}}, "mine,a"},
		{"current below a live row", []deviceRow{{Token: "legacy", Live: true}, {Token: "mine", Current: true}, {Token: "dead"}}, "mine,legacy,dead"},
		{"current last", []deviceRow{{Token: "a"}, {Token: "b"}, {Token: "mine", Current: true}}, "mine,a,b"},
		{"no current row", []deviceRow{{Token: "a"}, {Token: "b"}}, "a,b"},
		{"empty", nil, ""},
	}
	for _, c := range cases {
		if got := tokens(currentFirst(c.in)); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
