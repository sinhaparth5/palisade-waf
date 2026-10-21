package ui

import "testing"

// FuzzUABrowserOS checks the User-Agent matcher never panics and always
// returns a label for both halves.
func FuzzUABrowserOS(f *testing.F) {
	for _, s := range []string{
		"",
		"curl/8.5.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, ua string) {
		b, os := uaBrowserOS(ua)
		if b == "" || os == "" {
			t.Fatalf("uaBrowserOS(%q) = %q, %q", ua, b, os)
		}
		if browserOS(ua) == "" {
			t.Fatalf("browserOS(%q) is empty", ua)
		}
	})
}
