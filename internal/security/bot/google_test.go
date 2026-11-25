package bot

import (
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestGoogleService(t *testing.T) {
	set := &googleSet{
		goog:  []netip.Prefix{netip.MustParsePrefix("66.102.0.0/20"), netip.MustParsePrefix("34.0.0.0/8"), netip.MustParsePrefix("2001:4860::/32")},
		cloud: []netip.Prefix{netip.MustParsePrefix("34.82.0.0/16")},
	}
	tests := []struct {
		name   string
		set    *googleSet
		method string
		body   string
		ip     string
		want   bool
	}{
		{"google proxy GET", set, "GET", "", "66.102.8.165", true},
		{"google HEAD", set, "HEAD", "", "66.102.8.165", true},
		{"google ipv6", set, "GET", "", "2001:4860:4801::1", true},
		{"mapped ipv4", set, "GET", "", "::ffff:66.102.8.165", true},
		{"google cloud vm", set, "GET", "", "34.82.1.1", false},
		{"google POST", set, "POST", "x=1", "66.102.8.165", false},
		{"not google", set, "GET", "", "198.51.100.1", false},
		{"bad ip", set, "GET", "", "nope", false},
		{"feature off", nil, "GET", "", "66.102.8.165", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			googleRanges.Store(tt.set)
			t.Cleanup(func() { googleRanges.Store(nil) })
			r := httptest.NewRequest(tt.method, "/?gtm_latency=1", strings.NewReader(tt.body))
			r.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.8103.78 Mobile Safari/537.36")
			a := Analyze(r, tt.ip, 15169)
			if a.GoogleService != tt.want {
				t.Fatalf("GoogleService = %v, want %v (signals %v)", a.GoogleService, tt.want, a.Signals)
			}
			if a.IsTrustedCrawler {
				t.Fatal("a Google service IP must never be a trusted crawler")
			}
		})
	}
}

func TestParseGoogleRanges(t *testing.T) {
	var many strings.Builder
	many.WriteString(`{"syncToken":"1","prefixes":[{"ipv6Prefix":"2001:4860::/32"}`)
	for i := range googleMinRanges {
		many.WriteString(`,{"ipv4Prefix":"8.8.` + string(rune('0'+i%10)) + `.0/24"}`)
	}
	many.WriteString(`]}`)
	tests := []struct {
		name    string
		body    string
		want    int
		wantErr bool
	}{
		{"valid", many.String(), googleMinRanges + 1, false},
		{"too few", `{"prefixes":[{"ipv4Prefix":"8.8.8.0/24"}]}`, 0, true},
		{"bad prefix", `{"prefixes":[{"ipv4Prefix":"8.8.8.0/99"}]}`, 0, true},
		{"empty entry", `{"prefixes":[{}]}`, 0, true},
		{"html error page", `<html>`, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ps, err := parseGoogleRanges([]byte(tt.body))
			if (err != nil) != tt.wantErr || len(ps) != tt.want {
				t.Fatalf("got %d prefixes, err %v; want %d, err %v", len(ps), err, tt.want, tt.wantErr)
			}
		})
	}
}

func FuzzGoogleRanges(f *testing.F) {
	f.Add([]byte(`{"prefixes":[{"ipv4Prefix":"8.8.8.0/24"},{"ipv6Prefix":"2001:4860::/32"}]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		ps, err := parseGoogleRanges(body)
		if err != nil {
			return
		}
		for _, p := range ps {
			if !p.IsValid() || p != p.Masked() {
				t.Fatalf("invalid or unmasked prefix %v", p)
			}
		}
	})
}
