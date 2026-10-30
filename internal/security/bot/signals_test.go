package bot

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
)

func TestAnalyze(t *testing.T) {
	// Fake DNS: 66.249.66.1 is a real Googlebot (PTR + matching A record),
	// 203.0.113.9 claims a googlebot.com PTR it doesn't forward-confirm.
	ptr := map[string][]string{
		"66.249.66.1":  {"crawl-66-249-66-1.googlebot.com."},
		"203.0.113.9":  {"crawl.googlebot.com."},
		"203.0.113.7":  {"evilgooglebot.com."},
		"66.249.88.69": {"google-proxy-66-249-88-69.google.com."},
	}
	fwd := map[string][]string{
		"crawl-66-249-66-1.googlebot.com":      {"66.249.66.1"},
		"crawl.googlebot.com":                  {"66.249.66.2"},
		"evilgooglebot.com":                    {"203.0.113.7"},
		"google-proxy-66-249-88-69.google.com": {"66.249.88.69"},
	}
	lookupAddr = func(_ context.Context, ip string) ([]string, error) {
		if n, ok := ptr[ip]; ok {
			return n, nil
		}
		return nil, errors.New("no PTR")
	}
	lookupHost = func(_ context.Context, host string) ([]string, error) {
		return fwd[host], nil
	}
	clear(rdnsCache)
	saved := trustedCrawlers
	t.Cleanup(func() { trustedCrawlers = saved })
	if err := AddPinnedCrawlers("my-uptime=192.0.2.0/28"); err != nil {
		t.Fatal(err)
	}

	const googleUA = "Mozilla/5.0 (compatible; Googlebot/2.1)"
	browser := map[string]string{"Accept-Language": "en", "Accept": "*/*", "Accept-Encoding": "gzip"}
	tests := []struct {
		name        string
		ua          string
		ip          string
		asn         uint
		headers     map[string]string
		wantScore   int
		wantBot     bool
		wantTrusted bool
		wantSignal  string
	}{
		{"googlebot verified by rdns", googleUA, "66.249.66.1", 0, nil, 0, false, true, "trusted_crawler"},
		{"adsense infeed verified by rdns", "Mozilla/5.0 (Linux; Android 4.0.4) (KHTML, like Gecko; GoogleAdSenseInfeed) Chrome", "66.249.88.69", 15169, nil, 0, false, true, "trusted_crawler"},
		{"adsense infeed spoofed", "Mozilla/5.0 (KHTML, like Gecko; GoogleAdSenseInfeed)", "198.51.100.1", 15169, browser, 0, false, false, "unverified_crawler"},
		{"googlebot spoofed, no ptr", googleUA, "198.51.100.1", 0, browser, 0, false, false, "unverified_crawler"},
		{"googlebot ptr not forward-confirmed", googleUA, "203.0.113.9", 0, browser, 0, false, false, "unverified_crawler"},
		{"googlebot ptr suffix lookalike", googleUA, "203.0.113.7", 0, browser, 0, false, false, "unverified_crawler"},
		{"googlebot spoofed, scored normally", googleUA, "198.51.100.1", 0, nil, 4, false, false, "unverified_crawler"},
		{"facebook verified by asn", "facebookexternalhit/1.1", "31.13.24.1", 32934, nil, 0, false, true, "trusted_crawler"},
		{"facebook wrong asn", "facebookexternalhit/1.1", "31.13.24.1", 16509, browser, 0, false, false, "unverified_crawler"},
		{"twitter verified by second asn", "Twitterbot/1.0", "8.25.194.1", 35995, nil, 0, false, true, "trusted_crawler"},
		{"whatsapp from phone is a link preview", "WhatsApp/2.24.1 A", "198.51.100.1", 64500, nil, 4, false, false, "link_preview"},
		{"imessage from phone is a link preview", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/601.2.4 (KHTML, like Gecko) Version/9.0.1 Safari/601.2.4 facebookexternalhit/1.1 Facebot Twitterbot/1.0", "198.51.100.1", 64500, browser, 0, false, false, "link_preview"},
		{"whatsapp real request", "WhatsApp/2.23.20.0", "198.51.100.1", 64500, map[string]string{"Accept": "*/*", "Accept-Language": "en-GB", "Accept-Encoding": "gzip, br", "Range": "bytes=0-307199"}, 0, false, false, "link_preview"},
		{"pinned monitor", "my-uptime/1.0", "192.0.2.10", 0, nil, 0, false, true, "trusted_crawler"},
		{"pinned monitor wrong ip", "my-uptime/1.0", "198.51.100.1", 0, browser, 0, false, false, "unverified_crawler"},
		{"slackbot is not trusted", "Slackbot-LinkExpanding 1.0", "198.51.100.1", 0, browser, 0, false, false, ""},
		{"browser", "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0", "198.51.100.1", 0, browser, 0, false, false, ""},
		{"scanner", "sqlmap/1.7", "198.51.100.1", 0, browser, 10, true, false, "scanner_ua"},
		{"http lib", "curl/8.0.1", "198.51.100.1", 0, browser, 3, false, false, "http_lib_ua"},
		{"short ua", "abc", "198.51.100.1", 0, browser, 2, false, false, "short_ua"},
		{"missing everything", "", "198.51.100.1", 0, nil, 9, false, false, "missing_ua"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set("User-Agent", tt.ua)
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			a := Analyze(r, tt.ip, tt.asn)
			if a.Score != tt.wantScore || a.IsBot != tt.wantBot || a.IsTrustedCrawler != tt.wantTrusted {
				t.Fatalf("got %+v", a)
			}
			if tt.wantSignal != "" && !slices.Contains(a.Signals, tt.wantSignal) {
				t.Fatalf("signals %v missing %q", a.Signals, tt.wantSignal)
			}
		})
	}
}

func TestCrawlerPin(t *testing.T) {
	if verifyCrawler(&crawler{ua: []string{"x"}}, "192.0.2.1", 0) {
		t.Fatal("crawler with no verification method must not verify")
	}
	c := &crawler{ua: []string{"x"}, cidrs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
	for ip, want := range map[string]bool{"192.0.2.1": true, "::ffff:192.0.2.1": true, "192.0.3.1": false, "bogus": false} {
		if got := verifyCrawler(c, ip, 0); got != want {
			t.Errorf("verifyCrawler(%q) = %v, want %v", ip, got, want)
		}
	}
}

func TestAddPinnedCrawlers(t *testing.T) {
	saved := trustedCrawlers
	t.Cleanup(func() { trustedCrawlers = saved })
	if err := AddPinnedCrawlers(" a=192.0.2.1 ; B=2001:db8::/32,198.51.100.0/24 ;"); err != nil {
		t.Fatal(err)
	}
	if c := matchCrawler("b"); c == nil || len(c.cidrs) != 2 || !verifyCrawler(c, "2001:db8::1", 0) {
		t.Fatalf("entry b not parsed: %+v", c)
	}
	if c := matchCrawler("a"); c == nil || !verifyCrawler(c, "192.0.2.1", 0) || verifyCrawler(c, "192.0.2.2", 0) {
		t.Fatal("bare IP must pin exactly one address")
	}
	for _, bad := range []string{"noequals", "=192.0.2.1", "x=", "x=not-an-ip"} {
		if AddPinnedCrawlers(bad) == nil {
			t.Errorf("AddPinnedCrawlers(%q) accepted", bad)
		}
	}
}
