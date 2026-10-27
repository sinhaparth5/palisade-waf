package bot

import (
	"net/http/httptest"
	"slices"
	"testing"
)

func TestAnalyzeAICrawler(t *testing.T) {
	saved := trustedCrawlers
	t.Cleanup(func() { trustedCrawlers = saved })
	trustedCrawlers = slices.Clone(saved) // AddPinnedCrawlers edits entries in place
	if err := AddPinnedCrawlers("gptbot=192.0.2.0/24"); err != nil {
		t.Fatal(err)
	}
	if n := len(trustedCrawlers); n != len(saved) {
		t.Fatalf("pin for a listed UA added an entry: %d, want %d", n, len(saved))
	}

	tests := []struct {
		name, ua, ip string
		asn          uint
		wantCat      string
		wantVerified bool
	}{
		{"gptbot pinned", "Mozilla/5.0; compatible; GPTBot/1.2", "192.0.2.5", 0, AITraining, true},
		{"gptbot spoofed", "Mozilla/5.0; compatible; GPTBot/1.2", "198.51.100.1", 0, AITraining, false},
		{"claudebot never verifies unpinned", "ClaudeBot/1.0", "198.51.100.1", 0, AITraining, false},
		{"meta agent by asn", "meta-externalagent/1.1", "31.13.24.1", 32934, AITraining, true},
		{"meta agent wrong asn", "meta-externalagent/1.1", "31.13.24.1", 16509, AITraining, false},
		{"meta fetcher", "meta-externalfetcher/1.1", "31.13.24.1", 32934, AIUser, true},
		{"oai search", "OAI-SearchBot/1.0", "198.51.100.1", 0, AISearch, false},
		{"chatgpt user", "ChatGPT-User/1.0", "198.51.100.1", 0, AIUser, false},
		{"perplexity user", "Perplexity-User/1.0", "198.51.100.1", 0, AIUser, false},
		{"facebook preview is not AI", "facebookexternalhit/1.1", "31.13.24.1", 32934, "", false},
		{"browser", "Mozilla/5.0 Firefox/130.0", "198.51.100.1", 0, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set("User-Agent", tt.ua)
			a := Analyze(r, tt.ip, tt.asn)
			if a.AICategory != tt.wantCat || a.AIVerified != tt.wantVerified {
				t.Fatalf("got category %q verified %v, want %q %v", a.AICategory, a.AIVerified, tt.wantCat, tt.wantVerified)
			}
			if tt.wantCat != "" && a.IsTrustedCrawler {
				t.Fatal("an AI crawler must not be a trusted crawler; the policy decides")
			}
		})
	}
}

func TestParseAIPolicy(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"user=allow,training=block", "training=block,user=allow"},
		{"training=block,search=nope,other=block,user", "training=block"},
		{"search=challenge", "search=challenge"},
	}
	for _, tt := range tests {
		if got := ParseAIPolicy(tt.in).String(); got != tt.want {
			t.Errorf("ParseAIPolicy(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
