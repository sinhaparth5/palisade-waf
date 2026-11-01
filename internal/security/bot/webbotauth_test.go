package bot

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

// Test vector: draft-ietf-webbotauth-httpsig-protocol-00 Appendix E.2
// (RFC 9421 test-key-ed25519).
const (
	vecX     = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
	vecKeyID = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"
	vecAgent = "https://signature-agent.test"
)

func vecRequest(host, ua string, legacy bool) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = host
	r.Header.Set("User-Agent", ua)
	if legacy { // E.2.2, expired in 2025
		r.Header.Set("Signature-Agent", `"https://signature-agent.test"`)
		r.Header.Set("Signature-Input", `sig2=("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"`)
		r.Header.Set("Signature", `sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:`)
		return r
	}
	r.Header.Set("Signature-Agent", `agent2="https://signature-agent.test"`)
	r.Header.Set("Signature-Input", `sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";tag="web-bot-auth"`)
	r.Header.Set("Signature", `sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:`)
	return r
}

func TestWebBotAuth(t *testing.T) {
	saved := trustedCrawlers
	t.Cleanup(func() { trustedCrawlers = saved; clear(wbaCache) })
	trustedCrawlers = slices.Clone(saved)
	if err := AddPinnedCrawlers("gptbot=" + vecAgent + ";my-bot=" + vecAgent); err != nil {
		t.Fatal(err)
	}
	if jwkThumbprint(vecX) != vecKeyID {
		t.Fatalf("thumbprint %s, want %s", jwkThumbprint(vecX), vecKeyID)
	}
	pub, _ := base64.RawURLEncoding.DecodeString(vecX)

	// A directory still being fetched (fetching set, so no real request to
	// the test origin) leaves the request unverified.
	wbaMu.Lock()
	wbaCache[vecAgent] = &wbaDir{fetching: true}
	wbaMu.Unlock()
	if a := Analyze(vecRequest("example.com", "GPTBot/1.2", false), "198.51.100.1", 0); a.AIVerified {
		t.Fatal("verified before the directory was cached")
	}
	wbaMu.Lock()
	wbaCache[vecAgent] = &wbaDir{keys: map[string]ed25519.PublicKey{vecKeyID: pub}, exp: time.Now().Add(time.Hour), fetching: true}
	wbaMu.Unlock()

	tests := []struct {
		name, host, ua string
		legacy         bool
		want           bool
	}{
		{"valid", "example.com", "GPTBot/1.2", false, true},
		{"authority port 443", "example.com:443", "GPTBot/1.2", false, true},
		{"other host", "evil.example", "GPTBot/1.2", false, false},
		{"ua without that agent", "example.com", "ClaudeBot/1.0", false, false},
		{"legacy expired", "example.com", "GPTBot/1.2", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if a := Analyze(vecRequest(tt.host, tt.ua, tt.legacy), "198.51.100.1", 0); a.AIVerified != tt.want {
				t.Errorf("AIVerified = %v, want %v (%v)", a.AIVerified, tt.want, a.Signals)
			}
		})
	}
	t.Run("pinned non-AI crawler", func(t *testing.T) {
		if a := Analyze(vecRequest("example.com", "my-bot/1", false), "198.51.100.1", 0); !a.IsTrustedCrawler {
			t.Errorf("not trusted: %v", a.Signals)
		}
	})
	t.Run("tampered signature", func(t *testing.T) {
		r := vecRequest("example.com", "GPTBot/1.2", false)
		r.Header.Set("Signature", `sig2=:AAAAx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:`)
		if Analyze(r, "198.51.100.1", 0).AIVerified {
			t.Error("tampered signature verified")
		}
	})
	t.Run("agent not covered", func(t *testing.T) {
		r := vecRequest("example.com", "GPTBot/1.2", false)
		r.Header.Set("Signature-Input", `sig2=("@authority");created=1735689600;keyid="`+vecKeyID+`";expires=4889289600;tag="web-bot-auth"`)
		if Analyze(r, "198.51.100.1", 0).AIVerified {
			t.Error("verified without covering signature-agent")
		}
	})
}

func TestWebBotAuthFetch(t *testing.T) {
	t.Cleanup(func() { clear(wbaCache) })
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wbaDirPath {
			http.Redirect(w, r, wbaDirPath, http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + vecX + `"},{"kty":"OKP","crv":"Ed25519","x":"bad"}]}`))
	}))
	defer srv.Close()
	savedClient := wbaClient
	t.Cleanup(func() { wbaClient = savedClient })
	wbaClient = srv.Client()
	wbaClient.CheckRedirect = savedClient.CheckRedirect
	wbaClient.Timeout = savedClient.Timeout

	origin, err := parseSigAgent(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if wbaKey(origin, vecKeyID) != nil {
		t.Fatal("key served before fetch")
	}
	deadline := time.Now().Add(5 * time.Second)
	for wbaKey(origin, vecKeyID) == nil {
		if time.Now().After(deadline) {
			t.Fatal("directory never cached")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := fetchDir(origin + "/x"); err == nil {
		t.Error("followed a redirect")
	}
	for _, bad := range []string{"http://chatgpt.com", "https://chatgpt.com/keys", "https://u@chatgpt.com", "https://chatgpt.com?a"} {
		if _, err := parseSigAgent(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
