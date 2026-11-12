package bot

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// FuzzWebBotAuth feeds arbitrary Signature-Input, Signature and
// Signature-Agent headers through verification (issue #265). The key
// directory is pre-cached, so nothing is fetched; a request is only ever
// verified by the draft's real test signature.
func FuzzWebBotAuth(f *testing.F) {
	vec := vecRequest("example.com", "GPTBot/1.2", false)
	f.Add(vec.Header.Get("Signature-Input"), vec.Header.Get("Signature"), vec.Header.Get("Signature-Agent"))
	f.Add(`sig1=("@target-uri" "signature-agent");created=1;expires=2;tag="web-bot-auth"`, `sig1=:AAAA:`, `"https://signature-agent.test"`)
	f.Add(`a=(), b=("x";k=?1);c=1.5`, `a=:=:, b="s"`, `x=("y")`)
	f.Add(`sig=("@authority"`, `sig=:`, `"`)

	pub, _ := base64.RawURLEncoding.DecodeString(vecX)
	wbaMu.Lock()
	wbaCache[vecAgent] = &wbaDir{keys: map[string]ed25519.PublicKey{vecKeyID: pub}, exp: time.Now().Add(24 * time.Hour), fetching: true}
	wbaMu.Unlock()
	f.Cleanup(func() { clear(wbaCache) })
	c := &crawler{sigAgents: []string{vecAgent}}

	f.Fuzz(func(t *testing.T, input, sig, agent string) {
		_, _ = parseSFDict(input)
		_ = parseSigAgentHeader(agent)
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = "example.com"
		for k, v := range map[string]string{"Signature-Input": input, "Signature": sig, "Signature-Agent": agent} {
			if strings.ContainsAny(v, "\r\n\x00") {
				return
			}
			r.Header.Set(k, v)
		}
		if webBotAuthVerified(r, c) && sig != vec.Header.Get("Signature") {
			t.Fatalf("verified a request without the vector's signature: %q", sig)
		}
	})
}
