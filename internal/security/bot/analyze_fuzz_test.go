package bot

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

type offlineRT struct{}

func (offlineRT) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("offline")
}

// signalWeights is what each scored signal adds; the rest add nothing.
var signalWeights = map[string]int{
	"missing_ua": 5, "scanner_ua": 10, "http_lib_ua": 3, "short_ua": 2,
	"no_accept_language": 2, "no_accept": 1, "no_accept_encoding": 1,
}

// FuzzBotAnalyze (issue #307): arbitrary headers never panic, the score is
// the sum of its signals' weights and stays in 0..14 (scanner UA plus
// three missing headers), and a trusted crawler scores nothing. DNS and
// Web Bot Auth directory fetches are stubbed: a fuzz run stays offline.
func FuzzBotAnalyze(f *testing.F) {
	lookupAddr = func(context.Context, string) ([]string, error) { return nil, errors.New("offline") }
	lookupHost = lookupAddr
	wbaClient = &http.Client{Timeout: time.Second, Transport: offlineRT{}}

	f.Add("Mozilla/5.0 (X11; Linux x86_64)", "en", "text/html", "gzip", "GET", "", "", "203.0.113.5", uint(0))
	f.Add("", "", "", "", "POST", "", "", "", uint(0))
	f.Add("sqlmap/1.7", "", "", "", "GET", "", "", "::1", uint(0))
	f.Add("curl/8", "", "*/*", "", "HEAD", "", "", "198.51.100.1", uint(15169))
	f.Add("Mozilla/5.0 (compatible; Googlebot/2.1)", "", "", "", "GET", "", "", "66.249.66.1", uint(15169))
	f.Add("Mozilla/5.0 ChatGPT-User/1.0", "", "", "", "GET", `"https://chatgpt.com"`, `sig1=:AAAA:`, "20.0.0.1", uint(8075))
	f.Fuzz(func(t *testing.T, ua, lang, accept, enc, method, agent, sig, ip string, asn uint) {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.Method = method
		for k, v := range map[string]string{"User-Agent": ua, "Accept-Language": lang, "Accept": accept,
			"Accept-Encoding": enc, "Signature-Agent": agent, "Signature": sig,
			"Signature-Input": `sig1=("@authority" "signature-agent");keyid="k";tag="web-bot-auth"`} {
			if v != "" {
				r.Header.Set(k, v)
			}
		}
		a := Analyze(r, ip, asn)
		sum := 0
		for _, s := range a.Signals {
			sum += signalWeights[s]
		}
		if a.Score != sum || a.Score < 0 || a.Score > 14 {
			t.Fatalf("score %d, signals %v (sum %d)", a.Score, a.Signals, sum)
		}
		if a.IsTrustedCrawler && a.Score != 0 {
			t.Fatalf("trusted crawler scored %d", a.Score)
		}
	})
}
