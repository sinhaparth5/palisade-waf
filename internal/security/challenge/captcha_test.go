package challenge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestWithCaptcha(t *testing.T) {
	for _, tc := range []struct {
		provider, site, secret string
		want                   string
	}{
		{"turnstile", "site", "sec", "turnstile"},
		{"hcaptcha", "site", "sec", "hcaptcha"},
		{"recaptcha", "site", "sec", ""},
		{"turnstile", "", "sec", ""},
		{"turnstile", "site", "", ""},
		{"", "", "", ""},
	} {
		c := New("secret", 3600, 5).WithCaptcha(tc.provider, tc.site, tc.secret)
		if c.captchaProvider != tc.want {
			t.Errorf("WithCaptcha(%q, %q, %q) provider = %q, want %q", tc.provider, tc.site, tc.secret, c.captchaProvider, tc.want)
		}
	}
	var nilC *Challenger
	if nilC.WithCaptcha("turnstile", "s", "k") != nil {
		t.Error("nil challenger stayed nil")
	}
}

func TestVerifyCaptchaToken(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = string(body)
		q, _ := url.ParseQuery(got)
		fmt.Fprintf(w, `{"success":%v}`, q.Get("response") == "good")
	}))
	defer srv.Close()
	old := captchaVerifyURLs["turnstile"]
	captchaVerifyURLs["turnstile"] = srv.URL
	defer func() { captchaVerifyURLs["turnstile"] = old }()

	post := func(c *Challenger, nonce, token string, automation ...string) int {
		exp := time.Now().Unix() + 120
		body, _ := json.Marshal(map[string]any{
			"nonce": nonce, "exp": exp, "sig": c.signNonce(nonce, exp),
			"captcha_token": token, "automation": automation,
		})
		rec := httptest.NewRecorder()
		c.ServeVerify(rec, httptest.NewRequest(http.MethodPost, "/_cz/verify", bytes.NewReader(body)))
		return rec.Code
	}

	c := New("secret", 3600, 5).WithCaptcha("turnstile", "site", "sec")
	if code := post(c, "n1", "bad"); code != http.StatusForbidden {
		t.Errorf("rejected token: %d, want 403", code)
	}
	if code := post(c, "n2", "good"); code != http.StatusOK {
		t.Errorf("accepted token: %d, want 200", code)
	}
	if !strings.Contains(got, "secret=sec") || !strings.Contains(got, "response=good") {
		t.Errorf("siteverify body = %q", got)
	}
	if code := post(c, "n3", "good", "webdriver"); code != http.StatusForbidden {
		t.Errorf("automation with token: %d, want 403", code)
	}
	// No provider configured: a token is never accepted in place of the PoW.
	if code := post(New("secret", 3600, 5), "n4", "good"); code != http.StatusForbidden {
		t.Errorf("token without captcha configured: %d, want 403", code)
	}
}

func TestServePageCaptchaConfig(t *testing.T) {
	for provider, want := range map[string]bool{"": false, "hcaptcha": true} {
		c := New("secret", 3600, 5).WithCaptcha(provider, "site-key-1", "sec")
		rec := httptest.NewRecorder()
		c.ServePage(rec, httptest.NewRequest(http.MethodGet, c.ChallengeURL("/"), nil))
		body := rec.Body.String()
		if strings.Contains(body, "site-key-1") != want || strings.Contains(body, "js.hcaptcha.com") != want {
			t.Errorf("provider %q: captcha config in page = %v, want %v", provider, !want, want)
		}
		if strings.Contains(body, `"sec"`) {
			t.Errorf("provider %q: secret leaked into page", provider)
		}
	}
}
