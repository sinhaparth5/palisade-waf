package ui

import (
	"net/http"
	"strings"
	"testing"

	"palisade/internal/storage"
)

type protectionPage struct {
	Bot       botView       `json:"bot"`
	RateLimit rateLimitView `json:"rate_limit"`
	Trusted   []string      `json:"trusted_ips"`
	Varnish   varnishView   `json:"varnish"`
}

// TestProtectionSettings: bot, rate limit, trusted IPs and Varnish save,
// reload, refuse bad input with field errors and keep write-only secrets.
func TestProtectionSettings(t *testing.T) {
	env := newAdminEnv(t)
	const base = "/admin/api/settings/"

	goodBot := botView{Enabled: true, Threshold: 9, TTL: 600, CaptchaProvider: "turnstile", CaptchaSiteKey: "site", CaptchaSecret: "s3cret", AITraining: "block", AIUser: "allow"}
	for _, tc := range []struct {
		path  string
		body  any
		field string
	}{
		{"bot", botView{Threshold: 0, TTL: 600}, "threshold"},
		{"bot", botView{Threshold: 8, TTL: 10}, "ttl"},
		{"bot", botView{Threshold: 8, TTL: 600, CaptchaProvider: "recaptcha"}, "captcha_provider"},
		{"bot", botView{Threshold: 8, TTL: 600, CaptchaProvider: "hcaptcha", CaptchaSecret: "x"}, "captcha_site_key"},
		{"bot", botView{Threshold: 8, TTL: 600, CaptchaProvider: "hcaptcha", CaptchaSiteKey: "x"}, "captcha_secret"},
		{"bot", botView{Threshold: 8, TTL: 600, AISearch: "maybe"}, "ai_search"},
		{"rate-limit", rateLimitView{Enabled: true, RPS: 0, Burst: 5}, "rps"},
		{"rate-limit", rateLimitView{Enabled: true, RPS: 5, Burst: 0}, "burst"},
		{"trusted-ips", map[string]string{"trusted_ips": "10.0.0.1 nope"}, "trusted_ips"},
		{"varnish", varnishView{Addr: "6081"}, "addr"},
		{"varnish", varnishView{Addr: "10.0.0.5:6081"}, "addr"},
	} {
		var got jsonError
		if rec := env.doJSON(env.session, http.MethodPut, base+tc.path, tc.body, &got); rec.Code != http.StatusBadRequest || got.Fields[tc.field] == "" {
			t.Errorf("%s %+v: %d %s, want a %s error", tc.path, tc.body, rec.Code, rec.Body, tc.field)
		}
	}
	if env.count("bot") != 0 || env.count("ratelimit") != 0 {
		t.Fatal("a refused save reloaded")
	}

	for _, tc := range []struct {
		path string
		body any
	}{
		{"bot", goodBot},
		{"bot", botView{Enabled: true, Threshold: 9, TTL: 600, CaptchaProvider: "turnstile", CaptchaSiteKey: "site2", AITraining: "block", AIUser: "allow"}}, // blank secret kept
		{"rate-limit", rateLimitView{Enabled: true, RPS: 2.5, Burst: 10}},
		{"rate-limit", rateLimitView{Enabled: false}}, // off with blanks keeps the numbers
		{"trusted-ips", map[string]string{"trusted_ips": "203.0.113.10\n198.51.100.0/24 203.0.113.10"}},
		{"varnish", varnishView{Enabled: true, Addr: "[::1]:6081"}},
	} {
		if rec := env.doJSON(env.session, http.MethodPut, base+tc.path, tc.body, nil); rec.Code != http.StatusNoContent {
			t.Fatalf("%s: %d %s", tc.path, rec.Code, rec.Body)
		}
	}
	if env.count("bot") != 2 || env.count("ratelimit") != 2 {
		t.Errorf("reloads: bot %d, rate limit %d", env.count("bot"), env.count("ratelimit"))
	}
	if !env.h.registry.Trusted("198.51.100.7") {
		t.Error("trusted IPs not applied")
	}
	if env.h.registry.AIAction(nil, "training") != "block" {
		t.Error("registry not reloaded with the AI crawler policy")
	}

	var p protectionPage
	rec := env.doJSON(env.session, http.MethodGet, base+"protection", nil, &p)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "s3cret") {
		t.Fatalf("read: %d %s", rec.Code, rec.Body)
	}
	if b := p.Bot; !b.Enabled || b.Threshold != 9 || b.CaptchaSiteKey != "site2" || !b.CaptchaSecretSet || b.AITraining != "block" || b.AISearch != "" || b.AIUser != "allow" {
		t.Errorf("bot = %+v", b)
	}
	if cc, _ := env.db.GetCaptchaConfig(); cc.Secret != "s3cret" {
		t.Errorf("captcha secret = %q", cc.Secret)
	}
	if r := p.RateLimit; r.Enabled || r.RPS != 2.5 || r.Burst != 10 {
		t.Errorf("rate limit = %+v", r)
	}
	if len(p.Trusted) != 2 || p.Varnish != (varnishView{true, "[::1]:6081"}) {
		t.Errorf("trusted = %v, varnish = %+v", p.Trusted, p.Varnish)
	}

	viewer := env.sessionAs(storage.RoleViewer)
	if rec := env.doJSON(viewer, http.MethodGet, base+"protection", nil, nil); rec.Code != http.StatusOK {
		t.Errorf("viewer read: %d", rec.Code)
	}
	if rec := env.doJSON(viewer, http.MethodPut, base+"varnish", varnishView{}, nil); rec.Code != http.StatusForbidden {
		t.Errorf("viewer write: %d", rec.Code)
	}
}
