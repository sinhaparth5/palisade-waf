package waf

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerdictCacheGetSetAndExpiry(t *testing.T) {
	c := newVerdictCache(20*time.Millisecond, 10)
	want := Result{Blocked: true, Status: 403, RuleID: 942100, Action: "waf_rule"}
	c.put("key1", want)

	got, ok := c.get("key1")
	if !ok || got != want {
		t.Fatalf("get after put = %+v, %v; want %+v, true", got, ok, want)
	}

	time.Sleep(30 * time.Millisecond)
	if _, ok := c.get("key1"); ok {
		t.Fatalf("get after TTL expiry should miss")
	}
}

func TestVerdictCacheEvictsLeastRecentlyUsed(t *testing.T) {
	c := newVerdictCache(time.Minute, 2)
	c.put("a", Result{RuleID: 1})
	c.put("b", Result{RuleID: 2})
	// Touch "a" so "b" becomes the least recently used entry.
	if _, ok := c.get("a"); !ok {
		t.Fatalf("expected hit for a")
	}
	c.put("c", Result{RuleID: 3}) // should evict "b", not "a"

	if _, ok := c.get("b"); ok {
		t.Fatalf("b should have been evicted as least recently used")
	}
	if _, ok := c.get("a"); !ok {
		t.Fatalf("a should still be cached")
	}
	if _, ok := c.get("c"); !ok {
		t.Fatalf("c should be cached")
	}
}

func TestFingerprintEligible(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	if !fingerprintEligible(r) {
		t.Fatalf("plain request should be eligible")
	}

	withCookie := httptest.NewRequest("GET", "http://example.com/", nil)
	withCookie.Header.Set("Cookie", "session=x")
	if fingerprintEligible(withCookie) {
		t.Fatalf("cookie-bearing request must not be eligible")
	}

	withAuth := httptest.NewRequest("GET", "http://example.com/", nil)
	withAuth.Header.Set("Authorization", "Bearer x")
	if fingerprintEligible(withAuth) {
		t.Fatalf("Authorization-bearing request must not be eligible")
	}
}

func TestFingerprintDeterministicAndDistinguishesRequests(t *testing.T) {
	r1 := httptest.NewRequest("GET", "http://example.com/search?q=a", nil)
	r2 := httptest.NewRequest("GET", "http://example.com/search?q=a", nil)
	if fingerprint(r1, "ip", nil) != fingerprint(r2, "ip", nil) {
		t.Fatalf("identical requests should fingerprint identically")
	}

	r3 := httptest.NewRequest("GET", "http://example.com/search?q=b", nil)
	if fingerprint(r1, "ip", nil) == fingerprint(r3, "ip", nil) {
		t.Fatalf("requests with different queries should not collide")
	}

	if fingerprint(r1, "ip", []byte("body1")) == fingerprint(r1, "ip", []byte("body2")) {
		t.Fatalf("requests with different bodies should not collide")
	}
}

// Everything Coraza can inspect must change the key (issue #152).
func TestFingerprintCoversInspectedInputs(t *testing.T) {
	base := func() *http.Request {
		r := httptest.NewRequest("GET", "http://example.com/a/b", nil)
		r.Header.Set("User-Agent", "Mozilla/5.0")
		return r
	}
	want := fingerprint(base(), "203.0.113.1", nil)
	cases := []struct {
		name string
		mod  func(r *http.Request) string // returns the client IP to use
	}{
		{"header value", func(r *http.Request) string { r.Header.Set("User-Agent", "evil"); return "203.0.113.1" }},
		{"extra header", func(r *http.Request) string { r.Header.Set("X-Api-Version", "1"); return "203.0.113.1" }},
		{"header split differently", func(r *http.Request) string {
			r.Header["User-Agent"] = []string{"Mozilla/", "5.0"}
			return "203.0.113.1"
		}},
		{"unclean path", func(r *http.Request) string { r.URL.Path = "/a/x/../b"; return "203.0.113.1" }},
		{"client IP", func(r *http.Request) string { return "203.0.113.2" }},
	}
	for _, tc := range cases {
		r := base()
		ip := tc.mod(r)
		if fingerprint(r, ip, nil) == want {
			t.Errorf("%s: fingerprint unchanged", tc.name)
		}
	}
}
