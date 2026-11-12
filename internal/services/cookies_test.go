package services

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestHardenCookie(t *testing.T) {
	exempt := []string{"csrf_js"}
	for _, tc := range []struct {
		in   string
		tls  bool
		want string
	}{
		{"sid=abc; Path=/", true, "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"},
		{"sid=abc; Path=/", false, "sid=abc; Path=/; HttpOnly; SameSite=Lax"},
		{"sid=abc;", true, "sid=abc; Secure; HttpOnly; SameSite=Lax"},
		{"sid=abc; secure; HTTPONLY; samesite=Strict", true, "sid=abc; secure; HTTPONLY; samesite=Strict"},
		{"sid=abc; SameSite=None", true, "sid=abc; SameSite=None; Secure; HttpOnly"},
		{"csrf_js=x; Path=/", true, "csrf_js=x; Path=/"},
		{" csrf_js =x", true, " csrf_js =x"},
		{"sid=a; Expires=Wed, 21 Oct 2026 07:28:00 GMT", false, "sid=a; Expires=Wed, 21 Oct 2026 07:28:00 GMT; HttpOnly; SameSite=Lax"},
	} {
		if got := hardenCookie(tc.in, exempt, tc.tls); got != tc.want {
			t.Errorf("hardenCookie(%q, tls=%v) = %q, want %q", tc.in, tc.tls, got, tc.want)
		}
	}
}

// TestCookieHardeningProxy runs hardening through the registry's proxy:
// on for one service only, Secure only over TLS, and the stack headers
// stripped for every service.
func TestCookieHardeningProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "sid=abc; Path=/")
		w.Header().Add("Set-Cookie", "theme=dark")
		w.Header().Set("X-Runtime", "0.01")
		w.Header().Set("X-Generator", "Drupal 10")
	}))
	defer backend.Close()

	db := openTestDB(t)
	for _, n := range []string{"shop", "plain"} {
		if err := db.AddService(n, n+".example.com", "", backend.URL, 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	list, _ := db.ListServices()
	shopID := list[0].ID
	if list[0].Name != "shop" {
		shopID = list[1].ID
	}
	if err := db.SetServiceCookiePolicy(shopID, true, []string{"theme"}); err != nil {
		t.Fatal(err)
	}
	reg, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	get := func(svc string, overTLS bool) http.Header {
		h, _ := reg.Proxy(svc)
		r := httptest.NewRequest(http.MethodGet, "http://"+svc+".example.com/", nil)
		if overTLS {
			r.TLS = &tls.ConnectionState{}
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Header()
	}

	want := []string{"sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax", "theme=dark"}
	if got := get("shop", true).Values("Set-Cookie"); !slices.Equal(got, want) {
		t.Errorf("TLS cookies = %q, want %q", got, want)
	}
	if got := get("shop", false).Values("Set-Cookie")[0]; got != "sid=abc; Path=/; HttpOnly; SameSite=Lax" {
		t.Errorf("plain-HTTP cookie = %q", got)
	}
	plain := get("plain", true)
	if got := plain.Values("Set-Cookie")[0]; got != "sid=abc; Path=/" {
		t.Errorf("service with hardening off changed the cookie: %q", got)
	}
	if plain.Get("X-Runtime") != "" || plain.Get("X-Generator") != "" {
		t.Error("X-Runtime/X-Generator not stripped")
	}
}
