package ui

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"palisade/internal/proxy"
)

// TestAdminAllowAndListen pins issue #271. The harness's proxy pipeline
// answers 418, so 418 means "the admin UI isn't here for this request".
func TestAdminAllowAndListen(t *testing.T) {
	env := newAdminEnv(t)
	base := env.h.cfg.Admin.Path
	public := http.Handler(env.e)
	adminLn := AdminListener(base, env.e)

	get := func(h http.Handler, path, remote, xff string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = remote
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	const proxied = http.StatusTeapot

	// Off by default: anyone reaches the login page on the public listener.
	if c := get(public, base+"/login", "203.0.113.9:1234", ""); c != http.StatusOK {
		t.Fatalf("default: login = %d, want 200", c)
	}

	env.h.adminAllow = proxy.ParseTrustedProxyCIDRs([]string{"10.8.0.0/24", "198.51.100.7"})
	for _, tc := range []struct {
		name, path, remote, xff string
		want                    int
	}{
		{"allowed CIDR", "/login", "10.8.0.5:1", "", http.StatusOK},
		{"allowed single IP", "/login", "198.51.100.7:1", "", http.StatusOK},
		{"other IP, login", "/login", "203.0.113.9:1", "", proxied},
		{"other IP, SSO callback", "/login/sso/callback", "203.0.113.9:1", "", proxied},
		{"other IP, API", "/api/v1/stats", "203.0.113.9:1", "", proxied},
		{"other IP, metrics", "/metrics", "203.0.113.9:1", "", proxied},
		{"other IP, static", "/static/css/tailwind.min.css", "203.0.113.9:1", "", proxied},
		// No --trusted-proxies, so a forged header doesn't move the client IP.
		{"spoofed XFF", "/login", "203.0.113.9:1", "10.8.0.5", proxied},
	} {
		if c := get(public, base+tc.path, tc.remote, tc.xff); c != tc.want {
			t.Errorf("allowlist, %s: %d, want %d", tc.name, c, tc.want)
		}
	}
	// On the admin listener a refused client gets a plain 404, never the proxy.
	if c := get(adminLn, base+"/login", "203.0.113.9:1", ""); c != http.StatusNotFound {
		t.Errorf("allowlist on admin listener: %d, want 404", c)
	}
	env.h.adminAllow = nil

	env.h.cfg.Admin.Listen = "127.0.0.1:9090"
	if c := get(public, base+"/login", "127.0.0.1:1", ""); c != proxied {
		t.Errorf("--admin-listen: public listener served the login page (%d)", c)
	}
	if c := get(public, base+"/api/v1/stats", "127.0.0.1:1", ""); c != proxied {
		t.Errorf("--admin-listen: public listener served the API (%d)", c)
	}
	if c := get(adminLn, base+"/login", "127.0.0.1:1", ""); c != http.StatusOK {
		t.Errorf("--admin-listen: admin listener login = %d, want 200", c)
	}
	// The admin listener serves nothing outside the admin path.
	for _, p := range []string{"/", "/_cz/challenge", base + "x/login"} {
		if c := get(adminLn, p, "127.0.0.1:1", ""); c != http.StatusNotFound {
			t.Errorf("admin listener served %s: %d", p, c)
		}
	}
}
