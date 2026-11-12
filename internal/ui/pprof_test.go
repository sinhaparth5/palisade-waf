package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"palisade/internal/storage"
)

// TestPprofOwnerOnly pins issue #267: pprof is owner-only, same-origin, has
// a capped duration, and isn't on the REST API or on service hosts.
func TestPprofOwnerOnly(t *testing.T) {
	env := newAdminEnv(t)
	env.seedService("shop", "shop.example.com")
	admin := env.sessionAs(storage.RoleAdmin)
	viewer := env.sessionAs(storage.RoleViewer)

	get := func(path, session string, mod func(*http.Request)) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "127.0.0.1:12345"
		if session != "" {
			req.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
		}
		if mod != nil {
			mod(req)
		}
		rec := httptest.NewRecorder()
		env.e.ServeHTTP(rec, req)
		return rec
	}

	if rec := get("/admin/debug/pprof/", env.session, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "goroutine") {
		t.Errorf("owner index = %d", rec.Code)
	}
	if rec := get("/admin/debug/pprof/heap?debug=1", env.session, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "heap profile") {
		t.Errorf("owner heap = %d", rec.Code)
	}
	for _, tc := range []struct {
		name, path, session string
		mod                 func(*http.Request)
		want                int
	}{
		{"admin", "/admin/debug/pprof/", admin, nil, http.StatusForbidden},
		{"viewer", "/admin/debug/pprof/heap", viewer, nil, http.StatusForbidden},
		{"cross-site", "/admin/debug/pprof/heap", env.session, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, http.StatusForbidden},
		{"seconds cap", "/admin/debug/pprof/profile?seconds=999", env.session, nil, http.StatusBadRequest},
		{"unknown profile", "/admin/debug/pprof/nope", env.session, nil, http.StatusNotFound},
	} {
		if rec := get(tc.path, tc.session, tc.mod); rec.Code != tc.want {
			t.Errorf("%s: %s = %d, want %d", tc.name, tc.path, rec.Code, tc.want)
		}
	}
	if rec := get("/admin/debug/pprof/", "", nil); rec.Code == http.StatusOK {
		t.Error("anonymous request reached pprof")
	}
	if rec := get("/admin/api/v1/debug/pprof/", "", func(r *http.Request) { r.Header.Set("Authorization", "Bearer cwaf_x") }); rec.Code == http.StatusOK {
		t.Error("pprof reachable on the REST API")
	}
	if rec := get("/admin/debug/pprof/", env.session, func(r *http.Request) { r.Host = "shop.example.com" }); strings.Contains(rec.Body.String(), "goroutine") {
		t.Error("pprof reachable on a service host")
	}
}
