package ui

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"palisade/internal/storage"
)

// appFS is a built app as Vite lays it out (web/build/palisade.ts).
var appFS = fstest.MapFS{
	"app/dist/index.html": {Data: []byte(`<html><head><script type="module" src="{{.Base}}assets/index-x.js"></script></head>` +
		`<body data-admin="{{.AdminPath}}" data-csrf="{{.CSRF}}" data-role="{{.Role}}" data-email="{{.Email}}" data-demo="{{.Demo}}" data-nonce="{{.Nonce}}"></body></html>`)},
	"app/dist/assets/index-x.js":    {Data: []byte("plain")},
	"app/dist/assets/index-x.js.br": {Data: []byte("brotli")},
	"app/dist/assets/index-x.js.gz": {Data: []byte("gzip")},
	"app/dist/assets/tiny.js":       {Data: []byte("tiny")},
	"app/dist/assets/blob.zzz":      {Data: []byte("blob")},
	"app/dist/licenses.md":          {Data: []byte("# Licenses")},
}

func appEnv(t *testing.T) *adminEnv {
	env := newAdminEnv(t)
	if err := env.h.SetApp(appFS); err != nil {
		t.Fatal(err)
	}
	return env
}

func TestAppIndex(t *testing.T) {
	env := appEnv(t)
	for _, p := range []string{"/admin/app", "/admin/app/", "/admin/app/logs/5"} {
		rec := env.do(http.MethodGet, p, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", p, rec.Code)
		}
		body := rec.Body.String()
		for _, want := range []string{
			`src="/admin/app/assets/index-x.js"`,
			`data-admin="/admin"`,
			`data-csrf="` + csrfToken(env.session) + `"`,
			`data-role="owner"`,
			`data-email="` + testAdminEmail + `"`,
			`data-demo="false"`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("GET %s: missing %s in %s", p, want, body)
			}
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("GET %s: Cache-Control %q", p, cc)
		}
		// The CSP admits <style> only with the nonce rendered into the page.
		nonce := regexp.MustCompile(`data-nonce="([^"]+)"`).FindStringSubmatch(body)
		if nonce == nil {
			t.Fatalf("GET %s: no nonce in %s", p, body)
		}
		csp := rec.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "style-src 'self' 'nonce-"+nonce[1]+"'") || !strings.Contains(csp, "script-src 'self';") {
			t.Errorf("GET %s: CSP %q", p, csp)
		}
	}
	a := regexp.MustCompile(`data-nonce="([^"]+)"`)
	n1 := a.FindStringSubmatch(env.do(http.MethodGet, "/admin/app", nil).Body.String())[1]
	n2 := a.FindStringSubmatch(env.do(http.MethodGet, "/admin/app", nil).Body.String())[1]
	if n1 == n2 {
		t.Error("nonce reused across responses")
	}
}

func TestAppRole(t *testing.T) {
	env := appEnv(t)
	rec := env.doWith(http.MethodGet, "/admin/app", nil, env.sessionAs(storage.RoleViewer))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `data-role="viewer"`) {
		t.Fatalf("viewer: %d %s", rec.Code, rec.Body.String())
	}
}

// Without a session neither the page nor its JS is served.
func TestAppNeedsSession(t *testing.T) {
	env := appEnv(t)
	for _, p := range []string{"/admin/app", "/admin/app/logs", "/admin/app/assets/index-x.js", "/admin/app/licenses.md"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rec := httptest.NewRecorder()
		env.e.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound || !strings.HasSuffix(rec.Header().Get("Location"), "/admin/login") {
			t.Errorf("GET %s anonymous = %d %q", p, rec.Code, rec.Header().Get("Location"))
		}
		if strings.Contains(rec.Body.String(), "plain") {
			t.Errorf("GET %s anonymous leaked the asset", p)
		}
	}
}

func TestAppAsset(t *testing.T) {
	env := appEnv(t)
	cases := []struct {
		name, path, accept string
		code               int
		body, encoding     string
	}{
		{"brotli preferred", "/admin/app/assets/index-x.js", "gzip, deflate, br", 200, "brotli", "br"},
		{"gzip only", "/admin/app/assets/index-x.js", "gzip", 200, "gzip", "gzip"},
		{"br refused by q=0", "/admin/app/assets/index-x.js", "br;q=0, gzip", 200, "gzip", "gzip"},
		{"identity", "/admin/app/assets/index-x.js", "", 200, "plain", ""},
		{"no compressed copy", "/admin/app/assets/tiny.js", "br, gzip", 200, "tiny", ""},
		{"licenses", "/admin/app/licenses.md", "", 200, "# Licenses", ""},
		{"missing asset is 404, not the page", "/admin/app/assets/nope.js", "", 404, "", ""},
		{"unknown type", "/admin/app/assets/blob.zzz", "", 200, "blob", ""},
		{"compressed copy not addressable", "/admin/app/assets/index-x.js.br", "", 404, "", ""},
		{"no escape to the template", "/admin/app/assets/../index.html", "", 404, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := newReq(env, http.MethodGet, tc.path, "")
			req.Header.Set("Accept-Encoding", tc.accept)
			rec := serve(env, req)
			if rec.Code != tc.code {
				t.Fatalf("code %d, want %d (%s)", rec.Code, tc.code, rec.Body.String())
			}
			if tc.code != 200 {
				return
			}
			if rec.Body.String() != tc.body || rec.Header().Get("Content-Encoding") != tc.encoding {
				t.Errorf("body %q encoding %q", rec.Body.String(), rec.Header().Get("Content-Encoding"))
			}
			if strings.HasSuffix(tc.path, ".zzz") {
				if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
					t.Errorf("Content-Type %q", ct)
				}
			} else if strings.HasPrefix(tc.path, "/admin/app/assets/") {
				if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
					t.Errorf("Content-Type %q", ct)
				}
				if cc := rec.Header().Get("Cache-Control"); cc != "private, max-age=31536000, immutable" {
					t.Errorf("Cache-Control %q", cc)
				}
				if rec.Header().Get("Vary") != "Accept-Encoding" {
					t.Errorf("Vary %q", rec.Header().Get("Vary"))
				}
			}
		})
	}
}

func TestAppNotBuilt(t *testing.T) {
	env := newAdminEnv(t)
	if err := env.h.SetApp(fstest.MapFS{"app/.gitkeep": {}}); err != nil {
		t.Fatal(err)
	}
	if rec := env.do(http.MethodGet, "/admin/app", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unbuilt app = %d", rec.Code)
	}
}

func TestSetAppErrors(t *testing.T) {
	env := newAdminEnv(t)
	cases := map[string]fstest.MapFS{
		"index.html unreadable": {"app/dist/index.html/x": {}},
		"bad template":          {"app/dist/index.html": {Data: []byte("{{")}},
	}
	for name, fsys := range cases {
		if err := env.h.SetApp(fsys); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if err := env.h.SetApp(nil); err != nil {
		t.Errorf("nil FS: %v", err)
	}
}

// A template that fails while rendering is a 500, not a half-written page.
func TestAppRenderError(t *testing.T) {
	env := newAdminEnv(t)
	if err := env.h.SetApp(fstest.MapFS{"app/dist/index.html": {Data: []byte("{{index .AdminPath 99}}")}}); err != nil {
		t.Fatal(err)
	}
	if rec := env.do(http.MethodGet, "/admin/app", nil); rec.Code != http.StatusInternalServerError {
		t.Fatalf("render error = %d", rec.Code)
	}
}

func TestAcceptsEncoding(t *testing.T) {
	cases := []struct {
		header, token string
		want          bool
	}{
		{"gzip, br", "br", true},
		{"BR", "br", true},
		{"br;q=0.5", "br", true},
		{"br;q=0", "br", false},
		{"br; q=0.0", "br", false},
		{"brotli", "br", false},
		{"x-gzip", "gzip", false},
		{"", "gzip", false},
		{"*", "gzip", false}, // identity is always a safe answer to a wildcard
	}
	for _, tc := range cases {
		if got := acceptsEncoding(tc.header, tc.token); got != tc.want {
			t.Errorf("acceptsEncoding(%q, %q) = %v", tc.header, tc.token, got)
		}
	}
}
