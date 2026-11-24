package ui

import (
	"encoding/json"
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
		`<body data-admin="{{.AdminPath}}" data-csrf="{{.CSRF}}" data-role="{{.Role}}" data-email="{{.Email}}" data-demo="{{.Demo}}" data-waf="{{.WAF}}" data-nonce="{{.Nonce}}"></body></html>`)},
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
			`data-waf="true"`,
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

// The React app gets JSON from the endpoints the HTMX pages get HTML from.
func TestAppJSONViews(t *testing.T) {
	env := newAdminEnv(t)
	env.seedService("shop", "shop.example.com")
	env.seedLog(storage.RequestLog{AppName: "shop", RealIP: "198.51.100.7", Country: "NL", Method: "POST", Path: "/login", Blocked: true, RuleID: 942100, Action: "waf_blocked"})

	get := func(path string, out any) *httptest.ResponseRecorder {
		t.Helper()
		rec := env.doJSON(env.session, http.MethodGet, path, nil, out)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Vary"), "Accept") {
			t.Fatalf("%s = %d, Vary %q", path, rec.Code, rec.Header().Get("Vary"))
		}
		return rec
	}

	var groups []searchGroup
	get("/admin/search?q=shop", &groups)
	if len(groups) == 0 || groups[0].Label != "Services" || groups[0].Hits[0] != (searchHit{"shop", "shop.example.com", "/admin/services"}) {
		t.Errorf("search = %+v", groups)
	}
	if rec := get("/admin/search?q=+", &groups); len(groups) != 0 || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("empty search = %s", rec.Body)
	}
	if rec := get("/admin/search?q=zzz-nothing", &groups); strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("no hits = %s, want []", rec.Body)
	}

	var notif struct {
		Unread int `json:"unread"`
		Blocks []struct {
			IP, Country, Method, Path, App, Action string
			RuleID                                 int `json:"rule_id"`
		} `json:"blocks"`
	}
	get("/admin/api/notifications", &notif)
	if notif.Unread != 1 || len(notif.Blocks) != 1 {
		t.Fatalf("notifications = %+v", notif)
	}
	if b := notif.Blocks[0]; b.IP != "198.51.100.7" || b.Path != "/login" || b.App != "shop" || b.RuleID != 942100 || b.Action != "waf_blocked" {
		t.Errorf("block = %+v", b)
	}
}

// The React app gets every failure as {"error", "message"} with a real
// status (web/src/lib/api.ts), never a login redirect or an HTML/text body;
// the HTMX pages keep theirs.
func TestAppJSONErrors(t *testing.T) {
	env := newDemoEnv(t)
	demo, _ := env.db.GetAdminUserByEmail(demoEmail)
	demoSession, err := env.db.CreateSession(demo.ID, "127.0.0.1", "test", "")
	if err != nil {
		t.Fatal(err)
	}
	viewer := env.sessionAs(storage.RoleViewer)
	cases := []struct {
		name, session, method, path string
		body                        any
		status                      int
		code                        string
	}{
		{"no session", "", "GET", "/admin/search?q=x", nil, 401, "unauthenticated"},
		{"unknown session", "nope", "GET", "/admin/api/notifications", nil, 401, "unauthenticated"},
		{"role too low", viewer, "POST", "/admin/ip-rules", map[string]string{"ip": "192.0.2.1"}, 403, "forbidden"},
		{"demo write", demoSession, "POST", "/admin/settings/credentials", map[string]string{}, 403, "demo"},
		{"body over the limit", env.session, "POST", "/admin/ip-rules", map[string]string{"note": strings.Repeat("x", 1<<20)}, 413, "too_large"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got jsonError
			rec := env.doJSON(tc.session, tc.method, tc.path, tc.body, &got)
			if rec.Code != tc.status || got.Code != tc.code || got.Message == "" {
				t.Errorf("= %d %+v, want %d %s", rec.Code, got, tc.status, tc.code)
			}
		})
	}

	t.Run("missing CSRF", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/admin/api/notifications/seen", nil)
		req.Header.Set("Accept", "application/json")
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: env.session})
		rec := serve(env, req)
		var got jsonError
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != 403 || got.Code != "forbidden" || !strings.Contains(got.Message, "CSRF") {
			t.Errorf("= %d %s", rec.Code, rec.Body)
		}
	})

	t.Run("HTMX unchanged", func(t *testing.T) {
		if rec := env.doWith("GET", "/admin/search?q=x", nil, ""); rec.Code != http.StatusFound {
			t.Errorf("no session = %d, want the login redirect", rec.Code)
		}
		if rec := env.doWith("POST", "/admin/ip-rules", nil, viewer); rec.Code != 403 || rec.Body.String() != "Your role can't do this." {
			t.Errorf("viewer = %d %q", rec.Code, rec.Body)
		}
	})

	// A DB failure is a 500 that doesn't show the driver's error text.
	t.Run("storage failure", func(t *testing.T) {
		dropTables(t, env.dbPath, "name NOT IN ('sessions', 'meta') AND name NOT LIKE 'admin%'")
		for _, p := range []string{"/admin/api/notifications", "/admin/search?q=shop"} {
			var got jsonError
			rec := env.doJSON(env.session, "GET", p, nil, &got)
			if rec.Code != 500 || got.Code != "internal" || strings.Contains(rec.Body.String(), "no such table") {
				t.Errorf("GET %s = %d %s", p, rec.Code, rec.Body)
			}
		}
	})
}
