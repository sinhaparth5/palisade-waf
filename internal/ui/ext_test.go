package ui

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"palisade/internal/ext"
	"palisade/internal/storage"
)

// withExt registers f for the handlers built during the test.
func withExt(t *testing.T, f ext.Feature) {
	t.Helper()
	saved := ext.Mounts
	ext.Mounts = append(ext.Mounts[:len(ext.Mounts):len(ext.Mounts)], func(ext.Env) ext.Feature { return f })
	t.Cleanup(func() { ext.Mounts = saved })
}

func TestExtFeature(t *testing.T) {
	withExt(t, ext.Feature{
		Routes: []ext.Route{{Method: http.MethodPost, Path: "/settings/ext-test", Role: storage.RoleOwner,
			Handler: func(c *echo.Context) error { return c.String(http.StatusOK, "ok") }}},
		Card: func(_ *echo.Context, role string) template.HTML {
			if role != storage.RoleOwner {
				return ""
			}
			return `<div id="ext-test-card"></div>`
		},
	})
	env := newAdminEnv(t)
	for _, tc := range []struct {
		role    string
		post    int
		hasCard bool
	}{
		{storage.RoleOwner, http.StatusOK, true},
		{storage.RoleAdmin, http.StatusForbidden, false},
		{storage.RoleViewer, http.StatusForbidden, false},
	} {
		tok := env.sessionAs(tc.role)
		if rec := env.doWith(http.MethodPost, "/admin/settings/ext-test", nil, tok); rec.Code != tc.post {
			t.Errorf("%s: POST = %d, want %d", tc.role, rec.Code, tc.post)
		}
		body := env.doWith(http.MethodGet, "/admin/settings", nil, tok).Body.String()
		if strings.Contains(body, "ext-test-card") != tc.hasCard || strings.Contains(body, `id="settings-pro"`) != tc.hasCard {
			t.Errorf("%s: card shown = %v", tc.role, !tc.hasCard)
		}
	}
}

func TestExtRouteNeedsRole(t *testing.T) {
	withExt(t, ext.Feature{Routes: []ext.Route{{Method: http.MethodPost, Path: "/x",
		Handler: func(c *echo.Context) error { return nil }}}})
	defer func() {
		if recover() == nil {
			t.Error("route without a role was registered")
		}
	}()
	newAdminEnv(t)
}

func TestExtOpenRouteAndReload(t *testing.T) {
	var reload func() error
	saved := ext.Mounts
	ext.Mounts = append(ext.Mounts[:len(ext.Mounts):len(ext.Mounts)], func(env ext.Env) ext.Feature {
		reload = env.Reload
		return ext.Feature{Open: []ext.Route{{Method: http.MethodGet, Path: "/ext-open",
			Handler: func(c *echo.Context) error { return c.String(http.StatusOK, "open") }}}}
	})
	t.Cleanup(func() { ext.Mounts = saved })
	env := newAdminEnv(t)
	if rec := env.doWith(http.MethodGet, "/admin/ext-open", nil, ""); rec.Code != http.StatusOK {
		t.Errorf("open route without a session = %d, want 200", rec.Code)
	}
	if err := reload(); err != nil {
		t.Errorf("reload: %v", err)
	}
}

func TestExtHoldReplay(t *testing.T) {
	ran := 0
	withExt(t, ext.Feature{Routes: []ext.Route{{Method: http.MethodPost, Path: "/settings/ext-test", Role: storage.RoleAdmin,
		Handler: func(c *echo.Context) error { ran++; return c.String(http.StatusOK, "ran "+c.FormValue("v")) }}}})
	var held *http.Request
	ext.Hold = func(c *echo.Context, action string) bool {
		if action != "POST /settings/ext-test" {
			return false
		}
		held = c.Request()
		return c.String(http.StatusAccepted, "held") == nil
	}
	t.Cleanup(func() { ext.Hold = nil })
	env := newAdminEnv(t)
	if rec := env.do(http.MethodPost, "/admin/settings/ext-test", url.Values{"v": {"1"}}); rec.Code != http.StatusAccepted || ran != 0 || held == nil {
		t.Fatalf("not held: %d %q ran=%d", rec.Code, rec.Body, ran)
	}

	u, _ := env.db.GetAdminUser(env.uid)
	req := httptest.NewRequest(http.MethodPost, "/admin/settings/ext-test", strings.NewReader("v=2"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if code, body := ext.Replay(req, nil, "x"); code != http.StatusForbidden || ran != 0 {
		t.Fatalf("replay without a user: %d %s", code, body)
	}
	req = httptest.NewRequest(http.MethodPost, "/admin/settings/ext-test", strings.NewReader("v=2"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if code, body := ext.Replay(req, u, "a@x, approved by b@x"); code != http.StatusOK || string(body) != "ran 2" || ran != 1 {
		t.Fatalf("replay: %d %s", code, body)
	}
	if got, _, _ := env.db.ListAudit(1, 0); len(got) != 1 || got[0].Actor != "a@x, approved by b@x" {
		t.Fatalf("audit %+v", got)
	}
}

func TestExtSSOLogin(t *testing.T) {
	var id *ext.SSOIdentity
	withExt(t, ext.Feature{Open: []ext.Route{{Method: http.MethodGet, Path: "/login/ext-test",
		Handler: func(c *echo.Context) error { return ext.SSOLogin(c, id, c.QueryParam("refuse")) }}}})
	ext.LoginButton = func() (string, string) { return "Corp IdP", "/login/ext-test" }
	t.Cleanup(func() { ext.LoginButton = nil })
	env := newAdminEnv(t)

	if rec := env.doWith(http.MethodGet, "/admin/login", nil, ""); !strings.Contains(rec.Body.String(), `href="/admin/login/ext-test"`) {
		t.Fatal("no login button")
	}
	if rec := env.doWith(http.MethodGet, "/admin/login/ext-test?refuse=Nope.", nil, ""); !strings.Contains(rec.Body.String(), "Nope.") {
		t.Fatal("refusal not shown")
	}
	id = &ext.SSOIdentity{Issuer: "https://idp.test", Subject: "s1", Email: "Sam@Example.com", InGroup: true, Method: "saml"}
	if rec := env.doWith(http.MethodGet, "/admin/login/ext-test", nil, ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "been invited") {
		t.Fatalf("uninvited: %d", rec.Code)
	}
	if err := env.db.CreateSSOInvite("sam@example.com", storage.RoleViewer); err != nil {
		t.Fatal(err)
	}
	if rec := env.doWith(http.MethodGet, "/admin/login/ext-test", nil, ""); rec.Code != http.StatusFound {
		t.Fatalf("invited: %d %s", rec.Code, rec.Body)
	}
	if got, _, _ := env.db.ListAudit(1, 0); len(got) != 1 || got[0].Action != "SSO login" || got[0].Summary != "via=saml" {
		t.Fatalf("audit %+v", got)
	}
	id.InGroup = false
	if rec := env.doWith(http.MethodGet, "/admin/login/ext-test", nil, ""); !strings.Contains(rec.Body.String(), "not in the group") {
		t.Fatal("out of group let in")
	}
}

func TestExtBranding(t *testing.T) {
	env := newAdminEnv(t)
	if body := env.doWith(http.MethodGet, "/admin/login", nil, "").Body.String(); !strings.Contains(body, "<title>Sign in · Palisade</title>") ||
		!strings.Contains(body, `/admin/static/imgs/logo.svg`) || strings.Contains(body, "brand.css") {
		t.Fatal("default brand")
	}
	ext.Branding = func() ext.Brand {
		return ext.Brand{Name: "Acme <Shield>", Logo: "/brand/logo?v=1", CSS: "/brand.css?v=1"}
	}
	t.Cleanup(func() { ext.Branding = nil })
	body := env.doWith(http.MethodGet, "/admin/login", nil, "").Body.String()
	for _, want := range []string{"<title>Sign in · Acme &lt;Shield&gt;</title>", `src="/admin/brand/logo?v=1"`, `href="/admin/brand.css?v=1"`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(body, "Palisade") || strings.Contains(body, "logo.svg") {
		t.Error("Palisade left on the login page")
	}
	if body := env.do(http.MethodGet, "/admin/settings", nil).Body.String(); !strings.Contains(body, "Acme &lt;Shield&gt; logo") || !strings.Contains(body, `href="/admin/brand.css?v=1"`) {
		t.Error("dashboard not branded")
	}
}
