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
