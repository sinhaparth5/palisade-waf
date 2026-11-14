package ui

import (
	"html/template"
	"net/http"
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
