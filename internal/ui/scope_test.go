package ui

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"palisade/internal/ext"
	"palisade/internal/storage"
)

func TestScope(t *testing.T) {
	env := newAdminEnv(t)
	shop := env.seedService("shop", "shop-scope.test")
	blog := env.seedService("blog", "blog-scope.test")
	ext.Scope = func(u *storage.AdminUser) ([]int, bool) {
		return []int{shop.ID}, u.Email == "test-admin@example.com"
	}
	t.Cleanup(func() { ext.Scope = nil })
	tok := env.sessionAs(storage.RoleAdmin)
	logID := func(app string) int64 {
		id, err := env.db.InsertRequest(storage.RequestLog{Timestamp: time.Now().UTC(), AppName: app, Path: "/" + app + "-path"})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	shopLog, blogLog := logID("shop"), logID("blog")

	for _, tc := range []struct {
		method, path string
		form         url.Values
		want         int
	}{
		{http.MethodGet, "/admin", nil, http.StatusFound},
		{http.MethodGet, "/admin/ip-rules", nil, http.StatusForbidden},
		{http.MethodGet, "/admin/search?q=x", nil, http.StatusForbidden},
		{http.MethodPost, "/admin/ip-rules", url.Values{"ip": {"192.0.2.1"}}, http.StatusForbidden},
		{http.MethodPost, "/admin/services", url.Values{"name": {"x"}}, http.StatusForbidden},
		{http.MethodPost, fmt.Sprintf("/admin/services/bot/%d", blog.ID), url.Values{"bot_mode": {"off"}}, http.StatusForbidden},
		{http.MethodPost, fmt.Sprintf("/admin/services/bot/%d", shop.ID), url.Values{"bot_mode": {"off"}}, http.StatusOK},
		{http.MethodPost, "/admin/services/ratelimit", url.Values{"service_id": {fmt.Sprint(blog.ID)}}, http.StatusForbidden},
		{http.MethodGet, fmt.Sprintf("/admin/logs/%d", blogLog), nil, http.StatusNotFound},
		{http.MethodGet, fmt.Sprintf("/admin/logs/%d", shopLog), nil, http.StatusOK},
	} {
		if rec := env.doWith(tc.method, tc.path, tc.form, tok); rec.Code != tc.want {
			t.Errorf("%s %s = %d, want %d: %s", tc.method, tc.path, rec.Code, tc.want, rec.Body)
		}
	}

	services := env.doWith(http.MethodGet, "/admin/services", nil, tok).Body.String()
	if !strings.Contains(services, "shop-scope.test") || strings.Contains(services, "blog-scope.test") || strings.Contains(services, `id="notif-btn"`) {
		t.Error("services page not scoped")
	}
	logs := env.doWith(http.MethodGet, "/admin/logs?mode=history", nil, tok).Body.String()
	if !strings.Contains(logs, "/shop-path") || strings.Contains(logs, "/blog-path") {
		t.Error("logs not scoped")
	}
	if settings := env.doWith(http.MethodGet, "/admin/settings", nil, tok).Body.String(); strings.Contains(settings, "settings-protection") || strings.Contains(settings, "settings-activity") {
		t.Error("settings shows global sections")
	}
	// An owner is never scoped, whatever ext.Scope says.
	if rec := env.do(http.MethodGet, "/admin/ip-rules", nil); rec.Code != http.StatusOK {
		t.Errorf("owner: %d", rec.Code)
	}
}
