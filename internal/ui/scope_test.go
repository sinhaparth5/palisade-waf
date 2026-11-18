package ui

import (
	"fmt"
	"net/http"
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
	svc := func(id int, tab string) string { return fmt.Sprintf("/admin/api/services/%d/%s", id, tab) }

	for _, tc := range []struct {
		method, path string
		body         any
		want         int
	}{
		{http.MethodGet, "/admin", nil, http.StatusFound}, // the dashboard sums every service
		{http.MethodGet, "/admin/services", nil, http.StatusOK},
		{http.MethodGet, "/admin/api/dashboard", nil, http.StatusForbidden},
		{http.MethodGet, "/admin/api/ip-rules", nil, http.StatusForbidden},
		{http.MethodGet, "/admin/api/notifications", nil, http.StatusForbidden},
		{http.MethodGet, "/admin/api/settings/protection", nil, http.StatusForbidden},
		{http.MethodGet, "/admin/search?q=x", nil, http.StatusForbidden},
		{http.MethodPost, "/admin/api/ip-rules", map[string]any{"ip": []string{"192.0.2.1"}, "rule_type": "block"}, http.StatusForbidden},
		{http.MethodPost, "/admin/api/services", map[string]any{"name": "x"}, http.StatusForbidden},
		{http.MethodPut, svc(blog.ID, "bot"), map[string]string{"mode": "off"}, http.StatusForbidden},
		{http.MethodPut, svc(shop.ID, "bot"), map[string]string{"mode": "off"}, http.StatusNoContent},
		{http.MethodPut, svc(blog.ID, "rate-limit"), map[string]int{"rps": 1}, http.StatusForbidden},
		{http.MethodDelete, fmt.Sprintf("/admin/api/services/%d", blog.ID), nil, http.StatusForbidden},
		{http.MethodGet, fmt.Sprintf("/admin/logs/%d", blogLog), nil, http.StatusNotFound},
		{http.MethodGet, fmt.Sprintf("/admin/logs/%d", shopLog), nil, http.StatusOK},
		{http.MethodGet, "/admin/api/settings/account", nil, http.StatusOK},
	} {
		if rec := env.doJSON(tok, tc.method, tc.path, tc.body, nil); rec.Code != tc.want {
			t.Errorf("%s %s = %d, want %d: %.200s", tc.method, tc.path, rec.Code, tc.want, rec.Body)
		}
	}

	get := func(path string) string { return env.doJSON(tok, http.MethodGet, path, nil, nil).Body.String() }
	if s := get("/admin/api/services"); !strings.Contains(s, "shop-scope.test") || strings.Contains(s, "blog-scope.test") {
		t.Errorf("services not scoped: %.300s", s)
	}
	if s := get("/admin/api/logs"); !strings.Contains(s, "/shop-path") || strings.Contains(s, "/blog-path") {
		t.Errorf("logs not scoped: %.300s", s)
	}
	if s := get("/admin/api/logs/apps"); s != `["shop"]`+"\n" {
		t.Errorf("log apps = %s", s)
	}
	if s := get("/admin/services"); !strings.Contains(s, `data-scoped="true"`) {
		t.Errorf("app page doesn't say scoped: %.300s", s)
	}
	// An owner is never scoped, whatever ext.Scope says.
	if rec := env.doJSON(env.session, http.MethodGet, "/admin/api/ip-rules", nil, nil); rec.Code != http.StatusOK {
		t.Errorf("owner: %d", rec.Code)
	}
}
