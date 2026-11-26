package ui

import (
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/labstack/echo/v5"

	"palisade/internal/ext"
	"palisade/internal/storage"
)

// svcScope maps the ids of the services a scoped user may see and change
// (ext.Scope) to their names. nil means no limit.
type svcScope map[int]string

const ctxScope = "admin_scope"

// scopeOf returns the signed-in user's scope, nil when they see everything.
func scopeOf(c *echo.Context) svcScope {
	s, _ := c.Get(ctxScope).(svcScope)
	return s
}

func (s svcScope) hasName(name string) bool {
	if s == nil {
		return true
	}
	for _, n := range s {
		if n == name {
			return true
		}
	}
	return false
}

func (s svcScope) names() []string {
	out := make([]string, 0, len(s))
	for _, n := range s {
		out = append(out, n)
	}
	return out
}

func (h *Handler) loadScope(u *storage.AdminUser) svcScope {
	if ext.Scope == nil || u == nil || u.Role == storage.RoleOwner { // owners always see everything
		return nil
	}
	ids, ok := ext.Scope(u)
	if !ok {
		return nil
	}
	s := svcScope{}
	for _, svc := range h.registry.List() {
		if slices.Contains(ids, svc.ID) {
			s[svc.ID] = svc.Name
		}
	}
	return s
}

// scopedOpen are the routes a scoped user reaches besides their services'
// own routes: the app shell, the Services and Logs reads (filtered) and
// their own account. Everything else, global settings included, is closed
// to them. Patterns are relative to the admin path.
var scopedOpen = map[string]bool{
	"GET /*": true, "GET /app": true, "GET /app/*": true, // the app page and its assets; data is checked below
	"GET /api/services": true, "GET /api/services/cache-stats": true,
	"GET /api/logs": true, "GET /api/logs/apps": true, "GET /logs/stream": true, "GET /logs/stats": true, "GET /logs/:id": true,
	"GET /api/settings/account": true, "POST /logout": true, "PUT /api/settings/credentials": true,
	"POST /api/settings/2fa/start": true, "POST /api/settings/2fa/confirm": true, "POST /api/settings/2fa/disable": true,
	"POST /api/settings/passkeys/begin": true, "POST /api/settings/passkeys/finish": true, "DELETE /api/settings/passkeys/:id": true,
	"DELETE /api/settings/devices/:id": true, "POST /api/settings/devices/sign-out-others": true,
}

// allows reports whether a scoped user may run action (method + route
// pattern relative to the admin path): an open route, or an
// /api/services/:id route for one of their services.
func (s svcScope) allows(c *echo.Context, action string) bool {
	if scopedOpen[action] {
		return true
	}
	_, p, _ := strings.Cut(action, " ")
	if p != "/api/services/:id" && !strings.HasPrefix(p, "/api/services/:id/") {
		return false
	}
	n, err := strconv.Atoi(c.Param("id"))
	_, ok := s[n]
	return err == nil && ok
}

// enforceScope is requireRole's scope check; it returns true when it
// answered the request.
func (h *Handler) enforceScope(c *echo.Context, u *storage.AdminUser) (bool, error) {
	s := h.loadScope(u)
	if s == nil {
		return false, nil
	}
	c.Set(ctxScope, s)
	action := c.Request().Method + " " + strings.TrimPrefix(c.Path(), h.cfg.Admin.Path)
	if action == "GET " { // the dashboard sums every service
		return true, c.Redirect(http.StatusFound, h.cfg.Admin.Path+"/services")
	}
	if !s.allows(c, action) {
		return true, denied(c, "forbidden", "Your access is limited to some services.")
	}
	return false, nil
}
