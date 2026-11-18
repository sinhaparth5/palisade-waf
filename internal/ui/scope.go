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

// scopedOpen are the routes a scoped user reaches besides changes to their
// services: the Services and Logs pages (filtered) and their own account.
// Everything else, global settings included, is closed to them.
var scopedOpen = map[string]bool{
	"GET /services": true, "GET /services/rows": true,
	"GET /logs": true, "GET /logs/stream": true, "GET /logs/stats": true, "GET /logs/:id": true,
	"GET /settings": true, "POST /logout": true, "POST /settings/credentials": true,
	"POST /settings/2fa/start": true, "POST /settings/2fa/confirm": true, "POST /settings/2fa/disable": true,
	"POST /settings/passkeys/begin": true, "POST /settings/passkeys/finish": true, "DELETE /settings/passkeys/:id": true,
	"DELETE /settings/devices/:token": true, "POST /settings/devices/revoke-others": true,
}

// scopedByForm are service changes that name the service in a service_id
// form field rather than the path.
var scopedByForm = map[string]bool{
	"POST /services/tls/upload": true, "POST /services/tls/auto": true, "POST /services/tls/pool": true,
	"POST /services/tls/clear": true, "POST /services/ratelimit": true,
}

// allows reports whether a scoped user may run action (method + route
// pattern relative to the admin path): an open route, or a /services/…/:id
// route (or a scopedByForm one) for one of their services.
func (s svcScope) allows(c *echo.Context, action string) bool {
	if scopedOpen[action] {
		return true
	}
	id := c.Param("id")
	if scopedByForm[action] {
		id = c.FormValue("service_id")
	} else if _, p, _ := strings.Cut(action, " "); !strings.HasPrefix(p, "/services/") || !strings.HasSuffix(p, "/:id") {
		return false
	}
	n, err := strconv.Atoi(id)
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
		return true, c.String(http.StatusForbidden, "Your access is limited to some services.")
	}
	return false, nil
}
