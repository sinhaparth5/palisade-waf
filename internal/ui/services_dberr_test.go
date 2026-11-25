package ui

import (
	"net/http"
	"testing"
)

// serviceTabRoutes are the service dialog's writes with a valid body each,
// so a failure can only come from the id or the DB.
var serviceTabRoutes = []struct {
	method, path string
	body         any
}{
	{http.MethodPut, "/name", map[string]string{"name": "renamed"}},
	{http.MethodPut, "/hosts", svcHosts{}},
	{http.MethodPut, "/backends", map[string]any{"urls": []string{"http://127.0.0.1:9"}, "lb_policy": "round_robin"}},
	{http.MethodPut, "/rate-limit", svcRateLimit{RPS: 1}},
	{http.MethodPut, "/bot", svcBot{Mode: "off"}},
	{http.MethodPut, "/gate", map[string]any{}},
	{http.MethodPut, "/uploads", svcUploads{LargeJS: true}},
	{http.MethodPut, "/schema", svcSchema{Mode: "off"}},
	{http.MethodPut, "/openapi", svcOpenAPI{Mode: "off"}},
	{http.MethodPut, "/mcp", svcMCP{Mode: "off"}},
	{http.MethodPut, "/jwt", svcJWT{Mode: "off"}},
	{http.MethodPut, "/csp", svcCSP{Mode: "off"}},
	{http.MethodPut, "/cookies", svcCookies{Enabled: true}},
	{http.MethodPut, "/policy", svcPolicy{Mode: "off"}},
	{http.MethodPut, "/responses", map[string]string{"mode": "log"}},
	{http.MethodPut, "/cache", map[string]any{"enabled": true, "compress": true}},
	{http.MethodPut, "/tls", map[string]string{"mode": "none"}},
	{http.MethodPut, "/http3", map[string]bool{"enabled": true}},
	{http.MethodPut, "/mtls", map[string]string{"mode": "off"}},
}

// TestServiceTabsFail: a bad id, or a DB that can't read or write the
// service tables, is never answered as a successful save.
func TestServiceTabsFail(t *testing.T) {
	env := newAdminEnv(t)
	svc := env.seedService("svc", "svc.example.com")
	base := "/admin/api/services/"
	for _, r := range serviceTabRoutes {
		if rec := env.doJSON(env.session, r.method, base+"x"+r.path, r.body, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s x%s = %d, want 400", r.method, r.path, rec.Code)
		}
	}
	// Control: each body is valid, so the failures below are the DB's.
	for _, r := range serviceTabRoutes {
		if rec := env.doJSON(env.session, r.method, base+itoa(svc.ID)+r.path, r.body, nil); rec.Code != http.StatusNoContent {
			t.Errorf("%s %s = %d, control save failed: %.200s", r.method, r.path, rec.Code, rec.Body)
		}
	}
	dropTables(t, env.dbPath, "(name = 'services' OR name LIKE 'service\\_%' ESCAPE '\\')")
	for _, r := range serviceTabRoutes {
		if rec := env.doJSON(env.session, r.method, base+itoa(svc.ID)+r.path, r.body, nil); rec.Code < 500 {
			t.Errorf("%s %s with the tables gone = %d, want 5xx: %.200s", r.method, r.path, rec.Code, rec.Body)
		}
	}
}
