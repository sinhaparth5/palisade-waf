package ui

import (
	"net/http"
	"testing"
)

// serviceFormRoutes are the per-service settings forms with a valid
// submission each, so a failure can only come from the id or the DB.
var serviceFormRoutes = []struct {
	path string
	form []string
}{
	{"/admin/services/bot/", []string{"bot_mode", "off"}},
	{"/admin/services/uploads/", []string{"enabled", "1"}},
	{"/admin/services/http3/", []string{"enabled", "1"}},
	{"/admin/services/mtls/", []string{"mtls_mode", "off"}},
	{"/admin/services/login/", []string{"login_paths", "/login"}},
	{"/admin/services/ai/", []string{"ai_policy", "inherit"}},
	{"/admin/services/breach/", []string{"breach_action", "log", "breach_fields", "password"}},
	{"/admin/services/responses/", []string{"response_inspect", "log"}},
	{"/admin/services/gate/", []string{}},
	{"/admin/services/compress/", []string{"enabled", "1"}},
	{"/admin/services/backends/", []string{"backends", "http://127.0.0.1:9", "lb_policy", "round_robin"}},
	{"/admin/services/hosts/", []string{"host_aliases", "", "canonical_host", ""}},
	{"/admin/services/schema/", []string{"schema_mode", "off"}},
	{"/admin/services/openapi/", []string{"openapi_mode", "off"}},
	{"/admin/services/mcp/", []string{"mcp_mode", "off"}},
	{"/admin/services/jwt/", []string{"jwt_mode", "off"}},
	{"/admin/services/csp/", []string{"csp_mode", "off"}},
	{"/admin/services/cookies/", []string{"cookie_mode", "on"}},
	{"/admin/services/policy/", []string{"policy_mode", "off"}},
	{"/admin/services/cache/", []string{"enabled", "1"}},
	{"/admin/services/cache-session/", []string{"enabled", "1", "cookie_name", "sid"}},
	{"/admin/services/cache-tuning/", []string{}},
}

// failed reports whether a form response signals failure the way the audit
// log reads it: a non-2xx status or an HX-Retarget to the form's error slot.
func failed(code int, h http.Header) bool {
	return code >= 300 || h.Get("HX-Retarget") != ""
}

// TestServiceFormsFail: a bad id, or a DB that can't read or write the
// service tables, is never answered as a successful save.
func TestServiceFormsFail(t *testing.T) {
	env := newAdminEnv(t)
	if err := env.db.AddService("svc", "svc.example.com", "", env.backend.URL, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := env.h.registry.Reload(env.db); err != nil {
		t.Fatal(err)
	}
	for _, r := range serviceFormRoutes {
		if rec := env.do("POST", r.path+"x", form(r.form...)); !failed(rec.Code, rec.Header()) {
			t.Errorf("POST %sx = %d with no error signal", r.path, rec.Code)
		}
	}

	// Control: each submission is valid, so the failures below are the DB's.
	for _, r := range serviceFormRoutes {
		if rec := env.do("POST", r.path+"1", form(r.form...)); failed(rec.Code, rec.Header()) {
			t.Errorf("POST %s1 = %d, control save failed: %.200s", r.path, rec.Code, rec.Body)
		}
	}

	dropTables(t, env.dbPath, "(name = 'services' OR name LIKE 'service\\_%' ESCAPE '\\')")
	for _, r := range serviceFormRoutes {
		if rec := env.do("POST", r.path+"1", form(r.form...)); !failed(rec.Code, rec.Header()) {
			t.Errorf("POST %s1 with the tables gone = %d with no error signal: %.200s", r.path, rec.Code, rec.Body)
		}
	}
}
