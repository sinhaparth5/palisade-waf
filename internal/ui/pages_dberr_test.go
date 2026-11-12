package ui

import (
	"net/http"
	"testing"
)

// TestPagesStorageFailure: with everything but the auth tables gone, admin
// pages and fragments fail instead of rendering an empty view ("no rules",
// "no blocked IPs") that an operator would take at face value. Certificates,
// Threat intel and settings render best-effort on purpose and are
// not listed.
func TestPagesStorageFailure(t *testing.T) {
	env := newAdminEnv(t)
	dropTables(t, env.dbPath, "name NOT IN ('sessions', 'meta') AND name NOT LIKE 'admin%'")
	for _, path := range []string{
		"/admin/logs", "/admin/logs/stats", "/admin/logs/1", "/admin/ip-rules", "/admin/ip-rules/rows",
		"/admin/geo-rules", "/admin/services/openapi/1", "/admin/waf-rules", "/admin/settings/audit",
		"/admin/api/traffic", "/admin/api/threats",
	} {
		if rec := env.do("GET", path, nil); rec.Code < http.StatusInternalServerError {
			t.Errorf("GET %s = %d, want 5xx", path, rec.Code)
		}
	}
}
