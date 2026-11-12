package ui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"palisade/internal/security/waf"
)

// TestAPIWriteGeoExceptionsVPatches pins issue #262: geo rules, rule
// exceptions and virtual patches can be changed over the REST API, with
// validation, a WAF reload and an audit row, and a read-only key can't.
func TestAPIWriteGeoExceptionsVPatches(t *testing.T) {
	env := newAdminEnv(t)
	env.seedService("shop", "shop.example.com")
	key := createTestKey(t, env.h, false)
	roKey := createTestKey(t, env.h, true)
	do := func(method, path string, body any) (int, string) {
		rec := apiRequest(env.e, method, "/admin/api/v1"+path, key, body)
		return rec.Code, rec.Body.String()
	}
	want := func(name string, code, wantCode int, body string) {
		t.Helper()
		if code != wantCode {
			t.Fatalf("%s: status %d, want %d: %s", name, code, wantCode, body)
		}
	}

	// Geo rules.
	for _, bad := range []map[string]any{
		{"country_code": "USA", "rule_type": "block"},
		{"country_code": "1x", "rule_type": "block"},
		{"country_code": "us", "rule_type": "deny"},
		{"country_code": "us", "rule_type": "block", "app_name": "nope"},
	} {
		code, body := do("POST", "/geo-rules", bad)
		want(fmt.Sprint(bad), code, 400, body)
	}
	code, body := do("POST", "/geo-rules", map[string]any{"country_code": "cn", "rule_type": "block", "app_name": "shop"})
	want("geo create", code, 201, body)
	rules, _ := env.db.ListGeoRules()
	if len(rules) != 1 || rules[0].CountryCode != "CN" || rules[0].AppName != "shop" {
		t.Fatalf("geo rules = %+v", rules)
	}
	code, body = do("DELETE", fmt.Sprintf("/geo-rules/%d", rules[0].ID), nil)
	want("geo delete", code, 204, body)
	if rules, _ := env.db.ListGeoRules(); len(rules) != 0 {
		t.Fatalf("geo rule not deleted: %+v", rules)
	}

	// Rule exceptions.
	for _, bad := range []map[string]any{{"rule_id": 0}, {"rule_id": 942100, "service": "nope"}} {
		code, body := do("POST", "/rule-exceptions", bad)
		want(fmt.Sprint(bad), code, 400, body)
	}
	before := env.count("waf")
	code, body = do("POST", "/rule-exceptions", map[string]any{"rule_id": 942100, "reason": "false positive"})
	want("global exception", code, 201, body)
	code, body = do("POST", "/rule-exceptions", map[string]any{"rule_id": 941100, "service": "shop"})
	want("service exception", code, 201, body)
	global, _ := env.db.ListDisabledWAFRules()
	perSvc, _ := env.db.ListWAFServiceExceptions()
	if len(global) != 1 || global[0].RuleID != 942100 || len(perSvc) != 1 || perSvc[0].ServiceName != "shop" {
		t.Fatalf("exceptions = %+v %+v", global, perSvc)
	}
	code, body = do("DELETE", fmt.Sprintf("/rule-exceptions/global/%d", global[0].ID), nil)
	want("delete global", code, 204, body)
	code, body = do("DELETE", fmt.Sprintf("/rule-exceptions/services/%d", perSvc[0].ID), nil)
	want("delete service", code, 204, body)
	global, _ = env.db.ListDisabledWAFRules()
	perSvc, _ = env.db.ListWAFServiceExceptions()
	if len(global)+len(perSvc) != 0 {
		t.Fatalf("exceptions left: %+v %+v", global, perSvc)
	}
	if n := env.count("waf") - before; n != 4 {
		t.Errorf("waf reloads = %d, want 4", n)
	}

	// Virtual patches.
	vp := waf.VPatches()[0].RuleID
	code, body = do("PUT", "/vpatches/1", map[string]any{"enabled": false})
	want("unknown patch", code, 404, body)
	code, body = do("PUT", fmt.Sprintf("/vpatches/%d", vp), map[string]any{})
	want("no enabled", code, 400, body)
	code, body = do("PUT", fmt.Sprintf("/vpatches/%d", vp), map[string]any{"enabled": false, "service": "shop"})
	want("patch off for shop", code, 200, body)
	var views []vpatchView
	if err := json.Unmarshal([]byte(body), &views); err != nil {
		t.Fatal(err)
	}
	if views[0].GlobalOff || len(views[0].OffFor) != 1 || views[0].OffFor[0] != "shop" {
		t.Fatalf("view = %+v", views[0])
	}
	code, body = do("PUT", fmt.Sprintf("/vpatches/%d", vp), map[string]any{"enabled": false})
	want("patch off", code, 200, body)
	if g, _ := env.db.ListDisabledWAFRules(); len(g) != 1 || g[0].Reason != "Turned off via API" {
		t.Fatalf("global off = %+v", g)
	}
	for _, svc := range []string{"", "shop"} {
		code, body = do("PUT", fmt.Sprintf("/vpatches/%d", vp), map[string]any{"enabled": true, "service": svc})
		want("patch on "+svc, code, 200, body)
	}
	global, _ = env.db.ListDisabledWAFRules()
	perSvc, _ = env.db.ListWAFServiceExceptions()
	if len(global)+len(perSvc) != 0 {
		t.Fatalf("patch still off: %+v %+v", global, perSvc)
	}

	// Read-only keys are refused, and writes are audited.
	for _, r := range []struct{ method, path string }{
		{"POST", "/geo-rules"}, {"DELETE", "/geo-rules/1"}, {"POST", "/rule-exceptions"},
		{"DELETE", "/rule-exceptions/global/1"}, {"DELETE", "/rule-exceptions/services/1"}, {"PUT", fmt.Sprintf("/vpatches/%d", vp)},
	} {
		if rec := apiRequest(env.e, r.method, "/admin/api/v1"+r.path, roKey, map[string]any{}); rec.Code != http.StatusForbidden {
			t.Errorf("read-only %s %s: %d", r.method, r.path, rec.Code)
		}
	}
	entries, _, _ := env.db.ListAudit(100, 0)
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.Action+" "+e.Summary)
	}
	all := strings.Join(actions, "\n")
	for _, s := range []string{"POST /api/v1/geo-rules", "country_code=cn", "DELETE /api/v1/rule-exceptions/global/:id", "PUT /api/v1/vpatches/:id", "enabled=false"} {
		if !strings.Contains(all, s) {
			t.Errorf("audit missing %q in:\n%s", s, all)
		}
	}
}
