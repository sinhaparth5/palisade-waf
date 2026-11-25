package ui

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"palisade/internal/security/waf"
	"palisade/internal/storage"
)

type wafPage struct {
	VPatches    []vpatchJSON     `json:"vpatches"`
	Suggestions []suggestionJSON `json:"suggestions"`
	Feedback    struct {
		Threshold  int `json:"threshold"`
		WindowDays int `json:"window_days"`
	} `json:"feedback"`
	TopRules   []topRuleJSON    `json:"top_rules"`
	Custom     []customRuleJSON `json:"custom"`
	Exceptions []exceptionJSON  `json:"exceptions"`
	Services   []string         `json:"services"`
	WAFEnabled bool             `json:"waf_enabled"`
}

const wafAPI = "/admin/api/waf-rules"

// TestWAFRulesAPI covers the React WAF Rules page: exceptions (global and
// per service, virtual patches included), feedback thresholds, roles.
func TestWAFRulesAPI(t *testing.T) {
	env := newAdminEnv(t)
	env.seedService("shop", "shop.example.com")
	p := waf.VPatches()[0]
	for range 2 {
		env.seedLog(storage.RequestLog{Timestamp: time.Now(), RealIP: "203.0.113.5", Blocked: true, RuleID: p.RuleID, Status: 403})
	}

	for _, tc := range []struct {
		body  map[string]any
		field string
	}{
		{map[string]any{"rule_id": 0}, "rule_id"},
		{map[string]any{"rule_id": 942100, "service": "nope"}, "service"},
	} {
		var got jsonError
		if rec := env.doJSON(env.session, http.MethodPost, wafAPI+"/exceptions", tc.body, &got); rec.Code != http.StatusBadRequest || got.Fields[tc.field] == "" {
			t.Errorf("%v: %d %s, want a %s error", tc.body, rec.Code, rec.Body, tc.field)
		}
	}
	if rec := env.doJSON(env.session, http.MethodPost, wafAPI+"/exceptions", "nope", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("non-object body: %d", rec.Code)
	}
	for _, body := range []map[string]any{
		{"rule_id": 942100, "reason": " fp "},
		{"rule_id": p.RuleID, "service": "shop", "reason": "Virtual patch turned off"},
	} {
		if rec := env.doJSON(env.session, http.MethodPost, wafAPI+"/exceptions", body, nil); rec.Code != http.StatusCreated {
			t.Fatalf("add %v: %d %s", body, rec.Code, rec.Body)
		}
	}
	if n := env.count("waf"); n != 2 {
		t.Errorf("WAF reloads = %d, want 2", n)
	}

	viewer := env.sessionAs("viewer")
	var page wafPage
	if rec := env.doJSON(viewer, http.MethodGet, wafAPI, nil, &page); rec.Code != http.StatusOK {
		t.Fatalf("viewer GET: %d %s", rec.Code, rec.Body)
	}
	if len(page.VPatches) != len(waf.VPatches()) || page.VPatches[0].Hits != 2 || page.VPatches[0].GlobalOff || strings.Join(page.VPatches[0].OffFor, ",") != "shop" {
		t.Errorf("vpatches = %+v", page.VPatches[0])
	}
	if len(page.Exceptions) != 2 || page.Exceptions[0].Service != "" || page.Exceptions[0].Reason != "fp" || page.Exceptions[1].Service != "shop" || page.Exceptions[0].CreatedAt == "" {
		t.Errorf("exceptions = %+v", page.Exceptions)
	}
	if strings.Join(page.Services, ",") != "shop" || !page.WAFEnabled || page.Feedback.Threshold != 5 || page.Feedback.WindowDays != 7 {
		t.Errorf("services/feedback = %v %v %+v", page.Services, page.WAFEnabled, page.Feedback)
	}
	if len(page.TopRules) != 1 || page.TopRules[0].RuleID != p.RuleID || page.TopRules[0].Hits != 2 {
		t.Errorf("top rules = %+v", page.TopRules)
	}
	if rec := env.doJSON(viewer, http.MethodPost, wafAPI+"/exceptions", map[string]any{"rule_id": 1}, nil); rec.Code != http.StatusForbidden {
		t.Errorf("viewer POST: %d", rec.Code)
	}

	for _, tc := range []struct {
		body  map[string]any
		field string
	}{
		{map[string]any{"threshold": 0, "window_days": 7}, "threshold"},
		{map[string]any{"threshold": 5, "window_days": 91}, "window_days"},
	} {
		var got jsonError
		if rec := env.doJSON(env.session, http.MethodPut, wafAPI+"/feedback", tc.body, &got); rec.Code != http.StatusBadRequest || got.Fields[tc.field] == "" {
			t.Errorf("%v: %d %s", tc.body, rec.Code, rec.Body)
		}
	}
	if rec := env.doJSON(env.session, http.MethodPut, wafAPI+"/feedback", map[string]any{"threshold": 7, "window_days": 30}, nil); rec.Code != http.StatusNoContent {
		t.Errorf("feedback: %d %s", rec.Code, rec.Body)
	}
	if fc, _ := env.db.GetWAFRuleFeedbackConfig(); fc.Threshold != 7 || fc.WindowDays != 30 {
		t.Errorf("feedback cfg = %+v", fc)
	}

	g, s := page.Exceptions[0], page.Exceptions[1]
	for path, want := range map[string]int{
		wafAPI + "/exceptions/global/x":               http.StatusBadRequest,
		wafAPI + "/exceptions/services/0":             http.StatusBadRequest,
		wafAPI + "/exceptions/global/" + itoa(g.ID):   http.StatusNoContent,
		wafAPI + "/exceptions/services/" + itoa(s.ID): http.StatusNoContent,
	} {
		if rec := env.doJSON(env.session, http.MethodDelete, path, nil, nil); rec.Code != want {
			t.Errorf("DELETE %s = %d, want %d", path, rec.Code, want)
		}
	}
	if ids, _ := env.db.GetDisabledWAFRuleIDs(); len(ids) != 0 {
		t.Errorf("global exception left: %v", ids)
	}
	if ids, _ := env.db.GetWAFRuleIDsForService("shop"); len(ids) != 0 {
		t.Errorf("service exception left: %v", ids)
	}
}

// TestCustomRulesAPI: server-side validation as field errors, edit in
// place, toggle, delete, and a WAF reload for every change that lands.
func TestCustomRulesAPI(t *testing.T) {
	env := newAdminEnv(t)
	env.seedService("shop", "shop.example.com")
	const custom = wafAPI + "/custom"

	for _, tc := range []struct {
		name, field, want string
		req               customRuleRequest
	}{
		{"empty", "rule", "Enter a rule", customRuleRequest{Rule: " "}},
		{"crs id", "rule", "outside the custom range", customRuleRequest{Rule: `SecRule ARGS "@contains x" "id:942100,deny"`}},
		{"include", "rule", "Only SecRule", customRuleRequest{Rule: "Include /etc/passwd"}},
		{"unknown service", "service", "no longer exists", customRuleRequest{Rule: testCustomRule, Service: "nope"}},
	} {
		var got jsonError
		rec := env.doJSON(env.session, http.MethodPost, custom, tc.req, &got)
		if rec.Code != http.StatusBadRequest || !strings.Contains(got.Fields[tc.field], tc.want) {
			t.Errorf("%s: %d %s", tc.name, rec.Code, rec.Body)
		}
	}
	if n := env.count("waf"); n != 0 {
		t.Fatalf("rejected rules reloaded the WAF %d times", n)
	}

	if rec := env.doJSON(env.session, http.MethodPost, custom, customRuleRequest{Rule: testCustomRule, Service: "shop", Note: " probe "}, nil); rec.Code != http.StatusCreated {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	var page wafPage
	env.doJSON(env.session, http.MethodGet, wafAPI, nil, &page)
	if len(page.Custom) != 1 || !page.Custom[0].Enabled || page.Custom[0].Service != "shop" || page.Custom[0].Note != "probe" {
		t.Fatalf("custom = %+v", page.Custom)
	}
	id := itoa(page.Custom[0].ID)

	var dup jsonError
	if rec := env.doJSON(env.session, http.MethodPost, custom, customRuleRequest{Rule: testCustomRule}, &dup); rec.Code != http.StatusBadRequest || !strings.Contains(dup.Fields["rule"], "already used by custom rule") {
		t.Errorf("duplicate id accepted: %d %s", rec.Code, rec.Body)
	}
	for _, tc := range []struct {
		method, path string
		body         any
		want         int
	}{
		{http.MethodPut, custom + "/" + id, customRuleRequest{Rule: testCustomRule}, http.StatusNoContent},
		{http.MethodPut, custom + "/999", customRuleRequest{Rule: `SecAction "id:1000050,pass"`}, http.StatusNotFound},
		{http.MethodPut, custom + "/x", customRuleRequest{Rule: testCustomRule}, http.StatusBadRequest},
		{http.MethodPut, custom + "/" + id + "/enabled", map[string]any{}, http.StatusBadRequest},
		{http.MethodPut, custom + "/" + id + "/enabled", map[string]any{"enabled": false}, http.StatusNoContent},
	} {
		if rec := env.doJSON(env.session, tc.method, tc.path, tc.body, nil); rec.Code != tc.want {
			t.Errorf("%s %s = %d %s, want %d", tc.method, tc.path, rec.Code, rec.Body, tc.want)
		}
	}
	rules, _ := env.db.ListWAFCustomRules()
	if len(rules) != 1 || rules[0].Enabled || rules[0].ServiceName != "" {
		t.Fatalf("after edit+disable = %+v", rules)
	}
	if rec := env.doJSON(env.session, http.MethodDelete, custom+"/x", nil, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete bad id: %d", rec.Code)
	}
	if rec := env.doJSON(env.session, http.MethodDelete, custom+"/"+id, nil, nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete: %d", rec.Code)
	}
	if rules, _ := env.db.ListWAFCustomRules(); len(rules) != 0 {
		t.Error("custom rule not deleted")
	}
	if n := env.count("waf"); n != 4 {
		t.Errorf("WAF reloads = %d, want 4 (add, edit, toggle, delete)", n)
	}
}

func TestWAFDryRunAPI(t *testing.T) {
	env := newAdminEnv(t)
	env.seedLog(storage.RequestLog{AppName: "a", Method: "GET", Host: "a.test", Path: "/hello", Query: "x=1", Status: 200})
	const dry = wafAPI + "/dry-run"

	for _, rule := range []string{"", "this is not a directive"} {
		var got jsonError
		if rec := env.doJSON(env.session, http.MethodPost, dry, map[string]any{"rule": rule}, &got); rec.Code != http.StatusBadRequest || got.Fields["rule"] == "" {
			t.Errorf("%q: %d %s", rule, rec.Code, rec.Body)
		}
	}
	var res struct {
		Replayed int             `json:"replayed"`
		Hits     []dryRunHitJSON `json:"hits"`
	}
	rule := `SecRule ARGS:x "@streq 1" "id:9000001,phase:2,deny,status:403"`
	if rec := env.doJSON(env.session, http.MethodPost, dry, map[string]any{"rule": rule, "limit": -1}, &res); rec.Code != http.StatusOK {
		t.Fatalf("dry run: %d %s", rec.Code, rec.Body)
	}
	if res.Replayed != 1 || len(res.Hits) != 1 || res.Hits[0].Target != "/hello?x=1" || res.Hits[0].Before.Blocked || !res.Hits[0].After.Blocked || res.Hits[0].After.RuleID != 9000001 {
		t.Errorf("result = %+v", res)
	}
	if env.count("waf") != 0 {
		t.Error("a dry run reloaded the WAF")
	}

	env.h.cfg.WAF.Enabled = false
	if rec := env.doJSON(env.session, http.MethodPost, dry, map[string]any{"rule": rule}, nil); rec.Code != http.StatusConflict {
		t.Errorf("disabled WAF: %d", rec.Code)
	}
}
