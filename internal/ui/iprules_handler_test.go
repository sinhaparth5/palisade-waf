package ui

import (
	"fmt"
	"net/http"
	"testing"

	"palisade/internal/storage"
)

type ipRulesPage struct {
	Rules      []ipRuleView `json:"rules"`
	Page       int          `json:"page"`
	TotalPages int          `json:"total_pages"`
	Total      int          `json:"total"`
	BlockCount int          `json:"block_count"`
	AllowCount int          `json:"allow_count"`
}

// TestListIPRules checks paging (a page past the end falls back to the
// last one), the whole-table counts, auto-ban flags and threat scores.
func TestListIPRules(t *testing.T) {
	env := newAdminEnv(t)
	for i := range ipRulesPageSize + 2 {
		_ = env.db.AddIPRule("", fmt.Sprintf("10.0.0.%d", i+1), "block")
	}
	_ = env.db.AddIPRule("", "10.1.0.1", "allow")
	_ = env.db.AddIPRuleWithNote("", "10.2.0.1", "block", "Auto-banned — test")
	_ = env.db.UpsertIPThreatScore(storage.IPThreatScore{IP: "10.2.0.1", Total: 42})

	for _, tc := range []struct {
		query      string
		page, rows int
	}{
		{"", 1, ipRulesPageSize}, {"?page=0", 1, ipRulesPageSize}, {"?page=2", 2, 4}, {"?page=99", 2, 4},
	} {
		var got ipRulesPage
		if rec := env.doJSON(env.session, http.MethodGet, "/admin/api/ip-rules"+tc.query, nil, &got); rec.Code != http.StatusOK {
			t.Fatalf("%q: %d %s", tc.query, rec.Code, rec.Body)
		}
		if got.Page != tc.page || len(got.Rules) != tc.rows || got.TotalPages != 2 || got.Total != ipRulesPageSize+4 || got.BlockCount != ipRulesPageSize+3 || got.AllowCount != 1 {
			t.Errorf("%q: %+v", tc.query, got)
		}
	}
	var got ipRulesPage
	env.doJSON(env.session, http.MethodGet, "/admin/api/ip-rules", nil, &got)
	for _, r := range got.Rules {
		if r.IP == "10.2.0.1" && (!r.Auto || r.Score != 42 || r.Note == "") {
			t.Errorf("auto ban row = %+v", r)
		}
		if r.IP == "10.1.0.1" && (r.Auto || r.Score != 0) {
			t.Errorf("manual row = %+v", r)
		}
	}
}

func TestAddRemoveIPRules(t *testing.T) {
	env := newAdminEnv(t)
	for _, tc := range []struct {
		name, field string
		body        map[string]any
	}{
		{"bad entry refuses all", "ip", map[string]any{"ip": "1.2.3.4\nnope", "rule_type": "block"}},
		{"empty", "ip", map[string]any{"ip": " ", "rule_type": "block"}},
		{"bad type", "rule_type", map[string]any{"ip": "1.2.3.4", "rule_type": "maybe"}},
		{"unknown service", "app_name", map[string]any{"ip": "1.2.3.4", "rule_type": "block", "app_name": "ghost"}},
	} {
		var e jsonError
		if rec := env.doJSON(env.session, http.MethodPost, "/admin/api/ip-rules", tc.body, &e); rec.Code != http.StatusBadRequest || e.Fields[tc.field] == "" {
			t.Errorf("%s: %d %+v", tc.name, rec.Code, e)
		}
	}
	if rules, _ := env.db.ListIPRules(); len(rules) != 0 {
		t.Fatalf("a refused add wrote %v", rules)
	}

	var added map[string]int
	rec := env.doJSON(env.session, http.MethodPost, "/admin/api/ip-rules", map[string]any{"ip": "1.2.3.4, 10.0.1.5/24\n::ffff:1.2.3.4 2001:db8::1", "rule_type": "block"}, &added)
	if rec.Code != http.StatusCreated || added["added"] != 3 {
		t.Fatalf("add: %d %v", rec.Code, added)
	}
	rules, _ := env.db.ListIPRules()
	got := map[string]bool{}
	for _, r := range rules {
		got[r.IP] = true
	}
	for _, ip := range []string{"1.2.3.4", "10.0.1.0/24", "2001:db8::1"} {
		if !got[ip] {
			t.Errorf("missing %s in %v", ip, rules)
		}
	}
	if blocked, _ := env.h.ipbl.Check("1.2.3.4", ""); !blocked {
		t.Error("blocklist not reloaded after add")
	}

	ids := []int{rules[0].ID, rules[1].ID, 999999}
	if rec := env.doJSON(env.session, http.MethodPost, "/admin/api/ip-rules/remove", map[string]any{"ids": ids}, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body)
	}
	if left, _ := env.db.ListIPRules(); len(left) != 1 {
		t.Errorf("left after remove = %v", left)
	}
	if rec := env.doJSON(env.session, http.MethodPost, "/admin/api/ip-rules/remove", map[string]any{"ids": []int{}}, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("empty remove: %d", rec.Code)
	}
}

func TestIPRulesSettings(t *testing.T) {
	env := newAdminEnv(t)
	autoban := map[string]any{"enabled": true, "threshold": 7, "window": 5, "ban_hours": 0, "bad_status": true, "bad_codes": "404, 403", "bad_points": 2}
	if rec := env.doJSON(env.session, http.MethodPut, "/admin/api/ip-rules/autoban", autoban, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("autoban: %d %s", rec.Code, rec.Body)
	}
	if env.count("autoban") != 1 {
		t.Errorf("autoban reloads = %d", env.count("autoban"))
	}
	adaptive := map[string]any{"enabled": true, "high_threshold": 80, "low_threshold": 10, "high_scale": 0.3, "low_scale": 1.5, "force_challenge": 90}
	if rec := env.doJSON(env.session, http.MethodPut, "/admin/api/ip-rules/adaptive", adaptive, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("adaptive: %d %s", rec.Code, rec.Body)
	}
	if env.count("adaptive") != 1 {
		t.Errorf("adaptive reloads = %d", env.count("adaptive"))
	}
	if rec := env.doJSON(env.session, http.MethodPut, "/admin/api/ip-rules/honeypots", map[string]any{"honeypot_paths": "/xmlrpc.php\r\n/phpmyadmin/ /phpmyadmin/"}, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("honeypots: %d %s", rec.Code, rec.Body)
	}
	if !env.h.registry.Honeypot("/phpMyAdmin/setup.php") {
		t.Error("registry not updated without a reload")
	}

	var got struct {
		Autoban   autobanView  `json:"autoban"`
		Adaptive  adaptiveView `json:"adaptive"`
		Honeypots []string     `json:"honeypot_paths"`
	}
	env.doJSON(env.session, http.MethodGet, "/admin/api/ip-rules/settings", nil, &got)
	if a := got.Autoban; !a.Enabled || a.Threshold != 7 || a.Window != 5 || a.BanHours != 0 || a.BadCodes != "404, 403" || a.BadPoints != 2 {
		t.Errorf("autoban = %+v", a)
	}
	if a := got.Adaptive; !a.Enabled || a.HighThreshold != 80 || a.HighScale != 0.3 || a.ForceChallenge != 90 {
		t.Errorf("adaptive = %+v", a)
	}
	if len(got.Honeypots) != 2 {
		t.Errorf("honeypots = %v", got.Honeypots)
	}

	for _, tc := range []struct {
		path, field string
		body        map[string]any
	}{
		{"autoban", "threshold", map[string]any{"threshold": 0, "window": 5, "bad_codes": "404", "bad_points": 1}},
		{"autoban", "bad_codes", map[string]any{"threshold": 1, "window": 5, "bad_codes": "abc", "bad_points": 1}},
		{"adaptive", "high_scale", map[string]any{"high_threshold": 80, "high_scale": 2, "low_scale": 1.5, "force_challenge": 90}},
		{"honeypots", "honeypot_paths", map[string]any{"honeypot_paths": "/ok nope"}},
		// "/" would ban on every 404.
		{"honeypots", "honeypot_paths", map[string]any{"honeypot_paths": "/ok /"}},
	} {
		var e jsonError
		if rec := env.doJSON(env.session, http.MethodPut, "/admin/api/ip-rules/"+tc.path, tc.body, &e); rec.Code != http.StatusBadRequest || e.Fields[tc.field] == "" {
			t.Errorf("%s %s: %d %+v", tc.path, tc.field, rec.Code, e)
		}
	}
	if cfg, _ := env.db.GetAutobanConfig(); cfg.Threshold != 7 {
		t.Errorf("a refused save changed autoban: %+v", cfg)
	}
	if got, _ := env.db.GetHoneypotPaths(); len(got) != 2 {
		t.Errorf("a refused save changed the honeypots: %v", got)
	}
}

func TestAddRemoveGeoRules(t *testing.T) {
	env := newAdminEnv(t)
	var e jsonError
	if rec := env.doJSON(env.session, http.MethodPost, "/admin/api/geo-rules", map[string]any{"country_code": []string{"cn", "X1"}, "rule_type": "block"}, &e); rec.Code != http.StatusBadRequest || e.Fields["country_code"] == "" {
		t.Errorf("bad code: %d %+v", rec.Code, e)
	}
	var added map[string]int
	if rec := env.doJSON(env.session, http.MethodPost, "/admin/api/geo-rules", map[string]any{"country_code": []string{"cn", "RU", "CN"}, "rule_type": "block"}, &added); rec.Code != http.StatusCreated || added["added"] != 2 {
		t.Fatalf("add: %d %v", rec.Code, added)
	}
	var rules []storage.GeoRule
	env.doJSON(env.session, http.MethodGet, "/admin/api/geo-rules", nil, &rules)
	if len(rules) != 2 {
		t.Fatalf("rules = %v", rules)
	}
	if rec := env.doJSON(env.session, http.MethodPost, "/admin/api/geo-rules/remove", map[string]any{"ids": []int{rules[0].ID, rules[1].ID}}, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body)
	}
	if left, _ := env.db.ListGeoRules(); len(left) != 0 {
		t.Errorf("left = %v", left)
	}
}
