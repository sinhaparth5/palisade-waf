package ui

import (
	"net/url"
	"strings"
	"testing"

	"palisade/internal/storage"
)

func TestSearch(t *testing.T) {
	env := newAdminEnv(t)
	env.seedService("shop", "shop.example.com")
	_ = env.db.AddIPRule("", "203.0.113.9", "block")
	_ = env.db.AddThreatIntelSource("Tor exits", "https://example.com/tor.txt", 24)

	sessions := map[string]string{}
	search := func(role, q string) string {
		if sessions[role] == "" {
			sessions[role] = env.sessionAs(role)
		}
		rec := env.doJSON(sessions[role], "GET", "/admin/search?q="+url.QueryEscape(q), nil, nil)
		if rec.Code != 200 {
			t.Fatalf("%s search %q = %d", role, q, rec.Code)
		}
		return rec.Body.String()
	}

	cases := []struct {
		role, q, want string
		found         bool
	}{
		// Cards follow the role gates.
		{storage.RoleOwner, "api keys", `"title":"API Keys"`, true},
		{storage.RoleAdmin, "api keys", `"title":"API Keys"`, false},
		{storage.RoleAdmin, "add ip", "Add IP Rules", true},
		{storage.RoleViewer, "add ip", "Add IP Rule", false},
		{storage.RoleViewer, "active ip", `"url":"/admin/ip-rules"`, true},
		{storage.RoleViewer, "113.9", `"url":"/admin/ip-rules"`, true},
		{storage.RoleViewer, "rate limiting", `"url":"/admin/settings"`, true},
		{storage.RoleViewer, "two-factor", `"title":"Two-Factor Authentication"`, true},
		{storage.RoleViewer, "dashboard", `"url":"/admin/"`, true},
		{storage.RoleViewer, "enforcement", `"url":"/admin/"`, true},
		{storage.RoleViewer, "configured serv", `"url":"/admin/services"`, true},
		{storage.RoleAdmin, "add service", `"title":"Add Service"`, true},
		{storage.RoleViewer, "add service", `"title":"Add Service"`, false},
		// Live records.
		{storage.RoleViewer, "SHOP.example", `"url":"/admin/services"`, true},
		{storage.RoleViewer, "113.9", "203.0.113.9", true},
		{storage.RoleViewer, "tor", "Tor exits", true},
		{storage.RoleViewer, "zzz-nothing", "[]", true},
		{storage.RoleViewer, "  ", "[]", true},
	}
	for _, c := range cases {
		if got := strings.Contains(search(c.role, c.q), c.want); got != c.found {
			t.Errorf("%s search %q: contains %q = %v, want %v", c.role, c.q, c.want, got, c.found)
		}
	}
}

// A title match outranks cards that only match on their page name: Trusted
// IPs (Settings) before Automatic banning (on IP Rules, earlier in the sidebar).
func TestSearchRanksTitles(t *testing.T) {
	env := newAdminEnv(t)
	body := env.doJSON(env.session, "GET", "/admin/search?q=ip", nil, nil).Body.String()
	a, b := strings.Index(body, `"title":"Trusted IPs"`), strings.Index(body, `"title":"Automatic banning"`)
	if a < 0 || b < 0 || a > b {
		t.Errorf("want Trusted IPs before Automatic banning; at %d and %d", a, b)
	}
}
