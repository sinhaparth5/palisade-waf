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
		rec := env.doWith("GET", "/admin/search?q="+url.QueryEscape(q), nil, sessions[role])
		if rec.Code != 200 {
			t.Fatalf("%s search %q = %d", role, q, rec.Code)
		}
		return rec.Body.String()
	}

	cases := []struct {
		role, q, want string
		found         bool
	}{
		// Cards follow the role gates, including ones reached via {{template}}.
		{storage.RoleOwner, "api keys", "/admin/settings#find=API%20Keys", true},
		{storage.RoleAdmin, "api keys", "#find=API%20Keys", false},
		{storage.RoleAdmin, "add ip", "/admin/ip-rules#find=Add%20IP%20Rule", true},
		{storage.RoleViewer, "add ip", "Add IP Rule", false},
		{storage.RoleViewer, "active ip", "/admin/ip-rules#find=Active%20IP%20Rules", true},
		{storage.RoleViewer, "rate limiting", "Rate Limiting", false},
		{storage.RoleViewer, "two-factor", "/admin/settings#find=Two-Factor%20Authentication", true},
		{storage.RoleViewer, "dashboard", `href="/admin"`, true},
		// Live records.
		{storage.RoleViewer, "SHOP.example", "/admin/services", true},
		{storage.RoleViewer, "113.9", "203.0.113.9", true},
		{storage.RoleViewer, "tor", "Tor exits", true},
		{storage.RoleViewer, "zzz-nothing", "No results for", true},
		{storage.RoleViewer, "  ", "No results", false},
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
	body := env.do("GET", "/admin/search?q=ip", nil).Body.String()
	a, b := strings.Index(body, ">Trusted IPs<"), strings.Index(body, ">Automatic banning<")
	if a < 0 || b < 0 || a > b {
		t.Errorf("want Trusted IPs before Automatic banning; at %d and %d", a, b)
	}
}
