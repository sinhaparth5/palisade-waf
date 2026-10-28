package ui

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"palisade/internal/storage"
)

// These match markup that starts a write (an hx-post/put/patch/delete
// attribute or a POST form) or links a GET route, capturing the target URL.
var (
	hxWrite   = regexp.MustCompile(`hx-(post|put|patch|delete)="([^"]*)"`)
	hrefGet   = regexp.MustCompile(`href="(/admin/[^"]*)"`)
	formWrite = regexp.MustCompile(`(?is)<form\b[^>]*>`)
	formAttr  = regexp.MustCompile(`(?i)\b(method|action)="([^"]*)"`)
)

// writeTargets returns "METHOD path" for every write control and admin link
// in html. Links matter only when their GET route declares a role.
func writeTargets(html string) []string {
	var out []string
	for _, m := range hxWrite.FindAllStringSubmatch(html, -1) {
		out = append(out, strings.ToUpper(m[1])+" "+m[2])
	}
	for _, tag := range formWrite.FindAllString(html, -1) {
		method, action := "", ""
		for _, a := range formAttr.FindAllStringSubmatch(tag, -1) {
			if strings.EqualFold(a[1], "method") {
				method = strings.ToUpper(a[2])
			} else {
				action = a[2]
			}
		}
		if method == "POST" {
			out = append(out, "POST "+action)
		}
	}
	for _, m := range hrefGet.FindAllStringSubmatch(html, -1) {
		out = append(out, "GET "+strings.ReplaceAll(m[1], "&amp;", "&"))
	}
	return out
}

// routeFor maps a concrete "METHOD /admin/x/1" to its registered route key
// ("METHOD /admin/x/:id"), or "" if none matches. A static route wins over a
// param one, as in Echo's router (/logs/export over /logs/:id).
func routeFor(env *adminEnv, target string) string {
	method, path, _ := strings.Cut(target, " ")
	path, _, _ = strings.Cut(path, "?")
	match := ""
	for _, r := range env.e.Routes() {
		if r.Method != method {
			continue
		}
		if r.Path == path {
			return r.Method + " " + r.Path
		}
		pat := "^" + regexp.MustCompile(`:[a-z]+`).ReplaceAllString(regexp.QuoteMeta(r.Path), `[^/]+`) + "$"
		if regexp.MustCompile(pat).MatchString(path) {
			match = r.Method + " " + r.Path
		}
	}
	return match
}

// TestRolePageSweep fetches every admin page as a viewer and an admin and
// fails on any write control whose route the role can't use (issue #216).
// The allowlist is routeRoles itself, so it can't drift from requireRole.
func TestRolePageSweep(t *testing.T) {
	t.Chdir(t.TempDir()) // the seeded certificate is written relative to the working directory
	env := newAdminEnv(t)
	svc := env.seedService("shop", "shop.example.com")
	_ = env.db.AddIPRule("", "203.0.113.9", "block")
	_ = env.db.AddGeoRule("", "RU", "block")
	_ = env.db.DisableWAFRule(942100, "noisy")
	_ = env.db.DisableWAFRuleForService(svc.Name, 920420, "uploads")
	_ = env.db.AddThreatIntelSource("Feed", "https://example.com/list.txt", 24)
	env.do("POST", "/admin/waf-rules/custom", form("rules", `SecRule ARGS "@contains x" "id:1000001,phase:2,deny"`))
	certPEM, keyPEM := testCertPEM(t, "shop.example.com")
	env.do("POST", "/admin/certificates", form("name", "c", "cert_pem", certPEM, "key_pem", keyPEM))
	if n, _ := env.db.ListWAFCustomRules(); len(n) == 0 {
		t.Fatal("custom rule seed failed")
	}
	if n, _ := env.db.ListCertificates(); len(n) == 0 {
		t.Fatal("certificate seed failed")
	}
	id := env.seedLog(storage.RequestLog{AppName: svc.Name, RealIP: "203.0.113.9", Status: 403, Blocked: true, Action: "waf_blocked", Method: "GET", Path: "/x"})
	pages := []string{
		"/admin", "/admin/logs", "/admin/ip-rules", "/admin/ip-rules/rows", "/admin/geo-rules",
		"/admin/services", "/admin/services/rows", "/admin/certificates", "/admin/waf-rules",
		"/admin/ai-usage", "/admin/threat-intel", "/admin/settings", "/admin/settings/audit",
		"/admin/api/notifications", fmt.Sprintf("/admin/logs/%d", id),
	}
	for _, role := range []string{storage.RoleViewer, storage.RoleAdmin} {
		session := env.sessionAs(role)
		for _, p := range pages {
			rec := env.doWith("GET", p, nil, session)
			if rec.Code != 200 {
				t.Errorf("%s GET %s = %d", role, p, rec.Code)
				continue
			}
			for _, target := range writeTargets(rec.Body.String()) {
				key := routeFor(env, target)
				need, ok := env.h.routeRoles[key]
				if !ok && strings.HasPrefix(target, "GET ") {
					continue // undeclared GETs are open to every role
				}
				if !ok {
					t.Errorf("%s %s: control %q matches no declared route", role, p, target)
				} else if roleRank[role] < roleRank[need] {
					t.Errorf("%s %s: renders %q (needs %s)", role, p, target, need)
				}
			}
		}
	}
}

// TestViewerServiceView: a viewer reads a service's settings as text in the
// View modal's template, with no edit modal and no maintenance bypass token.
func TestViewerServiceView(t *testing.T) {
	env := newAdminEnv(t)
	svc := env.seedService("shop", "shop.example.com")
	if err := env.db.SetServiceCacheTuning(svc.ID, 60, 0, 0, 0, "cache /assets/\nbypass /api/"); err != nil {
		t.Fatal(err)
	}
	if err := env.db.SetServiceMTLS(svc.ID, storage.ServiceMTLS{Mode: "required", CAPath: "ca.pem"}); err != nil {
		t.Fatal(err)
	}
	if err := env.db.SetServiceGate(svc.ID, storage.ServiceGate{Maintenance: true, BypassToken: "secret-bypass-token"}); err != nil {
		t.Fatal(err)
	}
	if err := env.h.registry.Reload(env.db); err != nil {
		t.Fatal(err)
	}

	body := env.doWith("GET", "/admin/services", nil, env.sessionAs(storage.RoleViewer)).Body.String()
	for _, want := range []string{"svc-view-overlay", "svc-view-btn", "cache /assets/", "60s / none", "required · CA saved", "Maintenance"} {
		if !strings.Contains(body, want) {
			t.Errorf("viewer services page missing %q", want)
		}
	}
	for _, bad := range []string{"svc-modal-overlay", "svc-edit-btn", "service-wizard", "secret-bypass-token"} {
		if strings.Contains(body, bad) {
			t.Errorf("viewer services page contains %q", bad)
		}
	}
	if admin := env.do("GET", "/admin/services", nil).Body.String(); !strings.Contains(admin, "svc-edit-btn") || strings.Contains(admin, "svc-view-btn") {
		t.Error("owner should get the Edit button, not View")
	}
}
