package ui

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"palisade/internal/storage"
)

type servicesPage struct {
	Services []serviceJSON `json:"services"`
	Varnish  bool          `json:"varnish"`
}

func (env *adminEnv) services(t *testing.T, session string) []serviceJSON {
	t.Helper()
	var p servicesPage
	if rec := env.doJSON(session, http.MethodGet, "/admin/api/services", nil, &p); rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	return p.Services
}

// TestServicesJSON: add, rename, hosts, backends, rate limit and delete
// through the React page's routes, with field errors and roles.
func TestServicesJSON(t *testing.T) {
	env := newAdminEnv(t)
	const base = "/admin/api/services"
	add := map[string]any{"name": "blog", "match_type": "host", "match_value": "https://blog.example.com/", "backend": env.backend.URL, "rate_limit_rps": 5}
	if rec := env.doJSON(env.session, http.MethodPost, base, add, nil); rec.Code != http.StatusCreated {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	if rec := env.doJSON(env.session, http.MethodPost, base, add, nil); rec.Code != http.StatusConflict {
		t.Errorf("duplicate name: %d %s", rec.Code, rec.Body)
	}
	if rec := env.doJSON(env.session, http.MethodPost, base, map[string]any{"name": "x", "match_type": "host", "match_value": "x.example.com", "backend": "http://127.0.0.1:1"}, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("unreachable backend: %d %s", rec.Code, rec.Body)
	}
	list := env.services(t, env.session)
	if len(list) != 1 || list[0].Host != "blog.example.com" || list[0].RateLimit.RPS != 5 || list[0].Backends.LBPolicy != "round_robin" || list[0].Bot.Mode != "inherit" {
		t.Fatalf("list = %+v", list)
	}
	svc := "/admin/api/services/" + itoa(list[0].ID)

	for _, tc := range []struct {
		path  string
		body  any
		field string
	}{
		{"/name", map[string]string{"name": " "}, "name"},
		{"/hosts", svcHosts{Aliases: []string{"bad host"}}, "aliases"},
		{"/backends", svcBackends{URLs: []string{env.backend.URL}, LBPolicy: "random"}, "lb_policy"},
		{"/backends", svcBackends{URLs: []string{" "}, LBPolicy: "round_robin"}, "urls"},
		{"/backends", svcBackends{URLs: []string{env.backend.URL}, LBPolicy: "round_robin", CA: "not pem"}, "ca"},
		{"/rate-limit", svcRateLimit{RPS: -1}, "rps"},
		{"/rate-limit", svcRateLimit{PathRules: "GET nope"}, "path_rules"},
		// Limits: the form shows which field is over.
		{"/name", map[string]string{"name": strings.Repeat("a", 256)}, "name"},
		{"/backends", svcBackends{URLs: []string{env.backend.URL}, LBPolicy: "round_robin", HealthInterval: 3601}, "health_interval"},
		{"/bot", svcBot{Mode: "inherit", LoginPaths: many(loginPathsMax+1, "/login%d")}, "login_paths"},
		{"/bot", svcBot{Mode: "inherit", BreachFields: []string{strings.Repeat("f", 65)}}, "breach_fields"},
		{"/bot", svcBot{Mode: "inherit", BreachFields: many(11, "f%d")}, "breach_fields"},
		{"/gate", map[string]string{"message": strings.Repeat("m", 501)}, "message"},
		{"/gate", map[string]string{"wait_message": strings.Repeat("m", 501)}, "wait_message"},
		{"/openapi", svcOpenAPI{Mode: "log", Spec: strings.Repeat("a", openAPIMaxBytes+1)}, "spec"},
		{"/mcp", svcMCP{Mode: "block"}, "mode"},
		{"/csp", svcCSP{Mode: "report", Policy: "script-src " + strings.Repeat("a", 4096)}, "policy"},
		{"/csp", svcCSP{Mode: "report", Policy: "script-src 'self' caf\u00e9.example"}, "policy"},
		{"/csp", svcCSP{Mode: "block"}, "mode"},
		{"/cookies", svcCookies{Enabled: true, Exempt: many(51, "c%d")}, "exempt"},
		{"/policy", svcPolicy{Mode: "enforce", Methods: many(21, "M%d")}, "methods"},
		{"/policy", svcPolicy{Mode: "enforce", ContentTypes: many(31, "a/b%d")}, "content_types"},
		{"/policy", svcPolicy{Mode: "block"}, "mode"},
	} {
		var got jsonError
		if rec := env.doJSON(env.session, http.MethodPut, svc+tc.path, tc.body, &got); rec.Code != http.StatusBadRequest || got.Fields[tc.field] == "" {
			t.Errorf("%s %+v: %d %s, want a %s error", tc.path, tc.body, rec.Code, rec.Body, tc.field)
		}
	}

	for _, tc := range []struct {
		path string
		body any
	}{
		{"/name", map[string]string{"name": "journal"}},
		{"/hosts", svcHosts{Aliases: []string{"www.blog.example.com"}, Canonical: "blog.example.com"}},
		{"/backends", svcBackends{URLs: []string{env.backend.URL, env.backend.URL + "/"}, LBPolicy: "least_conn", HealthPath: "/healthz", HealthInterval: 30}},
		{"/rate-limit", svcRateLimit{RPS: 2.5, Burst: 9, PathRules: "POST /login 5/m 2"}},
	} {
		if rec := env.doJSON(env.session, http.MethodPut, svc+tc.path, tc.body, nil); rec.Code != http.StatusNoContent {
			t.Fatalf("%s: %d %s", tc.path, rec.Code, rec.Body)
		}
	}
	s := env.services(t, env.session)[0]
	if s.Name != "journal" || len(s.Hosts.Aliases) != 1 || s.Hosts.Canonical != "blog.example.com" || len(s.Backends.URLs) != 2 || s.Backends.LBPolicy != "least_conn" ||
		s.Backends.HealthInterval != 30 || s.RateLimit != (svcRateLimit{2.5, 9, "POST /login 5/m 2"}) {
		t.Errorf("after saves = %+v", s)
	}
	if env.h.registry.Match("www.blog.example.com", "/") == nil {
		t.Error("registry not reloaded with the alias")
	}

	viewer := env.sessionAs(storage.RoleViewer)
	if got := env.services(t, viewer); len(got) != 1 {
		t.Errorf("viewer list = %+v", got)
	}
	if rec := env.doJSON(viewer, http.MethodPut, svc+"/name", map[string]string{"name": "x"}, nil); rec.Code != http.StatusForbidden {
		t.Errorf("viewer write: %d", rec.Code)
	}
	if rec := env.doJSON(env.session, http.MethodPut, "/admin/api/services/999/name", map[string]string{"name": "x"}, nil); rec.Code != http.StatusNotFound {
		t.Errorf("missing service: %d", rec.Code)
	}
	if rec := env.doJSON(env.session, http.MethodDelete, svc, nil, nil); rec.Code != http.StatusNoContent || len(env.services(t, env.session)) != 0 {
		t.Errorf("delete: %d", rec.Code)
	}
}

// TestServicesJSONDocker: routing tabs refuse a Docker-managed service, the
// rest stay editable.
func TestServicesJSONDocker(t *testing.T) {
	env := newAdminEnv(t)
	if _, err := env.db.SetDockerService("app", []string{"app.example.com"}, "", []string{env.backend.URL}); err != nil {
		t.Fatal(err)
	}
	if err := env.h.registry.Reload(env.db); err != nil {
		t.Fatal(err)
	}
	s := env.services(t, env.session)[0]
	svc := "/admin/api/services/" + itoa(s.ID)
	if !s.Docker {
		t.Fatal("not marked docker")
	}
	for _, p := range []string{"/name", "/hosts", "/backends"} {
		if rec := env.doJSON(env.session, http.MethodPut, svc+p, map[string]any{}, nil); rec.Code != http.StatusConflict {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
	if rec := env.doJSON(env.session, http.MethodPut, svc+"/rate-limit", svcRateLimit{RPS: 1}, nil); rec.Code != http.StatusNoContent {
		t.Errorf("rate limit: %d %s", rec.Code, rec.Body)
	}
}

// TestCacheStatsJSON: off says so; on lists per-service results even when
// varnishstat is missing.
func TestCacheStatsJSON(t *testing.T) {
	env := newAdminEnv(t)
	var got map[string]any
	if rec := env.doJSON(env.session, http.MethodGet, "/admin/api/services/cache-stats", nil, &got); rec.Code != http.StatusOK || got["enabled"] != false {
		t.Fatalf("off: %d %v", rec.Code, got)
	}
	if err := env.db.SetVarnishConfig(storage.VarnishConfig{Enabled: true, Addr: "127.0.0.1:6081"}); err != nil {
		t.Fatal(err)
	}
	got = nil
	if rec := env.doJSON(env.session, http.MethodGet, "/admin/api/services/cache-stats", nil, &got); rec.Code != http.StatusOK || got["enabled"] != true || got["services"] == nil {
		t.Fatalf("on: %d %v", rec.Code, got)
	}
}

// TestServicesJSONBotGateUploads: the Bot, Availability and Uploads tabs
// refuse bad input with field errors, save, and keep the bypass token away
// from viewers.
func TestServicesJSONBotGateUploads(t *testing.T) {
	env := newAdminEnv(t)
	if err := env.db.AddService("blog", "blog.example.com", "", env.backend.URL, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := env.h.registry.Reload(env.db); err != nil {
		t.Fatal(err)
	}
	id := env.services(t, env.session)[0].ID
	svc := "/admin/api/services/" + itoa(id)
	okBot := svcBot{Mode: "always", AI: map[string]string{"training": "block"}}
	okGate := map[string]any{"waiting_room": true, "max_active": 50, "idle_mins": 10}

	for _, tc := range []struct {
		path  string
		body  any
		field string
	}{
		{"/bot", svcBot{Mode: "sometimes"}, "mode"},
		{"/bot", svcBot{Mode: "off", AI: map[string]string{"search": "maybe"}}, "ai_search"},
		{"/bot", svcBot{Mode: "off", LoginPaths: []string{"login"}}, "login_paths"},
		{"/bot", svcBot{Mode: "off", BreachAction: "warn"}, "breach_action"},
		{"/gate", map[string]any{"start": "tomorrow"}, "start"},
		{"/gate", map[string]any{"start": "2026-12-01T10:00", "end": "2026-12-01T09:00"}, "end"},
		{"/gate", map[string]any{"waiting_room": true, "max_active": 0, "idle_mins": 10}, "max_active"},
		{"/gate", map[string]any{"waiting_room": true, "max_active": 5, "idle_mins": 2000}, "idle_mins"},
		{"/uploads", svcUploads{MultipartMB: 300}, "multipart_mb"},
		{"/uploads", svcUploads{MalwareScan: "quarantine"}, "malware_scan"},
	} {
		var got jsonError
		if rec := env.doJSON(env.session, http.MethodPut, svc+tc.path, tc.body, &got); rec.Code != http.StatusBadRequest || got.Fields[tc.field] == "" {
			t.Errorf("%s %+v: %d %s, want a %s error", tc.path, tc.body, rec.Code, rec.Body, tc.field)
		}
	}

	okBot.LoginPaths = []string{"/login", "/login", " /wp-login.php "}
	okBot.BreachAction, okBot.BreachFields = "block", []string{"pw, password"}
	for _, tc := range []struct {
		path string
		body any
	}{
		{"/bot", okBot},
		{"/gate", okGate},
		{"/gate", map[string]any{"maintenance": true, "message": "Back soon", "start": "2026-12-01T10:00"}},
		{"/uploads", svcUploads{LargeJS: true, MultipartMB: 64, MalwareScan: "log"}},
	} {
		if rec := env.doJSON(env.session, http.MethodPut, svc+tc.path, tc.body, nil); rec.Code != http.StatusNoContent {
			t.Fatalf("%s: %d %s", tc.path, rec.Code, rec.Body)
		}
	}
	s := env.services(t, env.session)[0]
	if b := s.Bot; b.Mode != "always" || b.AI["training"] != "block" || len(b.LoginPaths) != 2 || b.BreachAction != "block" || len(b.BreachFields) != 2 {
		t.Errorf("bot = %+v", b)
	}
	if g := s.Gate; !g.Maintenance || g.Message != "Back soon" || g.Start != "2026-12-01T10:00" || g.Bypass == "" || g.WaitingRoom {
		t.Errorf("gate = %+v", g)
	}
	if s.Uploads != (svcUploads{true, 64, "log"}) {
		t.Errorf("uploads = %+v", s.Uploads)
	}
	token := s.Gate.Bypass
	env.doJSON(env.session, http.MethodPut, svc+"/gate", map[string]any{"maintenance": true}, nil)
	if got := env.services(t, env.session)[0].Gate.Bypass; got != token {
		t.Error("a save without new_bypass changed the token")
	}
	env.doJSON(env.session, http.MethodPut, svc+"/gate", map[string]any{"maintenance": true, "new_bypass": true}, nil)
	if got := env.services(t, env.session)[0].Gate.Bypass; got == token || got == "" {
		t.Error("new_bypass kept the token")
	}
	if got := env.services(t, env.sessionAs(storage.RoleViewer))[0].Gate.Bypass; got != "" {
		t.Errorf("viewer sees the bypass token %q", got)
	}
}

func TestServicesJSONRequestChecks(t *testing.T) {
	env := newAdminEnv(t)
	if err := env.db.AddService("api", "api.example.com", "", env.backend.URL, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := env.h.registry.Reload(env.db); err != nil {
		t.Fatal(err)
	}
	id := env.services(t, env.session)[0].ID
	if _, err := env.db.AddCSPScript(id, storage.CSPScript{Origin: "https://cdn.example.com", Page: "/", FirstSeen: time.Now()}); err != nil {
		t.Fatal(err)
	}
	svc := "/admin/api/services/" + itoa(id)
	const spec = "openapi: 3.0.3\npaths:\n  /users/{id}:\n    get: {}"

	for _, tc := range []struct {
		path  string
		body  any
		field string
	}{
		{"/schema", svcSchema{"enforce", "{nope"}, "schema"},
		{"/openapi", svcOpenAPI{"enforce", "not: [a spec"}, "spec"},
		{"/mcp", svcMCP{Mode: "enforce", Path: "mcp"}, "path"},
		{"/mcp", svcMCP{Mode: "log", Path: "/mcp", Origins: []string{"app.example.com"}}, "origins"},
		{"/jwt", svcJWT{Mode: "always"}, "mode"},
		{"/csp", svcCSP{Mode: "report", Policy: "script-src 'self'; report-uri /x"}, "policy"},
		{"/cookies", svcCookies{true, []string{"ok, bad;name"}}, "exempt"},
		{"/policy", svcPolicy{Mode: "enforce", Methods: []string{"GET", "G3T"}}, "methods"},
		{"/policy", svcPolicy{Mode: "enforce", ContentTypes: []string{"json"}}, "content_types"},
		{"/policy", svcPolicy{Mode: "log", MaxBodyKiB: -1}, "max_body_kib"},
		{"/responses", map[string]string{"mode": "redact"}, "mode"},
	} {
		var got jsonError
		if rec := env.doJSON(env.session, http.MethodPut, svc+tc.path, tc.body, &got); rec.Code != http.StatusBadRequest || got.Fields[tc.field] == "" {
			t.Errorf("%s %+v: %d %s, want a %s error", tc.path, tc.body, rec.Code, rec.Body, tc.field)
		}
	}
	for path, body := range map[string]any{
		"/jwt":    svcJWT{Mode: "enforce"}, // no key or JWKS URL
		"/policy": svcPolicy{Mode: "enforce"},
	} {
		if rec := env.doJSON(env.session, http.MethodPut, svc+path, body, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s %+v: %d, want 400", path, body, rec.Code)
		}
	}

	for _, tc := range []struct {
		path string
		body any
	}{
		{"/schema", svcSchema{"log", `{"type": "object"}`}},
		{"/openapi", svcOpenAPI{"enforce", spec}},
		{"/mcp", svcMCP{Mode: "enforce", Path: "/mcp", Origins: []string{"https://app.example.com"}, Methods: []string{"initialize", "tools/call"}, Tools: []string{"search"}}},
		{"/csp", svcCSP{Mode: "enforce", Approved: []string{"https://cdn.example.com", "https://evil.example.com"}}},
		{"/cookies", svcCookies{true, []string{"csrftoken, theme"}}},
		{"/policy", svcPolicy{Mode: "enforce", Methods: []string{"get", "post"}, ContentTypes: []string{"application/json"}, MaxBodyKiB: 1024}},
		{"/responses", map[string]string{"mode": "block"}},
	} {
		if rec := env.doJSON(env.session, http.MethodPut, svc+tc.path, tc.body, nil); rec.Code != http.StatusNoContent {
			t.Fatalf("%s: %d %s", tc.path, rec.Code, rec.Body)
		}
	}
	s := env.services(t, env.session)[0]
	if s.Schema != (svcSchema{"log", `{"type": "object"}`}) || s.OpenAPIMode != "enforce" {
		t.Errorf("schema = %+v, openapi %q", s.Schema, s.OpenAPIMode)
	}
	if m := s.MCP; m.Mode != "enforce" || m.Path != "/mcp" || len(m.Methods) != 2 || len(m.Tools) != 1 {
		t.Errorf("mcp = %+v", m)
	}
	if c := s.CSP; c.Mode != "enforce" || c.Policy != defaultCSP || len(c.Approved) != 1 || c.Approved[0] != "https://cdn.example.com" {
		t.Errorf("csp = %+v (an approval outside the inventory must be dropped)", c)
	}
	if c := s.Cookies; !c.Enabled || len(c.Exempt) != 2 {
		t.Errorf("cookies = %+v", c)
	}
	if p := s.Policy; p.Mode != "enforce" || p.Methods[0] != "GET" || p.MaxBodyKiB != 1024 {
		t.Errorf("policy = %+v", p)
	}
	if s.Responses != "block" {
		t.Errorf("responses = %q", s.Responses)
	}
	viewer := env.sessionAs(storage.RoleViewer)
	var o svcOpenAPI
	if rec := env.doJSON(viewer, http.MethodGet, svc+"/openapi", nil, &o); rec.Code != http.StatusOK || o != (svcOpenAPI{"enforce", spec}) {
		t.Errorf("openapi read: %d %+v", rec.Code, o)
	}

	// Off keeps the approvals for next time.
	env.doJSON(env.session, http.MethodPut, svc+"/csp", svcCSP{Mode: "off"}, nil)
	if c := env.services(t, env.session)[0].CSP; c.Mode != "off" || len(c.Approved) != 1 {
		t.Errorf("csp off = %+v", c)
	}
	if rec := env.doJSON(viewer, http.MethodPut, svc+"/responses", map[string]string{"mode": ""}, nil); rec.Code != http.StatusForbidden {
		t.Errorf("viewer write: %d", rec.Code)
	}
}

// many is n distinct values from format and their index.
func many(n int, format string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf(format, i)
	}
	return out
}
