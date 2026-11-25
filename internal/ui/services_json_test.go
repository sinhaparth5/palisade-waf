package ui

import (
	"net/http"
	"testing"

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
