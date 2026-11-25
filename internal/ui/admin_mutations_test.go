package ui

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"palisade/internal/storage"
)

func itoa[T int | int64](n T) string { return strconv.FormatInt(int64(n), 10) }

// wantCode fails unless rec has the given status.
func wantCode(t *testing.T, label string, got, want int, body string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: status %d want %d: %s", label, got, want, body)
	}
}

func TestAddAndDeleteService(t *testing.T) {
	env := newAdminEnv(t)
	for _, tc := range []struct {
		name string
		f    []string
		want string
	}{
		{"missing fields", []string{"name", "x"}, "fill in all required"},
		{"bad match type", []string{"name", "x", "match_type", "path", "match_value", "/", "backend", env.backend.URL}, "fill in all required"},
		{"metadata backend", []string{"name", "x", "match_type", "host", "match_value", "a.test", "backend", "http://169.254.169.254"}, ""},
		{"dead backend", []string{"name", "x", "match_type", "host", "match_value", "a.test", "backend", "http://127.0.0.1:1"}, "Fix the backend"},
		{"bad rps", []string{"name", "x", "match_type", "host", "match_value", "a.test", "backend", env.backend.URL, "rps", "fast"}, "must be a number"},
		{"bad burst", []string{"name", "x", "match_type", "host", "match_value", "a.test", "backend", env.backend.URL, "burst", "1.5"}, "whole number"},
	} {
		rec := env.do("POST", "/admin/services", form(tc.f...))
		if rec.Header().Get("HX-Retarget") != "#wizard-error" || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: retarget=%q body=%s", tc.name, rec.Header().Get("HX-Retarget"), rec.Body)
		}
	}

	rec := env.do("POST", "/admin/services", form("name", "shop", "match_type", "host", "match_value", "https://shop.example.com/", "backend", env.backend.URL, "rps", "-1", "burst", "-3"))
	wantCode(t, "add host", rec.Code, 200, rec.Body.String())
	rec = env.do("POST", "/admin/services", form("name", "api", "match_type", "prefix", "match_value", "/api", "backend", env.backend.URL, "rps", "5", "burst", "10"))
	wantCode(t, "add prefix", rec.Code, 200, rec.Body.String())
	svcs, _ := env.db.ListServices()
	if len(svcs) != 2 || svcs[0].Host != "shop.example.com" || svcs[0].RateLimitRPS != 0 || svcs[1].Prefix != "/api" || svcs[1].RateLimitBurst != 10 {
		t.Fatalf("services = %+v", svcs)
	}
	if !env.h.registry.IsServiceHost("shop.example.com") {
		t.Error("registry not reloaded")
	}

	wantCode(t, "delete bad", env.do("DELETE", "/admin/services/x", nil).Code, 400, "")
	wantCode(t, "delete", env.do("DELETE", "/admin/services/"+itoa(svcs[0].ID), nil).Code, 200, "")
	if env.h.registry.IsServiceHost("shop.example.com") {
		t.Error("deleted service still routed")
	}
}

// TestRenameService pins issue #320: the Name form renames a service,
// moves its name-keyed rules and rebuilds the WAF engines; empty, taken and
// unknown are refused in the form's error box.
func TestRenameService(t *testing.T) {
	env := newAdminEnv(t)
	svc := env.seedService("shop", "shop.example.com")
	env.seedService("blog", "blog.example.com")
	if err := env.db.AddIPRule("shop", "198.51.100.7", "block"); err != nil {
		t.Fatal(err)
	}
	id := itoa(svc.ID)
	for _, tc := range []struct{ id, name, want string }{
		{id, " ", "cannot be empty"}, {id, "blog", "already called blog"}, {"x", "a", "invalid service"}, {"99999", "a", "not found"},
	} {
		rec := env.do("POST", "/admin/services/name/"+tc.id, form("name", tc.name))
		if rec.Header().Get("HX-Retarget") != "#svc-name-error" || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%q: %s", tc.name, rec.Body)
		}
	}
	rec := env.do("POST", "/admin/services/name/"+id, form("name", " store "))
	if rec.Header().Get("HX-Trigger") != "name-saved" {
		t.Fatalf("rename: %s", rec.Body)
	}
	if got, _ := env.db.GetService(svc.ID); got.Name != "store" {
		t.Errorf("name = %q", got.Name)
	}
	if rules, _ := env.db.ListIPRules(); len(rules) != 1 || rules[0].AppName != "store" {
		t.Errorf("ip rules = %+v", rules)
	}
	if m := env.h.registry.Match("shop.example.com", "/"); m == nil || m.Name != "store" {
		t.Errorf("registry match = %+v", m)
	}
	if env.count("waf") != 1 {
		t.Errorf("waf reloads = %d", env.count("waf"))
	}
}

// TestDockerManagedLocked pins issue #341: the name, hosts and backends of
// a service created from container labels refuse edits in the UI and API;
// its other settings still save, even with no container running.
func TestDockerManagedLocked(t *testing.T) {
	env := newAdminEnv(t)
	if _, err := env.db.SetDockerService("app", []string{"app.example.com"}, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := env.h.registry.Reload(env.db); err != nil {
		t.Fatal(err)
	}
	svc := env.h.registry.List()[0]
	id := itoa(svc.ID)
	for _, tc := range []struct{ path, errBox string }{
		{"/admin/services/name/" + id, "#svc-name-error"},
		{"/admin/services/hosts/" + id, "#svc-hosts-error"},
		{"/admin/services/backends/" + id, "#svc-backends-error"},
	} {
		rec := env.do("POST", tc.path, form("name", "x", "aliases", "www.app.example.com", "backends", "http://127.0.0.1:9001"))
		if rec.Header().Get("HX-Retarget") != tc.errBox || !strings.Contains(rec.Body.String(), "Managed by Docker") {
			t.Errorf("%s: %s", tc.path, rec.Body)
		}
	}
	if rec := env.do("POST", "/admin/services/bot/"+id, form("bot_mode", "off")); rec.Code != 200 {
		t.Errorf("bot mode: %d %s", rec.Code, rec.Body)
	}
	got, _ := env.db.GetService(svc.ID)
	if got.Name != "app" || got.HostAliases != nil || got.Backend != "" || got.BotMode != "off" {
		t.Errorf("service = %+v", got)
	}
}

func TestServiceSettingHandlers(t *testing.T) {
	env := newAdminEnv(t)
	svc := env.seedService("shop", "shop.example.com")
	id := itoa(svc.ID)

	for _, tc := range []struct {
		path string
		f    []string
		want int
	}{
		{"/admin/services/bot/" + id, []string{"bot_mode", "always"}, 200},
		{"/admin/services/bot/0", nil, 400},
		{"/admin/services/uploads/" + id, []string{"enabled", "1"}, 200},
		{"/admin/services/uploads/x", nil, 400},
		{"/admin/services/uploads/" + id, []string{"multipart_mb", "257"}, 400},
		{"/admin/services/uploads/" + id, []string{"multipart_mb", "-1"}, 400},
		{"/admin/services/uploads/" + id, []string{"multipart_mb", "x"}, 400},
		{"/admin/services/uploads/" + id, []string{"malware_scan", "quarantine"}, 400},
		{"/admin/services/uploads/" + id, []string{"enabled", "1", "multipart_mb", "64", "malware_scan", "block"}, 200},
		{"/admin/services/http3/" + id, []string{"enabled", "1"}, 200},
		{"/admin/services/http3/x", nil, 400},
		{"/admin/services/compress/" + id, []string{"enabled", "1"}, 200},
		{"/admin/services/compress/x", nil, 400},
		{"/admin/services/backends/" + id, []string{"backends", "http://127.0.0.1:9001\nhttp://127.0.0.1:9002", "lb_policy", "least_conn", "health_path", "/healthz", "health_interval", "30"}, 200},
		{"/admin/services/schema/" + id, []string{"mode", "enforce", "schema", `{"type":"object"}`}, 200},
		{"/admin/services/schema/" + id, []string{"mode", "log", "schema", `{"type":`}, 400},
		{"/admin/services/schema/x", nil, 400},
		{"/admin/services/cache/" + id, []string{"enabled", "1"}, 200},
		{"/admin/services/cache/x", nil, 400},
		{"/admin/services/cache-session/" + id, []string{"session_enabled", "1"}, 400},
		{"/admin/services/cache-session/" + id, []string{"session_enabled", "1", "session_cookie_name", "sid"}, 200},
		{"/admin/services/cache-session/x", nil, 400},
		{"/admin/services/cache-tuning/" + id, []string{"ttl_floor", "-1"}, 400},
		{"/admin/services/cache-tuning/" + id, []string{"ttl_ceiling", "x"}, 400},
		{"/admin/services/cache-tuning/" + id, []string{"grace", "x"}, 400},
		{"/admin/services/cache-tuning/" + id, []string{"keep", "x"}, 400},
		{"/admin/services/cache-tuning/" + id, []string{"ttl_floor", "100", "ttl_ceiling", "50"}, 400},
		{"/admin/services/cache-tuning/" + id, []string{"ttl_floor", "60", "ttl_ceiling", "600", "grace", "10", "keep", "", "cache_rules", "cache /assets/\r\nbypass /api/"}, 200},
		{"/admin/services/cache-tuning/" + id, []string{"cache_rules", "keep /assets/"}, 400},
		{"/admin/services/cache-tuning/x", nil, 400},
	} {
		rec := env.do("POST", tc.path, form(tc.f...))
		wantCode(t, tc.path+" "+strings.Join(tc.f, "="), rec.Code, tc.want, rec.Body.String())
	}

	// The last uploads save set the multipart limit (issue #319).
	if got, _ := env.h.db.GetService(svc.ID); got.MultipartLimitMB != 64 || !got.AllowLargeJSUploads || got.MalwareScan != "block" {
		t.Errorf("uploads tab saved %+v", got)
	}

	// Backend list errors land in the tab's error box, escaped.
	rec := env.do("POST", "/admin/services/backends/"+id, form("backends", "http://127.0.0.1:1/<b>\nhttp://127.0.0.2:1/"))
	if rec.Header().Get("HX-Retarget") != "#svc-backends-error" || strings.Contains(rec.Body.String(), "<b>") {
		t.Errorf("backends error = %q (retarget %q)", rec.Body.String(), rec.Header().Get("HX-Retarget"))
	}

	// Trusted backend certificate (issue #313): a key is refused, a cert is
	// stored, and an empty field clears it.
	rec = env.do("POST", "/admin/services/backends/"+id, form("backends", "http://127.0.0.1:9001\nhttp://127.0.0.1:9002", "lb_policy", "least_conn", "health_path", "/healthz", "health_interval", "30", "backend_ca", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"))
	if rec.Header().Get("HX-Retarget") != "#svc-backends-error" || !strings.Contains(rec.Body.String(), "private key") {
		t.Errorf("backend key = %q (retarget %q)", rec.Body.String(), rec.Header().Get("HX-Retarget"))
	}
	ts := httptest.NewTLSServer(nil)
	ts.Close()
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}))
	for _, ca := range []string{certPEM, ""} {
		rec = env.do("POST", "/admin/services/backends/"+id, form("backends", "http://127.0.0.1:9001\nhttp://127.0.0.1:9002", "lb_policy", "least_conn", "health_path", "/healthz", "health_interval", "30", "backend_ca", ca))
		cas, err := env.db.ListServiceBackendCA()
		if rec.Header().Get("HX-Trigger") != "backends-saved" || err != nil || cas[svc.ID] != strings.TrimSpace(ca) {
			t.Errorf("backend ca save %q: %d %q, stored %q", ca, rec.Code, rec.Body.String(), cas[svc.ID])
		}
	}

	// Hosts tab: a name another service owns is refused in the tab's error box.
	env.seedService("blog", "blog.example.com")
	rec = env.do("POST", "/admin/services/hosts/"+id, form("aliases", "blog.example.com"))
	if rec.Header().Get("HX-Retarget") != "#svc-hosts-error" || !strings.Contains(rec.Body.String(), "blog") {
		t.Errorf("hosts conflict = %q (retarget %q)", rec.Body.String(), rec.Header().Get("HX-Retarget"))
	}
	rec = env.do("POST", "/admin/services/hosts/"+id, form("aliases", "WWW.shop.example.com\n", "canonical", "shop.example.com"))
	if rec.Header().Get("HX-Trigger") != "hosts-saved" {
		t.Errorf("hosts save = %d %q", rec.Code, rec.Body.String())
	}
	if !env.h.registry.IsServiceHost("www.shop.example.com") {
		t.Error("alias not routed after save")
	}

	got, _ := env.db.GetService(svc.ID)
	if len(got.HostAliases) != 1 || got.HostAliases[0] != "www.shop.example.com" || got.CanonicalHost != "shop.example.com" {
		t.Errorf("hosts = %v %q", got.HostAliases, got.CanonicalHost)
	}
	if got.BotMode != "always" || !got.AllowLargeJSUploads || !got.HTTP3Enabled || !got.CompressEnabled || len(got.ExtraBackends) != 1 || got.LBPolicy != "least_conn" || got.HealthPath != "/healthz" || got.SchemaMode != "enforce" || !got.CacheEnabled ||
		!got.CacheBySession || got.SessionCookieName != "sid" || got.CacheTTLFloor != 60 || got.CacheTTLCeiling != 600 || got.CacheGrace != 10 || got.CacheRules != "cache /assets/\nbypass /api/" {
		t.Errorf("service = %+v", got)
	}
	if env.count("waf") != 3 { // uploads twice + schema
		t.Errorf("waf reloads = %d", env.count("waf"))
	}

	// Rate limit tab.
	for _, tc := range []struct {
		f      []string
		code   int
		errBox bool
	}{
		{[]string{"service_id", "x"}, 400, false},
		{[]string{"service_id", id, "rps", "x"}, 200, true},
		{[]string{"service_id", id, "burst", "x"}, 200, true},
		{[]string{"service_id", id, "rps", "-2", "burst", "-1"}, 200, false},
		{[]string{"service_id", id, "rps", "3", "burst", "6", "path_rules", "POST /reset 5/q 1"}, 200, true},
		{[]string{"service_id", id, "rps", "3", "burst", "6", "path_rules", "post /reset 5/h 3\r\n* /search 2/s 10"}, 200, false},
	} {
		rec := env.do("POST", "/admin/services/ratelimit", form(tc.f...))
		wantCode(t, "ratelimit", rec.Code, tc.code, rec.Body.String())
		if (rec.Header().Get("HX-Retarget") == "#rl-error") != tc.errBox {
			t.Errorf("ratelimit %v: retarget=%q", tc.f, rec.Header().Get("HX-Retarget"))
		}
	}
	if got, _ := env.db.GetService(svc.ID); got.RateLimitRPS != 3 || got.RateLimitBurst != 6 {
		t.Errorf("rate limit = %v/%v", got.RateLimitRPS, got.RateLimitBurst)
	}
	if got, _ := env.db.ListServiceRateRules(); got[svc.ID] != "post /reset 5/h 3\n* /search 2/s 10" {
		t.Errorf("path rules = %q", got[svc.ID])
	}
	if _, rule := env.h.registry.AllowPath(svc.Name, "POST", "/reset/x", "1.2.3.4"); rule != "POST /reset 5/h 3" {
		t.Errorf("registry not reloaded: rule %q", rule)
	}

	// Purge: invalid id / unknown service / Varnish unreachable all report inline.
	for path, want := range map[string]string{
		"/admin/services/cache-purge/x":     "invalid service id",
		"/admin/services/cache-purge/99999": "service not found",
		"/admin/services/cache-purge/" + id: "text-red-600",
	} {
		rec := env.do("POST", path, form("path", "/blog/"))
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("purge %s: %s", path, rec.Body)
		}
	}
}

// testCertPEM returns a self-signed cert+key for the given DNS names.
func testCertPEM(t *testing.T, names ...string) (certPEM, keyPEM string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
}

func TestCertificateAndTLSHandlers(t *testing.T) {
	t.Chdir(t.TempDir()) // cert files are written relative to the working directory
	env := newAdminEnv(t)
	host := env.seedService("shop", "shop.example.com")
	prefix := storage.Service{}
	_ = env.db.AddService("api", "", "/api", env.backend.URL, 0, 0)
	svcs, _ := env.db.ListServices()
	for _, s := range svcs {
		if s.Name == "api" {
			prefix = s
		}
	}
	certPEM, keyPEM := testCertPEM(t, "shop.example.com")
	otherCert, otherKey := testCertPEM(t, "other.example.com")

	// Pool certificates (the API itself is covered in certificates_test.go).
	for _, r := range []certAddRequest{{"cert.pem", certPEM, keyPEM}, {"cert.pem", otherCert, otherKey}} {
		if rec := env.doJSON(env.session, "POST", "/admin/api/certificates", r, nil); rec.Code != http.StatusCreated {
			t.Fatalf("add cert: %d %s", rec.Code, rec.Body)
		}
	}
	certs, _ := env.db.ListCertificates()

	// Assign from the pool.
	for _, tc := range []struct {
		f    []string
		want string
	}{
		{[]string{"service_id", "x"}, "invalid service"},
		{[]string{"service_id", itoa(host.ID), "cert_id", "0"}, "select a certificate"},
		{[]string{"service_id", "99999", "cert_id", "1"}, "service not found"},
		{[]string{"service_id", itoa(prefix.ID), "cert_id", "1"}, "host-matched"},
		{[]string{"service_id", itoa(host.ID), "cert_id", "99999"}, "certificate not found"},
		{[]string{"service_id", itoa(host.ID), "cert_id", itoa(certs[1].ID)}, "shop.example.com"},
	} {
		rec := env.do("POST", "/admin/services/tls/pool", form(tc.f...))
		if rec.Header().Get("HX-Retarget") != "#tls-error" || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("assign %q: %s", tc.want, rec.Body)
		}
	}
	rec := env.do("POST", "/admin/services/tls/pool", form("service_id", itoa(host.ID), "cert_id", itoa(certs[0].ID)))
	if rec.Header().Get("HX-Trigger") != "tls-saved" {
		t.Errorf("assign ok: %s", rec.Body)
	}
	if got, _ := env.db.GetService(host.ID); got.CertID != certs[0].ID {
		t.Errorf("cert not assigned: %+v", got)
	}

	// Custom upload.
	for _, tc := range []struct {
		f    []string
		want string
	}{
		{[]string{"service_id", "x"}, "invalid service"},
		{[]string{"service_id", "99999"}, "service not found"},
		{[]string{"service_id", itoa(prefix.ID)}, "host-matched"},
		{[]string{"service_id", itoa(host.ID)}, "paste both"},
		{[]string{"service_id", itoa(host.ID), "cert_pem", otherCert, "key_pem", otherKey}, "shop.example.com"},
		{[]string{"service_id", itoa(host.ID), "cert_pem", certPEM, "key_pem", otherKey}, "invalid"},
	} {
		rec := env.do("POST", "/admin/services/tls/upload", form(tc.f...))
		if rec.Header().Get("HX-Retarget") != "#tls-error" || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("upload %q: %s", tc.want, rec.Body)
		}
	}
	rec = env.do("POST", "/admin/services/tls/upload", form("service_id", itoa(host.ID), "cert_pem", certPEM, "key_pem", keyPEM))
	if rec.Header().Get("HX-Trigger") != "tls-saved" {
		t.Errorf("upload ok: %s", rec.Body)
	}
	if got, _ := env.db.GetService(host.ID); got.TLSMode != "custom" {
		t.Errorf("tls mode = %q", got.TLSMode)
	}
	if _, err := os.Stat(filepath.Join("certs", "services", "by-id", itoa(host.ID), "key.pem")); err != nil {
		t.Errorf("custom cert dir: %v", err)
	}

	// Auto TLS: no ACME email yet asks the UI to collect one.
	for _, tc := range []struct{ id, want string }{{"x", "invalid service"}, {"99999", "service not found"}, {itoa(prefix.ID), "host-matched"}} {
		if rec := env.do("POST", "/admin/services/tls/auto", form("service_id", tc.id)); !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("auto %s: %s", tc.id, rec.Body)
		}
	}
	rec = env.do("POST", "/admin/services/tls/auto", form("service_id", itoa(host.ID)))
	if !strings.Contains(rec.Header().Get("HX-Trigger"), "need-acme-email") {
		t.Errorf("auto without email: %q", rec.Header().Get("HX-Trigger"))
	}
	if rec := env.do("POST", "/admin/settings/acme-email", form("email", "nope")); rec.Header().Get("HX-Retarget") != "#acme-email-error" {
		t.Error("invalid ACME email accepted")
	}
	rec = env.do("POST", "/admin/settings/acme-email", form("email", "ops@example.com", "service_id", itoa(host.ID)))
	// Both events: tls-saved closes the TLS modal, acme-email-saved the email one.
	if rec.Header().Get("HX-Trigger") != "tls-saved, acme-email-saved" {
		t.Errorf("acme email: %q", rec.Header().Get("HX-Trigger"))
	}
	if got, _ := env.db.GetService(host.ID); got.TLSMode != "auto" {
		t.Errorf("tls mode after acme = %q", got.TLSMode)
	}
	if rec := env.do("POST", "/admin/services/tls/auto", form("service_id", itoa(host.ID))); rec.Header().Get("HX-Trigger") != "tls-saved" {
		t.Errorf("auto with email: %q", rec.Header().Get("HX-Trigger"))
	}

	if rec := env.do("POST", "/admin/services/tls/clear", form("service_id", "x")); !strings.Contains(rec.Body.String(), "invalid service") {
		t.Error("clear bad id")
	}
	env.do("POST", "/admin/services/tls/clear", form("service_id", itoa(host.ID)))
	if got, _ := env.db.GetService(host.ID); got.TLSMode != "" && got.TLSMode != "none" {
		t.Errorf("tls mode after clear = %q", got.TLSMode)
	}

}

// TestBackupDownloads: the database and config downloads Settings links to.
func TestBackupDownloads(t *testing.T) {
	env := newAdminEnv(t)

	rec := env.do("POST", "/admin/settings/backup", nil)
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), "SQLite format 3") ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), "palisade-") {
		t.Errorf("backup: %d %q", rec.Code, rec.Header().Get("Content-Disposition"))
	}
	rec = env.do("POST", "/admin/settings/config-export", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"palisade-config"`) ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), "palisade-config-") {
		t.Errorf("config export: %d %q", rec.Code, rec.Header().Get("Content-Disposition"))
	}
}

// TestPasskeyEnrollment: a secure context gets a WebAuthn challenge, a bogus
// attestation spends the pending ceremony, and an expired slot isn't taken.
func TestPasskeyEnrollment(t *testing.T) {
	env := newAdminEnv(t)
	secure := func(method, path, body string) *httptestRecorder {
		r := newReq(env, method, path, body)
		r.Host = "localhost"
		r.Header.Set("Accept", "application/json")
		return serve(env, r)
	}
	rec := secure("POST", "/admin/api/settings/passkeys/begin", `{"name":"YubiKey"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "challenge") {
		t.Fatalf("begin enrollment: %d %s", rec.Code, rec.Body)
	}
	if rec := secure("POST", "/admin/api/settings/passkeys/finish", `{}`); rec.Code != 400 {
		t.Errorf("finish with bogus attestation = %d", rec.Code)
	}
	if rec := secure("POST", "/admin/api/settings/passkeys/finish", `{}`); rec.Code != 409 || !strings.Contains(rec.Body.String(), "expired") {
		t.Errorf("finish without a pending ceremony: %d %s", rec.Code, rec.Body)
	}

	_ = env.db.AddWebAuthnCredential(env.uid, "AQID", "Key", []byte(`{"id":"AQID"}`))
	creds, _ := env.db.ListWebAuthnCredentials(env.uid)
	if rec := env.doJSON(env.session, "DELETE", "/admin/api/settings/passkeys/"+itoa(creds[0].ID), nil, nil); rec.Code != 204 {
		t.Errorf("delete passkey: %d", rec.Code)
	}
	if creds, _ := env.db.ListWebAuthnCredentials(env.uid); len(creds) != 0 {
		t.Error("passkey not deleted")
	}

	env.h.pkEnroll.m[env.uid] = pkEnrollment{name: "x", expires: time.Now().Add(-time.Second)}
	if _, _, ok := env.h.pkEnroll.take(env.uid); ok {
		t.Error("expired enrollment should not be taken")
	}
}

func TestPasskeyLogin(t *testing.T) {
	env := newAdminEnv(t)
	_ = env.db.AddWebAuthnCredential(env.uid, "AQID", "Key", []byte(`{"id":"AQID"}`))

	post := func(path string, cookies ...*http.Cookie) *httptestRecorder {
		r := newReq(env, "POST", path, "{}")
		r.Host = "localhost"
		r.Header.Del("X-CSRF-Token")
		r.Header.Del("Cookie")
		for _, c := range cookies {
			r.AddCookie(c)
		}
		return serve(env, r)
	}
	if rec := post("/admin/login/webauthn/begin"); rec.Code != 400 {
		t.Errorf("begin without pending login = %d", rec.Code)
	}
	if rec := post("/admin/login/webauthn/finish"); rec.Code != 400 {
		t.Errorf("finish without pending login = %d", rec.Code)
	}

	// The password step parks the login because a passkey is registered.
	rec := env.doWith("POST", "/admin/login", form("email", testAdminEmail, "password", testAdminPassword), "")
	pending := cookieByName(rec, twoFACookie)
	if pending == nil {
		t.Fatalf("password step should park the login: %d", rec.Code)
	}
	if rec := post("/admin/login/webauthn/finish", pending); rec.Code != 400 {
		t.Errorf("finish before begin = %d", rec.Code)
	}
	if rec := post("/admin/login/webauthn/begin", pending); rec.Code != 200 || !strings.Contains(rec.Body.String(), "challenge") {
		t.Fatalf("begin: %d %s", rec.Code, rec.Body)
	}
	for range maxLoginFailures {
		post("/admin/login/webauthn/begin", pending)
		post("/admin/login/webauthn/finish", pending)
	}
	if rec := post("/admin/login/webauthn/begin", pending); rec.Code != http.StatusTooManyRequests {
		t.Errorf("begin after lockout = %d", rec.Code)
	}
	if rec := post("/admin/login/webauthn/finish", pending); rec.Code != http.StatusTooManyRequests {
		t.Errorf("finish after lockout = %d", rec.Code)
	}
}

func TestSetServiceLoginPaths(t *testing.T) {
	env := newAdminEnv(t)
	svc := env.seedService("shop", "shop.example.com")
	path := "/admin/services/login/" + itoa(svc.ID)

	rec := env.do("POST", path, form("login_paths", "/login\r\n/wp-login.php\n/login\n"))
	wantCode(t, "save", rec.Code, 200, rec.Body.String())
	if rec.Header().Get("HX-Trigger") != "login-saved" {
		t.Fatalf("no login-saved trigger: %s", rec.Body)
	}
	got, _ := env.db.GetService(svc.ID)
	if strings.Join(got.LoginPaths, ",") != "/login,/wp-login.php" {
		t.Errorf("stored = %v", got.LoginPaths)
	}
	if !strings.Contains(rec.Body.String(), "Login protected") {
		t.Error("row badge missing")
	}

	// Bad entries are refused inline and keep the old list.
	for _, bad := range []string{"login", "/"} {
		rec = env.do("POST", path, form("login_paths", "/signin\n"+bad))
		if rec.Header().Get("HX-Retarget") != "#svc-login-error" || !strings.Contains(rec.Body.String(), "is not a path") {
			t.Fatalf("%q: want inline error, got %s", bad, rec.Body)
		}
	}
	if got, _ = env.db.GetService(svc.ID); len(got.LoginPaths) != 2 {
		t.Errorf("rejected save changed the list: %v", got.LoginPaths)
	}

	// Empty turns it off.
	env.do("POST", path, form("login_paths", ""))
	if got, _ = env.db.GetService(svc.ID); got.LoginPaths != nil {
		t.Errorf("not cleared: %v", got.LoginPaths)
	}
	wantCode(t, "bad id", env.do("POST", "/admin/services/login/x", nil).Code, 200, "")
}

func TestSetServiceAICrawlers(t *testing.T) {
	env := newAdminEnv(t)
	svc := env.seedService("shop", "shop.example.com")
	path := "/admin/services/ai/" + itoa(svc.ID)

	rec := env.do("POST", path, form("ai_training", "block", "ai_search", "", "ai_user", "nope"))
	wantCode(t, "save", rec.Code, 200, rec.Body.String())
	got, _ := env.db.GetService(svc.ID)
	if got.AICrawlerPolicy != "training=block" {
		t.Errorf("stored = %q", got.AICrawlerPolicy)
	}
	if !strings.Contains(rec.Body.String(), "AI crawlers: custom") || !strings.Contains(rec.Body.String(), `data-ai="training=block"`) {
		t.Error("row badge or data-ai missing")
	}
	if app := env.h.registry.Match("shop.example.com", "/"); env.h.registry.AIAction(app, "training") != "block" {
		t.Error("registry not reloaded")
	}

	// All on inherit clears the override.
	env.do("POST", path, form("ai_training", ""))
	if got, _ = env.db.GetService(svc.ID); got.AICrawlerPolicy != "" {
		t.Errorf("not cleared: %q", got.AICrawlerPolicy)
	}
	wantCode(t, "bad id", env.do("POST", "/admin/services/ai/x", nil).Code, 400, "")
}

func TestSetServiceBreachCheck(t *testing.T) {
	env := newAdminEnv(t)
	svc := env.seedService("shop", "shop.example.com")
	path := "/admin/services/breach/" + itoa(svc.ID)

	rec := env.do("POST", path, form("breach_action", "block", "breach_fields", "user_pass, pwd user_pass"))
	wantCode(t, "save", rec.Code, 200, rec.Body.String())
	if rec.Header().Get("HX-Trigger") != "breach-saved" {
		t.Fatalf("no breach-saved trigger: %s", rec.Body)
	}
	got, _ := env.db.GetService(svc.ID)
	if got.BreachAction != "block" || strings.Join(got.BreachFields, ",") != "user_pass,pwd" {
		t.Errorf("stored = %q %v", got.BreachAction, got.BreachFields)
	}
	if !strings.Contains(rec.Body.String(), "Leaked passwords: block") || !strings.Contains(rec.Body.String(), `data-breach-fields="user_pass pwd"`) {
		t.Error("row badge or data attribute missing")
	}

	rec = env.do("POST", path, form("breach_action", "challenge"))
	if rec.Header().Get("HX-Retarget") != "#svc-breach-error" {
		t.Fatalf("unknown action: want inline error, got %s", rec.Body)
	}
	if got, _ = env.db.GetService(svc.ID); got.BreachAction != "block" {
		t.Error("rejected save changed the action")
	}

	env.do("POST", path, form("breach_action", ""))
	if got, _ = env.db.GetService(svc.ID); got.BreachAction != "" || got.BreachFields != nil {
		t.Errorf("not cleared: %q %v", got.BreachAction, got.BreachFields)
	}
}

func TestSetServiceOpenAPI(t *testing.T) {
	env := newAdminEnv(t)
	svc := env.seedService("api", "api.example.com")
	path := "/admin/services/openapi/" + itoa(svc.ID)
	const spec = "openapi: 3.0.3\npaths:\n  /users/{id}:\n    get: {}"

	rec := env.do("POST", path, form("openapi_spec", spec, "openapi_mode", "enforce"))
	wantCode(t, "save", rec.Code, 200, rec.Body.String())
	if rec.Header().Get("HX-Trigger") != "openapi-saved" {
		t.Fatalf("no openapi-saved trigger: %s", rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "OpenAPI: enforce") {
		t.Error("row badge missing")
	}
	if rec = env.do("GET", path, nil); rec.Body.String() != spec {
		t.Errorf("GET spec = %q", rec.Body)
	}

	rec = env.do("POST", path, form("openapi_spec", `{"swagger":"2.0"}`, "openapi_mode", "enforce"))
	if rec.Header().Get("HX-Retarget") != "#svc-openapi-error" || !strings.Contains(rec.Body.String(), "OpenAPI 3.x") {
		t.Fatalf("invalid spec: want inline error, got %s", rec.Body)
	}
	if got, _ := env.db.GetServiceOpenAPI(svc.ID); got.Spec != spec {
		t.Error("rejected save replaced the spec")
	}

	env.do("POST", path, form("openapi_spec", spec, "openapi_mode", "off"))
	if got, _ := env.db.GetServiceOpenAPI(svc.ID); got.Spec != spec || got.Mode != "off" {
		t.Errorf("off should keep the spec: %+v", got)
	}

	env.do("POST", path, form("openapi_spec", "", "openapi_mode", "log"))
	if got, _ := env.db.GetServiceOpenAPI(svc.ID); got.Spec != "" {
		t.Errorf("not removed: %+v", got)
	}
}

func TestSetServiceMCP(t *testing.T) {
	env := newAdminEnv(t)
	svc := env.seedService("mcp", "mcp.example.com")
	path := "/admin/services/mcp/" + itoa(svc.ID)

	rec := env.do("POST", path, form("mcp_mode", "enforce", "mcp_path", "/mcp", "mcp_origins", "https://app.example.com",
		"mcp_methods", "initialize\r\ntools/call", "mcp_tools", "search"))
	wantCode(t, "save", rec.Code, 200, rec.Body.String())
	if rec.Header().Get("HX-Trigger") != "mcp-saved" || !strings.Contains(rec.Body.String(), "MCP: enforce") {
		t.Fatalf("no mcp-saved trigger or badge: %s", rec.Body)
	}
	got, _ := env.db.ListServiceMCP()
	if m := got[svc.ID]; m.Path != "/mcp" || m.Methods != "initialize\ntools/call" || m.Tools != "search" {
		t.Errorf("stored %+v", m)
	}

	for _, bad := range [][]string{{"mcp_path", "mcp"}, {"mcp_path", "/mcp", "mcp_origins", "https://app.example.com/path"}, {"mcp_path", "/mcp", "mcp_origins", "app.example.com"}} {
		rec = env.do("POST", path, form(append([]string{"mcp_mode", "log"}, bad...)...))
		if rec.Header().Get("HX-Retarget") != "#svc-mcp-error" {
			t.Errorf("%v: want inline error, got %s", bad, rec.Body)
		}
	}
	if got, _ = env.db.ListServiceMCP(); got[svc.ID].Mode != "enforce" {
		t.Error("rejected save changed the guard")
	}

	env.do("POST", path, form("mcp_mode", "off"))
	if got, _ = env.db.ListServiceMCP(); len(got) != 0 {
		t.Errorf("off should remove the guard: %+v", got)
	}
}

func TestSetServiceCSP(t *testing.T) {
	env := newAdminEnv(t)
	svc := env.seedService("shop", "shop.example.com")
	path := "/admin/services/csp/" + itoa(svc.ID)

	rec := env.do("POST", path, form("csp_mode", "report", "csp_policy", ""))
	wantCode(t, "save", rec.Code, 200, rec.Body.String())
	if rec.Header().Get("HX-Trigger") != "csp-saved" || !strings.Contains(rec.Body.String(), "CSP: 0 script sources") {
		t.Fatalf("no csp-saved trigger or badge: %s", rec.Body)
	}
	if got, _ := env.db.ListServiceCSP(); got[svc.ID] != "script-src 'self'" {
		t.Errorf("empty policy should store the default, got %q", got[svc.ID])
	}
	if _, ok := env.h.registry.CSPService(svc.ID); !ok {
		t.Error("registry not reloaded")
	}

	for _, bad := range []string{"script-src 'self'; report-uri https://evil.example", "script-src 'self' \u00e9", strings.Repeat("a", 4097)} {
		rec = env.do("POST", path, form("csp_mode", "report", "csp_policy", bad))
		if rec.Header().Get("HX-Retarget") != "#svc-csp-error" {
			t.Errorf("%.40q: want inline error, got %s", bad, rec.Body)
		}
	}

	// Enforce (issue #283): only this service's inventory can be approved.
	if _, err := env.db.AddCSPScript(svc.ID, storage.CSPScript{Origin: "https://cdn.example", Page: "/", FirstSeen: time.Now()}); err != nil {
		t.Fatal(err)
	}
	rec = env.do("POST", path, url.Values{"csp_mode": {"enforce"}, "csp_policy": {""}, "csp_approved": {"https://cdn.example", "https://evil.example"}})
	wantCode(t, "enforce", rec.Code, 200, rec.Body.String())
	if !strings.Contains(rec.Body.String(), `data-csp-enforce="1" data-csp-recent="1"`) {
		t.Errorf("row data lacks enforce/recent: %s", rec.Body)
	}
	if got, _ := env.db.ListCSPEnforcement(); !got[svc.ID].Enforce || !slices.Equal(got[svc.ID].Approved, []string{"https://cdn.example"}) {
		t.Errorf("enforcement = %+v", got[svc.ID])
	}
	env.do("POST", path, url.Values{"csp_mode": {"report"}, "csp_approved": {"https://cdn.example"}})
	if got, _ := env.db.ListCSPEnforcement(); got[svc.ID].Enforce || len(got[svc.ID].Approved) != 1 {
		t.Errorf("report-only should keep approvals and stop enforcing: %+v", got[svc.ID])
	}

	env.do("POST", path, form("csp_mode", "off"))
	if got, _ := env.db.ListServiceCSP(); len(got) != 0 {
		t.Errorf("off should remove the policy: %+v", got)
	}
	if got, _ := env.db.ListCSPEnforcement(); len(got[svc.ID].Approved) != 1 {
		t.Errorf("off should keep approvals: %+v", got[svc.ID])
	}
}

func TestSetServiceMTLS(t *testing.T) {
	t.Chdir(t.TempDir()) // the CA bundle is written relative to the working directory
	env := newAdminEnv(t)
	svc := env.seedService("api", "api.example.com")
	path := "/admin/services/mtls/" + itoa(svc.ID)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	leafPEM, _ := testCertPEM(t, "client")

	rec := env.do("POST", path, form("mtls_mode", "required"))
	if rec.Header().Get("HX-Retarget") != "#svc-mtls-error" || !strings.Contains(rec.Body.String(), "CA certificate") {
		t.Fatalf("required without a CA: want inline error, got %s", rec.Body)
	}
	rec = env.do("POST", path, form("mtls_mode", "required", "mtls_ca", leafPEM))
	if !strings.Contains(rec.Body.String(), "not a CA certificate") {
		t.Fatalf("leaf as CA: want inline error, got %s", rec.Body)
	}

	rec = env.do("POST", path, form("mtls_mode", "required", "mtls_ca", caPEM, "mtls_allow", " svc-a \n\n svc-b "))
	wantCode(t, "save", rec.Code, 200, rec.Body.String())
	if rec.Header().Get("HX-Trigger") != "mtls-saved" || !strings.Contains(rec.Body.String(), "mTLS: required") {
		t.Fatalf("save: no trigger or badge: %s", rec.Body)
	}
	got, _ := env.db.ListServiceMTLS()
	if m := got[svc.ID]; m.Mode != "required" || m.Allow != "svc-a\nsvc-b" || m.CAPath == "" {
		t.Fatalf("stored %+v", m)
	}
	if env.h.registry.ClientCAs("api.example.com") == nil {
		t.Error("registry not reloaded")
	}

	// Off keeps the CA, and an empty CA field keeps it on the way back.
	env.do("POST", path, form("mtls_mode", "off"))
	if env.h.registry.ClientCAs("api.example.com") != nil {
		t.Error("off still requests client certs")
	}
	env.do("POST", path, form("mtls_mode", "optional"))
	if got, _ = env.db.ListServiceMTLS(); got[svc.ID].Mode != "optional" || got[svc.ID].CAPath == "" {
		t.Fatalf("re-enable without a CA: %+v", got[svc.ID])
	}

	env.do("DELETE", "/admin/services/"+itoa(svc.ID), nil)
	if got, _ = env.db.ListServiceMTLS(); len(got) != 0 {
		t.Errorf("policy outlived its service: %+v", got)
	}
}

func TestSetServiceResponseInspect(t *testing.T) {
	env := newAdminEnv(t)
	svc := env.seedService("api", "api.example.com")
	path := "/admin/services/responses/" + itoa(svc.ID)

	rec := env.do("POST", path, form("response_inspect", "block"))
	wantCode(t, "save", rec.Code, 200, rec.Body.String())
	if rec.Header().Get("HX-Trigger") != "responses-saved" || !strings.Contains(rec.Body.String(), "Responses: block") {
		t.Fatalf("save: no trigger or badge: %s", rec.Body)
	}
	if s, _ := env.db.GetService(svc.ID); s.ResponseInspect != "block" {
		t.Fatalf("stored %q", s.ResponseInspect)
	}
	rec = env.do("POST", path, form("response_inspect", "sometimes"))
	if rec.Header().Get("HX-Retarget") != "#svc-responses-error" {
		t.Fatalf("unknown mode: want inline error, got %s", rec.Body)
	}
	env.do("POST", path, form("response_inspect", ""))
	if s, _ := env.db.GetService(svc.ID); s.ResponseInspect != "" {
		t.Fatalf("off: stored %q", s.ResponseInspect)
	}
}

func TestSetServiceGate(t *testing.T) {
	env := newAdminEnv(t)
	svc := env.seedService("shop", "shop.example.com")
	path := "/admin/services/gate/" + itoa(svc.ID)
	gate := func() storage.ServiceGate {
		gates, err := env.db.ListServiceGates()
		if err != nil {
			t.Fatal(err)
		}
		return gates[svc.ID]
	}

	for _, bad := range [][]string{
		{"waiting_room", "1", "wr_max", "0", "wr_idle", "10"},
		{"waiting_room", "1", "wr_max", "10", "wr_idle", "0"},
		{"maintenance", "1", "maint_start", "2026-10-28T10:00", "maint_end", "2026-10-28T09:00"},
		{"maintenance", "1", "maint_end", "tomorrow"},
	} {
		if rec := env.do("POST", path, form(bad...)); rec.Header().Get("HX-Retarget") != "#svc-gate-error" {
			t.Errorf("%v: want inline error, got %s", bad, rec.Body)
		}
	}

	rec := env.do("POST", path, form("maintenance", "1", "maint_message", "Back soon", "maint_end", "2030-01-02T03:04",
		"waiting_room", "1", "wr_max", "500", "wr_idle", "15", "wr_crawlers", "deny"))
	wantCode(t, "save", rec.Code, 200, rec.Body.String())
	if rec.Header().Get("HX-Trigger") != "gate-saved" || !strings.Contains(rec.Body.String(), "Waiting room: 500") {
		t.Fatalf("save: no trigger or badge: %s", rec.Body)
	}
	g := gate()
	if !g.Maintenance || g.MaintMsg != "Back soon" || g.MaintEnd.Format("2006-01-02T15:04") != "2030-01-02T03:04" ||
		len(g.BypassToken) != 32 || g.MaxActive != 500 || g.IdleSecs != 900 || g.Crawlers != "deny" {
		t.Fatalf("stored %+v", g)
	}
	// The registry carries it to the proxy without a restart.
	if s := env.h.registry.Match("shop.example.com", "/"); s == nil || !s.Gate.Maintenance {
		t.Error("registry not reloaded")
	}

	// Saving again keeps the bypass token unless asked to replace it.
	token := g.BypassToken
	env.do("POST", path, form("maintenance", "1"))
	if gate().BypassToken != token {
		t.Error("bypass token changed on a plain save")
	}
	env.do("POST", path, form("maintenance", "1", "new_bypass", "1"))
	if gate().BypassToken == token {
		t.Error("new_bypass kept the old token")
	}

	env.do("POST", path, form())
	if g := gate(); g.Maintenance || g.WaitingRoom {
		t.Errorf("turning both off left %+v", g)
	}
}

func TestSetServiceCookies(t *testing.T) {
	env := newAdminEnv(t)
	svc := env.seedService("shop", "shop.example.com")
	path := "/admin/services/cookies/" + itoa(svc.ID)

	rec := env.do("POST", path, form("cookie_mode", "on", "cookie_exempt", "csrftoken, theme"))
	wantCode(t, "save", rec.Code, 200, rec.Body.String())
	if rec.Header().Get("HX-Trigger") != "cookies-saved" || !strings.Contains(rec.Body.String(), `data-cookie-exempt="csrftoken theme"`) {
		t.Fatalf("no cookies-saved trigger or row data: %s", rec.Body)
	}
	if got, _ := env.db.ListServiceCookiePolicies(); !slices.Equal(got[svc.ID], []string{"csrftoken", "theme"}) {
		t.Errorf("exempt = %q", got[svc.ID])
	}

	for _, bad := range []string{"a;b", "sid=x", "café"} {
		rec = env.do("POST", path, form("cookie_mode", "on", "cookie_exempt", bad))
		if rec.Header().Get("HX-Retarget") != "#svc-cookies-error" {
			t.Errorf("%q: want inline error, got %s", bad, rec.Body)
		}
	}

	env.do("POST", path, form("cookie_mode", "off"))
	if got, _ := env.db.ListServiceCookiePolicies(); len(got) != 0 {
		t.Errorf("off should remove the policy: %+v", got)
	}
}

func TestSetServiceRequestPolicy(t *testing.T) {
	env := newAdminEnv(t)
	svc := env.seedService("shop", "shop.example.com")
	path := "/admin/services/policy/" + itoa(svc.ID)

	rec := env.do("POST", path, form("policy_mode", "enforce", "policy_methods", "get, post", "policy_types", "Application/JSON image/*", "policy_max_kib", "1024"))
	wantCode(t, "save", rec.Code, 200, rec.Body.String())
	if rec.Header().Get("HX-Trigger") != "policy-saved" || !strings.Contains(rec.Body.String(), `data-policy-methods="GET POST"`) {
		t.Fatalf("no policy-saved trigger or row data: %s", rec.Body)
	}
	got, _ := env.db.ListServiceRequestPolicies()
	if p := got[svc.ID]; p.Mode != "enforce" || !slices.Equal(p.ContentTypes, []string{"application/json", "image/*"}) || p.MaxBodyKiB != 1024 {
		t.Errorf("stored %+v", p)
	}
	if app := env.h.registry.Match("shop.example.com", "/"); app == nil || app.Policy.Mode != "enforce" {
		t.Error("registry not reloaded")
	}

	for _, bad := range [][]string{
		{"policy_mode", "enforce"},
		{"policy_mode", "enforce", "policy_methods", "GET;"},
		{"policy_mode", "enforce", "policy_types", "json"},
		{"policy_mode", "enforce", "policy_max_kib", "-1"},
		{"policy_mode", "block", "policy_methods", "GET"},
	} {
		rec = env.do("POST", path, form(bad...))
		if rec.Header().Get("HX-Retarget") != "#svc-policy-error" {
			t.Errorf("%q: want inline error, got %s", bad, rec.Body)
		}
	}

	env.do("POST", path, form("policy_mode", "off"))
	if got, _ := env.db.ListServiceRequestPolicies(); len(got) != 0 {
		t.Errorf("off should remove the policy: %+v", got)
	}
}
