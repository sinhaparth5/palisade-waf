package ui

import (
	"bytes"
	"database/sql"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"palisade/internal/storage"
)

// TestReadsNeverHideStorageFailure: each read the app makes, with one table
// at a time gone, fails (a 5xx, or a 401 when sign-in reads that table) or
// answers exactly what it answers with every table there. A 2xx with other
// data would be an empty list or a missing setting shown as real.
func TestReadsNeverHideStorageFailure(t *testing.T) {
	env := newAdminEnv(t)
	svc := env.seedService("shop", "shop.example.com")
	db := env.db
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(db.AddIPRule("", "203.0.113.9", "block"))
	must(db.AddGeoRule("", "RU", "block"))
	must(db.SetTrustedIPs([]string{"198.51.100.1"}))
	must(db.AddThreatIntelSource("Feed", "https://example.com/list.txt", 24))
	must(db.AddCrowdSecSource("CrowdSec", "http://127.0.0.1:8080", "key", "machine", "pw"))
	_, err := db.AddCertificate("shop", "shop.example.com", "2030-01-01T00:00:00Z", "c.pem", "k.pem")
	must(err)
	_, err = db.CreateAPIKey("ci", "cwaf_abc", "hash", true)
	must(err)
	must(db.CreateSSOInvite("sso@example.com", "viewer"))
	must(db.AddWebAuthnCredential(1, "cred", "laptop", []byte("{}")))
	for _, w := range []struct {
		path string
		body any
	}{
		{"/admin/api/waf-rules/exceptions", map[string]any{"rule_id": 942100, "service": "shop", "reason": "noisy"}},
		{"/admin/api/waf-rules/exceptions", map[string]any{"rule_id": 942200, "service": "", "reason": "noisy"}},
		{"/admin/api/waf-rules/custom", map[string]any{"rule": `SecRule ARGS "@contains x" "id:1000001,phase:2,deny"`}},
		{"/admin/api/settings/users", map[string]any{"email": "new@example.com", "role": "viewer"}},
	} {
		if rec := env.doJSON(env.session, http.MethodPost, w.path, w.body, nil); rec.Code >= 300 {
			t.Fatalf("seed %s = %d %s", w.path, rec.Code, rec.Body)
		}
	}
	env.seedLog(storage.RequestLog{AppName: svc.Name, RealIP: "203.0.113.9", Country: "RU", Status: 403, Blocked: true, Action: "deny", Method: "GET", Path: "/"})

	raw, err := sql.Open("sqlite", env.dbPath)
	must(err)
	defer raw.Close()
	tables, err := tableNames(raw, "1")
	must(err)

	reads := []string{
		"/admin/api/settings/account", "/admin/api/settings/protection", "/admin/api/settings/team",
		"/admin/api/settings/alerts", "/admin/api/settings/audit?page=1", "/admin/api/certificates",
		"/admin/api/threat-intel", "/admin/api/ip-rules", "/admin/api/ip-rules/settings", "/admin/api/geo-rules",
		"/admin/api/waf-rules", "/admin/api/services", "/admin/api/logs", "/admin/api/logs/apps",
		"/admin/api/notifications", "/admin/search?q=shop",
	}
	get := func(p string) (int, []byte) {
		rec := env.doJSON(env.session, http.MethodGet, p, nil, nil)
		return rec.Code, rec.Body.Bytes()
	}
	for _, tbl := range tables {
		must(exec(raw, `ALTER TABLE "`+tbl+`" RENAME TO "gone_`+tbl+`"`))
		broken := make(map[string][]byte, len(reads))
		codes := make(map[string]int, len(reads))
		for _, p := range reads {
			codes[p], broken[p] = get(p)
		}
		must(exec(raw, `ALTER TABLE "gone_`+tbl+`" RENAME TO "`+tbl+`"`))
		for _, p := range reads {
			if codes[p] >= 300 {
				continue
			}
			code, want := get(p)
			if code != http.StatusOK {
				t.Fatalf("GET %s healthy = %d %s", p, code, want)
			}
			if !bytes.Equal(broken[p], want) {
				t.Errorf("without %s: GET %s = %d %.300s\nwant a failure or the healthy %.300s", tbl, p, codes[p], broken[p], want)
			}
		}
	}
}

func exec(raw *sql.DB, q string) error {
	_, err := raw.Exec(q)
	return err
}

// TestWritesRefuseBrokenJSON: every app write that reads a JSON body answers
// a body that isn't JSON with a 400 the form can show, never a 5xx or a save.
func TestWritesRefuseBrokenJSON(t *testing.T) {
	env := newAdminEnv(t)
	env.seedService("shop", "shop.example.com")
	// No body to read, or state is checked first: they act on the path alone.
	noBody := regexp.MustCompile(`/(sync|purge|test|logout|begin|start|disable|sign-out-others|seen|backup|config-export|invite|reset-2fa|renew|finish)$|^DELETE `)
	params := strings.NewReplacer(":id", "1", ":token", "x")
	checked := 0
	for _, r := range env.e.Router().Routes() {
		key := r.Method + " " + r.Path
		if (r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch && r.Method != http.MethodDelete) ||
			!strings.HasPrefix(r.Path, "/admin/api/") || strings.HasPrefix(r.Path, "/admin/api/v1") || noBody.MatchString(key) {
			continue
		}
		checked++
		var got jsonError
		rec := env.doJSON(env.session, r.Method, params.Replace(r.Path), []byte("{"), &got)
		if rec.Code != http.StatusBadRequest || got.Message == "" {
			t.Errorf("%s with a broken body = %d %s", key, rec.Code, rec.Body)
		}
	}
	if checked < 40 {
		t.Fatalf("checked %d writes; did the routes move?", checked)
	}
}
