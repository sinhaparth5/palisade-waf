package ui

import (
	"net/http"
	"strings"
	"testing"

	"palisade/internal/storage"
)

func TestAuditLog(t *testing.T) {
	env := newAdminEnv(t)
	audit := func() []storage.AuditEntry {
		t.Helper()
		got, _, err := env.db.ListAudit(50, 0)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	// A successful change is recorded with its allowlisted fields.
	if rec := env.do(http.MethodPost, "/admin/ip-rules", form("ip", "203.0.113.5", "rule_type", "block")); rec.Code != http.StatusOK {
		t.Fatalf("add ip rule: %d", rec.Code)
	}
	got := audit()
	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %+v", got)
	}
	if e := got[0]; e.Actor != testAdminEmail || e.Action != "POST /ip-rules" || e.Summary != "ip=203.0.113.5 rule_type=block" || e.IP == "" {
		t.Fatalf("entry = %+v", e)
	}

	// Route params land in Target.
	rules, _ := env.db.ListIPRules()
	env.do(http.MethodDelete, "/admin/ip-rules/"+itoa(rules[0].ID), nil)
	if e := audit()[0]; e.Action != "DELETE /ip-rules/:id" || e.Target != "id="+itoa(rules[0].ID) {
		t.Fatalf("delete entry = %+v", e)
	}

	// Rejected requests aren't changes: a 4xx, a 200 with an inline *Err
	// message, and skipped routes all leave the log alone.
	before := len(audit())
	env.do(http.MethodPost, "/admin/ip-rules", form("ip", "nope", "rule_type", "block"))
	env.do(http.MethodPost, "/admin/settings/api-keys", form("name", ""))
	env.do(http.MethodPost, "/admin/settings/credentials", form("current_password", "wrong", "new_password", "hunter22hunter22", "confirm_password", "hunter22hunter22"))
	env.do(http.MethodPost, "/admin/api/notifications/seen", nil)
	if n := len(audit()); n != before {
		t.Fatalf("rejected/skipped requests were logged: %+v", audit()[:n-before])
	}

	// Secret-bearing fields never reach the log, even on success.
	env.do(http.MethodPost, "/admin/settings/webhook", form("webhook_url", "https://hooks.example/T0/secret-path", "webhook_secret", "s3cr3t", "webhook_enabled", "on"))
	for _, e := range audit() {
		if strings.Contains(e.Summary+e.Target, "secret") || strings.Contains(e.Summary, "s3cr3t") {
			t.Fatalf("secret leaked into audit entry %+v", e)
		}
	}

	// API writes record the key, not the admin, and read JSON bodies.
	key := createTestKey(t, env.h, false)
	req := newReq(env, http.MethodPost, "/admin/api/v1/ip-rules", `{"ip":"198.51.100.7","rule_type":"allow"}`)
	req.Header.Set("Authorization", "Bearer "+key)
	if rec := serve(env, req); rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("api create: %d %s", rec.Code, rec.Body)
	}
	e := audit()[0]
	if !strings.HasPrefix(e.Actor, "api key test (") || e.Action != "POST /api/v1/ip-rules" || e.Summary != "ip=198.51.100.7 rule_type=allow" {
		t.Fatalf("api entry = %+v", e)
	}

	// The Settings card shows the trail.
	if body := env.do(http.MethodGet, "/admin/settings", nil).Body.String(); !strings.Contains(body, "POST /api/v1/ip-rules") {
		t.Fatal("settings page does not list audit entries")
	}
}

func TestAuditValue(t *testing.T) {
	for in, want := range map[string]string{
		"plain":                      "plain",
		"two words":                  `"two words"`,
		"a\nb":                       `"a\nb"`,
		strings.Repeat("x", 130):     strings.Repeat("x", auditValueMax) + "…",
		strings.Repeat("é", 100)[1:]: strings.ToValidUTF8(strings.Repeat("é", 100)[1:][:auditValueMax], "") + "…",
	} {
		if got := auditValue(in); got != want {
			t.Errorf("auditValue(%.20q) = %.30q, want %.30q", in, got, want)
		}
	}
}

func TestAuditRowsPagination(t *testing.T) {
	env := newAdminEnv(t)
	for range 25 {
		if err := env.db.InsertAudit(storage.AuditEntry{Actor: "admin", Action: "POST /ip-rules"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		path      string
		wantLabel string
		wantRows  int
	}{
		{"/admin/settings", "Page 1 of 3 · 25 entries", auditPageSize},
		{"/admin/settings/audit?page=2", "Page 2 of 3 · 25 entries", auditPageSize},
		{"/admin/settings/audit?page=3", "Page 3 of 3 · 25 entries", 5},
		{"/admin/settings/audit?page=99", "Page 3 of 3 · 25 entries", 5},
		{"/admin/settings/audit?page=junk", "Page 1 of 3 · 25 entries", auditPageSize},
	} {
		rec := env.do(http.MethodGet, tc.path, nil)
		body := rec.Body.String()
		if rec.Code != http.StatusOK || !strings.Contains(body, tc.wantLabel) {
			t.Errorf("%s: status %d, missing %q", tc.path, rec.Code, tc.wantLabel)
		}
		if n := strings.Count(body, "POST /ip-rules</span>"); n != tc.wantRows {
			t.Errorf("%s: %d rows, want %d", tc.path, n, tc.wantRows)
		}
	}
}
