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
	if rec := env.doJSON(env.session, http.MethodPost, "/admin/api/ip-rules", map[string]string{"ip": "203.0.113.5", "rule_type": "block"}, nil); rec.Code != http.StatusCreated {
		t.Fatalf("add ip rule: %d", rec.Code)
	}
	got := audit()
	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %+v", got)
	}
	if e := got[0]; e.Actor != testAdminEmail || e.Action != "POST /api/ip-rules" || e.Summary != "ip=203.0.113.5 rule_type=block" || e.IP == "" {
		t.Fatalf("entry = %+v", e)
	}

	// Route params land in Target.
	rules, _ := env.db.ListIPRules()
	env.doJSON(env.session, http.MethodPost, "/admin/api/ip-rules/remove", map[string][]int{"ids": {rules[0].ID}}, nil)
	if e := audit()[0]; e.Action != "POST /api/ip-rules/remove" || e.Summary != "ids=["+itoa(rules[0].ID)+"]" {
		t.Fatalf("remove entry = %+v", e)
	}

	// Rejected requests aren't changes: a 4xx, a 200 with an inline *Err
	// message, and skipped routes all leave the log alone.
	before := len(audit())
	env.doJSON(env.session, http.MethodPost, "/admin/api/ip-rules", map[string]string{"ip": "nope", "rule_type": "block"}, nil)
	env.doJSON(env.session, http.MethodPost, "/admin/api/settings/api-keys", map[string]string{"name": ""}, nil)
	env.doJSON(env.session, http.MethodPut, "/admin/api/settings/credentials", map[string]string{"current_password": "wrong", "new_password": "hunter22hunter22", "confirm_password": "hunter22hunter22"}, nil)
	env.do(http.MethodPost, "/admin/api/notifications/seen", nil)
	if n := len(audit()); n != before {
		t.Fatalf("rejected/skipped requests were logged: %+v", audit()[:n-before])
	}

	// Secret-bearing fields never reach the log, even on success.
	if rec := env.doJSON(env.session, http.MethodPut, "/admin/api/settings/webhook", map[string]any{"url": "https://hooks.example/T0/secret-path", "secret": "s3cr3t", "enabled": true, "events": []string{"blocked"}}, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("webhook: %d %s", rec.Code, rec.Body)
	}
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
	if body := env.doJSON(env.session, http.MethodGet, "/admin/api/settings/audit", nil, nil).Body.String(); !strings.Contains(body, "POST /api/v1/ip-rules") {
		t.Fatal("the audit read does not list entries")
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
