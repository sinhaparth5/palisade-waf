package ui

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"palisade/internal/storage"
)

// TestAlertSettings: webhook and email save with field errors, the email
// token stays write-only, and the test sends answer why they failed.
func TestAlertSettings(t *testing.T) {
	env := newAdminEnv(t)
	const base = "/admin/api/settings/"

	for _, tc := range []struct {
		path  string
		body  any
		field string
	}{
		{"webhook", webhookView{URL: "ftp://x"}, "url"},
		{"webhook", webhookView{URL: "https://hooks.example.com/x", Events: []string{"everything"}}, "events"},
		{"email", emailView{Enabled: true, Token: "t"}, "to"},
		{"email", emailView{Enabled: true, To: "ops@example.com"}, "token"},
	} {
		var got jsonError
		if rec := env.doJSON(env.session, http.MethodPut, base+tc.path, tc.body, &got); rec.Code != http.StatusBadRequest || got.Fields[tc.field] == "" {
			t.Errorf("%s %+v: %d %s, want a %s error", tc.path, tc.body, rec.Code, rec.Body, tc.field)
		}
	}
	for _, tc := range []struct {
		path string
		body any
	}{
		{"webhook", webhookView{Enabled: true, URL: "https://hooks.example.com/x", Secret: "s", Events: []string{"blocked", "scripts"}, DestinationType: "slack"}},
		{"email", emailView{Enabled: true, To: "ops@example.com", Token: "tok3n"}},
		{"email", emailView{Enabled: true, To: "a@example.com"}}, // blank token kept
	} {
		if rec := env.doJSON(env.session, http.MethodPut, base+tc.path, tc.body, nil); rec.Code != http.StatusNoContent {
			t.Fatalf("%s: %d %s", tc.path, rec.Code, rec.Body)
		}
	}
	var got struct {
		Webhook webhookView `json:"webhook"`
		Email   emailView   `json:"email"`
	}
	rec := env.doJSON(env.session, http.MethodGet, base+"alerts", nil, &got)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "tok3n") {
		t.Fatalf("read: %d %s", rec.Code, rec.Body)
	}
	if w := got.Webhook; !w.Enabled || w.Secret != "s" || strings.Join(w.Events, ",") != "blocked,scripts" || w.DestinationType != "slack" {
		t.Errorf("webhook = %+v", w)
	}
	if e := got.Email; !e.Enabled || e.To != "a@example.com" || !e.TokenSet || e.Sender == "" {
		t.Errorf("email = %+v", e)
	}

	for _, p := range []string{"webhook/test", "email/test"} {
		if rec := env.doJSON(env.session, http.MethodPost, base+p, map[string]any{}, nil); rec.Code != http.StatusNoContent {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
	env.h.sendTestWebhook = func() error { return errors.New("connection refused") }
	var failed jsonError
	if rec := env.doJSON(env.session, http.MethodPost, base+"webhook/test", map[string]any{}, &failed); rec.Code != http.StatusBadGateway || !strings.Contains(failed.Message, "connection refused") {
		t.Errorf("failed test: %d %s", rec.Code, rec.Body)
	}
	env.h.sendReportNow = nil
	if rec := env.doJSON(env.session, http.MethodPost, base+"email/test", map[string]any{}, nil); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("no mailer: %d", rec.Code)
	}

	admin := env.sessionAs(storage.RoleAdmin)
	if rec := env.doJSON(admin, http.MethodGet, base+"alerts", nil, nil); rec.Code != http.StatusForbidden {
		t.Errorf("admin reads alerts: %d", rec.Code)
	}
}

// TestAuditJSON: pages of the audit log, clamped, newest first.
func TestAuditJSON(t *testing.T) {
	env := newAdminEnv(t)
	for i := range auditPageSize + 2 {
		if err := env.db.InsertAudit(storage.AuditEntry{Actor: "a@example.com", IP: "192.0.2.1", Action: "PUT /api/settings/bot", Summary: "threshold=" + itoa(i)}); err != nil {
			t.Fatal(err)
		}
	}
	type page struct {
		Entries []auditJSON `json:"entries"`
		Page    int         `json:"page"`
		Pages   int         `json:"pages"`
		Total   int         `json:"total"`
	}
	viewer := env.sessionAs(storage.RoleViewer)
	for _, tc := range []struct {
		q          string
		page, rows int
	}{{"", 1, auditPageSize}, {"?page=2", 2, 2}, {"?page=99", 2, 2}, {"?page=junk", 1, auditPageSize}} {
		var p page
		if rec := env.doJSON(viewer, http.MethodGet, "/admin/api/settings/audit"+tc.q, nil, &p); rec.Code != http.StatusOK {
			t.Fatalf("%q: %d", tc.q, rec.Code)
		}
		if p.Page != tc.page || len(p.Entries) != tc.rows || p.Pages != 2 || p.Total < auditPageSize+2 || p.Entries[0].TS == "" {
			t.Errorf("%q: page %d of %d, %d rows, total %d", tc.q, p.Page, p.Pages, len(p.Entries), p.Total)
		}
	}
}
