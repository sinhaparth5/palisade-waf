package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"palisade/internal/storage"
)

// TestBaseTemplateCarriesCSRF renders a full page and checks the CSRF token
// lands where the clients pick it up: hx-headers on <body> (HTMX requests),
// data-csrf (fetch calls in clipboard.js/notify.js), and the logout form's hidden input.
func TestBaseTemplateCarriesCSRF(t *testing.T) {
	h := &Handler{}
	if err := h.parseTemplates(); err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	token := csrfToken("some-session")
	data := map[string]any{
		"Page":       "settings",
		"Heading":    "Settings",
		"AdminPath":  "/admin",
		"AlertCount": 0,
		"CSRF":       token,
		// Minimal card data mirroring SettingsPage's defaults.
		"AdminEmail":     "admin@example.com",
		"BotEnabled":     false,
		"BotThreshold":   5,
		"BotTTL":         3600,
		"WebhookURL":     "",
		"WebhookSecret":  "",
		"WebhookEnabled": false,
		"WebhookEvents":  "",
		"EmailEnabled":   false,
		"EmailSender":    "alert@example.com",
		"EmailTo":        "",
		"EmailTokenSet":  false,
		"Role":           "owner",
	}

	var buf bytes.Buffer
	if err := h.tmpls["settings"].ExecuteTemplate(&buf, "base", data); err != nil {
		t.Fatalf("execute settings template: %v", err)
	}
	page := buf.String()

	// The JSON quotes are template literals (not interpolated), so
	// html/template leaves them intact inside the single-quoted attribute
	// and HTMX can JSON-parse the value directly.
	wantHeaders := `hx-headers='{"X-CSRF-Token":"` + token + `"}'`
	for _, want := range []string{
		wantHeaders,
		`data-csrf="` + token + `"`,
		`name="_csrf" value="` + token + `"`,
		`action="/admin/settings/backup" method="POST"`, // backup must not be a GET link
	} {
		if !strings.Contains(page, want) {
			t.Errorf("rendered page missing %q", want)
		}
	}
	if strings.Contains(page, `href="/admin/settings/backup"`) {
		t.Error("backup is still reachable as a GET link")
	}
}

// TestHourlySeries checks sparse hourly points land in the right zero-filled
// slot, newest hour last.
func TestHourlySeries(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Hour)
	labels, allowed, blocked := hourlySeries([]storage.HourlyPoint{
		{Hour: now, Total: 5, Blocked: 2},
		{Hour: now.Add(-3 * time.Hour), Total: 1},
	}, 24)
	if len(labels) != 24 || len(allowed) != 24 || len(blocked) != 24 {
		t.Fatalf("got %d/%d/%d buckets, want 24", len(labels), len(allowed), len(blocked))
	}
	if allowed[23] != 3 || blocked[23] != 2 || allowed[20] != 1 || allowed[22] != 0 {
		t.Errorf("allowed=%v blocked=%v", allowed, blocked)
	}
}
