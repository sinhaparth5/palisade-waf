package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"palisade/internal/storage"
)

func TestDashboardTemplateRenders(t *testing.T) {
	h := &Handler{}
	if err := h.parseTemplates(); err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	data := map[string]any{
		"Page":         "dashboard",
		"Heading":      "Dashboard",
		"AdminPath":    "/admin",
		"AlertCount":   0,
		"Stats":        storage.Stats{TotalToday: 40, BlockedToday: 10},
		"Recent":       []storage.LogRow{},
		"TopBlocked":   []storage.LogRow{},
		"TopCountries": []dashboardCountry{},
		"AtAGlance":    dashboardAtAGlance(storage.AtAGlanceStats{RequestsLastMinute: 12}),
		"Enforcement":  dashboardEnforcement(storage.DailyReport{WAFBlocked: 3, BotChallenged: 9}),
		"BlockRate":    25,
		"SparkTotal":   sparkBars([]int{0, 4, 8}),
		"SparkBlocked": sparkBars([]int{0, 1, 2}),
		"Apps":         []any{"app-a", "app-b"},
		"Services":     []dashboardService{{Name: "shop", Route: "shop.example.com", Healthy: true, Known: true}},
		"Changes":      []storage.AuditEntry{{Actor: "admin", Action: "POST /services"}},
		"BotStats":     storage.BotStats{},
	}

	var buf bytes.Buffer
	if err := h.tmpls["dashboard"].ExecuteTemplate(&buf, "base", data); err != nil {
		t.Fatalf("execute dashboard template: %v", err)
	}
	for _, want := range []string{
		"Requests/sec", "Enforcement today", "shop.example.com", "POST /services",
		`stroke-dasharray="25 100"`,   // block rate ring
		`y="0" width="3" height="32"`, // busiest hour fills the sparkline
	} {
		if !bytes.Contains(buf.Bytes(), []byte(want)) {
			t.Errorf("dashboard missing %q", want)
		}
	}
}

// TestMeterSegments pins the meter math: ceil(count/max*12) filled cells,
// zero leaving the meter empty.
func TestMeterSegments(t *testing.T) {
	cases := []struct{ count, max, want int }{
		{0, 0, 0},
		{0, 10, 0},
		{1, 12, 1},
		{6, 12, 6},
		{7, 12, 7},
		{12, 12, 12},
		{1, 1000, 1}, // tiny but nonzero still shows one cell
	}
	for _, tc := range cases {
		got := 0
		for _, on := range meterSegments(tc.count, tc.max) {
			if on {
				got++
			}
		}
		if got != tc.want {
			t.Errorf("meterSegments(%d, %d) fills %d, want %d", tc.count, tc.max, got, tc.want)
		}
	}
}

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
