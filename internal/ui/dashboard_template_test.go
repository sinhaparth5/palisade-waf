package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"palisade/internal/storage"
)

// TestProPageCarriesCSRF checks the add-on cards page hands htmx the CSRF
// token: hx-headers on <body>, JSON quotes intact so htmx can parse them.
func TestProPageCarriesCSRF(t *testing.T) {
	h := &Handler{}
	if err := h.parseTemplates(); err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	token := csrfToken("some-session")
	var buf bytes.Buffer
	if err := h.pro.Execute(&buf, map[string]any{"AdminPath": "/admin", "CSRF": token}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`hx-headers='{"X-CSRF-Token":"` + token + `"}'`, `data-csrf="` + token + `"`, "Nothing here for your role"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("rendered page missing %q", want)
		}
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
