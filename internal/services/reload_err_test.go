package services

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	"palisade/internal/storage"
)

// TestReloadKeepsRoutingOnError: a Reload that fails on any table it reads
// returns the error and leaves the previous routing in place, so a DB hiccup
// never turns into "no services" (every request falling through to VPS).
func TestReloadKeepsRoutingOnError(t *testing.T) {
	for _, table := range []string{
		"services", "meta", "service_mtls", "service_jwt", "service_rate_rules", "service_gate",
		"service_request_policy", "service_csp", "csp_approved", "service_csp_enforce", "service_cookie_policy",
	} {
		t.Run(table, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "test.db")
			db, err := storage.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err := db.AddService("app", "app.example.com", "", "http://127.0.0.1:9", 0, 0); err != nil {
				t.Fatal(err)
			}
			r, err := New(db)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			if _, err := raw.Exec(`DROP TABLE "` + table + `"`); err != nil {
				t.Fatal(err)
			}
			if err := r.Reload(db); err == nil {
				t.Fatal("Reload succeeded with a table missing")
			}
			if r.Match("app.example.com", "/") == nil {
				t.Fatal("failed Reload dropped the existing routing")
			}
		})
	}
}

func TestValidateBackendsRejects(t *testing.T) {
	many := make([]string, maxBackends+1)
	for i := range many {
		many[i] = fmt.Sprintf("http://10.0.0.%d", i+1)
	}
	for name, tc := range map[string]struct {
		backends []string
		path     string
		interval int
	}{
		"none":         {nil, "", 0},
		"too many":     {many, "", 0},
		"duplicate":    {[]string{"http://10.0.0.1", "http://10.0.0.1"}, "", 0},
		"metadata":     {[]string{"http://169.254.169.254"}, "", 0},
		"mixed paths":  {[]string{"http://10.0.0.1/a", "http://10.0.0.2/b"}, "", 0},
		"health path":  {[]string{"http://10.0.0.1"}, "up", 0},
		"interval":     {[]string{"http://10.0.0.1"}, "/up", 3601},
		"neg interval": {[]string{"http://10.0.0.1"}, "/up", -1},
	} {
		if err := ValidateBackends(tc.backends, tc.path, tc.interval); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := ValidateBackends([]string{"http://10.0.0.1/a/", "http://10.0.0.2/a"}, "/up", 30); err != nil {
		t.Errorf("valid list: %v", err)
	}
}
