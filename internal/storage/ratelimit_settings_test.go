package storage

import (
	"testing"
)

func TestRateLimitSettingsRoundtrip(t *testing.T) {
	db := openTestDB(t)

	// Unset: disabled with the documented defaults.
	enabled, rps, burst, err := db.GetRateLimitSettings()
	if err != nil {
		t.Fatal(err)
	}
	if enabled || rps != 10 || burst != 20 {
		t.Errorf("unset settings = %v/%g/%d, want disabled/10/20", enabled, rps, burst)
	}

	if err := db.SetRateLimitSettings(true, 2.5, 40); err != nil {
		t.Fatal(err)
	}
	enabled, rps, burst, _ = db.GetRateLimitSettings()
	if !enabled || rps != 2.5 || burst != 40 {
		t.Errorf("roundtrip = %v/%g/%d, want enabled/2.5/40", enabled, rps, burst)
	}

	// Non-positive stored values are ignored in favor of defaults.
	if err := db.SetRateLimitSettings(false, 0, 0); err != nil {
		t.Fatal(err)
	}
	enabled, rps, burst, _ = db.GetRateLimitSettings()
	if enabled || rps != 10 || burst != 20 {
		t.Errorf("zeroed settings = %v/%g/%d, want disabled/10/20", enabled, rps, burst)
	}
}

// TestMigrateDropsRedisSettings pins the upgrade path from a version that had
// Redis: its leftover settings are deleted on startup, rate limiting keeps
// working from memory, and services still load from the old redis_mode column.
func TestMigrateDropsRedisSettings(t *testing.T) {
	db := openTestDB(t)
	for k, v := range map[string]string{"redis_addr": "10.0.0.5:6379", "redis_password": "pw", "redis_ns_key": "ab", "ratelimit_backend": "redis"} {
		if err := db.setMeta(k, v); err != nil {
			t.Fatal(err)
		}
	}
	db.exec(db.dialect.addColumnIfNotExists("services", "redis_mode TEXT NOT NULL DEFAULT ''")) //nolint // pre-removal schema
	if err := db.AddService("app", "a.example.com", "", "http://127.0.0.1:9", 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := db.migrate(); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"redis_addr", "redis_password", "redis_ns_key", "ratelimit_backend"} {
		if v, _ := db.getMeta(k); v != "" {
			t.Errorf("%s = %q after migrate, want deleted", k, v)
		}
	}
	if svcs, err := db.ListServices(); err != nil || len(svcs) != 1 {
		t.Errorf("services after migrate = %v, %v", svcs, err)
	}
}
