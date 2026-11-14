package app

import (
	"path/filepath"
	"testing"

	"palisade/internal/storage"
)

func TestEnsureDemoUser(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const email = "demo@example.com"
	for _, pw := range []string{"first-pass", "first-pass", "second-pass"} { // create, no-op, reset
		if err := ensureDemoUser(db, email, pw); err != nil {
			t.Fatalf("ensureDemoUser(%q): %v", pw, err)
		}
		u, _ := db.CheckAdminLogin(email, pw)
		if u == nil || u.Role != storage.RoleViewer {
			t.Fatalf("after ensureDemoUser(%q): login = %+v, want a viewer", pw, u)
		}
	}
	if _, err := db.CreateAdminUser("owner@example.com", "owner-pass", storage.RoleOwner); err != nil {
		t.Fatal(err)
	}
	if err := ensureDemoUser(db, "owner@example.com", "x"); err == nil {
		t.Error("ensureDemoUser turned an owner into the demo account")
	}
	if u, _ := db.CheckAdminLogin("owner@example.com", "owner-pass"); u == nil {
		t.Error("owner password changed")
	}
}
