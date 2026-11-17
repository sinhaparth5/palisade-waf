package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"palisade/internal/storage"
)

func TestBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "waf.db")
	backups := filepath.Join(dir, "backups")

	// No DB yet: --dir is a fresh install (no-op), --out is an error.
	if out, err := run([]string{"backup", "--db", path, "--dir", backups}, ""); err != nil || !strings.Contains(out, "nothing to back up") {
		t.Errorf("missing DB with --dir = %q, %v", out, err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("backup created the DB")
	}
	for _, args := range [][]string{
		{"--out", filepath.Join(dir, "x.db")},
		{},
		{"--out", "a", "--dir", "b"},
		{"--db-driver", "mysql", "--out", "a"},
	} {
		if _, err := run(append([]string{"backup", "--db", path}, args...), ""); err == nil {
			t.Errorf("%v: accepted", args)
		}
	}

	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddService("app", "", "/", "http://127.0.0.1:9000", 0, 0); err != nil {
		t.Fatal(err)
	}
	db.Close()

	one := filepath.Join(dir, "one.db")
	if _, err := run([]string{"backup", "--db", path, "--out", one}, ""); err != nil {
		t.Fatal(err)
	}
	copied, err := storage.Open(one)
	if err != nil {
		t.Fatal(err)
	}
	if svcs, err := copied.ListServices(); err != nil || len(svcs) != 1 || svcs[0].Name != "app" {
		t.Errorf("backup services = %v, %v", svcs, err)
	}
	copied.Close()

	// --keep 2 with three older backups (and an unrelated file) present.
	if err := os.MkdirAll(backups, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"waf-20200101T000000Z.db", "waf-20210101T000000Z.db", "waf-20220101T000000Z.db", "other.db"} {
		if err := os.WriteFile(filepath.Join(backups, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := run([]string{"backup", "--db", path, "--dir", backups, "--keep", "2"}, ""); err != nil {
		t.Fatal(err)
	}
	left, _ := filepath.Glob(filepath.Join(backups, "*.db"))
	if len(left) != 3 || filepath.Base(left[0]) != "other.db" || filepath.Base(left[1]) != "waf-20220101T000000Z.db" {
		t.Errorf("after --keep 2: %v", left)
	}
}
