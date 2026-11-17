package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"palisade/internal/storage"
)

// TestRunConfig: `config export` then `config import` into a fresh database
// (issue #263), with the CLI's argument errors.
func TestRunConfig(t *testing.T) {
	dir := t.TempDir()
	src, dst, file := filepath.Join(dir, "src.db"), filepath.Join(dir, "dst.db"), filepath.Join(dir, "config.json")
	db, err := storage.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddService("api", "api.example.com", "", "http://127.0.0.1:3000", 0, 0); err != nil {
		t.Fatal(err)
	}
	db.Close()

	if err := runConfig([]string{"export", "--db", src, "--out", file}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("export file: %v %v", fi, err)
	}
	var stdout bytes.Buffer
	if err := runConfig([]string{"export", "--db", src}, nil, &stdout); err != nil || !strings.Contains(stdout.String(), `"palisade-config"`) {
		t.Fatalf("export to stdout: %v %q", err, stdout.String())
	}
	if err := runConfig([]string{"import", "--db", dst, file}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := runConfig([]string{"import", "--db", dst, "-"}, strings.NewReader(stdout.String()), nil); err == nil {
		t.Fatal("second import without --replace succeeded")
	}
	// Seed mode: a database with config is left alone, and still exits 0.
	if err := runConfig([]string{"import", "--db", dst, "--if-empty", "-"}, strings.NewReader(stdout.String()), nil); err != nil {
		t.Fatalf("--if-empty over config: %v", err)
	}
	if err := runConfig([]string{"import", "--db", dst, "--replace", "-"}, strings.NewReader(stdout.String()), nil); err != nil {
		t.Fatal(err)
	}
	db, err = storage.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if svcs, _ := db.ListServices(); len(svcs) != 1 || svcs[0].Name != "api" {
		t.Fatalf("imported services = %+v", svcs)
	}

	for _, args := range [][]string{nil, {"dump"}, {"import", "--db", dst}, {"export", "--bogus"}, {"import", "--db", dst, "--replace", "--if-empty", file}, {"import", "--db", dst, "--if-empty", filepath.Join(dir, "missing.json")}} {
		if err := runConfig(args, nil, nil); err == nil {
			t.Errorf("%v: accepted", args)
		}
	}
}
