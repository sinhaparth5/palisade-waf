package storage

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

// FuzzStatusCodes checks ParseStatusCodes (issue #308): only 100-599 survive
// and FormatStatusCodes parses back to the same list.
func FuzzStatusCodes(f *testing.F) {
	for _, s := range []string{"404, 410", "200,,abc 99 600 +301 0500", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		codes := ParseStatusCodes(s)
		for _, c := range codes {
			if c < 100 || c > 599 {
				t.Fatalf("%q kept %d", s, c)
			}
		}
		if again := ParseStatusCodes(FormatStatusCodes(codes)); !slices.Equal(again, codes) {
			t.Fatalf("round trip of %q: %v -> %v", s, codes, again)
		}
	})
}

// FuzzImportConfig feeds arbitrary files to ImportConfig (issue #308) on a
// database that already has config. A failed import leaves every table and
// the schema unchanged; a successful one changes only configSteps tables.
func FuzzImportConfig(f *testing.F) {
	tmpl := filepath.Join(f.TempDir(), "tmpl.db")
	db, err := Open(tmpl)
	if err != nil {
		f.Fatal(err)
	}
	if err := db.AddService("api", "api.example.com", "", "http://127.0.0.1:3000", 5, 10); err != nil {
		f.Fatal(err)
	}
	if err := db.AddIPRule("", "198.51.100.0/24", "block"); err != nil {
		f.Fatal(err)
	}
	if _, err := db.CreateAdminUser("owner@example.com", "a long enough password", "owner"); err != nil {
		f.Fatal(err)
	}
	var buf bytes.Buffer
	if err := db.ExportConfig(&buf); err != nil {
		f.Fatal(err)
	}
	db.Close()
	image, err := os.ReadFile(tmpl)
	if err != nil {
		f.Fatal(err)
	}

	valid := buf.Bytes()
	f.Add(valid, false)
	f.Add(valid, true)
	// A row the temp DB stores but the copy can't scan: it fails after the
	// target was emptied, unless the import is checked first.
	var bad ConfigFile
	if err := json.Unmarshal(valid, &bad); err != nil {
		f.Fatal(err)
	}
	bad.Tables["services"][0]["rate_limit_burst"] = "abc"
	badJSON, _ := json.Marshal(bad)
	f.Add(badJSON, true)
	f.Add([]byte(`{"format":"palisade-config","version":1,"tables":{"sqlite_master":[]}}`), true)
	f.Add([]byte(`{"format":"palisade-config","version":1,"tables":{"meta":[{"key":"k","value":"v","x) VALUES (1);--":1}]}}`), false)

	f.Fuzz(func(t *testing.T, file []byte, replace bool) {
		path := filepath.Join(t.TempDir(), "waf.db")
		if err := os.WriteFile(path, image, 0o600); err != nil {
			t.Fatal(err)
		}
		db, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		before := snapshotDB(t, db)
		_, err = db.ImportConfig(bytes.NewReader(file), replace)
		after := snapshotDB(t, db)
		if err != nil {
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("failed import (%v) changed the database", err)
			}
			return
		}
		for name := range after {
			if !reflect.DeepEqual(before[name], after[name]) && name != "sqlite_sequence" &&
				!slices.ContainsFunc(configSteps, func(s configStep) bool { return s.table == name }) {
				t.Fatalf("import changed %s", name)
			}
		}
	})
}

// snapshotDB returns the schema (as "sqlite_master") and every table's rows.
func snapshotDB(t *testing.T, db *DB) map[string][]map[string]any {
	t.Helper()
	master, err := db.dumpTable("sqlite_master")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]map[string]any{"sqlite_master": master}
	for _, row := range master {
		if row["type"] != "table" {
			continue
		}
		name, _ := row["name"].(string)
		if out[name], err = db.dumpTable(`"` + name + `"`); err != nil {
			t.Fatal(err)
		}
	}
	return out
}
