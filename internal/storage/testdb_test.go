package storage

import (
	"path/filepath"
	"testing"
)

// openTestDB opens a fresh SQLite file in t.TempDir(), closed on cleanup.
func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
