package storage

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// v327Key unseals the secrets in testdata/v3.2.7*: what enableDBEncryption
// derives from a key file holding this text.
var v327Key = func() []byte {
	k := sha256.Sum256([]byte("palisade-v3.2.7-fixture-key-not-a-secret-0123456789"))
	return k[:]
}()

// assertNoRemovedMeta fails if any setting of a removed feature is stored.
func assertNoRemovedMeta(t *testing.T, db *DB) {
	t.Helper()
	var n int
	mustNoErr(t, db.queryRow(`SELECT COUNT(*) FROM meta WHERE key IN (`+placeholders(len(removedMetaKeys))+`)`, removedMetaKeys...).Scan(&n))
	if n != 0 {
		t.Errorf("%d removed meta keys left behind", n)
	}
}

// TestUpgradeFromV327 opens a database written by v3.2.7 (testdata/v3.2.7.sql:
// TypeSafe settings and calls, a saved Postgres connection, requests.ja3_hash)
// and checks the removals of #298-#301 upgrade it cleanly (issue #302).
func TestUpgradeFromV327(t *testing.T) {
	dump, err := os.ReadFile("testdata/v3.2.7.sql")
	mustNoErr(t, err)
	path := filepath.Join(t.TempDir(), "waf.db")
	raw, err := sql.Open("sqlite", path)
	mustNoErr(t, err)
	_, err = raw.Exec(string(dump))
	mustNoErr(t, err)
	mustNoErr(t, raw.Close())

	db, err := Open(path)
	mustNoErr(t, err)
	t.Cleanup(func() { db.Close() })
	// The stale sealed secrets are gone before the key is applied, so
	// startup with --db-key-file can't trip over them.
	mustNoErr(t, db.EnableSecretEncryption(v327Key))
	assertNoRemovedMeta(t, db)
	if _, err := db.exec(`SELECT 1 FROM typesafe_calls`); err == nil {
		t.Error("typesafe_calls survived the upgrade")
	}

	// Data that is still in use came through.
	if svcs, err := db.ListServices(); err != nil || len(svcs) != 1 || svcs[0].Name != "shop" {
		t.Errorf("services = %v, %v", svcs, err)
	}
	if users, err := db.ListAdminUsers(); err != nil || len(users) != 1 {
		t.Errorf("users = %v, %v", users, err)
	}
	if _, err := db.GetOrCreateChallengeSecret(); err != nil {
		t.Errorf("challenge secret: %v", err)
	}

	// The leftover requests.ja3_hash column doesn't get in the way of
	// logging, pruning, backup, vacuum or a config round trip.
	mustNoErr(t, db.insertRequestTx([]RequestLog{{Timestamp: time.Now(), AppName: "shop", RealIP: "198.51.100.8", Method: "GET", Host: "shop.example.test", Path: "/", Status: 200}}))
	_, err = db.PruneOldRequests(0)
	mustNoErr(t, err)
	mustNoErr(t, db.BackupTo(filepath.Join(t.TempDir(), "backup.db")))
	mustNoErr(t, db.Vacuum())
	var buf bytes.Buffer
	mustNoErr(t, db.ExportConfig(&buf))
	dst := openTestDB(t)
	mustNoErr(t, dst.EnableSecretEncryption(v327Key))
	_, err = dst.ImportConfig(&buf, false)
	mustNoErr(t, err)
}

// TestImportV327Config imports `palisade config export` output from v3.2.7.
// Its meta rows still carry the TypeSafe and DB connection settings; they
// are skipped, not brought back into the new database (issue #302).
func TestImportV327Config(t *testing.T) {
	f, err := os.Open("testdata/v3.2.7-config.json")
	mustNoErr(t, err)
	defer f.Close()
	db := openTestDB(t)
	mustNoErr(t, db.EnableSecretEncryption(v327Key))
	if _, err := db.ImportConfig(f, false); err != nil {
		t.Fatalf("import: %v", err)
	}
	assertNoRemovedMeta(t, db)
	if svcs, err := db.ListServices(); err != nil || len(svcs) != 1 || svcs[0].Name != "shop" {
		t.Errorf("services = %v, %v", svcs, err)
	}
	if rules, err := db.ListIPRules(); err != nil || len(rules) != 1 {
		t.Errorf("ip rules = %v, %v", rules, err)
	}
}
