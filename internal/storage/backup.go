package storage

// ── Backup ───────────────────────────────────────────────────────────────────

// BackupTo writes a consistent, fully-vacuumed copy of the database to path.
// VACUUM INTO is safe to call while the DB is live — SQLite holds a read lock
// for the duration and writes a fresh, defragmented file.
func (db *DB) BackupTo(path string) error {
	_, err := db.exec(`VACUUM INTO ?`, path)
	return err
}

// Vacuum rebuilds the database in place, returning freed pages to the OS —
// DELETE (e.g. PruneOldRequests) only moves pages to SQLite's free list for
// reuse and never shrinks the file. Meant for the one-shot prune CLI
// (`prune --vacuum`), not the live server: VACUUM is one long write
// transaction, so the running process's log worker would stall behind it for
// the whole rebuild. The TRUNCATE checkpoint afterwards matters because the
// rebuild is written through the WAL — without it the reclaimed space just
// sits in a ballooned -wal file until the last connection closes.
// Vacuum reclaims disk space after a prune. Behavior is dialect-specific:
// SQLite's plain DELETE never shrinks the file (pages are only free-listed
// for reuse), so this runs a full VACUUM rebuild followed by a WAL
// checkpoint truncate — see the "prune --vacuum" one-shot command for why
// this must never run inside the live server. Postgres has its own VACUUM
// with different semantics (reclaims space for reuse in place, no rebuild,
// no WAL-checkpoint-equivalent pragma to run afterward) but supports the
// same bare statement. MySQL has no database-wide VACUUM at all — space
// reclamation there is a per-table OPTIMIZE TABLE, and managed/cloud
// Postgres-family deployments (CockroachDB, Neon) typically handle storage
// reclamation server-side already — so this is a documented no-op for MySQL
// rather than a guess at equivalent behavior.
func (db *DB) Vacuum() error {
	switch db.dialect.name {
	case "mysql":
		return nil
	case "postgres":
		_, err := db.exec(`VACUUM`)
		return err
	default:
		if _, err := db.exec(`VACUUM`); err != nil {
			return err
		}
		_, err := db.exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
		return err
	}
}
