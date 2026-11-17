package storage

import "context"

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
func (db *DB) Vacuum() error {
	if _, err := db.exec(`VACUUM`); err != nil {
		return err
	}
	_, err := db.exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

// BackupFile is BackupTo for a database that isn't open as a store: it skips
// Open's migrate, so a backup taken by a newer binary before an upgrade holds
// the old schema, not a half-migrated one.
func BackupFile(src, dst string) error {
	conn, err := openSQLite(src)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.ExecContext(context.Background(), `VACUUM INTO ?`, dst)
	return err
}
