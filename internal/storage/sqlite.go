package storage

import (
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

// openSQLite opens the database file at path. PRAGMAs go in the DSN, not an
// Exec: only DSN params reach every pooled connection.
func openSQLite(path string) (*sql.DB, error) {
	conn, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	// One writer at a time regardless, but WAL lets reads (dashboard, logs)
	// run next to the request-log writer instead of queuing behind it.
	conn.SetMaxOpenConns(8)
	return conn, nil
}

// upsertIgnore is an INSERT that does nothing when a row conflicting on
// conflictCols already exists.
func upsertIgnore(table string, cols []string, placeholders string, conflictCols []string) string {
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON CONFLICT(%s) DO NOTHING",
		table, strings.Join(cols, ", "), placeholders, strings.Join(conflictCols, ", "))
}

// upsertUpdate is an INSERT that overwrites updateCols with the new values
// when a row conflicting on conflictCols already exists.
func upsertUpdate(table string, cols []string, placeholders string, conflictCols, updateCols []string) string {
	sets := make([]string, len(updateCols))
	for i, c := range updateCols {
		sets[i] = fmt.Sprintf("%s = excluded.%s", c, c)
	}
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON CONFLICT(%s) DO UPDATE SET %s",
		table, strings.Join(cols, ", "), placeholders, strings.Join(conflictCols, ", "), strings.Join(sets, ", "))
}
