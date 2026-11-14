package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Config export/import (issue #263): the configSteps tables as one JSON
// file. Both directions go through a temporary SQLite file and the same
// per-table copy code.
//
// Secrets: the temporary file uses the source's --db-key-file key, so every
// secret is re-sealed ("enc:v1:") under it. Without a key the secrets would
// be plaintext, so they are blanked instead (TOTP secrets included: those
// users re-enroll). Importing sealed values needs the same key file.

// ConfigFormat names the export file format.
const ConfigFormat = "palisade-config"

// ConfigFile is an exported configuration.
type ConfigFile struct {
	Format     string                      `json:"format"`
	Version    int                         `json:"version"`
	ExportedAt time.Time                   `json:"exported_at"`
	Sealed     bool                        `json:"sealed"` // secrets kept, sealed under the exporter's key
	Tables     map[string][]map[string]any `json:"tables"`
}

// ErrConfigNotEmpty is returned by ImportConfig without replace when the
// target already has configuration.
var ErrConfigNotEmpty = errors.New("the database already has configuration; import with replace to overwrite it")

// secretColumns lists the non-meta columns holding sealed secrets.
var secretColumns = map[string][]string{
	"admin_users":    secretUserColumns,
	"webhook_config": {"secret"},
}

// withTempConfigDB runs fn on an empty temporary SQLite database that seals
// secrets with db's key.
func (db *DB) withTempConfigDB(fn func(tmp *DB) error) error {
	dir, err := os.MkdirTemp("", "palisade-config-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	tmp, err := Open(filepath.Join(dir, "config.db"))
	if err != nil {
		return err
	}
	defer tmp.Close()
	tmp.secretGCM = db.secretGCM
	return fn(tmp)
}

// ExportConfig writes the configuration as JSON.
func (db *DB) ExportConfig(w io.Writer) error {
	out := ConfigFile{Format: ConfigFormat, Version: 1, ExportedAt: time.Now().UTC(), Sealed: db.secretGCM != nil, Tables: map[string][]map[string]any{}}
	err := db.withTempConfigDB(func(tmp *DB) error {
		if _, err := db.migrateConfigInto(tmp); err != nil {
			return err
		}
		for _, step := range configSteps {
			rows, err := tmp.dumpTable(step.table)
			if err != nil {
				return fmt.Errorf("export %s: %w", step.table, err)
			}
			out.Tables[step.table] = rows
		}
		return nil
	})
	if err != nil {
		return err
	}
	// Anything not sealed is plaintext: leave it out.
	unsealed := func(v any) bool { s, _ := v.(string); return s != "" && !strings.HasPrefix(s, secretPrefix) }
	for _, row := range out.Tables["meta"] {
		if k, _ := row["key"].(string); slices.Contains(secretMetaKeys, k) && unsealed(row["value"]) {
			row["value"] = ""
		}
	}
	for table, cols := range secretColumns {
		for _, row := range out.Tables[table] {
			for _, c := range cols {
				if unsealed(row[c]) {
					row[c] = ""
				}
			}
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// ImportConfig loads an exported configuration into db. Without replace it
// refuses a database that already has configuration (ErrConfigNotEmpty);
// with replace the config tables are emptied first. The request log is
// never touched.
func (db *DB) ImportConfig(r io.Reader, replace bool) (MigrationReport, error) {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	var in ConfigFile
	if err := dec.Decode(&in); err != nil {
		return MigrationReport{}, fmt.Errorf("read config file: %w", err)
	}
	if in.Format != ConfigFormat || in.Version != 1 {
		return MigrationReport{}, fmt.Errorf("not a %s v1 file", ConfigFormat)
	}
	known := map[string]bool{}
	for _, step := range configSteps {
		known[step.table] = true
	}
	for t := range in.Tables {
		if !known[t] {
			return MigrationReport{}, fmt.Errorf("unknown table %q", t)
		}
	}
	if in.Sealed && db.secretGCM == nil {
		return MigrationReport{}, errors.New("the file's secrets are sealed: import with the exporter's --db-key-file")
	}

	var report MigrationReport
	err := db.withTempConfigDB(func(tmp *DB) error {
		for _, step := range configSteps {
			if err := tmp.loadTable(step.table, in.Tables[step.table]); err != nil {
				return fmt.Errorf("import %s: %w", step.table, err)
			}
		}
		// A different key would replace every secret with ones nothing
		// here can open; tmp seals with db's key, so this tries it.
		if _, err := tmp.getSecretMeta("challenge_secret"); err != nil {
			return err
		}
		// Copy into a scratch DB first, so a row the copy can't read fails
		// before prepareConfigImport empties the target (issue #308).
		// ponytail: not a transaction; a target-side I/O error mid-copy can
		// still leave a partial import.
		if err := db.withTempConfigDB(func(check *DB) error {
			_, err := tmp.migrateConfigInto(check)
			return err
		}); err != nil {
			return err
		}
		if err := db.prepareConfigImport(replace); err != nil {
			return err
		}
		var err error
		report, err = tmp.migrateConfigInto(db)
		return err
	})
	return report, err
}

// volatileConfig is config the server rewrites while running (caches,
// counters, sync bookkeeping): ConfigDigest ignores it.
var volatileConfig = map[string][]string{
	"ip_threat_scores": nil, "ja4_reputation": nil, "threat_intel_ips": nil, "csp_scripts": nil,
	"api_keys":             {"last_used_at"},
	"admin_users":          {"totp_last_counter"},
	"threat_intel_sources": {"last_synced_at", "last_error", "ip_count"},
}

var volatileMeta = []string{"email_report_sent_for", metaKeyNotificationsSeenAt, metaKeySessionsHashed}

// ConfigDigest hashes the stored configuration, so a cluster can tell
// when it changed. Unlike ExportConfig it is stable: secrets are hashed as
// stored, not re-sealed with a fresh nonce.
func (db *DB) ConfigDigest() (string, error) {
	h := sha256.New()
	enc := json.NewEncoder(h)
	for _, step := range configSteps {
		cols, skip := volatileConfig[step.table]
		if skip && cols == nil {
			continue
		}
		rows, err := db.dumpTable(step.table)
		if err != nil {
			return "", err
		}
		for _, row := range rows {
			for _, c := range cols {
				delete(row, c)
			}
			if k, _ := row["key"].(string); step.table == "meta" && slices.Contains(volatileMeta, k) {
				continue
			}
			if err := enc.Encode([]any{step.table, row}); err != nil {
				return "", err
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// prepareConfigImport checks the target is empty, or empties it on replace.
// meta and webhook_config are upserted by the import, so they never count.
func (db *DB) prepareConfigImport(replace bool) error {
	if replace {
		for i := len(configSteps) - 1; i >= 0; i-- {
			if _, err := db.exec(`DELETE FROM ` + configSteps[i].table); err != nil {
				return err
			}
		}
		return nil
	}
	for _, step := range configSteps {
		if step.table == "meta" || step.table == "webhook_config" {
			continue
		}
		var n int
		if err := db.queryRow(`SELECT COUNT(*) FROM ` + step.table).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("%w (%s has rows)", ErrConfigNotEmpty, step.table)
		}
	}
	return nil
}

// dumpTable returns every row of a SQLite table as column -> value.
func (db *DB) dumpTable(table string) ([]map[string]any, error) {
	rows, err := db.query(`SELECT * FROM ` + table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make(map[string]any, len(cols))
		for i, c := range cols {
			if b, ok := vals[i].([]byte); ok {
				vals[i] = string(b)
			}
			row[c] = vals[i]
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// loadTable inserts rows into a SQLite table. Column names must be the
// table's own, so a crafted file can't inject SQL through them.
func (db *DB) loadTable(table string, rows []map[string]any) error {
	if _, err := db.exec(`DELETE FROM ` + table); err != nil { // rows Open seeded
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	cols, err := db.tableColumns(table)
	if err != nil {
		return err
	}
	for _, row := range rows {
		var names []string
		var args []any
		for k, v := range row {
			if !slices.Contains(cols, k) {
				return fmt.Errorf("unknown column %q", k)
			}
			if n, ok := v.(json.Number); ok {
				if i, err := n.Int64(); err == nil {
					v = i
				} else if v, err = n.Float64(); err != nil {
					return fmt.Errorf("column %q: %w", k, err)
				}
			}
			names = append(names, k)
			args = append(args, v)
		}
		q := fmt.Sprintf(`INSERT INTO %s (%s) VALUES (%s)`, table, strings.Join(names, ", "), placeholders(len(names)))
		if _, err := db.exec(q, args...); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) tableColumns(table string) ([]string, error) {
	rows, err := db.query(`SELECT * FROM ` + table + ` LIMIT 0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	return cols, rows.Err()
}
