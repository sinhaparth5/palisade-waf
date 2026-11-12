package storage

import (
	"database/sql"
	"errors"
	"time"
)

// TypeSafeConfig holds the opt-in settings for TypeSafe-backed ASN/hosting
// classification (internal/security/threatscore/typesafeclassify.go), which
// refines the hardcoded heuristic in asnclass.go for ASN organization names
// it doesn't recognize. Disabled by default: the heuristic works with no
// config at all, and enabling this adds an external API dependency and a
// credential to manage.
type TypeSafeConfig struct {
	Enabled bool
	APIKey  string
}

func (db *DB) GetTypeSafeConfig() (TypeSafeConfig, error) {
	var cfg TypeSafeConfig
	enabled, err := db.getMeta("typesafe_enabled")
	if err != nil {
		return TypeSafeConfig{}, err
	}
	cfg.Enabled = enabled == "1"
	if cfg.APIKey, err = db.getSecretMeta("typesafe_api_key"); err != nil {
		return TypeSafeConfig{}, err
	}
	return cfg, nil
}

// SetTypeSafeConfig persists the TypeSafe enable flag and API key.
func (db *DB) SetTypeSafeConfig(cfg TypeSafeConfig) error {
	enabled := "0"
	if cfg.Enabled {
		enabled = "1"
	}
	if err := db.setMeta("typesafe_enabled", enabled); err != nil {
		return err
	}
	return db.setSecretMeta("typesafe_api_key", cfg.APIKey)
}

// TypeSafeCall is one row in typesafe_calls: a single Jev API call made by
// the ASN/hosting classifier (threatscore/typesafeclassify.go), so an admin
// can see where TypeSafe token usage goes and why. Note that classifyASN
// retries a judgment on every request from an ASN whose last call errored
// (see its comment — only a successful judgment is cached), so a bad API
// key or a rate limit shows up here as repeated calls for the same ASN
// rather than the intended one-call-ever-per-ASN.
type TypeSafeCall struct {
	Ts           time.Time
	ASN          uint
	Org          string
	Hosting      bool
	InputTokens  int
	OutputTokens int
	DurationMs   int64
	Error        string
}

// typesafeCallsKeep bounds typesafe_calls the same way ratelimit/threatscore
// bound their in-memory maps — this one's on disk, so InsertTypeSafeCall
// prunes down to the newest N rows on every insert rather than relying on a
// scheduled job, since a misbehaving ASN can otherwise grow this table once
// per request instead of once per ASN.
const typesafeCallsKeep = 2000

// InsertTypeSafeCall records one Jev API call and prunes typesafe_calls back
// down to its newest typesafeCallsKeep rows.
func (db *DB) InsertTypeSafeCall(c TypeSafeCall) error {
	_, err := db.exec(
		`INSERT INTO typesafe_calls (ts, asn, org, hosting, input_tokens, output_tokens, duration_ms, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Ts.UTC(), c.ASN, c.Org, boolToInt(c.Hosting), c.InputTokens, c.OutputTokens, c.DurationMs, c.Error,
	)
	if err != nil {
		return err
	}
	var cutoff int64
	err = db.queryRow(`SELECT id FROM typesafe_calls ORDER BY id DESC LIMIT 1 OFFSET ?`, typesafeCallsKeep).Scan(&cutoff)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = db.exec(`DELETE FROM typesafe_calls WHERE id <= ?`, cutoff)
	return err
}

// ListTypeSafeCalls returns the most recent Jev API calls, newest first.
func (db *DB) ListTypeSafeCalls(limit int) ([]TypeSafeCall, error) {
	rows, err := db.query(
		`SELECT ts, asn, org, hosting, input_tokens, output_tokens, duration_ms, error
		 FROM typesafe_calls ORDER BY id DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TypeSafeCall
	for rows.Next() {
		var c TypeSafeCall
		var hosting int
		if err := rows.Scan(&c.Ts, &c.ASN, &c.Org, &hosting, &c.InputTokens, &c.OutputTokens, &c.DurationMs, &c.Error); err != nil {
			return nil, err
		}
		c.Hosting = hosting != 0
		out = append(out, c)
	}
	return out, rows.Err()
}

// TypeSafeUsage summarizes typesafe_calls since a cutoff — the "how many
// calls, how many tokens" header on the AI Usage page.
type TypeSafeUsage struct {
	Calls        int
	Errors       int
	InputTokens  int
	OutputTokens int
}

// TypeSafeUsageSince aggregates typesafe_calls with ts >= since. Plain
// comparison, not a SQL date function — see the SQLite date/time gotcha
// this codebase documents for the requests table's ts column.
func (db *DB) TypeSafeUsageSince(since time.Time) (TypeSafeUsage, error) {
	var u TypeSafeUsage
	err := db.queryRow(
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN error <> '' THEN 1 ELSE 0 END), 0),
		        COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0)
		 FROM typesafe_calls WHERE ts >= ?`, since.UTC(),
	).Scan(&u.Calls, &u.Errors, &u.InputTokens, &u.OutputTokens)
	return u, err
}
