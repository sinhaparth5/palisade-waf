package storage

import (
	"context"
	"palisade/internal/security/ratelimit"
	"strconv"
	"time"
)

// ── Rate limit state (StateStore impl) ───────────────────────────────────────

// SaveRateLimitState persists all in-memory token-bucket states to SQLite.
// It replaces the whole table in a single transaction — called every 10 s by
// Limiter.StartPersistence so restarts pick up near-current state.
func (db *DB) SaveRateLimitState(states []ratelimit.BucketState) error {
	tx, err := db.conn.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint
	if _, err := tx.ExecContext(context.Background(), `DELETE FROM rate_state`); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(context.Background(), db.conn.Rebind(`INSERT INTO rate_state (ip, tokens, last_refill) VALUES (?, ?, ?)`))
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, s := range states {
		if _, err := stmt.ExecContext(context.Background(), s.IP, s.Tokens, s.LastRefill.UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LoadRateLimitState reads all persisted bucket states. Called once at startup
// before traffic starts, so there's no concurrency concern.
func (db *DB) LoadRateLimitState() ([]ratelimit.BucketState, error) {
	rows, err := db.query(`SELECT ip, tokens, last_refill FROM rate_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ratelimit.BucketState
	for rows.Next() {
		var s ratelimit.BucketState
		var ts string
		if err := rows.Scan(&s.IP, &s.Tokens, &ts); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			s.LastRefill = t
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// PurgeRateLimitState deletes bucket states whose last_refill is before before,
// keeping the rate_state table from growing unboundedly.
func (db *DB) PurgeRateLimitState(before time.Time) error {
	_, err := db.exec(
		`DELETE FROM rate_state WHERE last_refill < ?`,
		before.UTC().Format(time.RFC3339Nano),
	)
	return err
}

// GetRateLimitSettings reads the global per-client-IP rate limit from the
// meta table. Returns defaults (disabled, 10 rps, burst 20) if never saved
// from the Settings page — global limiting is opt-in like bot protection,
// since a surprise default limit could 429 legitimate NAT'd traffic where
// many users share one IP.
func (db *DB) GetRateLimitSettings() (enabled bool, rps float64, burst int, err error) {
	rps, burst = 10, 20
	if v, e := db.getMeta("ratelimit_enabled"); e == nil {
		enabled = v == "1"
	}
	if v, e := db.getMeta("ratelimit_rps"); e == nil && v != "" {
		if f, e2 := strconv.ParseFloat(v, 64); e2 == nil && f > 0 {
			rps = f
		}
	}
	if v, e := db.getMeta("ratelimit_burst"); e == nil && v != "" {
		if n, e2 := strconv.Atoi(v); e2 == nil && n > 0 {
			burst = n
		}
	}
	return
}

// SetRateLimitSettings persists the global rate limit to the meta table.
func (db *DB) SetRateLimitSettings(enabled bool, rps float64, burst int) error {
	v := "0"
	if enabled {
		v = "1"
	}
	if err := db.setMeta("ratelimit_enabled", v); err != nil {
		return err
	}
	if err := db.setMeta("ratelimit_rps", strconv.FormatFloat(rps, 'f', -1, 64)); err != nil {
		return err
	}
	return db.setMeta("ratelimit_burst", strconv.Itoa(burst))
}
