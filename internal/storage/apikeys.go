package storage

import (
	"database/sql"
	"errors"
	"time"
)

// ── API keys ──────────────────────────────────────────────────────────────────

// APIKey is a row in the api_keys table. The raw key is never stored — only
// key_hash (a SHA-256 hex digest, computed by the caller) and key_prefix (a
// short, non-secret slice of the raw key kept for display so an admin can
// tell keys apart in the UI without ever seeing the secret again).
type APIKey struct {
	ID         int
	Name       string
	Prefix     string
	ReadOnly   bool // true: GET endpoints only, every mutating route 403s (see ui.requireWrite)
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// CreateAPIKey stores a new key and returns its row id. hash is the SHA-256
// hex digest of the raw key; the raw key itself is shown to the admin exactly
// once by the caller and never persisted.
func (db *DB) CreateAPIKey(name, prefix, hash string, readOnly bool) (int, error) {
	id, err := db.insertReturningID(
		`INSERT INTO api_keys (name, key_prefix, key_hash, read_only) VALUES (?, ?, ?, ?)`,
		name, prefix, hash, boolToInt(readOnly),
	)
	return int(id), err
}

// ListAPIKeys returns every key's metadata, newest first. key_hash is
// intentionally never selected.
func (db *DB) ListAPIKeys() ([]APIKey, error) {
	rows, err := db.query(
		`SELECT id, name, key_prefix, read_only, created_at, last_used_at FROM api_keys ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []APIKey
	for rows.Next() {
		var k APIKey
		var lastUsed sql.NullTime
		if err := rows.Scan(&k.ID, &k.Name, &k.Prefix, &k.ReadOnly, &k.CreatedAt, &lastUsed); err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			k.LastUsedAt = &lastUsed.Time
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RemoveAPIKey revokes a key by hard-deleting its row — matching this
// codebase's existing no-soft-delete convention (RemoveService, RemoveIPRule).
func (db *DB) RemoveAPIKey(id int) error {
	_, err := db.exec(`DELETE FROM api_keys WHERE id = ?`, id)
	return err
}

// ValidateAPIKey looks up a key by its SHA-256 hash. It returns (nil, nil)
// when no key matches — not an error — so callers can distinguish "invalid
// key" from a DB failure.
func (db *DB) ValidateAPIKey(hash string) (*APIKey, error) {
	var k APIKey
	var lastUsed sql.NullTime
	err := db.queryRow(
		`SELECT id, name, key_prefix, read_only, created_at, last_used_at FROM api_keys WHERE key_hash = ?`, hash,
	).Scan(&k.ID, &k.Name, &k.Prefix, &k.ReadOnly, &k.CreatedAt, &lastUsed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if lastUsed.Valid {
		k.LastUsedAt = &lastUsed.Time
	}
	return &k, nil
}

// TouchAPIKey records that a key was just used to authenticate a request.
// Callers should throttle how often this is invoked per key (see
// ui.apiKeyAuth) rather than calling it on every request.
func (db *DB) TouchAPIKey(id int) error {
	_, err := db.exec(`UPDATE api_keys SET last_used_at = ? WHERE id = ?`, time.Now().UTC(), id)
	return err
}
