package storage

import (
	"crypto/rand"
	"encoding/base64"
	"time"
)

// ── Admin passkeys (WebAuthn, issue #78) ─────────────────────────────────────
//
// A second, browser/authenticator-backed factor alongside TOTP — see
// internal/security/passkey. A user normally registers more than one
// passkey (phone, laptop, security key), so these live in their own table,
// keyed by user_id.

// WebAuthnCredential is one registered passkey.
type WebAuthnCredential struct {
	ID           int64
	CredentialID string // base64url(credential.ID), for fast lookup
	Data         []byte // JSON-encoded webauthn.Credential
	Name         string
	CreatedAt    time.Time
	LastUsedAt   string
}

// GetOrCreateWebAuthnHandle returns the user's stable, opaque WebAuthn user
// handle, generating and persisting one (32 random bytes) on first use. It
// is not a secret — knowing it alone proves nothing — just a stable non-PII
// identifier the spec requires, so it's stored unsealed.
func (db *DB) GetOrCreateWebAuthnHandle(uid int64) ([]byte, error) {
	s, err := db.userField(uid, "webauthn_handle")
	if err != nil {
		return nil, err
	}
	if s != "" {
		return base64.StdEncoding.DecodeString(s)
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := db.setUserField(uid, "webauthn_handle", base64.StdEncoding.EncodeToString(b)); err != nil {
		return nil, err
	}
	return b, nil
}

// WebAuthnEnabled reports whether the user has at least one registered
// passkey — the login page only offers the passkey option, and LoginPost
// only demands a second factor for passkey-only users, when this is true.
func (db *DB) WebAuthnEnabled(uid int64) (bool, error) {
	var n int
	err := db.queryRow(`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`, uid).Scan(&n)
	return n > 0, err
}

// ListWebAuthnCredentials returns the user's registered passkeys, newest first.
func (db *DB) ListWebAuthnCredentials(uid int64) ([]WebAuthnCredential, error) {
	rows, err := db.query(
		`SELECT id, credential_id, data, name, created_at, last_used_at FROM webauthn_credentials
		 WHERE user_id = ? ORDER BY created_at DESC`, uid,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []WebAuthnCredential
	for rows.Next() {
		var c WebAuthnCredential
		var data string
		if err := rows.Scan(&c.ID, &c.CredentialID, &data, &c.Name, &c.CreatedAt, &c.LastUsedAt); err != nil {
			return nil, err
		}
		c.Data = []byte(data)
		out = append(out, c)
	}
	return out, rows.Err()
}

// AddWebAuthnCredential stores a newly registered passkey for the user.
func (db *DB) AddWebAuthnCredential(uid int64, credentialID, name string, data []byte) error {
	_, err := db.exec(
		`INSERT INTO webauthn_credentials (user_id, credential_id, data, name, created_at) VALUES (?, ?, ?, ?, ?)`,
		uid, credentialID, string(data), name, time.Now(),
	)
	return err
}

// TouchWebAuthnCredential updates a credential's stored data (its sign
// counter changes on every successful login, guarding against a cloned
// authenticator) and last-used timestamp after a successful login.
func (db *DB) TouchWebAuthnCredential(credentialID string, data []byte) error {
	_, err := db.exec(
		`UPDATE webauthn_credentials SET data = ?, last_used_at = ? WHERE credential_id = ?`,
		string(data), time.Now().UTC().Format(time.RFC3339), credentialID,
	)
	return err
}

// DeleteWebAuthnCredential removes one of the user's passkeys by its row id.
func (db *DB) DeleteWebAuthnCredential(uid, id int64) error {
	_, err := db.exec(`DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?`, id, uid)
	return err
}
