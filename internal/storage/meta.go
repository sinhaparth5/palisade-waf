package storage

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const metaKeyNotificationsSeenAt = "notifications_seen_at"

// GetOrCreateChallengeSecret returns the HMAC secret used to sign JS challenge
// tokens and bypass cookies. If no secret is stored yet, a random 64-char hex
// string is generated and persisted so it survives restarts (a new secret on
// every restart would invalidate all outstanding bypass cookies).
func (db *DB) GetOrCreateChallengeSecret() (string, error) {
	const key = "challenge_secret"
	secret, err := db.getSecretMeta(key)
	if err != nil {
		// An unreadable stored secret (wrong/missing --db-key-file) must not
		// be silently replaced with a fresh one — that would invalidate every
		// outstanding bypass cookie and mask the key misconfiguration.
		return "", err
	}
	if secret != "" {
		return secret, nil
	}
	// Generate a new random secret and persist it.
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate challenge secret: %w", err)
	}
	secret = hex.EncodeToString(b)
	return secret, db.setSecretMeta(key, secret)
}

// GetAcmeEmail returns the Let's Encrypt contact email stored in the DB, or
// "" if none has been set yet. Used by the TLS startup path and the admin UI.
func (db *DB) GetAcmeEmail() (string, error) { return db.getMeta("acme_email") }

// GetPrimaryDomain returns the primary domain stored during setup (used for
// ACME host policy so the admin UI domain gets an auto-issued cert).
func (db *DB) GetPrimaryDomain() (string, error) { return db.getMeta("primary_domain") }

// SetPrimaryDomain stores the primary domain for ACME certificate issuance.
func (db *DB) SetPrimaryDomain(domain string) error { return db.setMeta("primary_domain", domain) }

// SetAcmeEmail stores the Let's Encrypt contact email. Must be set before
// any service can use auto-issue TLS.
func (db *DB) SetAcmeEmail(email string) error { return db.setMeta("acme_email", email) }

func (db *DB) getMeta(key string) (string, error) {
	var v string
	err := db.queryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func (db *DB) setMeta(key, value string) error {
	_, err := db.exec(
		upsertUpdate("meta", []string{"key", "value"}, "?, ?", []string{"key"}, []string{"value"}),
		key, value,
	)
	return err
}

// NotificationsSeenAt returns the last time the admin marked notifications as
// read. On first ever call (nothing stored yet) it initializes to now, so a
// fresh deployment doesn't immediately show a badge for all historical
// blocked requests.
func (db *DB) NotificationsSeenAt() (time.Time, error) {
	v, err := db.getMeta(metaKeyNotificationsSeenAt)
	if err != nil {
		return time.Time{}, err
	}
	if v == "" {
		now := time.Now().UTC()
		if err := db.setMeta(metaKeyNotificationsSeenAt, now.Format(time.RFC3339Nano)); err != nil {
			return time.Time{}, err
		}
		return now, nil
	}
	return time.Parse(time.RFC3339Nano, v)
}

// MarkNotificationsSeen records that the admin has viewed all current
// notifications, resetting the unread badge count going forward.
func (db *DB) MarkNotificationsSeen() error {
	return db.setMeta(metaKeyNotificationsSeenAt, time.Now().UTC().Format(time.RFC3339Nano))
}
