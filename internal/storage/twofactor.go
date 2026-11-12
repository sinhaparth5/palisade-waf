package storage

import (
	"fmt"
	"strconv"
	"strings"
)

// ── Admin TOTP (two-factor auth) ─────────────────────────────────────────────
//
// All state lives in the user's admin_users row:
//   totp_secret          active base32 secret ("" = 2FA disabled), sealed
//   totp_pending_secret  enrollment in progress, not yet confirmed, sealed
//   totp_backup_codes    comma-separated SHA-256 hex digests, removed on use
//   totp_last_counter    last accepted TOTP counter, to reject replays

// GetTOTPSecret returns the user's active TOTP secret, or "" when 2FA is disabled.
func (db *DB) GetTOTPSecret(uid int64) (string, error) {
	return db.getSecretUserField(uid, "totp_secret")
}

// TOTPEnabled reports whether the user's login requires a second factor.
// Reads the raw value: "is 2FA on" doesn't need the secret decrypted, so it
// keeps working (and keeps the login flow demanding a second factor) even
// when the key file is missing — failing open to password-only here would
// let a key misconfiguration disable 2FA.
func (db *DB) TOTPEnabled(uid int64) (bool, error) {
	s, err := db.userField(uid, "totp_secret")
	return s != "", err
}

// SetPendingTOTPSecret stores a not-yet-confirmed enrollment secret. It only
// becomes active via EnableTOTP after the user proves their authenticator
// produces a valid code; a stale pending secret is inert.
func (db *DB) SetPendingTOTPSecret(uid int64, secret string) error {
	return db.setSecretUserField(uid, "totp_pending_secret", secret)
}

// GetPendingTOTPSecret returns the enrollment secret awaiting confirmation.
func (db *DB) GetPendingTOTPSecret(uid int64) (string, error) {
	return db.getSecretUserField(uid, "totp_pending_secret")
}

// EnableTOTP promotes the pending secret to active and stores the backup-code
// hashes (SHA-256 hex — the codes are high-entropy random, so like API keys
// they don't need bcrypt). Returns an error if no enrollment is pending.
func (db *DB) EnableTOTP(uid int64, backupHashes []string) error {
	pending, err := db.GetPendingTOTPSecret(uid)
	if err != nil {
		return err
	}
	if pending == "" {
		return fmt.Errorf("no pending TOTP enrollment")
	}
	if err := db.setSecretUserField(uid, "totp_secret", pending); err != nil {
		return err
	}
	if err := db.setUserField(uid, "totp_backup_codes", strings.Join(backupHashes, ",")); err != nil {
		return err
	}
	if err := db.setUserField(uid, "totp_last_counter", ""); err != nil {
		return err
	}
	return db.setUserField(uid, "totp_pending_secret", "")
}

// DisableTOTP clears the user's secret, backup codes, and any pending enrollment.
func (db *DB) DisableTOTP(uid int64) error {
	_, err := db.exec(`UPDATE admin_users SET totp_secret = '', totp_pending_secret = '',
		totp_backup_codes = '', totp_last_counter = '' WHERE id = ?`, uid)
	return err
}

// ConsumeTOTPBackupCode removes hash from the user's backup codes and reports
// whether it was present — each code works exactly once.
func (db *DB) ConsumeTOTPBackupCode(uid int64, hash string) (bool, error) {
	stored, err := db.userField(uid, "totp_backup_codes")
	if err != nil || stored == "" {
		return false, err
	}
	codes := strings.Split(stored, ",")
	for i, c := range codes {
		if c == hash {
			codes = append(codes[:i], codes[i+1:]...)
			return true, db.setUserField(uid, "totp_backup_codes", strings.Join(codes, ","))
		}
	}
	return false, nil
}

// GetTOTPLastCounter returns the counter of the user's last accepted TOTP
// code (0 when none has been accepted yet).
func (db *DB) GetTOTPLastCounter(uid int64) (uint64, error) {
	v, err := db.userField(uid, "totp_last_counter")
	if err != nil || v == "" {
		return 0, err
	}
	n, parseErr := strconv.ParseUint(v, 10, 64)
	if parseErr != nil {
		return 0, nil
	}
	return n, nil
}

// SetTOTPLastCounter records the counter of an accepted code so the same
// code can't be replayed within its validity window.
func (db *DB) SetTOTPLastCounter(uid int64, counter uint64) error {
	return db.setUserField(uid, "totp_last_counter", strconv.FormatUint(counter, 10))
}
