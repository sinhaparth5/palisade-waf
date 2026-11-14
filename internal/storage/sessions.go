package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"time"
)

// ── Admin auth & sessions ─────────────────────────────────────────────────────
//
// Accounts live in admin_users (users.go); everything below is per user.

const sessionTTL = 24 * time.Hour

// sessionHistoryTTL is how long a session row survives after it was
// created. It is deliberately much longer than sessionTTL: a row stops
// authenticating anything after sessionTTL, but is kept as the device
// history the Settings page's "Registered devices" card lists, so a user
// can still see where the account was logged in last month.
const sessionHistoryTTL = 30 * 24 * time.Hour

// PruneExpiredSessions deletes session rows past sessionHistoryTTL and
// returns how many were removed — without it, rows would accumulate
// forever. created_at is RFC3339 UTC, which compares chronologically as a
// plain string, so no SQLite date functions are needed (see the date/time
// gotcha in CLAUDE.md).
func (db *DB) PruneExpiredSessions() (int64, error) {
	cutoff := time.Now().UTC().Add(-sessionHistoryTTL).Format(time.RFC3339)
	res, err := db.exec(`DELETE FROM sessions WHERE created_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Session is one row of the sessions table: a single login of one user on
// a single device.
type Session struct {
	// ID is SHA-256 of the cookie token (see SessionID): what the sessions
	// table stores and what device-list links carry. It can't be used to
	// sign in (#269).
	ID           string
	UserID       int64
	CreatedAt    time.Time
	IP           string
	UserAgent    string
	LastActiveAt time.Time
	RevokedAt    time.Time // zero value = never revoked
}

// Revoked reports whether the session was explicitly ended — by logging
// out, by being revoked from the Settings page, or by being superseded by a
// newer login. Distinct from Expired so the login page can tell the user
// which of the two happened.
func (s *Session) Revoked() bool { return !s.RevokedAt.IsZero() }

// Expired reports whether the session aged out of sessionTTL.
func (s *Session) Expired() bool { return time.Since(s.CreatedAt) >= sessionTTL }

// Live reports whether the session still authenticates requests.
func (s *Session) Live() bool { return !s.Revoked() && !s.Expired() }

// parseSessionTime maps the empty string (a column default, i.e. "never")
// onto the zero time rather than an error.
func parseSessionTime(v string) time.Time {
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t
}

const sessionColumns = `token, user_id, created_at, ip, user_agent, last_active_at, revoked_at`

func scanSession(row interface{ Scan(...any) error }) (*Session, error) {
	var s Session
	var created, lastActive, revoked string
	if err := row.Scan(&s.ID, &s.UserID, &created, &s.IP, &s.UserAgent, &lastActive, &revoked); err != nil {
		return nil, err
	}
	s.CreatedAt = parseSessionTime(created)
	s.LastActiveAt = parseSessionTime(lastActive)
	s.RevokedAt = parseSessionTime(revoked)
	return &s, nil
}

// SessionID maps a session cookie token to the id its row is stored under.
// Plain SHA-256, like API keys: the token is 256 random bits, so there is
// nothing for a slow hash to protect.
func SessionID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// metaKeySessionsHashed marks that sessions.token holds SessionID values.
const metaKeySessionsHashed = "sessions_hashed"

// hashSessionTokens rewrites raw tokens left by a version before #269 as
// their SessionID, once, so an upgrade signs nobody out. A raw token and its
// hash look alike (64 hex chars), hence the meta marker; one transaction, so
// a crash can't leave rows hashed without the marker and hash them twice.
func (db *DB) hashSessionTokens() error {
	if v, err := db.getMeta(metaKeySessionsHashed); err != nil || v != "" {
		return err
	}
	rows, err := db.query(`SELECT token FROM sessions`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var tokens []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return err
		}
		tokens = append(tokens, t)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	tx, err := db.conn.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	for _, t := range tokens {
		if _, err := tx.ExecContext(context.Background(), `UPDATE sessions SET token = ? WHERE token = ?`, SessionID(t), t); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(context.Background(),
		upsertUpdate("meta", []string{"key", "value"}, "?, ?", []string{"key"}, []string{"value"}),
		metaKeySessionsHashed, "1"); err != nil {
		return err
	}
	return tx.Commit()
}

// CreateSession generates a random token for user uid, stores its SessionID,
// and returns the token for use as a session cookie value.
//
// deviceID is the browser's long-lived device cookie (see ui.deviceCookie).
// A login replaces that device's earlier rows for the same user instead of
// adding another, so the "Registered devices" card lists each browser
// once, not once per login. Rows from before device IDs existed are matched
// on identical IP + user agent.
//
// Each user may only have one live session at a time, so this first
// revokes the user's sessions that are currently live: logging in on a new
// device immediately signs the old one out, and the old device is told why
// on its next request (see Session.Revoked). The legitimate owner of an
// account can therefore always take it back from someone else sitting on
// it — the alternative (refusing the new login while an old session lives)
// locks them out until the intruder's session happens to expire. Other
// users' sessions are untouched.
func (db *DB) CreateSession(uid int64, ip, userAgent, deviceID string) (string, error) {
	return db.createSession(uid, ip, userAgent, deviceID, true)
}

// CreateSharedSession is CreateSession without signing out the user's
// other sessions, for the --demo account that many visitors share.
func (db *DB) CreateSharedSession(uid int64, ip, userAgent, deviceID string) (string, error) {
	return db.createSession(uid, ip, userAgent, deviceID, false)
}

func (db *DB) createSession(uid int64, ip, userAgent, deviceID string, revokeOthers bool) (string, error) {
	// Opportunistically sweep aged-out rows — logins are the only way the
	// table grows, so pruning here keeps it bounded without a background
	// goroutine (the prune CLI covers deployments that never log in again).
	if _, err := db.PruneExpiredSessions(); err != nil {
		log.Printf("session prune: %v", err)
	}
	b := make([]byte, 32)
	rand.Read(b) //nolint — never errors on modern platforms
	token := hex.EncodeToString(b)
	now := time.Now().UTC().Format(time.RFC3339)
	if deviceID != "" {
		if _, err := db.exec(
			`DELETE FROM sessions WHERE user_id = ? AND (device_id = ? OR (device_id = '' AND ip = ? AND user_agent = ?))`,
			uid, deviceID, ip, userAgent,
		); err != nil {
			return "", err
		}
	}
	if revokeOthers {
		if _, err := db.exec(`UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at = ''`, now, uid); err != nil {
			return "", err
		}
	}
	_, err := db.exec(
		`INSERT INTO sessions (token, user_id, created_at, ip, user_agent, last_active_at, revoked_at, device_id)
		 VALUES (?, ?, ?, ?, ?, ?, '', ?)`,
		SessionID(token), uid, now, ip, userAgent, now, deviceID,
	)
	return token, err
}

// GetSession returns the row for a cookie token, or nil if there is none. Whether
// the session still authenticates anything is the caller's decision — see
// Session.Live/Revoked/Expired, which the login page uses to explain to a
// signed-out user which of the two happened.
func (db *DB) GetSession(token string) (*Session, error) {
	return db.GetSessionByID(SessionID(token))
}

// GetSessionByID is GetSession for a Session.ID, e.g. from a device-list
// link.
func (db *DB) GetSessionByID(id string) (*Session, error) {
	s, err := scanSession(db.queryRow(`SELECT `+sessionColumns+` FROM sessions WHERE token = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return s, err
}

// ValidateSession reports whether the cookie token authenticates a request.
func (db *DB) ValidateSession(token string) (bool, error) {
	s, err := db.GetSession(token)
	if err != nil || s == nil {
		return false, err
	}
	return s.Live(), nil
}

// TouchSession records that the session was just used. Called off the hot
// path and throttled by the caller, like TouchAPIKey. Like the functions
// below it takes a Session.ID, not a cookie token.
func (db *DB) TouchSession(id string) error {
	_, err := db.exec(
		`UPDATE sessions SET last_active_at = ? WHERE token = ?`,
		time.Now().UTC().Format(time.RFC3339), id,
	)
	return err
}

// ListSessions returns the user's session rows for the Settings page's
// "Registered devices" card: the live session first (which, given one live
// session per user is enforced at login, is the caller's own device), then
// signed-out devices newest first. Without the boolean order, two logins
// landing in the same RFC3339 second could list the current device below a
// dead one.
func (db *DB) ListSessions(uid int64) ([]Session, error) {
	rows, err := db.query(
		`SELECT `+sessionColumns+` FROM sessions WHERE user_id = ?
		 ORDER BY (revoked_at = '') DESC, created_at DESC`, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// RevokeSession ends one of the user's sessions without deleting its
// history row.
func (db *DB) RevokeSession(uid int64, id string) error {
	_, err := db.exec(
		`UPDATE sessions SET revoked_at = ? WHERE token = ? AND user_id = ? AND revoked_at = ''`,
		time.Now().UTC().Format(time.RFC3339), id, uid,
	)
	return err
}

// RevokeOtherSessions ends every live session of the user except keep.
// With one live session per user enforced at login this is normally a
// no-op, and exists for the "Log out of all other devices" button to be
// honest anyway — a row could still be live if it was created before this
// rule shipped.
func (db *DB) RevokeOtherSessions(uid int64, keep string) (int64, error) {
	res, err := db.exec(
		`UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at = '' AND token <> ?`,
		time.Now().UTC().Format(time.RFC3339), uid, keep,
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteSession removes the row on logout. Logging out deliberately drops
// the row rather than revoking it: a user who signs out on purpose does
// not need that device listed back at them as history.
func (db *DB) DeleteSession(id string) error {
	_, err := db.exec(`DELETE FROM sessions WHERE token = ?`, id)
	return err
}
