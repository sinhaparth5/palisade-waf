package storage

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ── Admin users (issue #196) ─────────────────────────────────────────────────
//
// Each admin account is one admin_users row holding its credentials, role
// and second-factor state (the TOTP fields are the old admin_totp_* meta
// keys, per user). Sessions and passkeys point at it by user_id.

// The fixed roles, most to least privileged. There is no custom role
// builder: owner manages users, DB connection, secrets and API keys; admin
// everything else; viewer is read-only.
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

// ValidRole reports whether r is one of the fixed roles.
func ValidRole(r string) bool { return r == RoleOwner || r == RoleAdmin || r == RoleViewer }

var (
	// ErrLastOwner refuses a change that would leave no owner able to sign
	// in, and with it nobody able to manage users.
	ErrLastOwner = errors.New("the last owner can't be demoted, disabled or deleted")
	// ErrUserExists is returned when an email is already taken.
	ErrUserExists = errors.New("a user with that email already exists")
)

// AdminUser is one admin account. The password hash and TOTP secrets stay
// in the table; only what the UI shows is loaded.
type AdminUser struct {
	ID          int64
	Email       string
	Role        string
	Disabled    bool
	TOTPEnabled bool
	SSO         bool // bound to an IdP identity (issue #197); has no password
	Invited     bool // hasn't set a password from their invite link yet (issue #229)
	CreatedAt   time.Time
}

// NormalizeEmail is the form emails are stored and looked up in, so login
// is case-insensitive on every dialect (MySQL's collation already was).
func NormalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

const adminUserColumns = `id, email, role, disabled, totp_secret <> '',
	(SELECT COUNT(*) FROM admin_sso_identities i WHERE i.user_id = admin_users.id) > 0,
	(SELECT COUNT(*) FROM admin_user_invites v WHERE v.user_id = admin_users.id) > 0, created_at`

func scanAdminUser(row interface{ Scan(...any) error }) (*AdminUser, error) {
	var u AdminUser
	err := row.Scan(&u.ID, &u.Email, &u.Role, &u.Disabled, &u.TOTPEnabled, &u.SSO, &u.Invited, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// GetAdminUser returns the user with id, or nil if there is none.
func (db *DB) GetAdminUser(id int64) (*AdminUser, error) {
	return scanAdminUser(db.queryRow(`SELECT `+adminUserColumns+` FROM admin_users WHERE id = ?`, id))
}

// GetAdminUserByEmail returns the user with email, or nil if there is none.
func (db *DB) GetAdminUserByEmail(email string) (*AdminUser, error) {
	return scanAdminUser(db.queryRow(`SELECT `+adminUserColumns+` FROM admin_users WHERE email = ?`, NormalizeEmail(email)))
}

// ListAdminUsers returns every user, oldest first.
func (db *DB) ListAdminUsers() ([]AdminUser, error) {
	rows, err := db.query(`SELECT ` + adminUserColumns + ` FROM admin_users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminUser
	for rows.Next() {
		u, err := scanAdminUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// CountAdminUsers returns how many accounts exist, disabled ones included.
func (db *DB) CountAdminUsers() (int, error) {
	var n int
	err := db.queryRow(`SELECT COUNT(*) FROM admin_users`).Scan(&n)
	return n, err
}

// CreateAdminUser adds an account with an initial password.
func (db *DB) CreateAdminUser(email, password, role string) (int64, error) {
	if !ValidRole(role) {
		return 0, fmt.Errorf("invalid role %q", role)
	}
	email = NormalizeEmail(email)
	if u, err := db.GetAdminUserByEmail(email); err != nil {
		return 0, err
	} else if u != nil {
		return 0, ErrUserExists
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, fmt.Errorf("hash password: %w", err)
	}
	return db.insertReturningID(
		`INSERT INTO admin_users (email, password_hash, role, created_at) VALUES (?, ?, ?, ?)`,
		email, string(hash), role, time.Now(),
	)
}

// dummyHash is compared against when no usable account matches, so a
// login for an unknown or disabled email costs the same bcrypt time as a
// real one and timing can't enumerate accounts.
var dummyHash = sync.OnceValue(func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte("palisade-dummy"), bcrypt.DefaultCost)
	return h
})

// CheckAdminLogin returns the enabled user whose email and password match,
// or nil for any mismatch — callers can't tell "no such user" from "wrong
// password", which avoids leaking which emails are registered.
func (db *DB) CheckAdminLogin(email, password string) (*AdminUser, error) {
	u, err := db.GetAdminUserByEmail(email)
	if err != nil {
		return nil, err
	}
	hash := dummyHash()
	if u != nil && !u.Disabled {
		stored, err := db.userField(u.ID, "password_hash")
		if err != nil {
			return nil, err
		}
		hash = []byte(stored)
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil || u == nil || u.Disabled {
		return nil, nil
	}
	return u, nil
}

// CheckAdminPassword reports whether password is user id's current one.
func (db *DB) CheckAdminPassword(id int64, password string) (bool, error) {
	hash, err := db.userField(id, "password_hash")
	if err != nil || hash == "" {
		return false, err
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil, nil
}

// SeedAdmin creates the owner account from the CLI setup subcommand.
// Idempotent: once any account exists it does nothing, so re-running the
// installer never overwrites a password.
func (db *DB) SeedAdmin(email, password string) error {
	n, err := db.CountAdminUsers()
	if err != nil {
		return err
	}
	if n > 0 {
		log.Printf("admin accounts already exist — skipping")
		return nil
	}
	_, err = db.CreateAdminUser(email, password, RoleOwner)
	return err
}

// UpdateAdminCredentials replaces user id's email and/or password. Pass ""
// to leave either unchanged. The user's sessions are deleted so none can
// outlive the old credentials.
func (db *DB) UpdateAdminCredentials(id int64, email, newPassword string) error {
	if email != "" {
		email = NormalizeEmail(email)
		if u, err := db.GetAdminUserByEmail(email); err != nil {
			return err
		} else if u != nil && u.ID != id {
			return ErrUserExists
		}
		if err := db.setUserField(id, "email", email); err != nil {
			return err
		}
	}
	if newPassword != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}
		if err := db.setUserField(id, "password_hash", string(hash)); err != nil {
			return err
		}
	}
	_, err := db.exec(`DELETE FROM sessions WHERE user_id = ?`, id)
	return err
}

// guardLastOwner returns ErrLastOwner when id is the only enabled owner,
// i.e. demoting, disabling or deleting it would leave nobody able to
// manage users.
func (db *DB) guardLastOwner(id int64) error {
	u, err := db.GetAdminUser(id)
	if err != nil || u == nil || u.Role != RoleOwner || u.Disabled {
		return err
	}
	var others int
	if err := db.queryRow(
		`SELECT COUNT(*) FROM admin_users WHERE role = ? AND disabled = 0 AND id <> ?`, RoleOwner, id,
	).Scan(&others); err != nil {
		return err
	}
	if others == 0 {
		return ErrLastOwner
	}
	return nil
}

// SetAdminUserRole changes a user's role.
func (db *DB) SetAdminUserRole(id int64, role string) error {
	if !ValidRole(role) {
		return fmt.Errorf("invalid role %q", role)
	}
	if role != RoleOwner {
		if err := db.guardLastOwner(id); err != nil {
			return err
		}
	}
	return db.setUserField(id, "role", role)
}

// SetAdminUserDisabled disables or re-enables a user. Disabling revokes the
// user's sessions at once.
func (db *DB) SetAdminUserDisabled(id int64, disabled bool) error {
	if disabled {
		if err := db.guardLastOwner(id); err != nil {
			return err
		}
	}
	if _, err := db.exec(`UPDATE admin_users SET disabled = ? WHERE id = ?`, boolToInt(disabled), id); err != nil {
		return err
	}
	if !disabled {
		return nil
	}
	return db.RevokeUserSessions(id)
}

// DeleteAdminUser removes a user with its sessions and passkeys.
func (db *DB) DeleteAdminUser(id int64) error {
	if err := db.guardLastOwner(id); err != nil {
		return err
	}
	for _, q := range []string{
		`DELETE FROM sessions WHERE user_id = ?`,
		`DELETE FROM webauthn_credentials WHERE user_id = ?`,
		`DELETE FROM admin_sso_identities WHERE user_id = ?`,
		`DELETE FROM admin_user_invites WHERE user_id = ?`,
		`DELETE FROM admin_users WHERE id = ?`,
	} {
		if _, err := db.exec(q, id); err != nil {
			return err
		}
	}
	return nil
}

// ResetAdminUser2FA turns off a user's TOTP and removes their passkeys, for
// someone who lost their authenticator. Their password still works.
func (db *DB) ResetAdminUser2FA(id int64) error {
	if err := db.DisableTOTP(id); err != nil {
		return err
	}
	_, err := db.exec(`DELETE FROM webauthn_credentials WHERE user_id = ?`, id)
	return err
}

// userField / setUserField read and write one admin_users column. col is
// always a literal from this package, never input.
func (db *DB) userField(id int64, col string) (string, error) {
	var v string
	err := db.queryRow(`SELECT `+col+` FROM admin_users WHERE id = ?`, id).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (db *DB) setUserField(id int64, col, v string) error {
	_, err := db.exec(`UPDATE admin_users SET `+col+` = ? WHERE id = ?`, v, id)
	return err
}

// getSecretUserField / setSecretUserField are the sealed twins, like
// getSecretMeta/setSecretMeta, for the TOTP secret columns.
func (db *DB) getSecretUserField(id int64, col string) (string, error) {
	v, err := db.userField(id, col)
	if err != nil || v == "" {
		return v, err
	}
	plain, err := db.openSecret(v)
	if err != nil {
		return "", fmt.Errorf("admin_users.%s: %w", col, err)
	}
	return plain, nil
}

func (db *DB) setSecretUserField(id int64, col, v string) error {
	sealed, err := db.sealSecret(v)
	if err != nil {
		return err
	}
	return db.setUserField(id, col, sealed)
}

// secretUserColumns are the admin_users columns that hold sealed secrets;
// migrateSecrets seals plaintext values in them.
var secretUserColumns = []string{"totp_secret", "totp_pending_secret"}

// legacyAdminMetaKeys is the single-admin account as it lived in meta before
// admin_users existed.
var legacyAdminMetaKeys = []string{
	"admin_email", "admin_password_hash", "admin_totp_secret", "admin_totp_pending_secret",
	"admin_totp_backup_codes", "admin_totp_last_counter", "admin_webauthn_handle",
}

// migrateAdminFromMeta moves the pre-#196 meta account into admin_users as
// the owner and hands it the existing sessions and passkeys, so an upgrade
// changes nothing for the person signing in. Sealed TOTP values are copied
// as stored: same key, same format. The meta keys are then deleted so no
// stale secret lingers.
func (db *DB) migrateAdminFromMeta() error {
	n, err := db.CountAdminUsers()
	if err != nil || n > 0 {
		return err
	}
	m := make(map[string]string, len(legacyAdminMetaKeys))
	for _, k := range legacyAdminMetaKeys {
		if m[k], err = db.getMeta(k); err != nil {
			return err
		}
	}
	if m["admin_email"] == "" {
		return nil
	}
	id, err := db.insertReturningID(
		`INSERT INTO admin_users (email, password_hash, role, totp_secret, totp_pending_secret,
		 totp_backup_codes, totp_last_counter, webauthn_handle, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		NormalizeEmail(m["admin_email"]), m["admin_password_hash"], RoleOwner, m["admin_totp_secret"],
		m["admin_totp_pending_secret"], m["admin_totp_backup_codes"], m["admin_totp_last_counter"],
		m["admin_webauthn_handle"], time.Now(),
	)
	if err != nil {
		return fmt.Errorf("move admin account: %w", err)
	}
	for _, t := range []string{"sessions", "webauthn_credentials"} {
		if _, err := db.exec(`UPDATE `+t+` SET user_id = ? WHERE user_id = 0`, id); err != nil {
			return err
		}
	}
	_, err = db.exec(`DELETE FROM meta WHERE `+db.dialect.quoteIdent("key")+` IN (`+placeholders(len(legacyAdminMetaKeys))+`)`,
		toAny(legacyAdminMetaKeys)...)
	return err
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// ── Password invites (issue #229) ────────────────────────────────────────────
//
// An invited user is an admin_users row with no password plus one
// admin_user_invites row. The token goes out in the invite email; only its
// SHA-256 is stored (it's 32 random bytes, so no bcrypt needed).

// UserInviteTTL is how long an invite link works.
const UserInviteTTL = 7 * 24 * time.Hour

func hashInviteToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// InviteAdminUser creates a password-less user with role and returns its
// id and invite token.
func (db *DB) InviteAdminUser(email, role string) (int64, string, error) {
	if !ValidRole(role) {
		return 0, "", fmt.Errorf("invalid role %q", role)
	}
	email = NormalizeEmail(email)
	if u, err := db.GetAdminUserByEmail(email); err != nil {
		return 0, "", err
	} else if u != nil {
		return 0, "", ErrUserExists
	}
	id, err := db.insertReturningID(`INSERT INTO admin_users (email, password_hash, role, created_at) VALUES (?, '', ?, ?)`,
		email, role, time.Now())
	if err != nil {
		return 0, "", err
	}
	token, err := db.setUserInvite(id)
	return id, token, err
}

// RenewUserInvite gives a pending user a fresh token and expiry; the old
// link stops working.
func (db *DB) RenewUserInvite(id int64) (string, error) {
	u, err := db.GetAdminUser(id)
	if err != nil {
		return "", err
	}
	if u == nil || !u.Invited {
		return "", errors.New("that user has already set a password")
	}
	return db.setUserInvite(id)
}

func (db *DB) setUserInvite(id int64) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	if _, err := db.exec(`DELETE FROM admin_user_invites WHERE user_id = ?`, id); err != nil {
		return "", err
	}
	_, err := db.exec(`INSERT INTO admin_user_invites (user_id, token_hash, expires_at) VALUES (?, ?, ?)`,
		id, hashInviteToken(token), time.Now().UTC().Add(UserInviteTTL))
	return token, err
}

// UserInvite returns the enabled user a live token belongs to, or nil for
// an unknown, spent or expired one.
func (db *DB) UserInvite(token string) (*AdminUser, error) {
	var id int64
	var expires time.Time
	err := db.queryRow(`SELECT user_id, expires_at FROM admin_user_invites WHERE token_hash = ?`, hashInviteToken(token)).Scan(&id, &expires)
	if err == sql.ErrNoRows || (err == nil && time.Now().After(expires)) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u, err := db.GetAdminUser(id)
	if u != nil && u.Disabled {
		return nil, err
	}
	return u, err
}

// AcceptUserInvite spends a live token and sets the user's password.
// Returns nil with no error when the token isn't live.
func (db *DB) AcceptUserInvite(token, password string) (*AdminUser, error) {
	u, err := db.UserInvite(token)
	if err != nil || u == nil {
		return nil, err
	}
	// Claim the token by deleting it, so two submits can't both spend it.
	res, err := db.exec(`DELETE FROM admin_user_invites WHERE token_hash = ?`, hashInviteToken(token))
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, nil
	}
	if err := db.UpdateAdminCredentials(u.ID, "", password); err != nil {
		return nil, err
	}
	u.Invited = false
	return u, nil
}
