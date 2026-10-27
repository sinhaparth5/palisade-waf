package storage

import (
	"database/sql"
	"fmt"
	"time"
)

// ── OIDC single sign-on (issue #197) ─────────────────────────────────────────
//
// Invite-only: the IdP proves who someone is, an owner's invite decides
// whether they get in and with which role. The first SSO login spends the
// invite, creates the user and binds it to the token's iss+sub in
// admin_sso_identities; later logins match on that pair, never on email.

// SSOConfig is the Settings → Single sign-on card. An empty Issuer means
// SSO is off.
type SSOConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	Group        string // required "groups" claim value; "" = no group gate
}

// SSOInviteTTL is how long an invite stays usable after it is sent or renewed.
const SSOInviteTTL = 7 * 24 * time.Hour

// SSOInvite is a pending invite: deleted when used or revoked.
type SSOInvite struct {
	ID        int64
	Email     string
	Role      string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// Expired reports whether the invite can no longer be used.
func (i SSOInvite) Expired() bool { return time.Now().After(i.ExpiresAt) }

func (db *DB) GetSSOConfig() (SSOConfig, error) {
	var c SSOConfig
	var err error
	for k, p := range map[string]*string{"sso_issuer": &c.Issuer, "sso_client_id": &c.ClientID, "sso_group": &c.Group} {
		if *p, err = db.getMeta(k); err != nil {
			return SSOConfig{}, err
		}
	}
	if c.ClientSecret, err = db.getSecretMeta("sso_client_secret"); err != nil {
		return SSOConfig{}, err
	}
	return c, nil
}

func (db *DB) SetSSOConfig(c SSOConfig) error {
	for k, v := range map[string]string{"sso_issuer": c.Issuer, "sso_client_id": c.ClientID, "sso_group": c.Group} {
		if err := db.setMeta(k, v); err != nil {
			return err
		}
	}
	return db.setSecretMeta("sso_client_secret", c.ClientSecret)
}

// CreateSSOInvite invites email with role, or renews the pending invite for
// that email with the new role.
func (db *DB) CreateSSOInvite(email, role string) error {
	if !ValidRole(role) {
		return fmt.Errorf("invalid role %q", role)
	}
	email = NormalizeEmail(email)
	if u, err := db.GetAdminUserByEmail(email); err != nil {
		return err
	} else if u != nil {
		return ErrUserExists
	}
	if _, err := db.exec(`DELETE FROM admin_sso_invites WHERE email = ?`, email); err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err := db.exec(`INSERT INTO admin_sso_invites (email, role, expires_at, created_at) VALUES (?, ?, ?, ?)`,
		email, role, now.Add(SSOInviteTTL), now)
	return err
}

// ListSSOInvites returns every pending invite, expired ones included so the
// owner can renew them.
func (db *DB) ListSSOInvites() ([]SSOInvite, error) {
	rows, err := db.query(`SELECT id, email, role, expires_at, created_at FROM admin_sso_invites ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SSOInvite
	for rows.Next() {
		var i SSOInvite
		if err := rows.Scan(&i.ID, &i.Email, &i.Role, &i.ExpiresAt, &i.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// RenewSSOInvite restarts an invite's expiry from now.
func (db *DB) RenewSSOInvite(id int64) error {
	_, err := db.exec(`UPDATE admin_sso_invites SET expires_at = ? WHERE id = ?`, time.Now().UTC().Add(SSOInviteTTL), id)
	return err
}

// DeleteSSOInvite revokes a pending invite.
func (db *DB) DeleteSSOInvite(id int64) error {
	_, err := db.exec(`DELETE FROM admin_sso_invites WHERE id = ?`, id)
	return err
}

// SSOUser returns the user bound to issuer+subject, or nil if none is.
func (db *DB) SSOUser(issuer, subject string) (*AdminUser, error) {
	var id int64
	err := db.queryRow(`SELECT user_id FROM admin_sso_identities WHERE issuer = ? AND subject = ?`, issuer, subject).Scan(&id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return db.GetAdminUser(id)
}

// AcceptSSOInvite spends the live invite for email: it creates the user
// with the invite's role and no password, bound to issuer+subject. Returns
// nil with no error when there is no live invite (none, revoked, used or
// expired).
func (db *DB) AcceptSSOInvite(email, issuer, subject string) (*AdminUser, error) {
	email = NormalizeEmail(email)
	var inv SSOInvite
	err := db.queryRow(`SELECT id, role, expires_at FROM admin_sso_invites WHERE email = ?`, email).Scan(&inv.ID, &inv.Role, &inv.ExpiresAt)
	if err == sql.ErrNoRows || (err == nil && inv.Expired()) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Claim the invite by deleting it, so two concurrent callbacks can't
	// both spend it.
	res, err := db.exec(`DELETE FROM admin_sso_invites WHERE id = ?`, inv.ID)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, nil
	}
	if u, err := db.GetAdminUserByEmail(email); err != nil || u != nil {
		// A password user took the email after the invite was sent.
		return nil, err
	}
	id, err := db.insertReturningID(`INSERT INTO admin_users (email, password_hash, role, created_at) VALUES (?, '', ?, ?)`,
		email, inv.Role, time.Now())
	if err != nil {
		return nil, err
	}
	if _, err := db.exec(`INSERT INTO admin_sso_identities (user_id, issuer, subject) VALUES (?, ?, ?)`, id, issuer, subject); err != nil {
		db.exec(`DELETE FROM admin_users WHERE id = ?`, id) //nolint — best-effort rollback; the insert error is what matters
		return nil, err
	}
	return db.GetAdminUser(id)
}

// RevokeUserSessions signs a user out everywhere.
func (db *DB) RevokeUserSessions(id int64) error {
	_, err := db.exec(`UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at = ''`,
		time.Now().UTC().Format(time.RFC3339), id)
	return err
}

func migrateSSOIdentitiesTable(source, target *DB, _ bool) (int, error) {
	rows, err := source.query(`SELECT user_id, issuer, subject FROM admin_sso_identities`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id int64
		var iss, sub string
		if err := rows.Scan(&id, &iss, &sub); err != nil {
			return n, err
		}
		if _, err := target.exec(`INSERT INTO admin_sso_identities (user_id, issuer, subject) VALUES (?, ?, ?)`, id, iss, sub); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}
