package storage

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// testUser creates an owner account for tests that need a user id.
func testUser(t *testing.T, db *DB) int64 {
	t.Helper()
	id, err := db.CreateAdminUser("owner@x.test", "owner-password", RoleOwner)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestMigrateAdminFromMeta is the upgrade path: a pre-#196 single-admin DB
// becomes one owner holding the same password, 2FA, sessions and passkeys.
func TestMigrateAdminFromMeta(t *testing.T) {
	db := openTestDB(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("legacy-password"), bcrypt.MinCost)
	for k, v := range map[string]string{
		"admin_email":             "Legacy@X.test",
		"admin_password_hash":     string(hash),
		"admin_totp_secret":       "LEGACYSECRET",
		"admin_totp_backup_codes": "b1,b2",
		"admin_totp_last_counter": "42",
		"admin_webauthn_handle":   "aGFuZGxl",
	} {
		mustNoErr(t, db.setMeta(k, v))
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.exec(`INSERT INTO sessions (token, created_at) VALUES (?, ?)`, SessionID("legacy-token"), now)
	mustNoErr(t, err)
	mustNoErr(t, db.AddWebAuthnCredential(0, "legacy-cred", "Key", []byte(`{}`)))

	mustNoErr(t, db.migrateAdminFromMeta())

	u, err := db.CheckAdminLogin("legacy@x.test", "legacy-password")
	if err != nil || u == nil || u.Role != RoleOwner {
		t.Fatalf("migrated login = %+v, %v; want the owner", u, err)
	}
	if secret, _ := db.GetTOTPSecret(u.ID); secret != "LEGACYSECRET" {
		t.Errorf("TOTP secret = %q", secret)
	}
	if n, _ := db.GetTOTPLastCounter(u.ID); n != 42 {
		t.Errorf("last counter = %d", n)
	}
	if used, _ := db.ConsumeTOTPBackupCode(u.ID, "b2"); !used {
		t.Error("backup code lost")
	}
	if s, _ := db.GetSession("legacy-token"); s == nil || s.UserID != u.ID {
		t.Errorf("session = %+v, want it moved to the owner", s)
	}
	if en, _ := db.WebAuthnEnabled(u.ID); !en {
		t.Error("passkey not moved to the owner")
	}
	for _, k := range legacyAdminMetaKeys {
		if v, _ := db.getMeta(k); v != "" {
			t.Errorf("meta %s still holds %q", k, v)
		}
	}
	// Idempotent: a second run (every restart) adds nothing.
	mustNoErr(t, db.migrateAdminFromMeta())
	if n, _ := db.CountAdminUsers(); n != 1 {
		t.Errorf("users after rerun = %d, want 1", n)
	}
}

func TestLastOwnerGuard(t *testing.T) {
	db := openTestDB(t)
	owner := testUser(t, db)
	for name, err := range map[string]error{
		"demote":  db.SetAdminUserRole(owner, RoleAdmin),
		"disable": db.SetAdminUserDisabled(owner, true),
		"delete":  db.DeleteAdminUser(owner),
	} {
		if !errors.Is(err, ErrLastOwner) {
			t.Errorf("%s last owner: err = %v, want ErrLastOwner", name, err)
		}
	}

	// A disabled second owner can't sign in, so it doesn't count.
	second, err := db.CreateAdminUser("second@x.test", "second-password", RoleOwner)
	mustNoErr(t, err)
	mustNoErr(t, db.SetAdminUserDisabled(second, true))
	if err := db.SetAdminUserRole(owner, RoleViewer); !errors.Is(err, ErrLastOwner) {
		t.Errorf("demote with only a disabled second owner: err = %v", err)
	}
	mustNoErr(t, db.SetAdminUserDisabled(second, false))
	mustNoErr(t, db.SetAdminUserRole(owner, RoleViewer))
	if err := db.DeleteAdminUser(second); !errors.Is(err, ErrLastOwner) {
		t.Errorf("delete the remaining owner: err = %v", err)
	}
}

// TestUsersHaveIndependentSessions: one live session per user, not per
// deployment, and disabling a user signs out only them.
func TestUsersHaveIndependentSessions(t *testing.T) {
	db := openTestDB(t)
	owner := testUser(t, db)
	viewer, err := db.CreateAdminUser("viewer@x.test", "viewer-password", RoleViewer)
	mustNoErr(t, err)

	a, err := db.CreateSession(owner, "10.0.0.1", "ua", "")
	mustNoErr(t, err)
	b, err := db.CreateSession(viewer, "10.0.0.2", "ua", "")
	mustNoErr(t, err)
	for _, tok := range []string{a, b} {
		if ok, _ := db.ValidateSession(tok); !ok {
			t.Fatalf("session %s not live with two users signed in", tok[:8])
		}
	}
	if rows, _ := db.ListSessions(owner); len(rows) != 1 || rows[0].ID != SessionID(a) {
		t.Errorf("owner's device list = %+v, want only their own session", rows)
	}

	mustNoErr(t, db.SetAdminUserDisabled(viewer, true))
	if ok, _ := db.ValidateSession(b); ok {
		t.Error("disabled user's session still live")
	}
	if ok, _ := db.ValidateSession(a); !ok {
		t.Error("disabling the viewer signed out the owner")
	}
	if u, _ := db.CheckAdminLogin("viewer@x.test", "viewer-password"); u != nil {
		t.Error("disabled user can still log in")
	}
}

func TestCheckAdminLoginAndCreate(t *testing.T) {
	db := openTestDB(t)
	testUser(t, db)
	for _, tc := range []struct {
		email, password string
		ok              bool
	}{
		{"owner@x.test", "owner-password", true},
		{" OWNER@x.test ", "owner-password", true},
		{"owner@x.test", "wrong", false},
		{"nobody@x.test", "owner-password", false},
	} {
		u, err := db.CheckAdminLogin(tc.email, tc.password)
		if err != nil || (u != nil) != tc.ok {
			t.Errorf("CheckAdminLogin(%q, %q) = %+v, %v; want ok=%v", tc.email, tc.password, u, err, tc.ok)
		}
	}
	if _, err := db.CreateAdminUser("Owner@x.test", "pw-12345678", RoleViewer); !errors.Is(err, ErrUserExists) {
		t.Errorf("duplicate email: err = %v, want ErrUserExists", err)
	}
	if _, err := db.CreateAdminUser("new@x.test", "pw-12345678", "superuser"); err == nil {
		t.Error("invalid role accepted")
	}
}

// TestUserInviteLifecycle: an invite token is single use, dies on expiry,
// on disable and with its user (issue #229).
func TestUserInviteLifecycle(t *testing.T) {
	db := openTestDB(t)
	id, token, err := db.InviteAdminUser("New@x.test", RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.InviteAdminUser("new@x.test", RoleViewer); !errors.Is(err, ErrUserExists) {
		t.Errorf("duplicate invite err = %v", err)
	}
	if u, _ := db.UserInvite(token); u == nil || u.ID != id || !u.Invited {
		t.Fatalf("UserInvite = %+v", u)
	}
	if u, _ := db.UserInvite("not-a-token"); u != nil {
		t.Error("unknown token accepted")
	}

	// Disabled users can't redeem.
	_ = db.SetAdminUserDisabled(id, true)
	if u, _ := db.AcceptUserInvite(token, "password-1"); u != nil {
		t.Error("disabled user redeemed an invite")
	}
	_ = db.SetAdminUserDisabled(id, false)

	// Expired.
	if _, err := db.exec(`UPDATE admin_user_invites SET expires_at = ? WHERE user_id = ?`, time.Now().Add(-time.Minute), id); err != nil {
		t.Fatal(err)
	}
	if u, _ := db.AcceptUserInvite(token, "password-1"); u != nil {
		t.Error("expired invite redeemed")
	}

	token, err = db.RenewUserInvite(id)
	if err != nil {
		t.Fatal(err)
	}
	if u, err := db.AcceptUserInvite(token, "password-1"); err != nil || u == nil || u.Invited {
		t.Fatalf("AcceptUserInvite = %+v, %v", u, err)
	}
	if u, _ := db.AcceptUserInvite(token, "password-2"); u != nil {
		t.Error("invite redeemed twice")
	}
	if u, _ := db.CheckAdminLogin("new@x.test", "password-1"); u == nil {
		t.Error("password from the invite doesn't work")
	}
	if _, err := db.RenewUserInvite(id); err == nil {
		t.Error("renewed an invite for a user with a password")
	}

	// Deleting a pending user removes the invite row too.
	id2, _, _ := db.InviteAdminUser("other@x.test", RoleAdmin)
	if err := db.DeleteAdminUser(id2); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.queryRow(`SELECT COUNT(*) FROM admin_user_invites WHERE user_id = ?`, id2).Scan(&n); err != nil || n != 0 {
		t.Errorf("invite rows after delete = %d, %v", n, err)
	}
}

// TestLoginRehashesOldCost: a hash made at a lower bcrypt cost is upgraded by
// the next successful login, and only by a successful one (issue #273).
func TestLoginRehashesOldCost(t *testing.T) {
	db := openTestDB(t)
	id := testUser(t, db)
	defer func(c int) { PasswordCost = c }(PasswordCost)
	PasswordCost++

	cost := func() int {
		h, err := db.userField(id, "password_hash")
		mustNoErr(t, err)
		c, err := bcrypt.Cost([]byte(h))
		mustNoErr(t, err)
		return c
	}
	if u, _ := db.CheckAdminLogin("owner@x.test", "wrong-password"); u != nil || cost() != PasswordCost-1 {
		t.Fatalf("failed login: user=%v cost=%d, want no user and the old cost", u, cost())
	}
	if u, _ := db.CheckAdminLogin("owner@x.test", "owner-password"); u == nil || cost() != PasswordCost {
		t.Fatalf("login: user=%v cost=%d, want cost %d", u, cost(), PasswordCost)
	}
	if u, _ := db.CheckAdminLogin("owner@x.test", "owner-password"); u == nil {
		t.Error("password stopped working after the rehash")
	}
}

// TestUserGuards: an email can't be moved onto another account, roles are
// checked on every path, and a sealed TOTP secret read with the wrong key is
// an error rather than "2FA not set up".
func TestUserGuards(t *testing.T) {
	db := openTestDB(t)
	a, err := db.CreateAdminUser("a@example.com", "password-aaaa", RoleOwner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateAdminUser("b@example.com", "password-bbbb", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateAdminCredentials(a, "B@Example.com", ""); !errors.Is(err, ErrUserExists) {
		t.Errorf("taking another user's email: %v, want ErrUserExists", err)
	}
	if err := db.UpdateAdminCredentials(a, "a@example.com", ""); err != nil {
		t.Errorf("keeping one's own email: %v", err)
	}
	if err := db.SetAdminUserRole(a, "root"); err == nil {
		t.Error("SetAdminUserRole accepted an unknown role")
	}
	if _, _, err := db.InviteAdminUser("c@example.com", "root"); err == nil {
		t.Error("InviteAdminUser accepted an unknown role")
	}
	if u, err := db.AcceptUserInvite("no-such-token", "password-cccc"); u != nil || err != nil {
		t.Errorf("unknown invite token = %+v, %v", u, err)
	}

	if err := db.EnableSecretEncryption(bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Fatal(err)
	}
	if err := db.SetPendingTOTPSecret(a, "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	if err := db.EnableSecretEncryption(bytes.Repeat([]byte{8}, 32)); err != nil {
		t.Fatal(err)
	}
	if s, err := db.GetPendingTOTPSecret(a); err == nil || s != "" {
		t.Errorf("wrong-key TOTP read = %q, %v; want an error", s, err)
	}
	if s, err := db.GetPendingTOTPSecret(999); err != nil || s != "" {
		t.Errorf("unknown user TOTP read = %q, %v; want empty", s, err)
	}
}
