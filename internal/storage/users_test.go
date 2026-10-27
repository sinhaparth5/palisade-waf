package storage

import (
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
	_, err := db.exec(`INSERT INTO sessions (token, created_at) VALUES (?, ?)`, "legacy-token", now)
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
	if rows, _ := db.ListSessions(owner); len(rows) != 1 || rows[0].Token != a {
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
