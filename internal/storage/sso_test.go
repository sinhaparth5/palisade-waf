package storage

import (
	"errors"
	"testing"
	"time"
)

// TestSSOInvites: an invite works once, only while live, and only for an
// email no user has.
func TestSSOInvites(t *testing.T) {
	db := openTestDB(t)
	testUser(t, db)
	const iss = "https://idp.example"

	if err := db.CreateSSOInvite("owner@x.test", RoleViewer); !errors.Is(err, ErrUserExists) {
		t.Errorf("invite for an existing user: err = %v", err)
	}
	if err := db.CreateSSOInvite("a@x.test", "root"); err == nil {
		t.Error("invalid role accepted")
	}
	if u, err := db.AcceptSSOInvite("a@x.test", iss, "a"); u != nil || err != nil {
		t.Errorf("uninvited accept = %+v, %v", u, err)
	}

	mustNoErr(t, db.CreateSSOInvite("A@x.test", RoleViewer))
	mustNoErr(t, db.CreateSSOInvite("a@x.test", RoleAdmin)) // re-invite replaces
	invites, err := db.ListSSOInvites()
	mustNoErr(t, err)
	if len(invites) != 1 || invites[0].Role != RoleAdmin || invites[0].Expired() {
		t.Fatalf("invites = %+v, want one live admin invite", invites)
	}

	// Expired, then renewed.
	_, err = db.exec(`UPDATE admin_sso_invites SET expires_at = ?`, time.Now().UTC().Add(-time.Minute))
	mustNoErr(t, err)
	if u, _ := db.AcceptSSOInvite("a@x.test", iss, "a"); u != nil {
		t.Error("expired invite accepted")
	}
	mustNoErr(t, db.RenewSSOInvite(invites[0].ID))

	u, err := db.AcceptSSOInvite("a@x.test", iss, "a")
	if err != nil || u == nil || u.Role != RoleAdmin || !u.SSO {
		t.Fatalf("accept = %+v, %v", u, err)
	}
	if got, _ := db.SSOUser(iss, "a"); got == nil || got.ID != u.ID {
		t.Errorf("SSOUser = %+v, want the new user", got)
	}
	if again, _ := db.AcceptSSOInvite("a@x.test", iss, "a2"); again != nil {
		t.Error("used invite accepted twice")
	}

	// Revoked.
	mustNoErr(t, db.CreateSSOInvite("b@x.test", RoleViewer))
	invites, _ = db.ListSSOInvites()
	mustNoErr(t, db.DeleteSSOInvite(invites[0].ID))
	if u, _ := db.AcceptSSOInvite("b@x.test", iss, "b"); u != nil {
		t.Error("revoked invite accepted")
	}

	// Deleting the user frees the identity for a fresh invite.
	mustNoErr(t, db.DeleteAdminUser(u.ID))
	if got, _ := db.SSOUser(iss, "a"); got != nil {
		t.Error("identity outlived its user")
	}
}
