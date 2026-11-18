package storage

import (
	"errors"
	"testing"
	"time"
)

// TestSSOInvites: an invite works once, only while live, and links an
// existing user by email.
func TestSSOInvites(t *testing.T) {
	db := openTestDB(t)
	testUser(t, db)
	const iss = "https://idp.example"

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

	// An existing user's email links that user (#296): role kept, no new
	// row, and a linked user can't be invited again.
	owner, _ := db.GetAdminUserByEmail("owner@x.test")
	mustNoErr(t, db.CreateSSOInvite("owner@x.test", RoleViewer))
	linked, err := db.AcceptSSOInvite("owner@x.test", iss, "o")
	if err != nil || linked == nil || linked.ID != owner.ID || linked.Role != owner.Role || !linked.SSO {
		t.Fatalf("link existing = %+v, %v; want user %d keeping role %s", linked, err, owner.ID, owner.Role)
	}
	if got, _ := db.SSOUser(iss, "o"); got == nil || got.ID != owner.ID {
		t.Errorf("SSOUser = %+v, want the existing user", got)
	}
	if err := db.CreateSSOInvite("owner@x.test", RoleViewer); !errors.Is(err, ErrSSOLinked) {
		t.Errorf("invite for a linked user: err = %v", err)
	}

	// Deleting the user frees the identity for a fresh invite.
	mustNoErr(t, db.DeleteAdminUser(u.ID))
	if got, _ := db.SSOUser(iss, "a"); got != nil {
		t.Error("identity outlived its user")
	}
}

// TestProvisionSSOUser: a provisioned user exists at once, their invite
// doesn't expire and binds them, and deleting them drops the invite.
func TestProvisionSSOUser(t *testing.T) {
	db := openTestDB(t)
	const iss = "https://idp.example"
	u, err := db.ProvisionSSOUser("P@x.test", RoleViewer)
	if err != nil || u == nil || u.Email != "p@x.test" || u.Invited || u.SSO {
		t.Fatalf("provision = %+v, %v", u, err)
	}
	if _, err := db.ProvisionSSOUser("p@x.test", RoleViewer); !errors.Is(err, ErrUserExists) {
		t.Errorf("twice: err = %v", err)
	}
	if inv, _ := db.ListSSOInvites(); len(inv) != 1 || inv[0].ExpiresAt.Before(time.Now().AddDate(50, 0, 0)) {
		t.Errorf("invites = %+v", inv)
	}
	if got, _ := db.AcceptSSOInvite("p@x.test", iss, "p"); got == nil || got.ID != u.ID || !got.SSO {
		t.Fatalf("accept = %+v", got)
	}

	q, _ := db.ProvisionSSOUser("q@x.test", RoleAdmin)
	mustNoErr(t, db.DeleteAdminUser(q.ID))
	if got, _ := db.AcceptSSOInvite("q@x.test", iss, "q"); got != nil {
		t.Error("deleted user came back through their invite")
	}
}
