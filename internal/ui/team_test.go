package ui

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"palisade/internal/storage"
)

type teamPage struct {
	Users   []userJSON      `json:"users"`
	Invites []ssoInviteJSON `json:"invites"`
	Keys    []apiKeyJSON    `json:"api_keys"`
	SSO     struct {
		Issuer      string `json:"issuer"`
		ClientID    string `json:"client_id"`
		SecretSet   bool   `json:"secret_set"`
		Group       string `json:"group"`
		CallbackURL string `json:"callback_url"`
	} `json:"sso"`
}

type inviteAnswer struct {
	Email     string `json:"email"`
	Sent      bool   `json:"sent"`
	Link      string `json:"link"`
	SendError string `json:"send_error"`
}

func (env *adminEnv) team() teamPage {
	env.t.Helper()
	var p teamPage
	if rec := env.doJSON(env.session, http.MethodGet, "/admin/api/settings/team", nil, &p); rec.Code != http.StatusOK {
		env.t.Fatalf("team: %d %s", rec.Code, rec.Body)
	}
	return p
}

// TestTeamUsers: invites by email (and the link when sending fails), role
// and disable changes, the last-owner guard, 2FA reset and removal.
func TestTeamUsers(t *testing.T) {
	env := newAdminEnv(t)
	const users = "/admin/api/settings/users"

	for _, tc := range []struct {
		req   inviteRequest
		field string
	}{
		{inviteRequest{Email: "nope", Role: "admin"}, "email"},
		{inviteRequest{Email: "a@example.com", Role: "god"}, "role"},
	} {
		var got jsonError
		if rec := env.doJSON(env.session, http.MethodPost, users, tc.req, &got); rec.Code != http.StatusBadRequest || got.Fields[tc.field] == "" {
			t.Errorf("%+v: %d %s", tc.req, rec.Code, rec.Body)
		}
	}
	var sent inviteAnswer
	if rec := env.doJSON(env.session, http.MethodPost, users, inviteRequest{Email: " A@Example.com ", Role: "admin"}, &sent); rec.Code != http.StatusCreated || !sent.Sent || sent.Link != "" {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	if len(env.invites) != 1 || !strings.HasPrefix(env.invites[0], "a@example.com http") {
		t.Errorf("invites = %v", env.invites)
	}
	var dup jsonError
	if rec := env.doJSON(env.session, http.MethodPost, users, inviteRequest{Email: "a@example.com", Role: "viewer"}, &dup); rec.Code != http.StatusConflict || dup.Fields["email"] == "" {
		t.Errorf("duplicate: %d %s", rec.Code, rec.Body)
	}

	env.inviteErr = errors.New("email is not set up")
	p := env.team()
	var a userJSON
	for _, u := range p.Users {
		if u.Email == "a@example.com" {
			a = u
		}
	}
	if !a.Invited || a.Role != "admin" || a.You || !p.Users[0].You {
		t.Fatalf("users = %+v", p.Users)
	}
	id := itoa(a.ID)
	var resent inviteAnswer
	if rec := env.doJSON(env.session, http.MethodPost, users+"/"+id+"/invite", map[string]any{}, &resent); rec.Code != http.StatusOK || resent.Sent || !strings.Contains(resent.Link, "/admin/invite/") || resent.SendError == "" {
		t.Errorf("resend: %d %s", rec.Code, rec.Body)
	}

	for _, tc := range []struct {
		method, path string
		body         any
		want         int
	}{
		{http.MethodPut, users + "/" + id, map[string]any{"role": "god"}, http.StatusBadRequest},
		{http.MethodPut, users + "/" + id, map[string]any{}, http.StatusBadRequest},
		{http.MethodPut, users + "/x", map[string]any{"role": "viewer"}, http.StatusBadRequest},
		{http.MethodPut, users + "/" + id, map[string]any{"role": "viewer"}, http.StatusNoContent},
		{http.MethodPut, users + "/" + id, map[string]any{"disabled": true}, http.StatusNoContent},
		{http.MethodPut, users + "/" + itoa(env.uid), map[string]any{"role": "admin"}, http.StatusConflict}, // last owner
		{http.MethodDelete, users + "/" + itoa(env.uid), nil, http.StatusConflict},
		{http.MethodPost, users + "/" + itoa(env.uid) + "/reset-2fa", map[string]any{}, http.StatusConflict}, // own 2FA
		{http.MethodPost, users + "/" + id + "/reset-2fa", map[string]any{}, http.StatusNoContent},
		{http.MethodDelete, users + "/" + id, nil, http.StatusNoContent},
	} {
		if rec := env.doJSON(env.session, tc.method, tc.path, tc.body, nil); rec.Code != tc.want {
			t.Errorf("%s %s %v = %d %s, want %d", tc.method, tc.path, tc.body, rec.Code, rec.Body, tc.want)
		}
	}
	if u, _ := env.db.GetAdminUserByEmail("a@example.com"); u != nil {
		t.Error("user not removed")
	}

	admin := env.sessionAs(storage.RoleAdmin)
	if rec := env.doJSON(admin, http.MethodGet, "/admin/api/settings/team", nil, nil); rec.Code != http.StatusForbidden {
		t.Errorf("admin reads the team: %d", rec.Code)
	}
}

// TestTeamSSOAndKeys: SSO field errors and discovery against the fake IdP,
// a kept secret, SSO invites, and API keys shown once.
func TestTeamSSOAndKeys(t *testing.T) {
	env := newAdminEnv(t)
	idp := newFakeIdP(t)
	const sso = "/admin/api/settings/sso"

	if rec := env.doJSON(env.session, http.MethodPost, "/admin/api/settings/sso-invites", inviteRequest{Email: "s@example.com", Role: "viewer"}, nil); rec.Code != http.StatusConflict {
		t.Errorf("invite before SSO: %d", rec.Code)
	}
	for _, tc := range []struct {
		req   ssoRequest
		field string
	}{
		{ssoRequest{Issuer: "not a url"}, "issuer"},
		{ssoRequest{Issuer: "http://idp.example", ClientID: "x", ClientSecret: "y"}, "issuer"},
		{ssoRequest{Issuer: idp.srv.URL, ClientSecret: "y"}, "client_id"},
		{ssoRequest{Issuer: idp.srv.URL, ClientID: "x"}, "client_secret"},
		{ssoRequest{Issuer: idp.srv.URL + "/wrong", ClientID: "x", ClientSecret: "y"}, "issuer"},
	} {
		var got jsonError
		if rec := env.doJSON(env.session, http.MethodPut, sso, tc.req, &got); rec.Code != http.StatusBadRequest || got.Fields[tc.field] == "" {
			t.Errorf("%+v: %d %s, want a %s error", tc.req, rec.Code, rec.Body, tc.field)
		}
	}
	if rec := env.doJSON(env.session, http.MethodPut, sso, ssoRequest{Issuer: idp.srv.URL + "/", ClientID: "palisade", ClientSecret: "s3cret", Group: "g"}, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	if rec := env.doJSON(env.session, http.MethodPut, sso, ssoRequest{Issuer: idp.srv.URL, ClientID: "palisade"}, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("save keeping the secret: %d %s", rec.Code, rec.Body)
	}
	p := env.team()
	if p.SSO.Issuer != idp.srv.URL || !p.SSO.SecretSet || p.SSO.Group != "" || !strings.HasSuffix(p.SSO.CallbackURL, "/admin/login/sso/callback") {
		t.Errorf("sso = %+v", p.SSO)
	}
	if strings.Contains(env.doJSON(env.session, http.MethodGet, "/admin/api/settings/team", nil, nil).Body.String(), "s3cret") {
		t.Error("client secret echoed")
	}

	if rec := env.doJSON(env.session, http.MethodPost, "/admin/api/settings/sso-invites", inviteRequest{Email: "s@example.com", Role: "viewer"}, nil); rec.Code != http.StatusCreated {
		t.Fatalf("SSO invite: %d %s", rec.Code, rec.Body)
	}
	p = env.team()
	if len(p.Invites) != 1 || p.Invites[0].Email != "s@example.com" || p.Invites[0].Expired {
		t.Fatalf("invites = %+v", p.Invites)
	}
	inv := itoa(p.Invites[0].ID)
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodPost, "/admin/api/settings/sso-invites/x/renew", http.StatusBadRequest},
		{http.MethodPost, "/admin/api/settings/sso-invites/" + inv + "/renew", http.StatusNoContent},
		{http.MethodDelete, "/admin/api/settings/sso-invites/" + inv, http.StatusNoContent},
	} {
		if rec := env.doJSON(env.session, tc.method, tc.path, map[string]any{}, nil); rec.Code != tc.want {
			t.Errorf("%s %s = %d", tc.method, tc.path, rec.Code)
		}
	}
	if rec := env.doJSON(env.session, http.MethodPut, sso, ssoRequest{}, nil); rec.Code != http.StatusNoContent {
		t.Errorf("turn off: %d", rec.Code)
	}
	if cfg, _ := env.db.GetSSOConfig(); cfg.Issuer != "" || cfg.ClientSecret != "" {
		t.Errorf("SSO still on: %+v", cfg)
	}

	var bad jsonError
	if rec := env.doJSON(env.session, http.MethodPost, "/admin/api/settings/api-keys", map[string]any{"name": " "}, &bad); rec.Code != http.StatusBadRequest || bad.Fields["name"] == "" {
		t.Errorf("unnamed key: %d", rec.Code)
	}
	var key struct{ Key string }
	if rec := env.doJSON(env.session, http.MethodPost, "/admin/api/settings/api-keys", map[string]any{"name": "ci", "read_only": true}, &key); rec.Code != http.StatusCreated || !strings.HasPrefix(key.Key, "cwaf_") {
		t.Fatalf("key: %d %s", rec.Code, rec.Body)
	}
	p = env.team()
	if len(p.Keys) != 1 || !p.Keys[0].ReadOnly || p.Keys[0].LastUsedAt != "" || !strings.HasPrefix(key.Key, p.Keys[0].Prefix) {
		t.Fatalf("keys = %+v", p.Keys)
	}
	if rec := env.doJSON(env.session, http.MethodDelete, "/admin/api/settings/api-keys/x", nil, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("bad key id: %d", rec.Code)
	}
	if rec := env.doJSON(env.session, http.MethodDelete, "/admin/api/settings/api-keys/"+itoa(p.Keys[0].ID), nil, nil); rec.Code != http.StatusNoContent || len(env.team().Keys) != 0 {
		t.Errorf("revoke: %d", rec.Code)
	}
}
