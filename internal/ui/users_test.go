package ui

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"palisade/internal/storage"
)

// TestRouteRoles walks the route table: every mutating admin route must
// declare a minimum role, a viewer gets 403 on every route above viewer,
// and an admin gets 403 on every owner route (issue #196).
func TestRouteRoles(t *testing.T) {
	env := newAdminEnv(t)
	viewer := env.sessionAs(storage.RoleViewer)
	admin := env.sessionAs(storage.RoleAdmin)
	public := map[string]bool{
		"POST /admin/login": true, "POST /admin/login/totp": true, "POST /admin/login/totp/email": true,
		"POST /admin/login/webauthn/begin": true, "POST /admin/login/webauthn/finish": true,
		"POST /admin/invite/:token": true,
	}
	params := strings.NewReplacer(":id", "1", ":token", "x")

	checked := 0
	for _, r := range env.e.Routes() {
		key := r.Method + " " + r.Path
		mutating := r.Method == http.MethodPost || r.Method == http.MethodPut ||
			r.Method == http.MethodPatch || r.Method == http.MethodDelete
		if !mutating || !strings.HasPrefix(r.Path, "/admin") || strings.HasPrefix(r.Path, "/admin/api/v1") ||
			strings.HasSuffix(r.Path, "*") || public[key] {
			continue
		}
		need, ok := env.h.routeRoles[key]
		if !ok {
			t.Errorf("%s declares no minimum role", key)
			continue
		}
		checked++
		path := params.Replace(r.Path)
		if need != storage.RoleViewer {
			if rec := env.doWith(r.Method, path, form(), viewer); rec.Code != http.StatusForbidden {
				t.Errorf("viewer %s = %d, want 403", key, rec.Code)
			}
		}
		if need == storage.RoleOwner {
			if rec := env.doWith(r.Method, path, form(), admin); rec.Code != http.StatusForbidden {
				t.Errorf("admin %s = %d, want 403", key, rec.Code)
			}
		}
	}
	if checked < 60 {
		t.Errorf("checked only %d mutating routes; is the route table wired?", checked)
	}
	// The one GET above viewer: export carries full request headers.
	if rec := env.doWith("GET", "/admin/logs/export", nil, viewer); rec.Code != http.StatusForbidden {
		t.Errorf("viewer log export = %d, want 403", rec.Code)
	}
	// Viewers still read everything else and manage their own account.
	for _, p := range []string{"/admin", "/admin/logs", "/admin/services", "/admin/settings"} {
		if rec := env.doWith("GET", p, nil, viewer); rec.Code != http.StatusOK {
			t.Errorf("viewer GET %s = %d, want 200", p, rec.Code)
		}
	}
	if rec := env.doWith("POST", "/admin/settings/devices/revoke-others", nil, viewer); rec.Code != http.StatusOK {
		t.Errorf("viewer revoke own devices = %d, want 200", rec.Code)
	}
}

func TestUsersCard(t *testing.T) {
	env := newAdminEnv(t)

	for _, tc := range []struct{ f []string }{
		{[]string{"email", "nope", "role", "viewer"}},
		{[]string{"email", "v@example.com", "role", "root"}},
		{[]string{"email", testAdminEmail, "role", "viewer"}},
	} {
		rec := env.do("POST", "/admin/settings/users", form(tc.f...))
		if !strings.Contains(rec.Body.String(), "bg-red-50") {
			t.Errorf("create %v: no error shown", tc.f)
		}
	}
	if n, _ := env.db.CountAdminUsers(); n != 1 {
		t.Fatalf("invalid creates added users: %d", n)
	}

	env.do("POST", "/admin/settings/users", form("email", "Dev@Example.com", "role", "viewer"))
	dev, _ := env.db.GetAdminUserByEmail("dev@example.com")
	if dev == nil || dev.Role != storage.RoleViewer {
		t.Fatalf("created user = %+v", dev)
	}
	devURL := "/admin/settings/users/" + itoa(int(dev.ID))

	env.do("POST", devURL, form("action", "role", "role", "admin"))
	if u, _ := env.db.GetAdminUser(dev.ID); u.Role != storage.RoleAdmin {
		t.Errorf("role = %q, want admin", u.Role)
	}

	// The only owner can't demote, disable or delete themselves.
	ownerURL := "/admin/settings/users/" + itoa(int(env.uid))
	for _, rec := range []*httptest.ResponseRecorder{
		env.do("POST", ownerURL, form("action", "role", "role", "viewer")),
		env.do("POST", ownerURL, form("action", "disable")),
		env.do("DELETE", ownerURL, nil),
	} {
		if !strings.Contains(rec.Body.String(), "last owner") {
			t.Errorf("last-owner change not refused: %s", rec.Body)
		}
	}
	if rec := env.do("POST", ownerURL, form("action", "reset-2fa")); !strings.Contains(rec.Body.String(), "your own 2FA") {
		t.Errorf("self 2FA reset not refused: %s", rec.Body)
	}
	if u, _ := env.db.GetAdminUser(env.uid); u == nil || u.Role != storage.RoleOwner || u.Disabled {
		t.Fatalf("owner changed: %+v", u)
	}

	// Disabling signs the user out at once.
	devSession, _ := env.db.CreateSession(dev.ID, "10.0.0.5", "ua", "")
	env.do("POST", devURL, form("action", "disable"))
	if rec := env.doWith("GET", "/admin", nil, devSession); rec.Code != http.StatusFound {
		t.Errorf("disabled user's session still works: %d", rec.Code)
	}
	env.do("POST", devURL, form("action", "enable"))
	if u, _ := env.db.GetAdminUser(dev.ID); u.Disabled {
		t.Error("user not re-enabled")
	}

	if err := env.db.SetPendingTOTPSecret(dev.ID, "S"); err != nil {
		t.Fatal(err)
	}
	if err := env.db.EnableTOTP(dev.ID, nil); err != nil {
		t.Fatal(err)
	}
	env.do("POST", devURL, form("action", "reset-2fa"))
	if on, _ := env.db.TOTPEnabled(dev.ID); on {
		t.Error("2FA not reset")
	}

	env.do("DELETE", devURL, nil)
	if u, _ := env.db.GetAdminUser(dev.ID); u != nil {
		t.Error("user not deleted")
	}

	// The audit log names the acting user, and refused changes aren't logged.
	entries, _, _ := env.db.ListAudit(50, 0)
	for _, e := range entries {
		if e.Actor != testAdminEmail {
			t.Errorf("audit actor = %q, want %q", e.Actor, testAdminEmail)
		}
	}
	if len(entries) != 6 {
		t.Errorf("audit entries = %d, want 6 (create, role, disable, enable, reset, delete; none for refusals)", len(entries))
	}
}

// login runs the password step from ip and returns the session cookie value.
func login(env *adminEnv, ip, email, password string) (*httptest.ResponseRecorder, string) {
	req := httptest.NewRequest("POST", "/admin/login", strings.NewReader(form("email", email, "password", password).Encode()))
	req.RemoteAddr = ip + ":12345"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.e.ServeHTTP(rec, req)
	if ck := cookieByName(rec, sessionCookie); ck != nil {
		return rec, ck.Value
	}
	return rec, ""
}

func TestTwoUsersLoggedIn(t *testing.T) {
	env := newAdminEnv(t)
	if _, err := env.db.CreateAdminUser("second@example.com", "second-password", storage.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	_, a := login(env, "10.0.0.1", testAdminEmail, testAdminPassword)
	_, b := login(env, "10.0.0.2", "second@example.com", "second-password")
	if a == "" || b == "" {
		t.Fatal("login did not issue a session")
	}
	for _, s := range []string{a, b} {
		if rec := env.doWith("GET", "/admin", nil, s); rec.Code != http.StatusOK {
			t.Errorf("session %s… = %d, want both users signed in", s[:8], rec.Code)
		}
	}
}

// TestAccountLoginThrottle: guesses spread over many IPs still lock the
// account, even for the right password from a fresh IP.
func TestAccountLoginThrottle(t *testing.T) {
	env := newAdminEnv(t)
	for i := range maxLoginFailures {
		login(env, "10.1.0."+itoa(i+1), testAdminEmail, "wrong")
	}
	rec, s := login(env, "10.2.0.1", testAdminEmail, testAdminPassword)
	if rec.Code != http.StatusTooManyRequests || s != "" {
		t.Errorf("locked account login = %d (session %v), want 429", rec.Code, s != "")
	}
}

// TestUserInvite: adding a user emails a set-password link (issue #229);
// the link works once, then the user signs in with that password.
func TestUserInvite(t *testing.T) {
	env := newAdminEnv(t)
	rec := env.do("POST", "/admin/settings/users", form("email", "new@example.com", "role", "admin"))
	if !strings.Contains(rec.Body.String(), "Invite sent to new@example.com") || len(env.invites) != 1 {
		t.Fatalf("no invite sent: %v\n%s", env.invites, rec.Body)
	}
	to, link, _ := strings.Cut(env.invites[0], " ")
	_, path, _ := strings.Cut(link, "://example.com")
	if to != "new@example.com" || !strings.HasPrefix(path, "/admin/invite/") {
		t.Fatalf("invite = %q", env.invites[0])
	}
	u, _ := env.db.GetAdminUserByEmail(to)
	if u == nil || !u.Invited || u.Role != storage.RoleAdmin {
		t.Fatalf("invited user = %+v", u)
	}
	if ok, _ := env.db.CheckAdminLogin(to, ""); ok != nil {
		t.Fatal("invited user signs in with an empty password")
	}

	public := func(method, p string, f url.Values) *httptest.ResponseRecorder { return env.doWith(method, p, f, "") }
	if rec := public("GET", path, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Set your password") || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("invite page = %d %q", rec.Code, rec.Header().Get("Referrer-Policy"))
	}
	if rec := public("POST", path, form("password", "brand-new-pass", "confirm_password", "other-pass")); !strings.Contains(rec.Body.String(), "do not match") {
		t.Error("mismatched passwords accepted")
	}
	rec = public("POST", path, form("password", "brand-new-pass", "confirm_password", "brand-new-pass"))
	if rec.Code != 302 || rec.Header().Get("Location") != "/admin" {
		t.Fatalf("set password = %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if ok, _ := env.db.CheckAdminLogin(to, "brand-new-pass"); ok == nil || ok.Invited {
		t.Fatalf("can't sign in after setting the password: %+v", ok)
	}
	// Spent.
	for _, m := range []string{"GET", "POST"} {
		if rec := public(m, path, form("password", "another-pass", "confirm_password", "another-pass")); rec.Code != 404 {
			t.Errorf("spent link %s = %d, want 404", m, rec.Code)
		}
	}
	if rec := env.do("POST", "/admin/settings/users/"+itoa(int(u.ID))+"/invite", nil); !strings.Contains(rec.Body.String(), "already set a password") {
		t.Error("resend allowed after the password was set")
	}
}

// Without working email the user is still created and the owner gets the
// link once; resend replaces it, killing the old one.
func TestUserInviteFallbackAndResend(t *testing.T) {
	env := newAdminEnv(t)
	env.inviteErr = errors.New("email is not set up")
	rec := env.do("POST", "/admin/settings/users", form("email", "v@example.com", "role", "viewer"))
	_, first, _ := strings.Cut(env.invites[0], " ")
	if !strings.Contains(rec.Body.String(), `value="`+first+`"`) || !strings.Contains(rec.Body.String(), "email is not set up") {
		t.Fatalf("link not shown on send failure:\n%s", rec.Body)
	}
	if strings.Contains(env.do("GET", "/admin/settings", nil).Body.String(), first) {
		t.Error("link shown again on a later page load")
	}

	env.inviteErr = nil
	u, _ := env.db.GetAdminUserByEmail("v@example.com")
	env.do("POST", "/admin/settings/users/"+itoa(int(u.ID))+"/invite", nil)
	_, second, _ := strings.Cut(env.invites[1], " ")
	if second == first {
		t.Fatal("resend reused the token")
	}
	for link, want := range map[string]int{first: 404, second: 200} {
		_, p, _ := strings.Cut(link, "://example.com")
		if rec := env.doWith("GET", p, nil, ""); rec.Code != want {
			t.Errorf("GET %s = %d, want %d", p, rec.Code, want)
		}
	}
}
