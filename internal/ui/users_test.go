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
	for _, r := range env.e.Router().Routes() {
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
	for _, p := range []string{"/admin/api/dashboard", "/admin/api/logs", "/admin/api/services", "/admin/api/settings/account", "/admin/api/settings/protection", "/admin/api/settings/audit"} {
		if rec := env.doWith("GET", p, nil, viewer); rec.Code != http.StatusOK {
			t.Errorf("viewer GET %s = %d, want 200", p, rec.Code)
		}
	}
	if rec := env.doJSON(viewer, "POST", "/admin/api/settings/devices/sign-out-others", map[string]any{}, nil); rec.Code != http.StatusNoContent {
		t.Errorf("viewer revoke own devices = %d, want 200", rec.Code)
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
		if rec := env.doWith("GET", "/admin/api/settings/account", nil, s); rec.Code != http.StatusOK {
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
	rec := env.doJSON(env.session, "POST", "/admin/api/settings/users", inviteRequest{Email: "new@example.com", Role: "admin"}, nil)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"sent":true`) || len(env.invites) != 1 {
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
	// One password rule on every path (issue #273).
	for pw, want := range map[string]string{
		"elevenchars":        "at least 12",
		breachedTestPassword: "known data breach",
	} {
		if rec := public("POST", path, form("password", pw, "confirm_password", pw)); !strings.Contains(rec.Body.String(), want) {
			t.Errorf("invite password %q: want %q in the page", pw, want)
		}
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
	if rec := env.doJSON(env.session, "POST", "/admin/api/settings/users/"+itoa(int(u.ID))+"/invite", map[string]any{}, nil); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "already set a password") {
		t.Error("resend allowed after the password was set")
	}
}

// Without working email the user is still created and the owner gets the
// link once; resend replaces it, killing the old one.
func TestUserInviteFallbackAndResend(t *testing.T) {
	env := newAdminEnv(t)
	env.inviteErr = errors.New("email is not set up")
	var sent inviteAnswer
	env.doJSON(env.session, "POST", "/admin/api/settings/users", inviteRequest{Email: "v@example.com", Role: "viewer"}, &sent)
	_, first, _ := strings.Cut(env.invites[0], " ")
	if sent.Link != first || sent.SendError != "email is not set up" {
		t.Fatalf("link not given on send failure: %+v", sent)
	}
	if strings.Contains(env.doJSON(env.session, "GET", "/admin/api/settings/team", nil, nil).Body.String(), first) {
		t.Error("link given again on a later read")
	}

	env.inviteErr = nil
	u, _ := env.db.GetAdminUserByEmail("v@example.com")
	env.doJSON(env.session, "POST", "/admin/api/settings/users/"+itoa(int(u.ID))+"/invite", map[string]any{}, nil)
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
