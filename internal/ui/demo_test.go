package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"palisade/internal/storage"
)

const demoEmail, demoPass = "demo@example.com", "demo-password"

// newDemoEnv is newAdminEnv with --demo on and its viewer account created.
func newDemoEnv(t *testing.T) *adminEnv {
	t.Helper()
	env := newAdminEnv(t)
	if _, err := env.db.CreateAdminUser(demoEmail, demoPass, storage.RoleViewer); err != nil {
		t.Fatal(err)
	}
	env.h.cfg.Admin.DemoEmail, env.h.cfg.Admin.DemoPassword = demoEmail, demoPass
	return env
}

// demoLogin posts the login form from ip and returns the response.
func demoLogin(env *adminEnv, ip, password string) *httptest.ResponseRecorder {
	v := url.Values{"email": {demoEmail}, "password": {password}}
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(v.Encode()))
	req.RemoteAddr = ip + ":1234"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.e.ServeHTTP(rec, req)
	return rec
}

func demoCookie(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return c.Value
		}
	}
	t.Fatalf("no session cookie (status %d)", rec.Code)
	return ""
}

func TestDemoSharedSessions(t *testing.T) {
	env := newDemoEnv(t)
	// Same IP and browser too: neither visitor may replace the other.
	a := demoCookie(t, demoLogin(env, "10.0.0.1", demoPass))
	b := demoCookie(t, demoLogin(env, "10.0.0.1", demoPass))
	c := demoCookie(t, demoLogin(env, "10.0.0.2", demoPass))
	for _, tok := range []string{a, b, c} {
		if ok, _ := env.db.ValidateSession(tok); !ok {
			t.Fatalf("demo session %s… was signed out by a later visitor", tok[:8])
		}
	}
	// One visitor's device list never shows another's IP.
	if body := env.doWith(http.MethodGet, "/admin/settings", nil, a).Body.String(); strings.Contains(body, "10.0.0.2") {
		t.Error("settings page lists another demo visitor's IP")
	}
}

func TestDemoAccountNotLockable(t *testing.T) {
	env := newDemoEnv(t)
	// Failures spread over IPs would lock a normal account.
	for i := range maxLoginFailures + 2 {
		demoLogin(env, "10.1.0."+string(rune('1'+i)), "wrong")
	}
	if rec := demoLogin(env, "10.2.0.1", demoPass); rec.Code != http.StatusFound {
		t.Fatalf("demo login after failures elsewhere = %d, want 302", rec.Code)
	}
}

func TestDemoWritesBlocked(t *testing.T) {
	env := newDemoEnv(t)
	tok := demoCookie(t, demoLogin(env, "10.0.0.1", demoPass))
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodPost, "/admin/settings/credentials", http.StatusForbidden},
		{http.MethodPost, "/admin/settings/2fa/start", http.StatusForbidden},
		{http.MethodPost, "/admin/settings/passkeys/begin", http.StatusForbidden},
		{http.MethodPost, "/admin/settings/devices/revoke-others", http.StatusForbidden},
		{http.MethodGet, "/admin/settings", http.StatusOK},
		{http.MethodPost, "/admin/logout", http.StatusFound},
	} {
		if rec := env.doWith(tc.method, tc.path, form("current_password", demoPass), tok); rec.Code != tc.want {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
	}
	// A normal viewer keeps its own account controls.
	if rec := env.doWith(http.MethodPost, "/admin/settings/2fa/start", nil, env.sessionAs(storage.RoleViewer)); rec.Code == http.StatusForbidden {
		t.Error("non-demo viewer blocked from 2FA enrollment")
	}
}

func TestDemoLoginBanner(t *testing.T) {
	env := newDemoEnv(t)
	body := env.doWith(http.MethodGet, "/admin/login", nil, "").Body.String()
	if !strings.Contains(body, "Live demo") || !strings.Contains(body, `value="`+demoPass+`"`) {
		t.Error("login page missing the demo banner or prefilled password")
	}
	env.h.cfg.Admin.DemoEmail = ""
	if body := env.doWith(http.MethodGet, "/admin/login", nil, "").Body.String(); strings.Contains(body, "Live demo") {
		t.Error("demo banner shown with --demo off")
	}
}
