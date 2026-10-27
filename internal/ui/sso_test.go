package ui

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
	jose "github.com/go-jose/go-jose/v4"

	"palisade/internal/storage"
)

// fakeIdP is a minimal OIDC provider: discovery, JWKS, a token endpoint
// that checks PKCE and signs whatever claims the test set, and userinfo.
type fakeIdP struct {
	srv  *httptest.Server
	key  *rsa.PrivateKey
	mu   sync.Mutex
	chal string         // code_challenge from the last authorize redirect
	idt  map[string]any // ID token claims for the next exchange
	info map[string]any // userinfo claims
	sign *rsa.PrivateKey
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, sign: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		u := f.srv.URL
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": u, "authorization_endpoint": u + "/auth", "token_endpoint": u + "/token",
			"jwks_uri": u + "/keys", "userinfo_endpoint": u + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key.Public(), KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != f.chal {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		claims := map[string]any{"iss": f.srv.URL, "aud": "palisade", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix()}
		for k, v := range f.idt {
			claims[k] = v
		}
		raw, _ := json.Marshal(claims)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 60,
			"id_token": oidctest.SignIDToken(f.sign, "k1", oidc.RS256, string(raw)),
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(f.info)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) set(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

// ssoLogin runs the browser side of one SSO login: start, follow to the
// IdP (which answers with idt over the request's nonce, so a test can
// override even that), and the callback. Returns the callback response.
func (f *fakeIdP) ssoLogin(t *testing.T, env *adminEnv, idt map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	rec := env.doWith("GET", "/admin/login/sso", nil, "")
	loc, err := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || err != nil || !strings.HasPrefix(loc.String(), f.srv.URL+"/auth") {
		t.Fatalf("start = %d %q, want a redirect to the IdP", rec.Code, rec.Header().Get("Location"))
	}
	q := loc.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" {
		t.Fatalf("authorize request lacks PKCE/nonce/state: %v", q)
	}
	f.mu.Lock()
	f.chal = q.Get("code_challenge")
	f.idt = map[string]any{"nonce": q.Get("nonce")}
	for k, v := range idt {
		f.idt[k] = v
	}
	f.mu.Unlock()

	req := httptest.NewRequest("GET", "/admin/login/sso/callback?code=c&state="+url.QueryEscape(q.Get("state")), nil)
	req.AddCookie(cookieByName(rec, ssoCookie))
	out := httptest.NewRecorder()
	env.e.ServeHTTP(out, req)
	return out
}

func newSSOEnv(t *testing.T) (*adminEnv, *fakeIdP) {
	env := newAdminEnv(t)
	idp := newFakeIdP(t)
	if err := env.db.SetSSOConfig(storage.SSOConfig{Issuer: idp.srv.URL, ClientID: "palisade", ClientSecret: "s3cret"}); err != nil {
		t.Fatal(err)
	}
	return env, idp
}

func loggedIn(rec *httptest.ResponseRecorder) bool {
	return rec.Code == http.StatusFound && cookieByName(rec, sessionCookie) != nil
}

func TestSSOLogin(t *testing.T) {
	env, idp := newSSOEnv(t)
	alice := map[string]any{"sub": "alice-1", "email": "Alice@Example.com", "email_verified": true, "amr": []string{"pwd", "otp"}}

	if rec := idp.ssoLogin(t, env, alice); loggedIn(rec) || !strings.Contains(rec.Body.String(), "been invited") {
		t.Fatalf("uninvited login = %d %s", rec.Code, rec.Body)
	}
	if n, _ := env.db.CountAdminUsers(); n != 1 {
		t.Fatalf("uninvited login created a user: %d users", n)
	}

	if rec := env.do("POST", "/admin/settings/users/invites", form("email", "alice@example.com", "role", "admin")); rec.Code != http.StatusOK {
		t.Fatalf("invite = %d", rec.Code)
	}
	for name, claims := range map[string]map[string]any{
		"unverified":     {"sub": "alice-1", "email": "alice@example.com", "email_verified": false},
		"missing verify": {"sub": "alice-1", "email": "alice@example.com"},
	} {
		if rec := idp.ssoLogin(t, env, claims); loggedIn(rec) || !strings.Contains(rec.Body.String(), "verified at the identity provider") {
			t.Errorf("%s: login = %d %s", name, rec.Code, rec.Body)
		}
	}

	if rec := idp.ssoLogin(t, env, alice); !loggedIn(rec) {
		t.Fatalf("invited login = %d %s", rec.Code, rec.Body)
	}
	u, _ := env.db.GetAdminUserByEmail("alice@example.com")
	if u == nil || u.Role != storage.RoleAdmin || !u.SSO {
		t.Fatalf("created user = %+v, want an SSO admin", u)
	}
	if inv, _ := env.db.ListSSOInvites(); len(inv) != 0 {
		t.Errorf("invite not spent: %+v", inv)
	}
	if ok, _ := env.db.CheckAdminLogin("alice@example.com", ""); ok != nil {
		t.Error("SSO user can sign in with an empty password")
	}
	if entries, _, _ := env.db.ListAudit(10, 0); len(entries) == 0 || entries[0].Action != "SSO login" || entries[0].Summary != "amr=pwd,otp" {
		t.Errorf("audit = %+v, want an SSO login with amr", entries)
	}

	// Matched by iss+sub: a changed email at the IdP is the same account,
	// and the old email with a new sub (recycled address) gets nothing.
	if rec := idp.ssoLogin(t, env, map[string]any{"sub": "alice-1", "email": "alice@new.example", "email_verified": true}); !loggedIn(rec) {
		t.Errorf("changed email login = %d %s", rec.Code, rec.Body)
	}
	if rec := idp.ssoLogin(t, env, map[string]any{"sub": "mallory", "email": "alice@example.com", "email_verified": true}); loggedIn(rec) {
		t.Error("a new sub with a bound user's email signed in")
	}
	if n, _ := env.db.CountAdminUsers(); n != 2 {
		t.Errorf("users = %d, want 2", n)
	}

	if err := env.db.SetAdminUserDisabled(u.ID, true); err != nil {
		t.Fatal(err)
	}
	if rec := idp.ssoLogin(t, env, alice); loggedIn(rec) || !strings.Contains(rec.Body.String(), "disabled") {
		t.Errorf("disabled user login = %d", rec.Code)
	}

	// The local owner's password login keeps working with SSO on.
	if _, s := login(env, "10.9.0.1", testAdminEmail, testAdminPassword); s == "" {
		t.Error("local owner login failed with SSO on")
	}
}

func TestSSOGroupGate(t *testing.T) {
	env, idp := newSSOEnv(t)
	cfg, _ := env.db.GetSSOConfig()
	cfg.Group = "palisade"
	if err := env.db.SetSSOConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err := env.db.CreateSSOInvite("bob@example.com", storage.RoleViewer); err != nil {
		t.Fatal(err)
	}

	bob := map[string]any{"sub": "bob", "email": "bob@example.com", "email_verified": true}
	if rec := idp.ssoLogin(t, env, bob); loggedIn(rec) || !strings.Contains(rec.Body.String(), "group") {
		t.Fatalf("login outside the group = %d %s", rec.Code, rec.Body)
	}
	// Groups only in userinfo, as Authelia does by default.
	idp.set(func() { idp.info = map[string]any{"sub": "bob", "groups": []string{"staff", "palisade"}} })
	rec := idp.ssoLogin(t, env, bob)
	if !loggedIn(rec) {
		t.Fatalf("login in the group (via userinfo) = %d %s", rec.Code, rec.Body)
	}
	session := cookieByName(rec, sessionCookie).Value

	// Removed from the group: the next login is refused and the live
	// session revoked.
	idp.set(func() { idp.info = map[string]any{"sub": "bob", "groups": []string{"staff"}} })
	if rec := idp.ssoLogin(t, env, bob); loggedIn(rec) {
		t.Fatal("login after leaving the group succeeded")
	}
	if ok, _ := env.db.ValidateSession(session); ok {
		t.Error("session survived leaving the group")
	}
}

func TestSSOTokenChecks(t *testing.T) {
	env, idp := newSSOEnv(t)
	if err := env.db.CreateSSOInvite("eve@example.com", storage.RoleOwner); err != nil {
		t.Fatal(err)
	}
	eve := map[string]any{"sub": "eve", "email": "eve@example.com", "email_verified": true}

	for name, claims := range map[string]map[string]any{
		"wrong nonce":    {"nonce": "replayed"},
		"wrong audience": {"aud": "someone-else"},
		"expired":        {"exp": time.Now().Add(-time.Hour).Unix()},
		"wrong issuer":   {"iss": "https://evil.example"},
	} {
		c := map[string]any{}
		for k, v := range eve {
			c[k] = v
		}
		for k, v := range claims {
			c[k] = v
		}
		if rec := idp.ssoLogin(t, env, c); loggedIn(rec) {
			t.Errorf("%s: signed in", name)
		}
	}

	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	idp.set(func() { idp.sign = other })
	if rec := idp.ssoLogin(t, env, eve); loggedIn(rec) {
		t.Error("token signed by an unknown key accepted")
	}
	idp.set(func() { idp.sign = idp.key })

	// State must match the browser's cookie.
	rec := env.doWith("GET", "/admin/login/sso", nil, "")
	req := httptest.NewRequest("GET", "/admin/login/sso/callback?code=c&state=forged", nil)
	req.AddCookie(cookieByName(rec, ssoCookie))
	out := httptest.NewRecorder()
	env.e.ServeHTTP(out, req)
	if loggedIn(out) || !strings.Contains(out.Body.String(), "expired") {
		t.Errorf("forged state = %d", out.Code)
	}

	if n, _ := env.db.CountAdminUsers(); n != 1 {
		t.Errorf("failed logins created users: %d", n)
	}
	if rec := idp.ssoLogin(t, env, eve); !loggedIn(rec) {
		t.Errorf("valid login after the failures = %d %s", rec.Code, rec.Body)
	}
}

func TestSSOSettings(t *testing.T) {
	env := newAdminEnv(t)
	idp := newFakeIdP(t)

	for _, tc := range []struct {
		f    []string
		want string
	}{
		{[]string{"issuer", "http://idp.example", "client_id", "x", "client_secret", "y"}, "https"},
		{[]string{"issuer", idp.srv.URL, "client_id", "x"}, "required"},
		{[]string{"issuer", idp.srv.URL + "/wrong", "client_id", "x", "client_secret", "y"}, "discovery failed"},
	} {
		if rec := env.do("POST", "/admin/settings/sso", form(tc.f...)); !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("save %v: body lacks %q", tc.f, tc.want)
		}
	}
	if cfg, _ := env.db.GetSSOConfig(); cfg.Issuer != "" {
		t.Fatalf("invalid config saved: %+v", cfg)
	}

	env.do("POST", "/admin/settings/sso", form("issuer", idp.srv.URL+"/", "client_id", "palisade", "client_secret", "s3cret", "group", "palisade"))
	// A blank secret keeps the stored one, which is never echoed.
	rec := env.do("POST", "/admin/settings/sso", form("issuer", idp.srv.URL, "client_id", "palisade", "group", "palisade"))
	if cfg, _ := env.db.GetSSOConfig(); cfg.Issuer != idp.srv.URL || cfg.ClientSecret != "s3cret" || cfg.Group != "palisade" {
		t.Fatalf("saved config = %+v", cfg)
	}
	page := env.do("GET", "/admin/settings", nil).Body.String()
	if strings.Contains(rec.Body.String()+page, "s3cret") {
		t.Error("client secret echoed back")
	}
	if !strings.Contains(page, "/admin/login/sso/callback") {
		t.Error("settings page doesn't show the redirect URI")
	}
	if body := env.doWith("GET", "/admin/login", nil, "").Body.String(); !strings.Contains(body, "Sign in with "+strings.TrimPrefix(idp.srv.URL, "http://")) {
		t.Error("login page has no SSO button")
	}

	env.do("POST", "/admin/settings/sso", form("issuer", ""))
	if cfg, _ := env.db.GetSSOConfig(); cfg != (storage.SSOConfig{}) {
		t.Errorf("turning SSO off left %+v", cfg)
	}
}
