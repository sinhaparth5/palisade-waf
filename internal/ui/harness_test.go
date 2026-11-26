package ui

import (
	"crypto/sha1" //nolint:gosec // HIBP's range API is keyed by SHA-1
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/labstack/echo/v5"
	"golang.org/x/crypto/bcrypt"

	"palisade/internal/config"
	"palisade/internal/security/blocklist"
	"palisade/internal/security/breach"
	"palisade/internal/security/challenge"
	"palisade/internal/security/geo"
	"palisade/internal/security/threatscore"
	"palisade/internal/services"
	"palisade/internal/storage"
)

// adminEnv is a fully wired admin UI — the real NewHandler and Register —
// over a temp SQLite DB, plus a logged-in session. Callback hooks count
// their invocations so tests can assert a save actually triggered a reload.
type adminEnv struct {
	t       *testing.T
	h       *Handler
	e       *echo.Echo
	db      *storage.DB
	dbPath  string
	session string
	uid     int64 // the owner the session belongs to
	calls   map[string]*atomic.Int32
	backend *httptest.Server
	// invites records each sendInvite call as "to link"; inviteErr fails it.
	invites   []string
	inviteErr error
}

const testAdminEmail, testAdminPassword = "admin@example.com", "correct horse battery"

// breachedTestPassword is the one password the harness's fake HIBP lists.
const breachedTestPassword = "correct-horse-battery"

// bcrypt at the production cost would add about a quarter second per account.
func init() { storage.PasswordCost = bcrypt.MinCost }

func newAdminEnv(t *testing.T) *adminEnv {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "waf.db")
	db, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.SeedAdmin(testAdminEmail, testAdminPassword); err != nil {
		t.Fatal(err)
	}
	reg, err := services.New(db)
	if err != nil {
		t.Fatal(err)
	}
	ipbl, err := blocklist.NewIPBlocklist(db)
	if err != nil {
		t.Fatal(err)
	}
	geoBl, err := geo.New("", db)
	if err != nil {
		t.Fatal(err)
	}

	env := &adminEnv{t: t, db: db, dbPath: dbPath, calls: map[string]*atomic.Int32{}}
	hook := func(name string) func() {
		env.calls[name] = &atomic.Int32{}
		return func() { env.calls[name].Add(1) }
	}
	reloadRL, reloadWAF, reloadAutoban, reloadAdaptive := hook("ratelimit"), hook("waf"), hook("autoban"), hook("adaptive")
	syncIntel, report, webhook, loginCode, reloadBot := hook("intel"), hook("report"), hook("webhook"), hook("logincode"), hook("bot")

	cfg := config.Defaults()
	h, err := NewHandler(cfg, db, ipbl, geoBl, reg, NewLogBroadcaster(),
		embed.FS{}, embed.FS{}, embed.FS{},
		func(*challenge.Challenger) { reloadBot() },
		func(enabled bool, threshold, ttl int) *challenge.Challenger { return nil },
		reloadRL, reloadWAF,
		func(int64) { syncIntel() },
		func() error { report(); return nil },
		func() error { webhook(); return nil },
		func(string) error { loginCode(); return nil },
		func(to, _, _, link string) error {
			env.invites = append(env.invites, to+" "+link)
			return env.inviteErr
		},
		reloadAutoban,
		threatscore.New(db, func(string) int { return 0 }, nil),
		reloadAdaptive,
		func(c *echo.Context) error { return c.String(http.StatusTeapot, "proxied") },
	)
	if err != nil {
		t.Fatal(err)
	}
	env.h = h
	// Never call the real HIBP from tests: a local range server that lists
	// exactly one password, breachedTestPassword.
	hibp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sum := sha1.Sum([]byte(breachedTestPassword)) //nolint:gosec // HIBP's range API is keyed by SHA-1
		hx := strings.ToUpper(hex.EncodeToString(sum[:]))
		if strings.HasSuffix(r.URL.Path, hx[:5]) {
			fmt.Fprintf(w, "%s:42\r\n", hx[5:])
		}
	}))
	t.Cleanup(hibp.Close)
	h.pwBreach = breach.New(hibp.URL + "/")
	if err := h.SetApp(appFS); err != nil {
		t.Fatal(err)
	}
	env.e = echo.New()
	h.Register(env.e)
	h.RegisterAPI(env.e)

	owner, _ := db.GetAdminUserByEmail(testAdminEmail)
	env.uid = owner.ID
	env.session, err = db.CreateSession(env.uid, "127.0.0.1", "test", "")
	if err != nil {
		t.Fatal(err)
	}

	env.backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(env.backend.Close)
	return env
}

// do sends an authenticated admin request (session cookie + CSRF header).
func (env *adminEnv) do(method, path string, form url.Values) *httptest.ResponseRecorder {
	env.t.Helper()
	return env.doWith(method, path, form, env.session)
}

func (env *adminEnv) doWith(method, path string, form url.Values, session string) *httptest.ResponseRecorder {
	env.t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, body)
	req.RemoteAddr = "127.0.0.1:12345"
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if session != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
		req.Header.Set("X-CSRF-Token", csrfToken(session))
	}
	rec := httptest.NewRecorder()
	env.e.ServeHTTP(rec, req)
	return rec
}

// doJSON sends a request the way the React app does (web/src/lib/api.ts):
// Accept JSON, a JSON body when body isn't nil, session cookie and CSRF
// header (none for session ""), and decodes the answer into out unless nil.
// A []byte body is sent as it is.
func (env *adminEnv) doJSON(session, method, path string, body, out any) *httptest.ResponseRecorder {
	env.t.Helper()
	var r *strings.Reader
	switch b := body.(type) {
	case nil:
		r = strings.NewReader("")
	case []byte:
		r = strings.NewReader(string(b))
	default:
		raw, err := json.Marshal(body)
		if err != nil {
			env.t.Fatal(err)
		}
		r = strings.NewReader(string(raw))
	}
	req := httptest.NewRequest(method, path, r)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if session != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
		req.Header.Set("X-CSRF-Token", csrfToken(session))
	}
	rec := httptest.NewRecorder()
	env.e.ServeHTTP(rec, req)
	if out != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			env.t.Fatalf("%s %s = %d, not JSON: %v: %s", method, path, rec.Code, err, rec.Body)
		}
	}
	return rec
}

func (env *adminEnv) count(name string) int32 { return env.calls[name].Load() }

// sessionAs creates a user with role and returns a live session for them.
func (env *adminEnv) sessionAs(role string) string {
	env.t.Helper()
	uid, err := env.db.CreateAdminUser("test-"+role+"@example.com", "password-"+role, role)
	if err != nil {
		env.t.Fatal(err)
	}
	tok, err := env.db.CreateSession(uid, "127.0.0.1", "test", "")
	if err != nil {
		env.t.Fatal(err)
	}
	return tok
}

// seedService adds a service pointing at the env's live test backend.
func (env *adminEnv) seedService(name, host string) storage.Service {
	env.t.Helper()
	if err := env.db.AddService(name, host, "", env.backend.URL, 0, 0); err != nil {
		env.t.Fatal(err)
	}
	if err := env.h.registry.Reload(env.db); err != nil {
		env.t.Fatal(err)
	}
	svcs, _ := env.db.ListServices()
	for _, s := range svcs {
		if s.Name == name {
			return s
		}
	}
	env.t.Fatalf("service %q not found", name)
	return storage.Service{}
}

func (env *adminEnv) seedLog(r storage.RequestLog) int64 {
	env.t.Helper()
	if r.Timestamp.IsZero() {
		r.Timestamp = time.Now()
	}
	id, err := env.db.InsertRequest(r)
	if err != nil {
		env.t.Fatal(err)
	}
	return id
}

func form(kv ...string) url.Values {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Add(kv[i], kv[i+1])
	}
	return v
}

type httptestRecorder = httptest.ResponseRecorder

// newReq builds an authenticated request with a raw (JSON) body.
func newReq(env *adminEnv, method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: env.session})
	req.Header.Set("X-CSRF-Token", csrfToken(env.session))
	return req
}

func serve(env *adminEnv, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	env.e.ServeHTTP(rec, req)
	return rec
}

// appFS is a built app as Vite lays it out (web/build/palisade.ts).
var appFS = fstest.MapFS{
	"app/dist/index.html": {Data: []byte(`<html><head><title>{{.BrandName}}</title><link rel="icon" href="{{.AdminPath}}{{.BrandLogo}}">{{if .BrandCSS}}<link rel="stylesheet" href="{{.AdminPath}}{{.BrandCSS}}">{{end}}<script type="module" src="{{.Base}}assets/index-x.js"></script></head>` +
		`<body data-admin="{{.AdminPath}}" data-brand="{{.BrandName}}" data-brand-logo="{{.AdminPath}}{{.BrandLogo}}" data-csrf="{{.CSRF}}" data-role="{{.Role}}" data-email="{{.Email}}" data-demo="{{.Demo}}" data-scoped="{{.Scoped}}" data-waf="{{.WAF}}" data-nonce="{{.Nonce}}"></body></html>`)},
	"app/dist/assets/index-x.js":    {Data: []byte("plain")},
	"app/dist/assets/index-x.js.br": {Data: []byte("brotli")},
	"app/dist/assets/index-x.js.gz": {Data: []byte("gzip")},
	"app/dist/assets/tiny.js":       {Data: []byte("tiny")},
	"app/dist/assets/blob.zzz":      {Data: []byte("blob")},
	"app/dist/licenses.md":          {Data: []byte("# Licenses")},
	// The sign-in page's own build (web/login.html): every field it reads.
	"app/dist/login/login.html": {Data: []byte(`<html><head><title>Sign in · {{.BrandName}}</title><link rel="icon" href="{{.AdminPath}}{{.BrandLogo}}">{{if .BrandCSS}}<link rel="stylesheet" href="{{.AdminPath}}{{.BrandCSS}}">{{end}}<script type="module" src="{{.Base}}assets/l.js"></script></head>` +
		`<body data-admin="{{.AdminPath}}" data-brand="{{.BrandName}}" data-brand-logo="{{.AdminPath}}{{.BrandLogo}}" data-stage="{{.Stage}}" data-error="{{.Error}}" data-notice="{{.Notice}}" data-sso="{{.SSO}}" ` +
		`data-demo-email="{{.DemoEmail}}" data-demo-pass="{{.DemoPass}}" data-passkeys="{{.Passkeys}}" data-email-code="{{.EmailCode}}" ` +
		`data-invite-email="{{.InviteEmail}}" data-token="{{.Token}}" data-ext-login="{{.ExtLogin}}" data-ext-login-path="{{.ExtLoginPath}}"></body></html>`)},
	"app/dist/login/assets/l.js": {Data: []byte("login")},
}
