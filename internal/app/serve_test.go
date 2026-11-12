//go:build unix

package app

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"palisade/internal/config"
	"palisade/internal/security/ratelimit"
	"palisade/internal/storage"

	"github.com/quic-go/quic-go/http3"
)

// started is a serve run in the background: the addresses it bound, by
// listening name, and a stop that cancels it and returns its error.
type started struct {
	addr map[string]string
	stop func() error
}

// startServe runs serve with args until stop, waiting for want listeners.
func startServe(t *testing.T, args []string, want ...string) started {
	t.Helper()
	got := make(chan [2]string, 8)
	listening = func(name string, a net.Addr) { got <- [2]string{name, a.String()} }
	t.Cleanup(func() { listening = func(string, net.Addr) {} })

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- serve(ctx, args, "test", Assets{}) }()
	s := started{addr: map[string]string{}, stop: func() error {
		cancel()
		select {
		case err := <-errc:
			return err
		case <-time.After(15 * time.Second):
			t.Fatal("serve did not return after cancel")
			return nil
		}
	}}
	for len(s.addr) < len(want) {
		select {
		case l := <-got:
			s.addr[l[0]] = l[1]
		case err := <-errc:
			cancel()
			t.Fatalf("serve returned before listening: %v", err)
		case <-time.After(30 * time.Second):
			cancel()
			t.Fatal("serve never listened")
		}
	}
	return s
}

func get(t *testing.T, c *http.Client, url, host string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if host != "" {
		req.Host = host
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

// TestServeHTTP starts the plain-HTTP server with an admin-only listener,
// checks the probes, the challenge logo and where the admin UI answers, then
// shuts it down: serve returns nil and the listeners are closed.
func TestServeHTTP(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetBotSettings(true, 50, 3600); err != nil {
		t.Fatal(err)
	}
	db.Close()
	key := filepath.Join(dir, "db.key")
	if err := os.WriteFile(key, []byte(strings.Repeat("k", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	s := startServe(t, []string{
		"--db", filepath.Join(dir, "waf.db"), "--db-key-file", key, "--listen", "127.0.0.1:0", "--admin-listen", "127.0.0.1:0",
		"--access-log", filepath.Join(dir, "access.log"), "--prune-interval", "1h", "--certs", dir,
		"--trusted-proxies", "10.0.0.0/8", "--admin-allow", "127.0.0.1,::1/128",
	}, "http", "admin")
	c := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	pub, admin := "http://"+s.addr["http"], "http://"+s.addr["admin"]
	for path, want := range map[string]int{"/_cz/healthz": 200, "/_cz/readyz": 200, "/_cz/logo.svg": 404, "/_cz/challenge": 400, "/_cz/fp.js": 200} {
		if r := get(t, c, pub+path, ""); r.StatusCode != want {
			t.Errorf("%s = %d, want %d", path, r.StatusCode, want)
		}
	}
	for path, want := range map[string]int{"/_cz/verify": http.StatusForbidden, "/_cz/csp-report?s=1": http.StatusNoContent} {
		r, err := c.Post(pub+path, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != want {
			t.Errorf("POST %s = %d, want %d", path, r.StatusCode, want)
		}
	}
	if r := get(t, c, admin+"/admin/login", ""); r.StatusCode != http.StatusOK {
		t.Errorf("admin listener /admin/login = %d", r.StatusCode)
	}
	// With --admin-listen the public listener proxies the admin path, and
	// no service matches here.
	if r := get(t, c, pub+"/admin/login", ""); r.StatusCode == http.StatusOK {
		t.Errorf("public listener served the admin UI")
	}

	if err := s.stop(); err != nil {
		t.Fatalf("serve = %v", err)
	}
	for _, a := range s.addr {
		if conn, err := net.DialTimeout("tcp", a, time.Second); err == nil {
			conn.Close()
			t.Errorf("%s still accepting after shutdown", a)
		}
	}
}

// TestServeTLS: HTTPS with the self-signed fallback cert speaks HTTP/2, the
// plain listener redirects to HTTPS, HTTP/3 binds, and all of it shuts down.
func TestServeTLS(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if err := runGencert([]string{"--cert", cert, "--key", key, "--hosts", "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "waf.db")
	db, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	// An ACME contact turns on autocert; no host matches it here, so the
	// fallback cert still answers.
	if err := db.SetAcmeEmail("ops@example.com"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	s := startServe(t, []string{
		"--db", dbPath, "--certs", filepath.Join(dir, "certs"), "--listen", "127.0.0.1:0",
		"--listen-tls", "127.0.0.1:0", "--listen-h3", "127.0.0.1:0", "--tls-cert", cert, "--tls-key", key,
	}, "redirect", "https", "h3")
	insecure := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // self-signed test cert
	c := &http.Client{
		Timeout:       5 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: insecure, ForceAttemptHTTP2: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if r := get(t, c, "https://"+s.addr["https"]+"/_cz/healthz", ""); r.StatusCode != 200 || r.ProtoMajor != 2 {
		t.Errorf("https healthz = %d over %s", r.StatusCode, r.Proto)
	}
	r := get(t, c, "http://"+s.addr["redirect"]+"/x?y=1", "waf.example")
	if loc := r.Header.Get("Location"); r.StatusCode != http.StatusMovedPermanently || loc != "https://waf.example/x?y=1" {
		t.Errorf("redirect = %d %q", r.StatusCode, loc)
	}
	// No service opted into HTTP/3, so QUIC answers 421.
	h3 := &http3.Transport{TLSClientConfig: insecure}
	defer h3.Close()
	if r := get(t, &http.Client{Transport: h3, Timeout: 5 * time.Second}, "https://"+s.addr["h3"]+"/", ""); r.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("h3 = %d", r.StatusCode)
	}
	if err := s.stop(); err != nil {
		t.Fatalf("serve = %v", err)
	}
}

// TestServeStartupErrors: every bad flag, file or taken port stops startup
// with an error instead of a half-running server.
func TestServeStartupErrors(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "waf.db")
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	busy := taken.Addr().String()
	short := filepath.Join(dir, "short.key")
	if err := os.WriteFile(short, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := map[string][]string{
		"unknown flag":       {"--bogus"},
		"h3 without tls":     {"--listen-h3", ":0"},
		"admin-allow typo":   {"--admin-allow", "10.0.0.300"},
		"trusted-crawlers":   {"--trusted-crawlers", "nonsense"},
		"prune-interval":     {"--prune-interval", "30s"},
		"db driver":          {"--db-driver", "nosuch"},
		"db key":             {"--db-key-file", short},
		"access log":         {"--access-log", filepath.Join(short, "a.log")},
		"listen taken":       {"--listen", busy},
		"admin-listen taken": {"--admin-listen", busy},
		"redirect taken":     {"--listen", busy, "--listen-tls", "127.0.0.1:0"},
		"https taken":        {"--listen", "127.0.0.1:0", "--listen-tls", busy, "--admin-listen", "127.0.0.1:0"},
		"fallback cert":      {"--listen", "127.0.0.1:0", "--listen-tls", "127.0.0.1:0", "--tls-cert", short, "--tls-key", short},
		"h3 address":         {"--listen", "127.0.0.1:0", "--listen-tls", "127.0.0.1:0", "--listen-h3", "noport"},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // stops a case that wrongly started
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() {
				done <- serve(ctx, append([]string{"--db", db, "--certs", dir, "--listen", "127.0.0.1:0"}, args...), "test", Assets{})
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Error("started")
				}
			case <-time.After(30 * time.Second):
				t.Fatal("serve did not fail")
			}
		})
	}
}

func TestCheckWritable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes anywhere")
	}
	dir := t.TempDir()
	if err := checkWritable(dir); err != nil {
		t.Errorf("writable dir: %v", err)
	}
	if err := checkWritable(filepath.Join(dir, "missing")); err != nil {
		t.Errorf("missing dir is left to the real open: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700) //nolint:errcheck // restores the temp dir for cleanup
	if err := checkWritable(dir); err == nil || !strings.Contains(err.Error(), "chown -R 65532") {
		t.Errorf("read-only dir: %v", err)
	}
	if _, err := run([]string{"--db", filepath.Join(dir, "waf.db")}, ""); err == nil {
		t.Error("serve started on a read-only data dir")
	}
}

// TestBuildWAFAll: only services that need their own engine get one, and a
// read failure is an error, not a half-built set.
func TestBuildWAFAll(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, name := range []string{"plain", "js", "schema", "spec", "mcp", "except", "custom"} {
		if err := db.AddService(name, name+".example.com", "", "http://127.0.0.1:1", 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	id := map[string]int{}
	svcs, _ := db.ListServices()
	for _, s := range svcs {
		id[s.Name] = s.ID
	}
	for _, err := range []error{
		db.SetServiceLargeJSUploads(id["js"], true),
		db.SetServiceSchema(id["schema"], `{"type":"object"}`, "enforce"),
		db.SetServiceOpenAPI(id["spec"], "not a spec", "log"), // invalid: logged, engine still built
		db.SetServiceMCP(id["mcp"], storage.ServiceMCP{Mode: "enforce", Path: "/mcp"}),
		db.DisableWAFRuleForService("except", 942100, "fp"),
		db.SaveWAFCustomRule(storage.WAFCustomRule{ServiceName: "custom", Rule: `SecAction "id:1000001,phase:1,pass,nolog"`, Enabled: true}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	def, by, err := buildWAFAll(db, config.Defaults().WAF)
	if err != nil || def == nil {
		t.Fatalf("buildWAFAll: %v", err)
	}
	if _, ok := by["plain"]; ok || len(by) != 6 {
		t.Errorf("per-service engines = %d, plain included = %v", len(by), ok)
	}

	db.Close()
	if _, _, err := buildWAFAll(db, config.Defaults().WAF); err == nil {
		t.Error("closed DB: built anyway")
	}
}

// TestReloadOnHUP: SIGHUP runs the reload, a failed one is survived, and
// nothing runs after ctx ends.
func TestReloadOnHUP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := make(chan struct{}, 4)
	reloadOnHUP(ctx, func() error { calls <- struct{}{}; return context.Canceled })
	for range 2 {
		syscall.Kill(os.Getpid(), syscall.SIGHUP) //nolint:errcheck
		select {
		case <-calls:
		case <-time.After(5 * time.Second):
			t.Fatal("SIGHUP did not reload")
		}
	}
	cancel()
}

func TestStartCacheReturn(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, addr := range []string{"0.0.0.0:6082", "no-port", "example.com:6082"} {
		if err := db.SetVarnishConfig(storage.VarnishConfig{ReturnAddr: addr}); err != nil {
			t.Fatal(err)
		}
		if srv := startCacheReturn(db, nil); srv != nil {
			srv.Close()
			t.Errorf("%s: started", addr)
		}
	}
	db.Close()
	if srv := startCacheReturn(db, nil); srv != nil {
		t.Error("closed DB: started")
	}
}

// TestBuildRateLimit: disabled is a limiter that allows everything; enabled
// restores the persisted buckets, so a client out of tokens stays limited
// across a restart.
func TestBuildRateLimit(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	off := buildRateLimit(db)
	defer off.Stop()
	for range 50 {
		if !off.Allow("203.0.113.9").Allowed {
			t.Fatal("disabled limiter refused")
		}
	}
	if err := db.SetRateLimitSettings(true, 0.001, 5); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveRateLimitState([]ratelimit.BucketState{{IP: "203.0.113.9", Tokens: 0, LastRefill: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	on := buildRateLimit(db)
	defer on.Stop()
	if on.Allow("203.0.113.9").Allowed {
		t.Error("restored empty bucket allowed a request")
	}
	if !on.Allow("203.0.113.10").Allowed {
		t.Error("fresh client refused")
	}
}

// TestServeUntilServeError: when Serve fails outright, the other servers are
// closed rather than left running with no drain to stop them.
func TestServeUntilServeError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	other := &http.Server{} //nolint:gosec // never serves
	otherLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- other.Serve(otherLn) }()
	if err := serveUntil(context.Background(), &http.Server{}, ln, []shutdowner{other}); err == nil { //nolint:gosec // never serves
		t.Fatal("serve on a closed listener succeeded")
	}
	select {
	case err := <-served:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("other server: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("other server left running")
	}
}
