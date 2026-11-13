package app

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // HIBP's range API is keyed by SHA-1
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"palisade/internal/storage"
)

// leakedPassword is the one password fakeHIBP lists.
const leakedPassword = "correct-horse-battery"

// fakeHIBP points setup's leaked-password check at a local range API.
func fakeHIBP(t *testing.T) {
	t.Helper()
	sum := sha1.Sum([]byte(leakedPassword)) //nolint:gosec // HIBP's range API is keyed by SHA-1
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, h[:5]) {
			fmt.Fprintf(w, "%s:42\r\n", h[5:])
		}
	}))
	t.Cleanup(srv.Close)
	old := hibpURL
	hibpURL = srv.URL + "/range/"
	t.Cleanup(func() { hibpURL = old })
}

func run(args []string, stdin string) (string, error) {
	var out bytes.Buffer
	err := Run(context.Background(), args, "v9.9.9", Assets{}, strings.NewReader(stdin), &out)
	return out.String(), err
}

func TestRunVersionAndHelp(t *testing.T) {
	if out, err := run([]string{"--version"}, ""); err != nil || out != "palisade v9.9.9\n" {
		t.Errorf("version = %q, %v", out, err)
	}
	for _, cmd := range []string{"prune", "setup", "gencert", "healthcheck"} {
		if _, err := run([]string{cmd, "-h"}, ""); !errors.Is(err, flag.ErrHelp) {
			t.Errorf("%s -h = %v, want flag.ErrHelp", cmd, err)
		}
		if _, err := run([]string{cmd, "--bogus"}, ""); err == nil || !strings.HasPrefix(err.Error(), cmd+": ") {
			t.Errorf("%s --bogus = %v", cmd, err)
		}
	}
}

func TestGencert(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if _, err := run([]string{"gencert", "--cert", cert, "--key", key, "--hosts", " 10.0.0.1, waf.example ,", "--days", "2"}, ""); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(cert)
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("no PEM certificate")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.IPAddresses) != 1 || c.IPAddresses[0].String() != "10.0.0.1" || len(c.DNSNames) != 1 || c.DNSNames[0] != "waf.example" {
		t.Errorf("SANs = %v %v", c.IPAddresses, c.DNSNames)
	}
	if left := time.Until(c.NotAfter); left < 47*time.Hour || left > 49*time.Hour {
		t.Errorf("NotAfter in %s, want ~48h", left)
	}
	if fi, err := os.Stat(key); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v %v", fi, err)
	}
	if _, err := run([]string{"gencert", "--cert", filepath.Join(dir, "nope", "c.pem"), "--key", key}, ""); err == nil {
		t.Error("unwritable cert path accepted")
	}
	if _, err := run([]string{"gencert", "--cert", cert, "--key", filepath.Join(dir, "nope", "k.pem")}, ""); err == nil {
		t.Error("unwritable key path accepted")
	}
}

func TestSetup(t *testing.T) {
	fakeHIBP(t)
	path := filepath.Join(t.TempDir(), "waf.db")
	setup := func(stdin string, extra ...string) error {
		_, err := run(append([]string{"setup", "--db", path}, extra...), stdin)
		return err
	}
	for name, err := range map[string]error{
		"no email":       setup("long-enough-password\n"),
		"plain name":     setup("long-enough-password\n", "--admin-email", "amir"),
		"empty password": setup("\n", "--admin-email", "a@example.com"),
		"short password": setup("short\n", "--admin-email", "a@example.com"),
		"leaked":         setup(leakedPassword+"\n", "--admin-email", "a@example.com"),
		"bad driver":     setup("long-enough-password\n", "--admin-email", "a@example.com", "--db-driver", "nosuch"),
	} {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := setup(leakedPassword+"\n", "--admin-email", "a@example.com"); err == nil || !strings.Contains(err.Error(), "breach") {
		t.Errorf("leaked password: %v", err)
	}
	if err := setup("long-enough-password\n", "--admin-email", "a@example.com", "--domain", "waf.example"); err != nil {
		t.Fatal(err)
	}
	// A re-run is a no-op for the account, even with a password that would
	// now be refused, and updates the ACME settings.
	if err := setup("short\n", "--admin-email", "a@example.com", "--domain", "waf2.example", "--acme-email", "ops@example.com"); err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if u, err := db.CheckAdminLogin("a@example.com", "long-enough-password"); err != nil || u == nil {
		t.Errorf("login after setup = %v, %v", u, err)
	}
	domain, _ := db.GetPrimaryDomain()
	acme, _ := db.GetAcmeEmail()
	if domain != "waf2.example" || acme != "ops@example.com" {
		t.Errorf("domain %q acme %q", domain, acme)
	}
}

// TestSetupMessagesAndReset pins issue #315: setup says whether it created
// the account or left it alone, and --reset-password replaces an existing
// user's password, signs out their sessions and writes an audit row.
func TestSetupMessagesAndReset(t *testing.T) {
	fakeHIBP(t)
	path := filepath.Join(t.TempDir(), "waf.db")
	setup := func(stdin string, extra ...string) (string, error) {
		return run(append([]string{"setup", "--db", path}, extra...), stdin)
	}
	if out, err := setup("long-enough-password\n", "--admin-email", "A@Example.com"); err != nil || !strings.Contains(out, "admin account created (a@example.com)") {
		t.Fatalf("create: %q, %v", out, err)
	}
	if out, err := setup("another-long-password\n", "--admin-email", "a@example.com"); err != nil || !strings.Contains(out, "password unchanged (use --reset-password") {
		t.Fatalf("re-run: %q, %v", out, err)
	}

	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	u, _ := db.GetAdminUserByEmail("a@example.com")
	token, err := db.CreateSession(u.ID, "203.0.113.1", "test", "")
	if err != nil {
		t.Fatal(err)
	}

	for name, args := range map[string][]string{
		"unknown user": {"--admin-email", "b@example.com", "--reset-password"},
		"short":        {"--admin-email", "a@example.com", "--reset-password"},
	} {
		stdin := "another-long-password\n"
		if name == "short" {
			stdin = "short\n"
		}
		if _, err := setup(stdin, args...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	out, err := setup("another-long-password\n", "--admin-email", "a@example.com", "--reset-password")
	if err != nil || !strings.Contains(out, "password reset for a@example.com") {
		t.Fatalf("reset: %q, %v", out, err)
	}
	if u, _ := db.CheckAdminLogin("a@example.com", "another-long-password"); u == nil {
		t.Error("new password refused")
	}
	if u, _ := db.CheckAdminLogin("a@example.com", "long-enough-password"); u != nil {
		t.Error("old password still works")
	}
	if ok, _ := db.ValidateSession(token); ok {
		t.Error("session survived the reset")
	}
	if rows, _, _ := db.ListAudit(10, 0); len(rows) != 1 || rows[0].Action != "setup --reset-password" {
		t.Errorf("audit = %+v", rows)
	}
}

// TestSetupReset2FA pins issue #317: --reset-2fa alone needs no password,
// clears TOTP and passkeys, keeps the password, signs out and audits; it
// combines with --reset-password.
func TestSetupReset2FA(t *testing.T) {
	fakeHIBP(t)
	path := filepath.Join(t.TempDir(), "waf.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	uid, _ := db.CreateAdminUser("a@example.com", "long-enough-password", storage.RoleOwner)
	enroll := func() string {
		t.Helper()
		if err := db.SetPendingTOTPSecret(uid, "JBSWY3DPEHPK3PXP"); err != nil {
			t.Fatal(err)
		}
		if err := db.EnableTOTP(uid, []string{"backup-hash"}); err != nil {
			t.Fatal(err)
		}
		if err := db.AddWebAuthnCredential(uid, "cred-1", "key", []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		token, err := db.CreateSession(uid, "203.0.113.1", "test", "")
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	check := func(name, token string) {
		t.Helper()
		if on, _ := db.TOTPEnabled(uid); on {
			t.Errorf("%s: TOTP still on", name)
		}
		if ok, _ := db.ConsumeTOTPBackupCode(uid, "backup-hash"); ok {
			t.Errorf("%s: backup code still works", name)
		}
		if on, _ := db.WebAuthnEnabled(uid); on {
			t.Errorf("%s: passkey still there", name)
		}
		if ok, _ := db.ValidateSession(token); ok {
			t.Errorf("%s: session survived", name)
		}
	}
	setup := func(stdin string, extra ...string) (string, error) {
		return run(append([]string{"setup", "--db", path}, extra...), stdin)
	}

	if _, err := setup("", "--admin-email", "b@example.com", "--reset-2fa"); err == nil {
		t.Error("unknown user accepted")
	}
	token := enroll()
	out, err := setup("", "--admin-email", "a@example.com", "--reset-2fa")
	if err != nil || !strings.Contains(out, "2FA reset for a@example.com") {
		t.Fatalf("reset: %q, %v", out, err)
	}
	check("2fa only", token)
	if u, _ := db.CheckAdminLogin("a@example.com", "long-enough-password"); u == nil || u.TOTPEnabled {
		t.Errorf("password login after reset: %+v", u)
	}

	token = enroll()
	out, err = setup("another-long-password\n", "--admin-email", "a@example.com", "--reset-2fa", "--reset-password")
	if err != nil || !strings.Contains(out, "password reset") || !strings.Contains(out, "2FA reset") {
		t.Fatalf("both: %q, %v", out, err)
	}
	check("both", token)
	if u, _ := db.CheckAdminLogin("a@example.com", "another-long-password"); u == nil {
		t.Error("new password refused")
	}
	var actions []string
	rows, _, _ := db.ListAudit(10, 0)
	for _, r := range rows {
		actions = append(actions, r.Action)
	}
	if got := strings.Join(actions, ","); got != "setup --reset-2fa,setup --reset-password,setup --reset-2fa" {
		t.Errorf("audit = %s", got)
	}
}

// TestSetupListUsers pins issue #316: one row per user with its sign-in
// state, nothing secret, no writes.
func TestSetupListUsers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "waf.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := db.CreateAdminUser("owner@example.com", "long-enough-password", storage.RoleOwner)
	if _, err := db.CreateSession(owner, "203.0.113.1", "test", ""); err != nil {
		t.Fatal(err)
	}
	if err := db.AddWebAuthnCredential(owner, "cred-1", "key", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.InviteAdminUser("new@example.com", storage.RoleViewer); err != nil {
		t.Fatal(err)
	}
	db.Close()
	before, _ := os.ReadFile(path)

	out, err := run([]string{"setup", "--db", path, "--list-users"}, "")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "EMAIL") ||
		!regexp.MustCompile(`^owner@example\.com +owner +- +- +1 +- +- +\S+ \S+ +\S+ \S+ UTC from 203\.0\.113\.1$`).MatchString(lines[1]) ||
		!regexp.MustCompile(`^new@example\.com +viewer +- +- +0 +- +yes .* never$`).MatchString(lines[2]) {
		t.Fatalf("output:\n%s", out)
	}
	if strings.Contains(out, "$2a$") {
		t.Error("printed a password hash")
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Error("--list-users changed the database")
	}
	if _, err := run([]string{"setup", "--db", path, "--list-users", "--admin-email", "a@example.com"}, ""); err == nil {
		t.Error("--list-users with --admin-email accepted")
	}
}

// MySQL/Postgres setups (#300) fail with the migration path, not a
// half-working open.
func TestRemovedDBBackends(t *testing.T) {
	for _, args := range [][]string{
		{"prune", "--db-driver", "mysql"},
		{"config", "export", "--db-driver", "postgres"},
		{"prune", "--db", "postgres://u:p@db:5432/waf?sslmode=require"},
		{"prune", "--db", "u:p@tcp(db:3306)/waf"},
		{"prune", "--db", "u@unix(/run/mysqld.sock)/waf"},
	} {
		if _, err := run(args, ""); !errors.Is(err, errNoExternalDB) {
			t.Errorf("%v: err = %v, want errNoExternalDB", args, err)
		}
	}
}

func TestHealthcheck(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
	defer srv.Close()
	if _, err := run([]string{"healthcheck", "--url", srv.URL}, ""); err != nil {
		t.Errorf("ready: %v", err)
	}
	status = http.StatusServiceUnavailable
	if _, err := run([]string{"healthcheck", "--url", srv.URL}, ""); err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("not ready: %v", err)
	}
	for _, u := range []string{"http://127.0.0.1:1/", "::bad"} {
		if _, err := run([]string{"healthcheck", "--url", u}, ""); err == nil {
			t.Errorf("%s: accepted", u)
		}
	}
}

func TestPrune(t *testing.T) {
	path := filepath.Join(t.TempDir(), "waf.db")
	for _, args := range [][]string{
		{"--retention", "7", "--vacuum"},
		{"--retention", "0"},
		{"--vacuum", "--db-driver", "SQLite"},
	} {
		if _, err := run(append([]string{"prune", "--db", path}, args...), ""); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}

	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err := pruneOnce(db, 7); err == nil {
		t.Error("prune on a closed DB succeeded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runPruneLoop(ctx, db, time.Hour, 0) // returns once ctx is done
}

func TestEnableDBEncryption(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	dir := t.TempDir()
	short := filepath.Join(dir, "short.key")
	if err := os.WriteFile(short, []byte("  tooshort\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := enableDBEncryption(db, short); err == nil || !strings.Contains(err.Error(), "need at least 32") {
		t.Errorf("short key: %v", err)
	}
	if err := enableDBEncryption(db, filepath.Join(dir, "missing")); err == nil {
		t.Error("missing key file accepted")
	}
}

func TestFormatBytes(t *testing.T) {
	for n, want := range map[int64]string{512: "512 B", 1536: "1.5 KiB", 3 << 20: "3.0 MiB", -10: "-10 B"} {
		if got := formatBytes(n); got != want {
			t.Errorf("formatBytes(%d) = %q, want %q", n, got, want)
		}
	}
	if got := splitCSV(" a, ,b,"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("splitCSV = %q", got)
	}
}
