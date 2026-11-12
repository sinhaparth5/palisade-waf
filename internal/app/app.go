// Package app is the palisade binary minus main (issue #287): flag parsing,
// the subcommands and server startup/shutdown, written as functions that take
// their arguments and return errors so they can be tested.
package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"palisade/internal/security/breach"
	"palisade/internal/storage"
	"palisade/internal/ui"
)

// Assets are the //go:embed trees. They live at the repo root, where
// //go:embed can reach static/, and are passed in.
type Assets struct{ JS, CSS, Imgs embed.FS }

// hibpURL is the leaked-password range API setup checks against (empty =
// the real one); tests point it at a fake.
var hibpURL = ""

// Run is one invocation of the binary; args is os.Args[1:]. The server runs
// until ctx ends (main cancels it on SIGINT/SIGTERM), then drains.
func Run(ctx context.Context, args []string, version string, assets Assets, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return serve(ctx, args, version, assets)
	}
	var err error
	switch cmd, rest := args[0], args[1:]; cmd {
	case "--version", "version":
		_, err = fmt.Fprintln(stdout, "palisade", version)
		return err
	case "prune":
		err = runPrune(rest)
	case "setup":
		err = runSetup(rest, stdin, stdout)
	case "config":
		err = runConfig(rest, stdin, stdout)
	case "gencert":
		err = runGencert(rest)
	case "healthcheck":
		err = runHealthcheck(ctx, rest)
	default:
		return serve(ctx, args, version, assets)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", args[0], err)
	}
	return nil
}

// dbFlags registers --db. --db-driver stays so units written before #300,
// which pass --db-driver sqlite, still start; openDB refuses anything else.
func dbFlags(fs *flag.FlagSet) (path, driver *string) {
	return fs.String("db", "waf.db", "SQLite database file"),
		fs.String("db-driver", "sqlite", "deprecated: only sqlite is supported")
}

// errNoExternalDB names the way off MySQL/Postgres, which #300 removed.
var errNoExternalDB = errors.New(`only SQLite is supported: MySQL and Postgres were removed. ` +
	`Run "palisade config export" with the previous release against the old database, ` +
	`then "palisade config import" into a SQLite --db (see README)`)

// checkSQLite rejects a non-sqlite --db-driver or a --db that is a server DSN.
func checkSQLite(driver, path string) error {
	if !strings.EqualFold(strings.TrimSpace(driver), "sqlite") ||
		strings.Contains(path, "://") || strings.Contains(path, "@tcp(") || strings.Contains(path, "@unix(") {
		return errNoExternalDB
	}
	return nil
}

// openDB opens the SQLite store at path after checkSQLite.
func openDB(driver, path string) (*storage.DB, error) {
	if err := checkSQLite(driver, path); err != nil {
		return nil, err
	}
	return storage.Open(path)
}

// runPrune opens the DB, deletes request logs older than the configured
// retention window plus expired admin sessions, logs the result, and returns
// — it does not start the WAF, proxy, or admin UI. retention <= 0 disables
// request-log pruning (logs kept forever); expired sessions are always swept.
// --vacuum additionally rebuilds the DB file afterwards to hand freed pages
// back to the OS — DELETE alone never shrinks a SQLite file, only marks pages
// reusable, so without an occasional VACUUM the file sits at its high-water
// mark forever. It lives in this one-shot mode rather than the server because
// VACUUM is a single long write transaction: here the live server's writers
// just wait their busy_timeout turn, instead of the rebuild monopolizing the
// serving process's own connection pool.
// Invoked as: palisade prune [--db path] [--retention days] [--vacuum]
func runPrune(args []string) error {
	fs := flag.NewFlagSet("prune", flag.ContinueOnError)
	dbPath, dbDriver := dbFlags(fs)
	retention := fs.Int("retention", 30, "log retention in days (0 = keep forever)")
	vacuum := fs.Bool("vacuum", false, "rebuild the DB file after pruning to reclaim disk space")
	if err := fs.Parse(args); err != nil {
		return err
	}

	db, err := openDB(*dbDriver, *dbPath)
	if err != nil {
		return fmt.Errorf("db: %w", err)
	}
	defer db.Close()

	if err := pruneOnce(db, *retention); err != nil {
		return err
	}
	if !*vacuum {
		return nil
	}
	before := dbDiskSize(*dbPath)
	start := time.Now()
	if err := db.Vacuum(); err != nil {
		return fmt.Errorf("vacuum: failed after %s: %w", time.Since(start), err)
	}
	after := dbDiskSize(*dbPath)
	log.Printf("vacuum: reclaimed %s (%s -> %s, took %s)",
		formatBytes(before-after), formatBytes(before), formatBytes(after), time.Since(start))
	return nil
}

// pruneOnce deletes expired sessions, request logs older than retention days
// and audit entries older than max(retention, a year) (<= 0 keeps both
// forever). Shared by the prune subcommand and the
// in-process --prune-interval loop.
func pruneOnce(db *storage.DB, retention int) error {
	if n, err := db.PruneExpiredSessions(); err != nil {
		log.Printf("session prune failed: %v", err)
	} else {
		log.Printf("session prune: deleted %d expired sessions", n)
	}
	if retention <= 0 {
		log.Printf("log retention: disabled (retention <= 0), nothing to prune")
		return nil
	}
	if n, err := db.PruneAudit(max(retention, storage.AuditRetentionDays)); err != nil {
		log.Printf("audit prune failed: %v", err)
	} else {
		log.Printf("audit prune: deleted %d entries", n)
	}
	start := time.Now()
	n, err := db.PruneOldRequests(retention)
	dur := time.Since(start)
	if err != nil {
		return fmt.Errorf("log retention: prune failed after %s: %w", dur, err)
	}
	log.Printf("log retention: deleted %d requests older than %d days (took %s)", n, retention, dur)
	return nil
}

// runPruneLoop is --prune-interval: the prune subcommand run in-process, for
// deployments with no cron/systemd timer to call it (the Docker image). It
// prunes once at startup, so a container restarted more often than the
// interval still prunes, then on every tick until ctx ends. PruneOldRequests
// deletes in small batches, so the live log worker is never locked out for
// long. No VACUUM here: that single long write transaction stays in the
// one-shot `prune --vacuum` mode.
func runPruneLoop(ctx context.Context, db *storage.DB, every time.Duration, retention int) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := pruneOnce(db, retention); err != nil {
			log.Print(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// runHealthcheck probes a running server's readiness endpoint and fails when
// it is not ready. The Docker image is FROM scratch, with no curl or wget, so
// its HEALTHCHECK needs the binary itself to make the request.
// Invoked as: palisade healthcheck [--url http://127.0.0.1:8080/_cz/readyz]
func runHealthcheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := fs.String("url", "http://127.0.0.1:8080/_cz/readyz", "readiness URL to probe")
	if err := fs.Parse(args); err != nil {
		return err
	}
	client := http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("not ready: %s", resp.Status)
	}
	return nil
}

// dbDiskSize sums the on-disk footprint of a SQLite database: the main file
// plus its -wal and -shm sidecars (right after a big prune the WAL can dwarf
// the main file, so counting waf.db alone would misstate what VACUUM
// reclaimed). Missing sidecars contribute zero.
func dbDiskSize(path string) int64 {
	var total int64
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if fi, err := os.Stat(p); err == nil {
			total += fi.Size()
		}
	}
	return total
}

// runConfig is `palisade config export|import` (issue #263): the config
// tables as one JSON file. export writes to --out or stdout; import reads a
// file argument or stdin ("-") and refuses a database with config unless
// --replace. Secrets stay sealed under --db-key-file, or are left out of an
// export without one.
func runConfig(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 || (args[0] != "export" && args[0] != "import") {
		return errors.New("usage: palisade config export [--out file] | import [--replace] file (plus --db, --db-key-file)")
	}
	cmd := args[0]
	fs := flag.NewFlagSet("config "+cmd, flag.ContinueOnError)
	dbPath, dbDriver := dbFlags(fs)
	keyFile := fs.String("db-key-file", "", "the server's key file: secrets are exported sealed under it, and sealed files need it to import")
	out := fs.String("out", "", "export: write here instead of stdout (created 0600)")
	replace := fs.Bool("replace", false, "import: empty the config tables first instead of refusing a database that has config")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	db, err := openDB(*dbDriver, *dbPath)
	if err != nil {
		return fmt.Errorf("db: %w", err)
	}
	defer db.Close()
	if *keyFile != "" {
		if err := enableDBEncryption(db, *keyFile); err != nil {
			return fmt.Errorf("db-key-file: %w", err)
		}
	}

	if cmd == "export" {
		w := stdout
		if *out != "" {
			f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // G703: the operator's own --out path
			if err != nil {
				return err
			}
			defer f.Close()
			w = f
		}
		return db.ExportConfig(w)
	}

	if fs.NArg() != 1 {
		return errors.New("import needs one file argument (- for stdin)")
	}
	r := stdin
	if fs.Arg(0) != "-" {
		f, err := os.Open(fs.Arg(0)) //nolint:gosec // G703: the operator's own file argument
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}
	rep, err := db.ImportConfig(r, *replace)
	if err != nil {
		return err
	}
	log.Printf("config import: %d rows in %d tables", rep.TotalRows, len(rep.Tables))
	return nil
}

// enableDBEncryption turns on secrets-at-rest encryption from a key file.
// The AES-256 key is SHA-256 of the file's whitespace-trimmed contents rather
// than the raw bytes, so any high-entropy file works regardless of format
// (`openssl rand -hex 32 > db.key`, raw binary, base64) and an editor adding
// a trailing newline doesn't silently derive a different key. The file must
// carry at least 32 bytes so a short passphrase can't quietly stand in for
// real key material — hashing would mask how weak it is.
func enableDBEncryption(db *storage.DB, path string) error {
	data, err := os.ReadFile(path) //nolint:gosec // G703: the operator's own --db-key-file
	if err != nil {
		return err
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) < 32 {
		return fmt.Errorf("key file %s holds %d bytes; need at least 32 — generate one with: openssl rand -hex 32 > %s", path, len(trimmed), path)
	}
	key := sha256.Sum256(trimmed)
	return db.EnableSecretEncryption(key[:])
}

// formatBytes renders a byte count human-readably for prune log lines.
func formatBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// readLine reads the one stdin line setup takes a password from.
func readLine(r io.Reader) string {
	s := bufio.NewScanner(r)
	s.Scan()
	return strings.TrimSpace(s.Text())
}

// runSetup seeds admin credentials and optional TLS config into the DB.
// Idempotent for admin credentials: when an admin exists (upgrades, re-runs)
// the account is left alone unless --reset-password names an existing user,
// whose password is then replaced (issue #315). Domain and ACME email are
// always overwritten (safe to update during upgrades).
// Invoked as: palisade setup --db path --admin-email email [--reset-password] [--domain d] [--acme-email e]
// Password is read from stdin (one line).
func runSetup(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	dbPath, dbDriver := dbFlags(fs)
	adminEmail := fs.String("admin-email", "", "admin email address (the login name)")
	reset := fs.Bool("reset-password", false, "replace the password of the existing user --admin-email")
	domain := fs.String("domain", "", "primary domain for ACME (Let's Encrypt)")
	acmeEmail := fs.String("acme-email", "", "ACME contact email (defaults to admin email)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *adminEmail == "" {
		return errors.New("--admin-email is required")
	}
	// The login form is type="email": a plain name could never be typed in.
	if !storage.ValidEmail(*adminEmail) {
		return fmt.Errorf("--admin-email %q is not an email address (it is the login name, e.g. you@example.com)", *adminEmail)
	}

	fmt.Fprint(os.Stderr, "Admin password: ")
	password := readLine(stdin)
	if password == "" {
		return errors.New("password cannot be empty")
	}

	db, err := openDB(*dbDriver, *dbPath)
	if err != nil {
		return fmt.Errorf("db: %w", err)
	}
	defer db.Close()

	// Only a password that will actually be stored is judged: a re-run on
	// an existing install must stay a no-op.
	n, err := db.CountAdminUsers()
	if err != nil {
		return err
	}
	validate := func() error {
		return ui.ValidateAdminPassword(context.Background(), breach.New(hibpURL), *adminEmail, password)
	}
	switch {
	case *reset:
		u, err := db.GetAdminUserByEmail(*adminEmail)
		if err != nil {
			return err
		}
		if u == nil {
			return fmt.Errorf("no admin user %q to reset", storage.NormalizeEmail(*adminEmail))
		}
		if err := validate(); err != nil {
			return err
		}
		if err := db.UpdateAdminCredentials(u.ID, "", password); err != nil { // also signs out their sessions
			return err
		}
		if err := db.InsertAudit(storage.AuditEntry{Actor: "palisade setup (shell)", Action: "setup --reset-password", Target: fmt.Sprintf("id=%d", u.ID), Summary: "email=" + u.Email}); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "setup: password reset for %s; their sessions were signed out\n", u.Email)
	case n > 0:
		fmt.Fprintln(stdout, "setup: an admin account already exists, password unchanged (use --reset-password to change it)")
	default:
		if err := validate(); err != nil {
			return err
		}
		if _, err := db.CreateAdminUser(*adminEmail, password, storage.RoleOwner); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "setup: admin account created (%s)\n", storage.NormalizeEmail(*adminEmail))
	}

	if *domain == "" {
		return nil
	}
	if err := db.SetPrimaryDomain(*domain); err != nil {
		return fmt.Errorf("store domain: %w", err)
	}
	contactEmail := *acmeEmail
	if contactEmail == "" {
		contactEmail = *adminEmail
	}
	if err := db.SetAcmeEmail(contactEmail); err != nil {
		return fmt.Errorf("store acme email: %w", err)
	}
	log.Printf("setup: ACME configured for domain %s (contact: %s)", *domain, contactEmail)
	return nil
}

// runGencert generates a self-signed ECDSA P-256 certificate and writes PEM
// files. The certificate includes the provided hostnames/IPs as SANs so
// browsers don't get a hostname-mismatch error on IP-based access.
// Invoked as: palisade gencert --cert path --key path --hosts ip1,ip2,...
func runGencert(args []string) error {
	fs := flag.NewFlagSet("gencert", flag.ContinueOnError)
	certFile := fs.String("cert", "cert.pem", "output PEM certificate file")
	keyFile := fs.String("key", "key.pem", "output PEM private key file")
	hosts := fs.String("hosts", "", "comma-separated hostnames and/or IP addresses for SANs")
	days := fs.Int("days", 3650, "certificate validity in days")
	if err := fs.Parse(args); err != nil {
		return err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Palisade"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Duration(*days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range splitCSV(*hosts) {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	if err := writePEM(*certFile, 0o644, "CERTIFICATE", certDER); err != nil {
		return err
	}
	if err := writePEM(*keyFile, 0o600, "EC PRIVATE KEY", keyDER); err != nil {
		return err
	}
	log.Printf("gencert: wrote %s and %s (valid %d days, hosts: %s)", *certFile, *keyFile, *days, *hosts)
	return nil
}

func writePEM(path string, perm os.FileMode, typ string, der []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm) //nolint:gosec // G302/G304: the operator's own output path; only the certificate is 0644
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
