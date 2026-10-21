package storage

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

// connTestTimeout bounds how long TestConnection waits for a dial+ping
// before giving up — short enough that a misconfigured host (wrong IP,
// closed port, unreachable Docker network) fails fast in the admin UI
// instead of hanging an HTTP request open, matching services.Probe's
// probeTimeout philosophy for the analogous "is this reachable" check.
const connTestTimeout = 5 * time.Second

// DBConnFields describes a database connection built from individual pieces
// (host, port, credentials, ...) rather than a hand-typed DSN — the admin
// Settings page's "Database connection" card offers both, since a raw DSN is
// easy to get wrong (an unescaped ":" or "@" in a password silently corrupts
// a MySQL DSN or a postgres:// URL) and BuildDSN does that escaping
// correctly via each driver's own DSN builder instead of string
// concatenation.
type DBConnFields struct {
	Driver   string // anything resolveDialect accepts: sqlite, mysql/mariadb, postgres/postgresql/cockroachdb/cockroach/neon
	Host     string
	Port     string
	Username string
	Password string
	DBName   string
	SSLMode  string // postgres: sslmode value (disable/allow/prefer/require/verify-ca/verify-full); mysql: tls value (false/true/skip-verify/preferred); ignored for sqlite
	Extra    string // raw "key=value&key2=value2" extra params, dialect-specific, merged in as-is
}

// BuildDSN constructs a dialect-appropriate DSN from individual fields via
// each driver's own config/URL builder — go-sql-driver/mysql's mysql.Config
// and Go's net/url both handle escaping special characters in a
// user/password correctly, which a fmt.Sprintf-based concatenation would not
// (e.g. a password containing "@" or ":" would silently shift where the
// parser thinks the host starts).
func BuildDSN(f DBConnFields) (string, error) {
	d, err := resolveDialect(f.Driver)
	if err != nil {
		return "", err
	}

	if d.name != "sqlite" && !validDBHost(f.Host) {
		return "", fmt.Errorf("host %q is not a hostname or IP address", f.Host)
	}

	switch d.name {
	case "sqlite":
		// sqlite has no host/port/credentials — Host doubles as the file
		// path, matching the existing --db flag's meaning for this driver.
		if strings.TrimSpace(f.Host) == "" {
			return "", fmt.Errorf("sqlite requires a database file path")
		}
		return f.Host, nil

	case "mysql":
		port, err := portOrDefault(f.Port, "3306")
		if err != nil {
			return "", err
		}
		// The driver writes the user unescaped and splits user:password at
		// the first colon, so a colon in the user can't round-trip, and it
		// drops a password that has no user.
		if strings.Contains(f.Username, ":") {
			return "", fmt.Errorf("mysql username cannot contain ':'")
		}
		if f.Username == "" && f.Password != "" {
			return "", fmt.Errorf("mysql password needs a username")
		}
		cfg := mysql.NewConfig()
		cfg.User = f.Username
		cfg.Passwd = f.Password
		cfg.Net = "tcp"
		cfg.Addr = net.JoinHostPort(f.Host, port)
		cfg.DBName = f.DBName
		cfg.ParseTime = true
		if f.SSLMode != "" {
			cfg.TLSConfig = f.SSLMode
		}
		if extra, err := parseExtraParams(f.Extra); err != nil {
			return "", fmt.Errorf("extra params: %w", err)
		} else if len(extra) > 0 {
			cfg.Params = extra
		}
		return cfg.FormatDSN(), nil

	case "postgres":
		port, err := portOrDefault(f.Port, "5432")
		if err != nil {
			return "", err
		}
		u := &url.URL{
			Scheme: "postgres",
			User:   url.UserPassword(f.Username, f.Password),
			Host:   net.JoinHostPort(f.Host, port),
			Path:   "/" + f.DBName,
		}
		q := url.Values{}
		if f.SSLMode != "" {
			q.Set("sslmode", f.SSLMode)
		}
		extra, err := parseExtraParams(f.Extra)
		if err != nil {
			return "", fmt.Errorf("extra params: %w", err)
		}
		for k, v := range extra {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
		return u.String(), nil

	default:
		return "", fmt.Errorf("BuildDSN: unsupported driver %q", f.Driver)
	}
}

// validDBHost reports whether host is an IP address or uses only hostname
// characters. Anything else, such as a space or one of "/?#@", ends up in a
// DSN its own driver can't parse back.
func validDBHost(host string) bool {
	if strings.Contains(host, ":") {
		return net.ParseIP(host) != nil
	}
	return !strings.ContainsFunc(host, func(r rune) bool {
		return !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_", r)
	})
}

func portOrDefault(port, def string) (string, error) {
	if strings.TrimSpace(port) == "" {
		return def, nil
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("port %q must be a number from 1 to 65535", port)
	}
	return strconv.Itoa(n), nil // Atoi accepts "+1", which a URL port does not
}

// parseExtraParams parses a "key=value&key2=value2" string (the admin
// Settings page's free-form "Extra parameters" field, for anything the
// structured fields don't cover — e.g. Neon's pooler-endpoint options or a
// connect_timeout) the same way a URL query string is parsed, so admins can
// paste values copied from a provider's own connection-string examples.
func parseExtraParams(extra string) (map[string]string, error) {
	extra = strings.TrimSpace(extra)
	if extra == "" {
		return nil, nil
	}
	vals, err := url.ParseQuery(extra)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(vals))
	for k, v := range vals {
		// The mysql driver writes keys unescaped, so a "/" or ")" in one
		// corrupts the DSN. Real driver options are identifiers.
		if k == "" || strings.ContainsFunc(k, func(r rune) bool {
			return !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_", r)
		}) {
			return nil, fmt.Errorf("parameter name %q must be letters, digits or '_'", k)
		}
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out, nil
}

// TestConnection dials the target database and pings it, then closes the
// connection without running any schema migration or leaving anything open
// — a shallow reachability check only, mirroring services.Probe's "any
// response counts as reachable" philosophy but for a database dial instead
// of an HTTP GET. Used by the Settings page's "Test connection" button so
// admins can validate a DSN/field-built connection (including one pointed at
// a Docker-internal hostname/IP or a managed cloud endpoint) before saving
// it or restarting the server with it — this never touches the live
// server's actual DB connection.
func TestConnection(driverName, dsn string) error {
	d, err := resolveDialect(driverName)
	if err != nil {
		return err
	}
	conn, err := d.openDB(dsn)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), connTestTimeout)
	defer cancel()
	return conn.PingContext(ctx)
}

// DBConnConfig is the admin-entered database connection persisted in the
// meta table purely for the Settings page's convenience (pre-filling the
// form on next visit) — it has no effect on the live server's actual DB
// connection, which is fixed at process start via the --db-driver/--db CLI
// flags (see main.go). Applying a saved config requires restarting the
// process with the shown flags.
type DBConnConfig struct {
	Driver   string
	Mode     string // "dsn" or "fields"
	DSN      string // raw DSN, used when Mode == "dsn"
	Host     string
	Port     string
	Username string
	Password string
	DBName   string
	SSLMode  string
	Extra    string
}

// GetDBConnConfig reads the saved (not necessarily active) database
// connection config. Password/DSN are decrypted via getSecretMeta like any
// other stored credential.
func (db *DB) GetDBConnConfig() (DBConnConfig, error) {
	var cfg DBConnConfig
	var err error
	if cfg.Driver, err = db.getMeta("db_conn_driver"); err != nil {
		return DBConnConfig{}, err
	}
	if cfg.Mode, err = db.getMeta("db_conn_mode"); err != nil {
		return DBConnConfig{}, err
	}
	if cfg.DSN, err = db.getSecretMeta("db_conn_dsn"); err != nil {
		return DBConnConfig{}, err
	}
	if cfg.Host, err = db.getMeta("db_conn_host"); err != nil {
		return DBConnConfig{}, err
	}
	if cfg.Port, err = db.getMeta("db_conn_port"); err != nil {
		return DBConnConfig{}, err
	}
	if cfg.Username, err = db.getMeta("db_conn_username"); err != nil {
		return DBConnConfig{}, err
	}
	if cfg.Password, err = db.getSecretMeta("db_conn_password"); err != nil {
		return DBConnConfig{}, err
	}
	if cfg.DBName, err = db.getMeta("db_conn_dbname"); err != nil {
		return DBConnConfig{}, err
	}
	if cfg.SSLMode, err = db.getMeta("db_conn_sslmode"); err != nil {
		return DBConnConfig{}, err
	}
	if cfg.Extra, err = db.getMeta("db_conn_extra"); err != nil {
		return DBConnConfig{}, err
	}
	if cfg.Mode == "" {
		cfg.Mode = "fields"
	}
	return cfg, nil
}

// SetDBConnConfig persists cfg. A blank Password or DSN means "keep the
// currently stored value" — the same convention EmailConfig.Token uses
// (never re-echoed to the browser, so the only way to "clear" it is to
// overwrite with a new non-blank value).
func (db *DB) SetDBConnConfig(cfg DBConnConfig) error {
	if cfg.Password == "" || cfg.DSN == "" {
		stored, err := db.GetDBConnConfig()
		if err != nil {
			return err
		}
		if cfg.Password == "" {
			cfg.Password = stored.Password
		}
		if cfg.DSN == "" {
			cfg.DSN = stored.DSN
		}
	}
	for _, kv := range []struct{ key, val string }{
		{"db_conn_driver", cfg.Driver},
		{"db_conn_mode", cfg.Mode},
		{"db_conn_host", cfg.Host},
		{"db_conn_port", cfg.Port},
		{"db_conn_username", cfg.Username},
		{"db_conn_dbname", cfg.DBName},
		{"db_conn_sslmode", cfg.SSLMode},
		{"db_conn_extra", cfg.Extra},
	} {
		if err := db.setMeta(kv.key, kv.val); err != nil {
			return err
		}
	}
	if err := db.setSecretMeta("db_conn_password", cfg.Password); err != nil {
		return err
	}
	return db.setSecretMeta("db_conn_dsn", cfg.DSN)
}
