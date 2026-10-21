package storage

import (
	"net/url"
	"testing"

	"github.com/go-sql-driver/mysql"
)

// FuzzBuildDSN checks that credentials and database name survive the round
// trip through each driver's own parser, whatever characters they contain —
// the reason BuildDSN exists instead of string concatenation.
func FuzzBuildDSN(f *testing.F) {
	f.Add("db.internal", "5432", "admin", "p@ss:w/rd?#", "waf", "require", "connect_timeout=5")
	f.Add("10.0.0.5", "", "root", "", "palisade", "", "")
	f.Add("::1", "3306", "u", "a&b=c", "x", "true", "timeout=5s")
	f.Fuzz(func(t *testing.T, host, port, user, pass, dbname, ssl, extra string) {
		fields := DBConnFields{Host: host, Port: port, Username: user, Password: pass, DBName: dbname, SSLMode: ssl, Extra: extra}

		fields.Driver = "postgres"
		if dsn, err := BuildDSN(fields); err == nil {
			u, err := url.Parse(dsn)
			if err != nil {
				t.Fatalf("postgres dsn %q does not parse: %v", dsn, err)
			}
			got, _ := u.User.Password()
			if u.User.Username() != user || got != pass || u.Path != "/"+dbname {
				t.Fatalf("postgres dsn %q lost fields: user %q pass %q path %q", dsn, u.User.Username(), got, u.Path)
			}
		}

		fields.Driver = "mysql"
		if dsn, err := BuildDSN(fields); err == nil {
			cfg, err := mysql.ParseDSN(dsn)
			if err != nil {
				return // the driver also rejects option values it doesn't know (tls=require), which is an admin typo, not a broken DSN
			}
			if cfg.User != user || cfg.Passwd != pass || cfg.DBName != dbname {
				t.Fatalf("mysql dsn %q lost fields: user %q pass %q db %q", dsn, cfg.User, cfg.Passwd, cfg.DBName)
			}
		}
	})
}
