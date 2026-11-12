package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// MigrationReport summarizes a config import: how many rows moved per
// table, in the order they were copied.
type MigrationReport struct {
	Tables    []MigrationTableResult
	TotalRows int
}

// MigrationTableResult is one table's row count within a MigrationReport.
type MigrationTableResult struct {
	Table string
	Rows  int
}

// configStep copies one config table from source to target.
type configStep struct {
	table string
	fn    func(source, target *DB) (int, error)
}

// configSteps is every config table, in dependency order, for the config
// export/import (configfile.go). Not copied: requests (log history),
// sessions and rate_state (runtime state). Ids are kept, since
// services.cert_id and threat_intel_ips.source_id reference them, and
// timestamp columns go through time.Time.
var configSteps = []configStep{
	{"meta", migrateMetaTable},
	{"admin_users", migrateAdminUsersTable},
	{"admin_sso_identities", migrateSSOIdentitiesTable},
	{"certificates", migrateCertificatesTable},
	{"services", migrateServicesTable},
	{"service_openapi", migrateServiceOpenAPITable},
	{"service_mtls", migrateServiceMTLSTable},
	{"service_mcp", migrateServiceMCPTable},
	{"service_jwt", migrateServiceJWTTable},
	{"service_rate_rules", migrateServiceRateRulesTable},
	{"service_gate", migrateServiceGateTable},
	{"service_csp", migrateServiceCSPTable},
	{"csp_scripts", migrateCSPScriptsTable},
	{"service_cookie_policy", migrateServiceCookiePolicyTable},
	{"service_request_policy", migrateServiceRequestPolicyTable},
	{"csp_approved", migrateCSPApprovedTable},
	{"service_csp_enforce", migrateCSPEnforceTable},
	{"ip_rules", migrateIPRulesTable},
	{"geo_rules", migrateGeoRulesTable},
	{"api_keys", migrateAPIKeysTable},
	{"waf_disabled_rules", migrateWAFDisabledRulesTable},
	{"waf_service_rule_exceptions", migrateWAFServiceExceptionsTable},
	{"waf_custom_rules", migrateWAFCustomRulesTable},
	{"threat_intel_sources", migrateThreatIntelSourcesTable},
	{"threat_intel_ips", migrateThreatIntelIPsTable},
	{"webhook_config", migrateWebhookConfigTable},
	{"ip_threat_scores", migrateIPThreatScoresTable},
	{"ja4_reputation", migrateJA4ReputationTable},
}

// migrateConfigInto copies every config table into an open target.
func (db *DB) migrateConfigInto(target *DB) (MigrationReport, error) {
	var report MigrationReport
	for _, step := range configSteps {
		n, err := step.fn(db, target)
		report.Tables = append(report.Tables, MigrationTableResult{Table: step.table, Rows: n})
		report.TotalRows += n
		if err != nil {
			return report, fmt.Errorf("migrate %s (after %d rows): %w", step.table, n, err)
		}
	}
	return report, nil
}

// placeholders returns "?, ?, ..., ?" for n items — used instead of
// hand-counting "?" per INSERT, since several tables here have 15-20+
// columns and a miscount would bind the wrong value to the wrong column
// silently (Go's database/sql has no compile-time arity check).
func placeholders(n int) string {
	ph := make([]string, n)
	for i := range ph {
		ph[i] = "?"
	}
	return strings.Join(ph, ", ")
}

func migrateMetaTable(source, target *DB) (int, error) {
	rows, err := source.query(`SELECT key, value FROM meta`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	isSecret := make(map[string]bool, len(secretMetaKeys))
	for _, k := range secretMetaKeys {
		isSecret[k] = true
	}

	n := 0
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return n, err
		}
		if isSecret[key] {
			// value may be sealed under the source's own encryption key (or
			// plaintext if none configured) — decrypt via the source's own
			// state first, then let the target reseal under whatever key
			// (if any) it has. Copying the raw stored value verbatim would
			// produce an undecryptable ciphertext blob on a target with a
			// different (or absent) --db-key-file.
			plain, err := source.openSecret(value)
			if err != nil {
				return n, fmt.Errorf("decrypt %s: %w", key, err)
			}
			if err := target.setSecretMeta(key, plain); err != nil {
				return n, err
			}
		} else if err := target.setMeta(key, value); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateCertificatesTable(source, target *DB) (int, error) {
	rows, err := source.query(`SELECT id, name, domains, expires_at, cert_path, key_path, created_at FROM certificates`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var id int64
		var name, domains, expiresAt, certPath, keyPath string
		var createdAt time.Time
		if err := rows.Scan(&id, &name, &domains, &expiresAt, &certPath, &keyPath, &createdAt); err != nil {
			return n, err
		}
		q := fmt.Sprintf(`INSERT INTO certificates (id, name, domains, expires_at, cert_path, key_path, created_at) VALUES (%s)`,
			placeholders(7))
		if _, err := target.exec(q, id, name, domains, expiresAt, certPath, keyPath, createdAt); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateServicesTable(source, target *DB) (int, error) {
	rows, err := source.query(`SELECT ` + serviceColumns + ` FROM services`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		s, err := source.scanService(rows)
		if err != nil {
			return n, err
		}
		q := fmt.Sprintf(`INSERT INTO services (%s) VALUES (%s)`,
			serviceColumns, placeholders(38))
		if _, err := target.exec(q,
			s.ID, s.Name, s.Host, s.Prefix, s.Backend, s.CreatedAt, s.TLSMode, s.TLSCertPath, s.TLSKeyPath, s.TLSExpiresAt,
			s.RateLimitRPS, s.RateLimitBurst, s.BotMode, s.CertID, boolToInt(s.CacheEnabled), boolToInt(s.CacheBySession),
			s.SessionCookieName, s.CacheTTLFloor, s.CacheTTLCeiling, s.CacheGrace, s.CacheKeep,
			boolToInt(s.AllowLargeJSUploads), s.RequestSchema, s.SchemaMode, boolToInt(s.HTTP3Enabled), boolToInt(s.CompressEnabled),
			strings.Join(s.ExtraBackends, "\n"), s.LBPolicy, s.HealthPath, s.HealthInterval,
			strings.Join(s.HostAliases, "\n"), s.CanonicalHost, strings.Join(s.LoginPaths, "\n"), s.AICrawlerPolicy,
			s.BreachAction, strings.Join(s.BreachFields, "\n"), s.ResponseInspect, s.CacheRules,
		); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateIPRulesTable(source, target *DB) (int, error) {
	rows, err := source.query(`SELECT id, app_name, ip, rule_type, note, created_at FROM ip_rules`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var id int
		var appName, ip, ruleType, note string
		var createdAt time.Time
		if err := rows.Scan(&id, &appName, &ip, &ruleType, &note, &createdAt); err != nil {
			return n, err
		}
		q := fmt.Sprintf(`INSERT INTO ip_rules (id, app_name, ip, rule_type, note, created_at) VALUES (%s)`,
			placeholders(6))
		if _, err := target.exec(q, id, appName, ip, ruleType, note, createdAt); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateGeoRulesTable(source, target *DB) (int, error) {
	rows, err := source.query(`SELECT id, app_name, country_code, rule_type, created_at FROM geo_rules`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var id int
		var appName, countryCode, ruleType string
		var createdAt time.Time
		if err := rows.Scan(&id, &appName, &countryCode, &ruleType, &createdAt); err != nil {
			return n, err
		}
		q := fmt.Sprintf(`INSERT INTO geo_rules (id, app_name, country_code, rule_type, created_at) VALUES (%s)`,
			placeholders(5))
		if _, err := target.exec(q, id, appName, countryCode, ruleType, createdAt); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateAdminUsersTable(source, target *DB) (int, error) {
	// Sealed TOTP columns are copied as stored, like meta's secrets.
	const cols = `id, email, password_hash, role, disabled, totp_secret, totp_pending_secret, totp_backup_codes, totp_last_counter, webauthn_handle, created_at`
	rows, err := source.query(`SELECT ` + cols + ` FROM admin_users`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var id int64
		var email, hash, role, totp, pending, backup, counter, handle string
		var disabled bool
		var createdAt time.Time
		if err := rows.Scan(&id, &email, &hash, &role, &disabled, &totp, &pending, &backup, &counter, &handle, &createdAt); err != nil {
			return n, err
		}
		q := fmt.Sprintf(`INSERT INTO admin_users (%s) VALUES (%s)`, cols, placeholders(11))
		if _, err := target.exec(q, id, email, hash, role, boolToInt(disabled), totp, pending, backup, counter, handle, createdAt); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateAPIKeysTable(source, target *DB) (int, error) {
	// key_hash is deliberately included here (unlike ListAPIKeys, which
	// never selects it for display purposes) — without it a migrated key
	// would be a useless row that can never authenticate again.
	rows, err := source.query(`SELECT id, name, key_prefix, key_hash, read_only, created_at, last_used_at FROM api_keys`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var id int
		var name, prefix, hash string
		var readOnly bool
		var createdAt time.Time
		var lastUsed sql.NullTime
		if err := rows.Scan(&id, &name, &prefix, &hash, &readOnly, &createdAt, &lastUsed); err != nil {
			return n, err
		}
		q := fmt.Sprintf(`INSERT INTO api_keys (id, name, key_prefix, key_hash, read_only, created_at, last_used_at) VALUES (%s)`,
			placeholders(7))
		if _, err := target.exec(q, id, name, prefix, hash, boolToInt(readOnly), createdAt, lastUsed); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateWAFDisabledRulesTable(source, target *DB) (int, error) {
	rows, err := source.query(`SELECT id, rule_id, reason, created_at FROM waf_disabled_rules`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var id int64
		var ruleID int
		var reason string
		var createdAt time.Time
		if err := rows.Scan(&id, &ruleID, &reason, &createdAt); err != nil {
			return n, err
		}
		q := fmt.Sprintf(`INSERT INTO waf_disabled_rules (id, rule_id, reason, created_at) VALUES (%s)`,
			placeholders(4))
		if _, err := target.exec(q, id, ruleID, reason, createdAt); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateWAFServiceExceptionsTable(source, target *DB) (int, error) {
	rows, err := source.query(`SELECT id, service_name, rule_id, reason, created_at FROM waf_service_rule_exceptions`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var id int64
		var serviceName, reason string
		var ruleID int
		var createdAt time.Time
		if err := rows.Scan(&id, &serviceName, &ruleID, &reason, &createdAt); err != nil {
			return n, err
		}
		q := fmt.Sprintf(`INSERT INTO waf_service_rule_exceptions (id, service_name, rule_id, reason, created_at) VALUES (%s)`,
			placeholders(5))
		if _, err := target.exec(q, id, serviceName, ruleID, reason, createdAt); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateWAFCustomRulesTable(source, target *DB) (int, error) {
	rows, err := source.query(`SELECT id, service_name, rule, note, enabled, created_at FROM waf_custom_rules`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var id int64
		var serviceName, rule, note string
		var enabled int
		var createdAt time.Time
		if err := rows.Scan(&id, &serviceName, &rule, &note, &enabled, &createdAt); err != nil {
			return n, err
		}
		q := fmt.Sprintf(`INSERT INTO waf_custom_rules (id, service_name, rule, note, enabled, created_at) VALUES (%s)`,
			placeholders(6))
		if _, err := target.exec(q, id, serviceName, rule, note, enabled, createdAt); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateThreatIntelSourcesTable(source, target *DB) (int, error) {
	rows, err := source.query(`SELECT id, label, url, interval_hours, enabled, last_synced_at, last_error, ip_count, created_at FROM threat_intel_sources`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var id int64
		var label, url, lastSyncedAt, lastError string
		var intervalHours, ipCount int
		var enabled bool
		var createdAt time.Time
		if err := rows.Scan(&id, &label, &url, &intervalHours, &enabled, &lastSyncedAt, &lastError, &ipCount, &createdAt); err != nil {
			return n, err
		}
		q := fmt.Sprintf(`INSERT INTO threat_intel_sources (id, label, url, interval_hours, enabled, last_synced_at, last_error, ip_count, created_at) VALUES (%s)`,
			placeholders(9))
		if _, err := target.exec(q, id, label, url, intervalHours, boolToInt(enabled), lastSyncedAt, lastError, ipCount, createdAt); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateThreatIntelIPsTable(source, target *DB) (int, error) {
	rows, err := source.query(`SELECT source_id, ip FROM threat_intel_ips`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var sourceID int64
		var ip string
		if err := rows.Scan(&sourceID, &ip); err != nil {
			return n, err
		}
		if _, err := target.exec(`INSERT INTO threat_intel_ips (source_id, ip) VALUES (?, ?)`, sourceID, ip); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

// migrateWebhookConfigTable copies the singleton webhook_config row (id=1,
// always pre-seeded by schema migration on the freshly-opened target) via
// the existing Get/SetWebhookConfig, which already handle the secret column
// correctly through each DB's own encryption state — no hand-rolled SQL
// needed, and no insert-vs-update branching since SetWebhookConfig always
// UPDATEs the pre-existing row rather than INSERTing a new one.
func migrateWebhookConfigTable(source, target *DB) (int, error) {
	cfg, err := source.GetWebhookConfig()
	if err != nil {
		return 0, err
	}
	if err := target.SetWebhookConfig(cfg); err != nil {
		return 0, err
	}
	return 1, nil
}

func migrateIPThreatScoresTable(source, target *DB) (int, error) {
	rows, err := source.query(`SELECT ip, total_score, autoban_score, bot_score, asn_score, geo_score, ja4_score, updated_at FROM ip_threat_scores`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var ip string
		var total, autoban, bot, asn, geo, ja4 int
		var updatedAt time.Time
		if err := rows.Scan(&ip, &total, &autoban, &bot, &asn, &geo, &ja4, &updatedAt); err != nil {
			return n, err
		}
		if _, err := target.exec(
			`INSERT INTO ip_threat_scores (ip, total_score, autoban_score, bot_score, asn_score, geo_score, ja4_score, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			ip, total, autoban, bot, asn, geo, ja4, updatedAt,
		); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateJA4ReputationTable(source, target *DB) (int, error) {
	rows, err := source.query(`SELECT ja4, hits, blocked_hits, last_seen FROM ja4_reputation`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var ja4 string
		var hits, blockedHits int
		var lastSeen time.Time
		if err := rows.Scan(&ja4, &hits, &blockedHits, &lastSeen); err != nil {
			return n, err
		}
		if _, err := target.exec(
			`INSERT INTO ja4_reputation (ja4, hits, blocked_hits, last_seen) VALUES (?, ?, ?, ?)`,
			ja4, hits, blockedHits, lastSeen,
		); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func migrateServiceOpenAPITable(source, target *DB) (int, error) {
	specs, err := source.ListServiceOpenAPI()
	if err != nil {
		return 0, err
	}
	n := 0
	for id, o := range specs {
		if _, err := target.exec(`INSERT INTO service_openapi (service_id, spec, mode) VALUES (?, ?, ?)`, id, o.Spec, o.Mode); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func migrateServiceMTLSTable(source, target *DB) (int, error) {
	policies, err := source.ListServiceMTLS()
	if err != nil {
		return 0, err
	}
	n := 0
	for id, m := range policies {
		if err := target.SetServiceMTLS(id, m); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func migrateServiceMCPTable(source, target *DB) (int, error) {
	guards, err := source.ListServiceMCP()
	if err != nil {
		return 0, err
	}
	n := 0
	for id, m := range guards {
		if err := target.SetServiceMCP(id, m); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func migrateServiceJWTTable(source, target *DB) (int, error) {
	checks, err := source.ListServiceJWT()
	if err != nil {
		return 0, err
	}
	n := 0
	for id, j := range checks {
		if err := target.SetServiceJWT(id, j); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func migrateServiceRateRulesTable(source, target *DB) (int, error) {
	all, err := source.ListServiceRateRules()
	if err != nil {
		return 0, err
	}
	n := 0
	for id, rules := range all {
		if err := target.SetServiceRateRules(id, rules); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
