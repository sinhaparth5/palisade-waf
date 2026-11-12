package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ── Services ─────────────────────────────────────────────────────────────────

// Service is one backend app the proxy can route to, matched by Host header
// or path Prefix (at least one of the two must be set).
//
// TLS fields only apply to Host-matched services — TLS termination happens
// via SNI at the handshake, which needs a domain name, not a path prefix.
// TLSMode is "none" (plain HTTP only), "custom" (admin-uploaded cert/key,
// paths point at files under certs/services/<name>/), or "auto" (issued
// on-demand via Let's Encrypt/autocert). TLSExpiresAt is RFC3339, "" if
// unknown or not yet issued.
type Service struct {
	ID                  int
	Name                string
	Host                string
	Prefix              string
	Backend             string
	CreatedAt           time.Time
	TLSMode             string
	TLSCertPath         string
	TLSKeyPath          string
	TLSExpiresAt        string
	RateLimitRPS        float64
	RateLimitBurst      int
	BotMode             string // "inherit" | "always" | "off"
	CertID              int64  // >0 when TLS cert comes from the shared cert pool
	CacheEnabled        bool   // route clean traffic through the local Varnish cache
	CacheBySession      bool   // partition cached objects by SessionCookieName's value instead of refusing to cache any cookie-bearing request
	SessionCookieName   string // name of this service's session cookie; required for CacheBySession to take effect
	CacheTTLFloor       int    // seconds; 0 = no floor beyond the built-in 1h default for static assets
	CacheTTLCeiling     int    // seconds; 0 = no ceiling, backend Cache-Control wins
	CacheGrace          int    // seconds; 0 = VCL default (30s) — how long a stale object may still be served
	CacheKeep           int    // seconds; 0 = VCL default (30s) — how long a stale object stays around for conditional revalidation after grace
	AllowLargeJSUploads bool   // stream JavaScript request bodies without deep WAF body inspection
	RequestSchema       string // JSON Schema text validated against JSON request bodies; "" disables validation
	SchemaMode          string // "off" | "log" | "enforce" — see waf.Engine.SetRequestSchema
	HTTP3Enabled        bool   // advertise and accept HTTP/3 for this service's Host (needs --listen-h3)
	CompressEnabled     bool   // zstd/gzip-encode text-like responses for clients that accept it
	// ExtraBackends are load-balanced alongside Backend. Kept out of the
	// backend column so an older binary rolled back still reads a single URL.
	ExtraBackends  []string
	LBPolicy       string // "round_robin" | "least_conn"
	HealthPath     string // active health check path, e.g. "/healthz"; "" = passive checks only
	HealthInterval int    // seconds between active checks; 0 = DefaultHealthInterval
	// HostAliases are extra hostnames routed to this service alongside Host,
	// e.g. "www.example.com". Kept out of the host column for the same
	// rollback reason as ExtraBackends.
	HostAliases   []string
	CanonicalHost string // "" = serve every name as-is; else Host or one alias, which the others 301 to
	// LoginPaths get the login protection preset (issue #132): a forced bot
	// challenge and a strict per-client limit on submissions. Empty = off.
	LoginPaths []string
	// AICrawlerPolicy overrides the global AI crawler policy per category
	// (issue #187), encoded by bot.AIPolicy; "" inherits every category.
	AICrawlerPolicy string
	// BreachAction checks login passwords against known breaches (issue
	// #188): "" off, "log" or "block". BreachFields name the password
	// field; empty = breach.DefaultFields.
	BreachAction string
	BreachFields []string
	// ResponseInspect runs CRS's outbound rules over the backend's text
	// responses (issue #192): "" off, "log" or "block".
	ResponseInspect string
	// CacheRules are per-path Varnish overrides (issue #212), one
	// "cache /path" or "bypass /path" per line; see services.ParseCacheRules.
	CacheRules string
	// Gate is the maintenance mode and waiting room (issue #198), filled
	// from service_gate by services.Registry.Reload.
	Gate ServiceGate
}

// DefaultHealthInterval is the active health check interval used when a
// service sets a HealthPath but no interval.
const DefaultHealthInterval = 10

// Backends returns every backend URL of the service, Backend first.
func (s Service) Backends() []string {
	return append([]string{s.Backend}, s.ExtraBackends...)
}

// Hosts returns every hostname the service answers to, Host first, or nil
// for a Prefix-matched service.
func (s Service) Hosts() []string {
	if s.Host == "" {
		return nil
	}
	return append([]string{s.Host}, s.HostAliases...)
}

// SetServiceLoginPaths replaces a service's login-protected paths.
func (db *DB) SetServiceLoginPaths(id int, paths []string) error {
	_, err := db.exec(`UPDATE services SET login_paths = ? WHERE id = ?`, strings.Join(paths, "\n"), id)
	return err
}

// SetServiceAICrawlerPolicy replaces a service's AI crawler policy overrides.
func (db *DB) SetServiceAICrawlerPolicy(id int, policy string) error {
	_, err := db.exec(`UPDATE services SET ai_crawler_policy = ? WHERE id = ?`, policy, id)
	return err
}

// SetServiceBreachCheck sets a service's leaked-password check.
func (db *DB) SetServiceBreachCheck(id int, action string, fields []string) error {
	_, err := db.exec(`UPDATE services SET breach_action = ?, breach_fields = ? WHERE id = ?`, action, strings.Join(fields, "\n"), id)
	return err
}

// SetServiceResponseInspect sets a service's response inspection mode.
func (db *DB) SetServiceResponseInspect(id int, mode string) error {
	if mode != "log" && mode != "block" {
		mode = ""
	}
	_, err := db.exec(`UPDATE services SET response_inspect = ? WHERE id = ?`, mode, id)
	return err
}

// GetAICrawlerPolicy reads the global AI crawler policy ("" = none).
func (db *DB) GetAICrawlerPolicy() (string, error) {
	return db.getMeta("ai_crawler_policy")
}

// SetAICrawlerPolicy persists the global AI crawler policy.
func (db *DB) SetAICrawlerPolicy(policy string) error {
	return db.setMeta("ai_crawler_policy", policy)
}

// SetServiceHosts replaces a service's host aliases and canonical host.
func (db *DB) SetServiceHosts(id int, aliases []string, canonical string) error {
	_, err := db.exec(`UPDATE services SET host_aliases = ?, canonical_host = ? WHERE id = ?`,
		strings.Join(aliases, "\n"), canonical, id)
	return err
}

// SetServiceBackends replaces a service's backend list (backends[0] becomes
// the primary) and its balancing and active health check settings.
func (db *DB) SetServiceBackends(id int, backends []string, policy, healthPath string, healthInterval int) error {
	if len(backends) == 0 {
		return fmt.Errorf("at least one backend is required")
	}
	if policy != "least_conn" {
		policy = "round_robin"
	}
	_, err := db.exec(
		`UPDATE services SET backend = ?, extra_backends = ?, lb_policy = ?, health_path = ?, health_interval = ? WHERE id = ?`,
		backends[0], strings.Join(backends[1:], "\n"), policy, healthPath, healthInterval, id,
	)
	return err
}

func (db *DB) AddService(name, host, prefix, backend string, rps float64, burst int) error {
	_, err := db.exec(
		`INSERT INTO services (name, host, prefix, backend, rate_limit_rps, rate_limit_burst) VALUES (?, ?, ?, ?, ?, ?)`,
		name, host, prefix, backend, rps, burst,
	)
	return err
}

func (db *DB) UpdateService(id int, name, host, prefix, backend string) error {
	_, err := db.exec(
		`UPDATE services SET name = ?, host = ?, prefix = ?, backend = ? WHERE id = ?`,
		name, host, prefix, backend, id,
	)
	return err
}

func (db *DB) RemoveService(id int) error {
	for _, t := range []string{"service_openapi", "service_mtls", "service_mcp", "service_jwt", "service_rate_rules", "service_gate", "service_csp", "csp_scripts", "service_cookie_policy"} {
		if _, err := db.exec(`DELETE FROM `+t+` WHERE service_id = ?`, id); err != nil {
			return err
		}
	}
	_, err := db.exec(`DELETE FROM services WHERE id = ?`, id)
	return err
}

// SetServiceTLS records a service's TLS configuration. For mode "custom",
// certPath/keyPath point at files on disk (see services.SaveCustomCert);
// for mode "auto" they're left empty since autocert manages its own cache.
func (db *DB) SetServiceTLS(id int, mode, certPath, keyPath, expiresAt string) error {
	_, err := db.exec(
		`UPDATE services SET tls_mode = ?, tls_cert_path = ?, tls_key_path = ?, tls_expires_at = ? WHERE id = ?`,
		mode, certPath, keyPath, expiresAt, id,
	)
	return err
}

// ClearServiceTLS reverts a service to plain HTTP (no TLS), including clearing
// any reference to a pool cert.
func (db *DB) ClearServiceTLS(id int) error {
	_, err := db.exec(
		`UPDATE services SET tls_mode = 'none', tls_cert_path = '', tls_key_path = '', tls_expires_at = '', cert_id = 0 WHERE id = ?`,
		id,
	)
	return err
}

// SetServiceCertID links a service to a cert-pool entry. Sets tls_mode to
// "custom" and clears the old per-service cert paths since the cert now comes
// from the pool. Set certID to 0 to remove the pool association (use
// ClearServiceTLS to fully revert to plain HTTP).
func (db *DB) SetServiceCertID(serviceID int, certID int64) error {
	_, err := db.exec(
		`UPDATE services SET cert_id = ?, tls_mode = 'custom', tls_cert_path = '', tls_key_path = '', tls_expires_at = '' WHERE id = ?`,
		certID, serviceID,
	)
	return err
}

// SetServiceRateLimit configures a per-service per-IP rate limit.
// rps=0 disables per-service limiting for this service (falls through to the
// global limiter only).
func (db *DB) SetServiceRateLimit(id int, rps float64, burst int) error {
	_, err := db.exec(
		`UPDATE services SET rate_limit_rps = ?, rate_limit_burst = ? WHERE id = ?`,
		rps, burst, id,
	)
	return err
}

// SetServiceBotMode sets the per-service bot protection override.
// mode must be one of "inherit", "always", or "off".
func (db *DB) SetServiceBotMode(id int, mode string) error {
	_, err := db.exec(`UPDATE services SET bot_mode = ? WHERE id = ?`, mode, id)
	return err
}

// SetServiceHTTP3 controls whether the service's Host is offered HTTP/3.
func (db *DB) SetServiceHTTP3(id int, enabled bool) error {
	_, err := db.exec(`UPDATE services SET http3_enabled = ? WHERE id = ?`, boolToInt(enabled), id)
	return err
}

// SetServiceCompress controls whether the service's responses are compressed.
func (db *DB) SetServiceCompress(id int, enabled bool) error {
	_, err := db.exec(`UPDATE services SET compress_enabled = ? WHERE id = ?`, boolToInt(enabled), id)
	return err
}

// SetServiceLargeJSUploads controls whether JavaScript request bodies for a
// service bypass deep body inspection and stream to its backend. Header-phase
// WAF rules and every other request control remain active.
func (db *DB) SetServiceLargeJSUploads(id int, enabled bool) error {
	_, err := db.exec(`UPDATE services SET allow_large_js_uploads = ? WHERE id = ?`, boolToInt(enabled), id)
	return err
}

// serviceSchemaModes is the allowed set for Service.SchemaMode. Anything else
// (empty, typo, a value from a future version rolled back) is normalized to
// "off" — the safe, non-blocking default — rather than silently enforcing or
// silently skipping validation depending on what happened to be in the row.
var serviceSchemaModes = map[string]bool{
	"off":     true,
	"log":     true,
	"enforce": true,
}

// SetServiceSchema attaches a JSON Schema to a service's request-body
// validation. schemaJSON is expected to already have been compiled once by
// the caller (waf.ValidateSchema) so a malformed schema is rejected at save
// time rather than discovered during a WAF reload. mode "off" or an empty
// schema disables validation; "log" records violations without blocking;
// "enforce" rejects a mismatching JSON body with 400. See
// waf.Engine.SetRequestSchema for how this is applied per request.
func (db *DB) SetServiceSchema(id int, schemaJSON, mode string) error {
	if !serviceSchemaModes[mode] {
		mode = "off"
	}
	if schemaJSON == "" {
		mode = "off"
	}
	_, err := db.exec(`UPDATE services SET request_schema = ?, schema_mode = ? WHERE id = ?`, schemaJSON, mode, id)
	return err
}

// ServiceOpenAPI is a service's OpenAPI document and mode ("log" or
// "enforce") — see waf.Engine.SetOpenAPI.
type ServiceOpenAPI struct {
	Spec string
	Mode string
}

// SetServiceOpenAPI stores a service's OpenAPI spec (issue #190), already
// checked by waf.ValidateOpenAPI. Mode "off" keeps the spec but disables
// it; an empty spec removes it.
func (db *DB) SetServiceOpenAPI(id int, spec, mode string) error {
	if spec == "" {
		_, err := db.exec(`DELETE FROM service_openapi WHERE service_id = ?`, id)
		return err
	}
	if !serviceSchemaModes[mode] {
		mode = "off"
	}
	_, err := db.exec(db.dialect.upsertUpdate("service_openapi", []string{"service_id", "spec", "mode"}, "?, ?, ?",
		[]string{"service_id"}, []string{"spec", "mode"}), id, spec, mode)
	return err
}

// ListServiceOpenAPI returns every stored spec by service id.
func (db *DB) ListServiceOpenAPI() (map[int]ServiceOpenAPI, error) {
	rows, err := db.query(`SELECT service_id, spec, mode FROM service_openapi`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]ServiceOpenAPI{}
	for rows.Next() {
		var id int
		var o ServiceOpenAPI
		if err := rows.Scan(&id, &o.Spec, &o.Mode); err != nil {
			return nil, err
		}
		out[id] = o
	}
	return out, rows.Err()
}

// GetServiceOpenAPI returns one service's spec; zero value when it has none.
func (db *DB) GetServiceOpenAPI(id int) (ServiceOpenAPI, error) {
	var o ServiceOpenAPI
	err := db.queryRow(`SELECT spec, mode FROM service_openapi WHERE service_id = ?`, id).Scan(&o.Spec, &o.Mode)
	if errors.Is(err, sql.ErrNoRows) {
		return ServiceOpenAPI{}, nil
	}
	return o, err
}

// ListServiceOpenAPIModes returns each service's spec mode without the
// specs themselves, for the polled services table.
func (db *DB) ListServiceOpenAPIModes() (map[int]string, error) {
	rows, err := db.query(`SELECT service_id, mode FROM service_openapi`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]string{}
	for rows.Next() {
		var id int
		var mode string
		if err := rows.Scan(&id, &mode); err != nil {
			return nil, err
		}
		out[id] = mode
	}
	return out, rows.Err()
}

// ServiceMTLS is a service's client-certificate policy (issue #191). CAPath
// is the client CA bundle on disk (certs/services/<name>/client-ca.pem);
// Allow is a newline-separated list of subject CNs, SAN DNS names or SHA-256
// fingerprints, empty meaning any cert from the CA.
type ServiceMTLS struct {
	Mode   string // "off", "optional" or "required"
	CAPath string
	Allow  string
}

// SetServiceMTLS stores a service's mTLS policy. Mode "off" keeps the CA
// for later; an empty CAPath removes the policy.
func (db *DB) SetServiceMTLS(id int, m ServiceMTLS) error {
	if m.CAPath == "" {
		_, err := db.exec(`DELETE FROM service_mtls WHERE service_id = ?`, id)
		return err
	}
	if m.Mode != "optional" && m.Mode != "required" {
		m.Mode = "off"
	}
	_, err := db.exec(db.dialect.upsertUpdate("service_mtls", []string{"service_id", "mode", "ca_path", "allow_list"}, "?, ?, ?, ?",
		[]string{"service_id"}, []string{"mode", "ca_path", "allow_list"}), id, m.Mode, m.CAPath, m.Allow)
	return err
}

// ListServiceMTLS returns every service's mTLS policy by service id.
func (db *DB) ListServiceMTLS() (map[int]ServiceMTLS, error) {
	rows, err := db.query(`SELECT service_id, mode, ca_path, allow_list FROM service_mtls`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]ServiceMTLS{}
	for rows.Next() {
		var id int
		var m ServiceMTLS
		if err := rows.Scan(&id, &m.Mode, &m.CAPath, &m.Allow); err != nil {
			return nil, err
		}
		out[id] = m
	}
	return out, rows.Err()
}

// ServiceMCP is a service's MCP endpoint guard (issue #234), see
// waf.MCPConfig. Origins, Methods and Tools are newline-separated.
type ServiceMCP struct {
	Mode    string // "off", "log" or "enforce"
	Path    string
	Origins string
	Methods string
	Tools   string
}

// SetServiceMCP stores a service's MCP guard; mode "off" removes it.
func (db *DB) SetServiceMCP(id int, m ServiceMCP) error {
	if m.Mode != "log" && m.Mode != "enforce" {
		_, err := db.exec(`DELETE FROM service_mcp WHERE service_id = ?`, id)
		return err
	}
	_, err := db.exec(db.dialect.upsertUpdate("service_mcp", []string{"service_id", "mode", "path", "origins", "methods", "tools"}, "?, ?, ?, ?, ?, ?",
		[]string{"service_id"}, []string{"mode", "path", "origins", "methods", "tools"}), id, m.Mode, m.Path, m.Origins, m.Methods, m.Tools)
	return err
}

// ListServiceMCP returns every service's MCP guard by service id.
func (db *DB) ListServiceMCP() (map[int]ServiceMCP, error) {
	rows, err := db.query(`SELECT service_id, mode, path, origins, methods, tools FROM service_mcp`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]ServiceMCP{}
	for rows.Next() {
		var id int
		var m ServiceMCP
		if err := rows.Scan(&id, &m.Mode, &m.Path, &m.Origins, &m.Methods, &m.Tools); err != nil {
			return nil, err
		}
		out[id] = m
	}
	return out, rows.Err()
}

// SetServiceRateRules stores a service's per-path rate limits (issue #280);
// empty rules remove the row.
func (db *DB) SetServiceRateRules(id int, rules string) error {
	if rules == "" {
		_, err := db.exec(`DELETE FROM service_rate_rules WHERE service_id = ?`, id)
		return err
	}
	cols := []string{"service_id", "rules"}
	_, err := db.exec(db.dialect.upsertUpdate("service_rate_rules", cols, "?, ?", []string{"service_id"}, cols[1:]), id, rules)
	return err
}

// ListServiceRateRules returns every service's per-path rate limits by id.
func (db *DB) ListServiceRateRules() (map[int]string, error) {
	rows, err := db.query(`SELECT service_id, rules FROM service_rate_rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]string{}
	for rows.Next() {
		var id int
		var rules string
		if err := rows.Scan(&id, &rules); err != nil {
			return nil, err
		}
		out[id] = rules
	}
	return out, rows.Err()
}

// ServiceJWT is a service's bearer-token check (issue #279), see
// jwtauth.Config. Algorithms and Prefixes are newline-separated.
type ServiceJWT struct {
	Mode       string // "off", "log" or "enforce"
	JWKSURL    string
	PublicKey  string
	Issuer     string
	Audience   string
	Algorithms string
	Prefixes   string
}

// SetServiceJWT stores a service's JWT check; mode "off" removes it.
func (db *DB) SetServiceJWT(id int, j ServiceJWT) error {
	if j.Mode != "log" && j.Mode != "enforce" {
		_, err := db.exec(`DELETE FROM service_jwt WHERE service_id = ?`, id)
		return err
	}
	cols := []string{"service_id", "mode", "jwks_url", "public_key", "issuer", "audience", "algorithms", "prefixes"}
	_, err := db.exec(db.dialect.upsertUpdate("service_jwt", cols, "?, ?, ?, ?, ?, ?, ?, ?", []string{"service_id"}, cols[1:]),
		id, j.Mode, j.JWKSURL, j.PublicKey, j.Issuer, j.Audience, j.Algorithms, j.Prefixes)
	return err
}

// ListServiceJWT returns every service's JWT check by service id.
func (db *DB) ListServiceJWT() (map[int]ServiceJWT, error) {
	rows, err := db.query(`SELECT service_id, mode, jwks_url, public_key, issuer, audience, algorithms, prefixes FROM service_jwt`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]ServiceJWT{}
	for rows.Next() {
		var id int
		var j ServiceJWT
		if err := rows.Scan(&id, &j.Mode, &j.JWKSURL, &j.PublicKey, &j.Issuer, &j.Audience, &j.Algorithms, &j.Prefixes); err != nil {
			return nil, err
		}
		out[id] = j
	}
	return out, rows.Err()
}

// SetServiceCache toggles routing this service's clean traffic through the
// local Varnish cache. Only takes effect while the global Varnish integration
// (VarnishConfig.Enabled) is on — the flag is kept independent so per-service
// choices survive the cache layer being switched off and on.
func (db *DB) SetServiceCache(id int, enabled bool) error {
	_, err := db.exec(`UPDATE services SET cache_enabled = ? WHERE id = ?`, boolToInt(enabled), id)
	return err
}

// SetServiceCacheSession configures opt-in session-aware caching for a
// service: when enabled, cached objects are partitioned per session-cookie
// value (see services.Registry's Director and deploy/varnish/default.vcl)
// instead of Varnish refusing to cache any request that carries a cookie.
// cookieName is the name of this service's session cookie; enabled has no
// effect until it's set to a non-empty value.
func (db *DB) SetServiceCacheSession(id int, enabled bool, cookieName string) error {
	_, err := db.exec(`UPDATE services SET cache_by_session = ?, session_cookie_name = ? WHERE id = ?`, boolToInt(enabled), cookieName, id)
	return err
}

// SetServiceCacheTuning configures per-service Varnish TTL/grace/keep
// overrides (see services.Registry's Director and deploy/varnish/default.vcl,
// which read these back as X-Cache-TTL-Floor/-Ceiling/-Grace/-Keep headers).
// Each value is seconds; 0 means "unset", falling back to the VCL's own
// defaults (a 1h floor for static assets, no ceiling, 30s grace/keep).
// rules are the per-path cache rules (Service.CacheRules).
func (db *DB) SetServiceCacheTuning(id, ttlFloor, ttlCeiling, grace, keep int, rules string) error {
	_, err := db.exec(
		`UPDATE services SET cache_ttl_floor = ?, cache_ttl_ceiling = ?, cache_grace = ?, cache_keep = ?, cache_rules = ? WHERE id = ?`,
		ttlFloor, ttlCeiling, grace, keep, rules, id,
	)
	return err
}

// serviceColumns is shared by ListServices/GetService so their SELECT list
// and Scan args can't drift out of sync as columns are added.
const serviceColumns = `id, name, host, prefix, backend, created_at, tls_mode, tls_cert_path, tls_key_path, tls_expires_at, rate_limit_rps, rate_limit_burst, bot_mode, cert_id, cache_enabled, cache_by_session, session_cookie_name, cache_ttl_floor, cache_ttl_ceiling, cache_grace, cache_keep, allow_large_js_uploads, request_schema, schema_mode, http3_enabled, compress_enabled, extra_backends, lb_policy, health_path, health_interval, host_aliases, canonical_host, login_paths, ai_crawler_policy, breach_action, breach_fields, response_inspect, cache_rules`

func (db *DB) scanService(row interface{ Scan(...any) error }) (Service, error) {
	var s Service
	var extra, aliases, login, breachFields string
	err := row.Scan(&s.ID, &s.Name, &s.Host, &s.Prefix, &s.Backend, &s.CreatedAt, &s.TLSMode, &s.TLSCertPath, &s.TLSKeyPath, &s.TLSExpiresAt, &s.RateLimitRPS, &s.RateLimitBurst, &s.BotMode, &s.CertID, &s.CacheEnabled, &s.CacheBySession, &s.SessionCookieName, &s.CacheTTLFloor, &s.CacheTTLCeiling, &s.CacheGrace, &s.CacheKeep, &s.AllowLargeJSUploads, &s.RequestSchema, &s.SchemaMode, &s.HTTP3Enabled, &s.CompressEnabled, &extra, &s.LBPolicy, &s.HealthPath, &s.HealthInterval, &aliases, &s.CanonicalHost, &login, &s.AICrawlerPolicy, &s.BreachAction, &breachFields, &s.ResponseInspect, &s.CacheRules)
	if extra != "" {
		s.ExtraBackends = strings.Split(extra, "\n")
	}
	if aliases != "" {
		s.HostAliases = strings.Split(aliases, "\n")
	}
	if login != "" {
		s.LoginPaths = strings.Split(login, "\n")
	}
	if breachFields != "" {
		s.BreachFields = strings.Split(breachFields, "\n")
	}
	return s, err
}

func (db *DB) ListServices() ([]Service, error) {
	rows, err := db.query(`SELECT ` + serviceColumns + ` FROM services ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Service
	for rows.Next() {
		s, err := db.scanService(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// GetService fetches a single service by ID.
func (db *DB) GetService(id int) (Service, error) {
	return db.scanService(db.queryRow(`SELECT `+serviceColumns+` FROM services WHERE id = ?`, id))
}

const metaKeyServicesMigrated = "services_migrated_from_config"

// ConfigApp is the subset of a legacy config.yaml apps: entry needed to
// seed the services table on first startup.
type ConfigApp struct {
	Name, Host, Prefix, Backend string
}

// MigrateConfigApps copies legacy config.yaml apps: entries into the
// services table, exactly once. Safe to call on every startup — after the
// first successful run it's a no-op even if the services table is later
// emptied by the admin.
func (db *DB) MigrateConfigApps(apps []ConfigApp) error {
	done, err := db.getMeta(metaKeyServicesMigrated)
	if err != nil {
		return err
	}
	if done != "" {
		return nil
	}
	for _, a := range apps {
		if err := db.AddService(a.Name, a.Host, a.Prefix, a.Backend, 0, 0); err != nil {
			return fmt.Errorf("migrate app %q: %w", a.Name, err)
		}
	}
	return db.setMeta(metaKeyServicesMigrated, "1")
}
