package ui

import (
	"cmp"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	neturl "net/url"
	"os"
	"palisade/internal/security/bot"
	"palisade/internal/security/csp"
	"palisade/internal/security/jwtauth"
	"palisade/internal/security/waf"
	"palisade/internal/services"
	"palisade/internal/storage"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
)

// ── Services ──────────────────────────────────────────────────────────────────

// ServiceView pairs a stored service with its last-known reachability, for
// rendering the status dot in the services table.
type ServiceView struct {
	storage.Service
	Healthy  bool
	Known    bool
	CertName string // pool cert name when CertID > 0, otherwise ""
	Health   []services.BackendStatus
	// OpenAPIMode is "log" or "enforce" when the service has a spec; the
	// spec itself is fetched by the edit modal (ServiceOpenAPI), since this
	// table is polled.
	OpenAPIMode  string
	MTLS         storage.ServiceMTLS // zero value when no client CA is stored
	MCP          storage.ServiceMCP  // zero value when the MCP guard is off
	JWT          storage.ServiceJWT  // zero value when the JWT check is off
	RateRules    string              // per-path rate limits, "" when none
	CSP          string              // report-only policy, "" when off
	Scripts      []storage.CSPScript // script sources its reports named
	CSPEnforce   bool                // enforcing (issue #283)
	CSPApproved  []string            // approved inventory entries
	CSPRecent    bool                // a source first seen in the last 7 days
	CSPFull      bool                // inventory at csp.MaxSources (#311)
	CookiesOn    bool                // Set-Cookie hardening (issue #281)
	CookieExempt string              // cookie names it leaves alone, space-separated
}

func (h *Handler) serviceViews() []ServiceView {
	list := h.registry.List()
	certMap := make(map[int64]string)
	if certs, err := h.db.ListCertificates(); err == nil {
		for _, c := range certs {
			certMap[c.ID] = c.Name
		}
	}
	modes, _ := h.db.ListServiceOpenAPIModes()
	mtls, _ := h.db.ListServiceMTLS()
	mcp, _ := h.db.ListServiceMCP()
	jwts, _ := h.db.ListServiceJWT()
	rateRules, _ := h.db.ListServiceRateRules()
	cspPolicies, _ := h.db.ListServiceCSP()
	scripts, _ := h.db.ListCSPScripts()
	cookies, _ := h.db.ListServiceCookiePolicies()
	cspEnforce, _ := h.db.ListCSPEnforcement()
	backendCAs, _ := h.db.ListServiceBackendCA()
	weekAgo := time.Now().Add(-7 * 24 * time.Hour)
	out := make([]ServiceView, len(list))
	for i, s := range list {
		s.BackendCA = backendCAs[s.ID]
		healthy, known := h.registry.IsHealthy(s.Name)
		out[i] = ServiceView{Service: s, Healthy: healthy, Known: known, CertName: certMap[s.CertID], Health: h.registry.BackendHealth(s.Name), OpenAPIMode: modes[s.ID], MTLS: mtls[s.ID], MCP: mcp[s.ID], JWT: jwts[s.ID], RateRules: rateRules[s.ID], CSP: cspPolicies[s.ID], Scripts: scripts[s.ID]}
		exempt, on := cookies[s.ID]
		out[i].CookiesOn, out[i].CookieExempt = on, strings.Join(exempt, " ")
		out[i].CSPEnforce, out[i].CSPApproved = cspEnforce[s.ID].Enforce, cspEnforce[s.ID].Approved
		out[i].CSPFull = len(out[i].Scripts) >= csp.MaxSources
		out[i].CSPRecent = slices.ContainsFunc(out[i].Scripts, func(sc storage.CSPScript) bool { return sc.FirstSeen.After(weekAgo) })
	}
	return out
}

// sanitizeHost strips any scheme (http://, https://) and trailing slashes
// from a host value so "http://example.com/" is stored as "example.com".
// This prevents a common paste mistake where the full URL is entered instead
// of just the hostname.
func sanitizeHost(h string) string {
	h = strings.TrimSpace(h)
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	h = strings.TrimRight(h, "/")
	// Strip port only if it matches the default (80/443); non-standard ports
	// are kept because they're meaningful for matching.
	return h
}

// errDockerManaged refuses a routing edit of a service created from
// container labels (issue #341): the next sync would undo it.
const errDockerManaged = "Managed by Docker: change the container's palisade.* labels instead."

const multipartRangeErr = "multipart limit must be 0 (default 12.5 MiB) to 256 MiB"

// validMultipartMB checks a service's multipart limit in MiB (issue #319):
// 0 keeps the default, the rest are capped at waf.MaxMultipartLimit.
func validMultipartMB(mb int) bool { return mb >= 0 && mb <= waf.MaxMultipartLimit>>20 }

const malwareScanErr = `malware scan must be "", "log" or "block"`

// validMalwareScan checks a service's upload malware scan mode (issue #340).
func validMalwareScan(mode string) bool { return mode == "" || mode == "log" || mode == "block" }

// loginPathsMax caps a service's login protection list.
const loginPathsMax = 20

// openAPIMaxBytes caps an uploaded OpenAPI document.
const openAPIMaxBytes = 2 << 20

// defaultCSP reports every script not served from the page's own origin.
const defaultCSP = "script-src 'self'"

// cookieName matches an RFC 6265 cookie name (a token).
var cookieName = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")

var (
	methodToken = regexp.MustCompile(`^[A-Z]{1,20}$`)
	mediaType   = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]*/([a-z0-9][a-z0-9!#$&^_.+-]*|\*)$`)
)

// splitList splits a form list on commas and whitespace.
func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' })
}

// cacheRatio formats hits as a share of cacheable lookups (hits+misses);
// passes are excluded, since they were never eligible for a hit.
func cacheRatio(hits, misses uint64) string {
	if hits+misses == 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f%%", float64(hits)*100/float64(hits+misses))
}

func fmtMiB(b uint64) string {
	return fmt.Sprintf("%.0f MiB", float64(b)/(1<<20))
}

// ── Services in the React app (issue #356) ───────────────────────────────────

// The page reads every service with all its settings in one GET, grouped as
// its tabs are, and writes one tab at a time. Lists travel as arrays; the
// line-based rule grammars (path limits, cache rules) as text.

type backendJSON struct {
	URL     string `json:"url"`
	Healthy bool   `json:"healthy"`
	Known   bool   `json:"known"`
}

type svcBackends struct {
	URLs           []string      `json:"urls"`
	Health         []backendJSON `json:"health,omitempty"` // read only
	LBPolicy       string        `json:"lb_policy"`
	HealthPath     string        `json:"health_path"`
	HealthInterval int           `json:"health_interval"`
	CA             string        `json:"ca"`
}

type svcHosts struct {
	Aliases   []string `json:"aliases"`
	Canonical string   `json:"canonical"`
}

type svcRateLimit struct {
	RPS       float64 `json:"rps"`
	Burst     int     `json:"burst"`
	PathRules string  `json:"path_rules"`
}

type svcBot struct {
	Mode         string            `json:"mode"`
	AI           map[string]string `json:"ai"`
	LoginPaths   []string          `json:"login_paths"`
	BreachAction string            `json:"breach_action"`
	BreachFields []string          `json:"breach_fields"`
}

// gateTimeLayout is what <input type="datetime-local"> submits; the form
// labels it UTC.
const gateTimeLayout = "2006-01-02T15:04"

// svcGate times are UTC in the datetime-local layout the form edits.
type svcGate struct {
	Maintenance bool   `json:"maintenance"`
	Message     string `json:"message"`
	Start       string `json:"start"`
	End         string `json:"end"`
	Bypass      string `json:"bypass,omitempty"` // admins only
	WaitingRoom bool   `json:"waiting_room"`
	MaxActive   int    `json:"max_active"`
	IdleMins    int    `json:"idle_mins"`
	WaitMessage string `json:"wait_message"`
	Crawlers    string `json:"crawlers"`
}

type svcUploads struct {
	LargeJS     bool   `json:"large_js"`
	MultipartMB int    `json:"multipart_mb"`
	MalwareScan string `json:"malware_scan"`
}

type svcSchema struct {
	Mode   string `json:"mode"`
	Schema string `json:"schema"`
}

type svcMCP struct {
	Mode    string   `json:"mode"`
	Path    string   `json:"path"`
	Origins []string `json:"origins"`
	Methods []string `json:"methods"`
	Tools   []string `json:"tools"`
}

type svcJWT struct {
	Mode       string   `json:"mode"`
	JWKSURL    string   `json:"jwks_url"`
	PublicKey  string   `json:"public_key"`
	Issuer     string   `json:"issuer"`
	Audience   string   `json:"audience"`
	Algorithms []string `json:"algorithms"`
	Prefixes   []string `json:"prefixes"`
}

type cspScriptJSON struct {
	Origin    string `json:"origin"`
	Page      string `json:"page"`
	FirstSeen string `json:"first_seen"`
}

type svcCSP struct {
	Mode     string          `json:"mode"` // off | report | enforce
	Policy   string          `json:"policy"`
	Scripts  []cspScriptJSON `json:"scripts,omitempty"` // read only
	Approved []string        `json:"approved"`
	Recent   bool            `json:"recent,omitempty"` // read only
	Full     bool            `json:"full,omitempty"`   // read only
}

type svcCookies struct {
	Enabled bool     `json:"enabled"`
	Exempt  []string `json:"exempt"`
}

type svcPolicy struct {
	Mode         string   `json:"mode"`
	Methods      []string `json:"methods"`
	ContentTypes []string `json:"content_types"`
	MaxBodyKiB   int      `json:"max_body_kib"`
}

type svcCache struct {
	Enabled       bool   `json:"enabled"`
	BySession     bool   `json:"by_session"`
	SessionCookie string `json:"session_cookie"`
	TTLFloor      int    `json:"ttl_floor"`
	TTLCeiling    int    `json:"ttl_ceiling"`
	Grace         int    `json:"grace"`
	Keep          int    `json:"keep"`
	Rules         string `json:"rules"`
}

type svcMTLS struct {
	Mode  string   `json:"mode"`
	CASet bool     `json:"ca_set"`
	Allow []string `json:"allow"`
}

type svcTLS struct {
	Mode      string  `json:"mode"` // custom | auto | ""
	CertID    int64   `json:"cert_id"`
	CertName  string  `json:"cert_name"`
	ExpiresAt string  `json:"expires_at"`
	HTTP3     bool    `json:"http3"`
	MTLS      svcMTLS `json:"mtls"`
}

type serviceJSON struct {
	ID          int          `json:"id"`
	Name        string       `json:"name"`
	Host        string       `json:"host"`
	Prefix      string       `json:"prefix"`
	Docker      bool         `json:"docker"`
	CreatedAt   string       `json:"created_at"`
	Healthy     bool         `json:"healthy"`
	Known       bool         `json:"known"`
	Hosts       svcHosts     `json:"hosts"`
	Backends    svcBackends  `json:"backends"`
	RateLimit   svcRateLimit `json:"rate_limit"`
	Bot         svcBot       `json:"bot"`
	Gate        svcGate      `json:"gate"`
	Uploads     svcUploads   `json:"uploads"`
	Schema      svcSchema    `json:"schema"`
	OpenAPIMode string       `json:"openapi_mode"`
	MCP         svcMCP       `json:"mcp"`
	JWT         svcJWT       `json:"jwt"`
	CSP         svcCSP       `json:"csp"`
	Cookies     svcCookies   `json:"cookies"`
	Policy      svcPolicy    `json:"policy"`
	Responses   string       `json:"responses"`
	Cache       svcCache     `json:"cache"`
	Compress    bool         `json:"compress"`
	TLS         svcTLS       `json:"tls"`
}

func gateTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(gateTimeLayout)
}

// lines splits a newline-joined stored list into a JSON array.
func lines(s string) []string { return nonNil(strings.Fields(s)) }

func serviceToJSON(v ServiceView, admin bool) serviceJSON {
	s := v.Service
	health := make([]backendJSON, len(v.Health))
	for i, b := range v.Health {
		health[i] = backendJSON{b.URL, b.Healthy, b.Known}
	}
	scripts := make([]cspScriptJSON, len(v.Scripts))
	for i, sc := range v.Scripts {
		scripts[i] = cspScriptJSON{sc.Origin, sc.Page, rfc3339(sc.FirstSeen)}
	}
	cspMode := "off"
	if v.CSP != "" {
		cspMode = "report"
		if v.CSPEnforce {
			cspMode = "enforce"
		}
	}
	g := svcGate{
		Maintenance: s.Gate.Maintenance, Message: s.Gate.MaintMsg, Start: gateTime(s.Gate.MaintStart), End: gateTime(s.Gate.MaintEnd),
		WaitingRoom: s.Gate.WaitingRoom, MaxActive: s.Gate.MaxActive, IdleMins: s.Gate.IdleMins(), WaitMessage: s.Gate.WaitMsg, Crawlers: s.Gate.Crawlers,
	}
	if admin {
		g.Bypass = s.Gate.BypassToken
	}
	if g.Crawlers == "" {
		g.Crawlers = "bypass"
	}
	tlsMode := s.TLSMode
	if tlsMode != "custom" && tlsMode != "auto" {
		tlsMode = "" // "none" after a clear, "" before any
	}
	mtlsMode := v.MTLS.Mode
	if mtlsMode == "" {
		mtlsMode = "off"
	}
	return serviceJSON{
		ID: s.ID, Name: s.Name, Host: s.Host, Prefix: s.Prefix, Docker: s.DockerManaged, CreatedAt: rfc3339(s.CreatedAt),
		Healthy: v.Healthy, Known: v.Known,
		Hosts: svcHosts{nonNil(s.HostAliases), s.CanonicalHost},
		Backends: svcBackends{
			URLs: nonNil(s.Backends()), Health: health, LBPolicy: cmp.Or(s.LBPolicy, "round_robin"),
			HealthPath: s.HealthPath, HealthInterval: s.HealthInterval, CA: s.BackendCA,
		},
		RateLimit: svcRateLimit{s.RateLimitRPS, s.RateLimitBurst, v.RateRules},
		Bot: svcBot{
			Mode: cmp.Or(s.BotMode, "inherit"), AI: bot.ParseAIPolicy(s.AICrawlerPolicy), LoginPaths: nonNil(s.LoginPaths),
			BreachAction: s.BreachAction, BreachFields: nonNil(s.BreachFields),
		},
		Gate:        g,
		Uploads:     svcUploads{s.AllowLargeJSUploads, s.MultipartLimitMB, s.MalwareScan},
		Schema:      svcSchema{cmp.Or(s.SchemaMode, "off"), s.RequestSchema},
		OpenAPIMode: cmp.Or(v.OpenAPIMode, "off"),
		MCP:         svcMCP{cmp.Or(v.MCP.Mode, "off"), v.MCP.Path, lines(v.MCP.Origins), lines(v.MCP.Methods), lines(v.MCP.Tools)},
		JWT: svcJWT{
			Mode: cmp.Or(v.JWT.Mode, "off"), JWKSURL: v.JWT.JWKSURL, PublicKey: v.JWT.PublicKey, Issuer: v.JWT.Issuer, Audience: v.JWT.Audience,
			Algorithms: lines(v.JWT.Algorithms), Prefixes: lines(v.JWT.Prefixes),
		},
		CSP:       svcCSP{cspMode, v.CSP, scripts, nonNil(v.CSPApproved), v.CSPRecent, v.CSPFull},
		Cookies:   svcCookies{v.CookiesOn, lines(v.CookieExempt)},
		Policy:    svcPolicy{cmp.Or(s.Policy.Mode, "off"), nonNil(s.Policy.Methods), nonNil(s.Policy.ContentTypes), s.Policy.MaxBodyKiB},
		Responses: s.ResponseInspect,
		Cache:     svcCache{s.CacheEnabled, s.CacheBySession, s.SessionCookieName, s.CacheTTLFloor, s.CacheTTLCeiling, s.CacheGrace, s.CacheKeep, s.CacheRules},
		Compress:  s.CompressEnabled,
		TLS: svcTLS{
			Mode: tlsMode, CertID: s.CertID, CertName: v.CertName, ExpiresAt: s.TLSExpiresAt, HTTP3: s.HTTP3Enabled,
			MTLS: svcMTLS{mtlsMode, v.MTLS.CAPath != "", lines(v.MTLS.Allow)},
		},
	}
}

type poolCertJSON struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Domains string `json:"domains"`
}

// ListServices answers GET /api/services: every service, the certificate
// pool a service can pick from, and the server facts the tabs mention. The
// page polls it for the health dots.
func (h *Handler) ListServices(c *echo.Context) error {
	certs, err := h.db.ListCertificates()
	if err != nil {
		return err
	}
	email, err := h.db.GetAcmeEmail()
	if err != nil {
		return err
	}
	vcfg, err := h.db.GetVarnishConfig()
	if err != nil {
		return err
	}
	u := currentUser(c)
	admin := u != nil && roleRank[u.Role] >= roleRank[storage.RoleAdmin]
	views := h.serviceViews()
	out := make([]serviceJSON, len(views))
	for i, v := range views {
		out[i] = serviceToJSON(v, admin)
	}
	pool := make([]poolCertJSON, len(certs))
	for i, ct := range certs {
		pool[i] = poolCertJSON{ct.ID, ct.Name, ct.Domains}
	}
	return c.JSON(http.StatusOK, map[string]any{
		"services": out, "certificates": pool, "acme_email": email != "",
		"http3_listener": h.cfg.ListenAddrH3 != "", "varnish": vcfg.Enabled,
	})
}

// serviceFor loads the :id service, or answers 404.
func (h *Handler) serviceFor(c *echo.Context) (storage.Service, error) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return storage.Service{}, badBody("Invalid service id.")
	}
	s, err := h.db.GetService(id)
	if errors.Is(err, sql.ErrNoRows) {
		return s, &jsonError{Status: http.StatusNotFound, Code: "not_found", Message: "No such service."}
	}
	return s, err
}

// routingFor is serviceFor for the routing tabs, which a Docker-managed
// service takes from its container labels instead.
func (h *Handler) routingFor(c *echo.Context) (storage.Service, error) {
	s, err := h.serviceFor(c)
	if err == nil && s.DockerManaged {
		return s, &jsonError{Status: http.StatusConflict, Code: "docker_managed", Message: errDockerManaged}
	}
	return s, err
}

// applied reloads the registry (and the WAF engines when a tab feeds them)
// after a service write and answers 204.
func (h *Handler) applied(c *echo.Context, wafToo bool) error {
	if err := h.registry.Reload(h.db); err != nil {
		return err
	}
	if wafToo && h.reloadWAF != nil {
		h.reloadWAF()
	}
	return c.NoContent(http.StatusNoContent)
}

// SetServiceName answers PUT /api/services/:id/name (issue #320).
func (h *Handler) SetServiceName(c *echo.Context) error {
	s, err := h.routingFor(c)
	if err != nil {
		return err
	}
	var v struct {
		Name string `json:"name"`
	}
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	name := strings.TrimSpace(v.Name)
	switch {
	case name == "":
		return fieldError("name", "Give the service a name.")
	case len(name) > 255:
		return fieldError("name", "At most 255 characters.")
	case name == s.Name:
		return c.NoContent(http.StatusNoContent)
	}
	for _, o := range h.registry.List() {
		if o.Name == name {
			return fieldError("name", "Another service is already called "+name+".")
		}
	}
	if err := h.db.UpdateService(s.ID, name, s.Host, s.Prefix, s.Backend); err != nil {
		return err
	}
	return h.applied(c, true)
}

// SetServiceHostsJSON answers PUT /api/services/:id/hosts.
func (h *Handler) SetServiceHostsJSON(c *echo.Context) error {
	s, err := h.routingFor(c)
	if err != nil {
		return err
	}
	var v svcHosts
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	if s.Host == "" {
		return badBody("Extra hostnames need a host-matched service.")
	}
	aliases, canonical, err := services.ValidateHosts(s.ID, s.Host, v.Aliases, v.Canonical, h.registry.List())
	if err != nil {
		return fieldError("aliases", err.Error())
	}
	if err := h.db.SetServiceHosts(s.ID, aliases, canonical); err != nil {
		return err
	}
	return h.applied(c, false)
}

// SetServiceBackendsJSON answers PUT /api/services/:id/backends: the list
// (first = primary), balancing, active health check and trusted backend
// certificate.
func (h *Handler) SetServiceBackendsJSON(c *echo.Context) error {
	s, err := h.routingFor(c)
	if err != nil {
		return err
	}
	var v svcBackends
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	var urls []string
	for _, u := range v.URLs {
		if u = strings.TrimSpace(u); u != "" {
			urls = append(urls, u)
		}
	}
	if v.LBPolicy != "round_robin" && v.LBPolicy != "least_conn" {
		return fieldError("lb_policy", "Pick round robin or least connections.")
	}
	path := strings.TrimSpace(v.HealthPath)
	if v.HealthInterval < 0 || v.HealthInterval > 3600 {
		return fieldError("health_interval", "Between 1 and 3600 seconds, or blank.")
	}
	if err := services.ValidateBackends(urls, path, v.HealthInterval); err != nil {
		return fieldError("urls", err.Error())
	}
	ca := strings.TrimSpace(strings.ReplaceAll(v.CA, "\r\n", "\n"))
	if err := services.ValidateBackendCA(ca); err != nil {
		return fieldError("ca", err.Error())
	}
	if err := h.db.SetServiceBackends(s.ID, urls, v.LBPolicy, path, v.HealthInterval); err != nil {
		return err
	}
	if err := h.db.SetServiceBackendCA(s.ID, ca); err != nil {
		return err
	}
	return h.applied(c, false)
}

// SetServiceRateLimitJSON answers PUT /api/services/:id/rate-limit: 0 falls
// through to the global limit; path limits ride on top (issue #280).
func (h *Handler) SetServiceRateLimitJSON(c *echo.Context) error {
	s, err := h.serviceFor(c)
	if err != nil {
		return err
	}
	var v svcRateLimit
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	rc := rangeCheck{}
	rc.num("rps", v.RPS, 0, 1e6)
	rc.num("burst", float64(v.Burst), 0, 1e6)
	if err := rc.err(); err != nil {
		return err
	}
	rules := strings.TrimSpace(strings.ReplaceAll(v.PathRules, "\r\n", "\n"))
	if _, err := services.ParseRateRules(rules); err != nil {
		return fieldError("path_rules", err.Error())
	}
	if err := h.db.SetServiceRateLimit(s.ID, v.RPS, v.Burst); err != nil {
		return err
	}
	if err := h.db.SetServiceRateRules(s.ID, rules); err != nil {
		return err
	}
	return h.applied(c, false)
}

type cacheRowJSON struct {
	App    string `json:"app"`
	Hits   int64  `json:"hits"`
	Misses int64  `json:"misses"`
	Passes int64  `json:"passes"`
	Errors int64  `json:"errors"`
	Ratio  string `json:"ratio"`
}

// CacheStats answers GET /api/services/cache-stats: Varnish-wide counters
// from varnishstat (best effort: stats_error says why they're missing) and
// per-service results of the last 24 hours from the request log.
func (h *Handler) CacheStats(c *echo.Context) error {
	vcfg, err := h.db.GetVarnishConfig()
	if err != nil {
		return err
	}
	out := map[string]any{"enabled": vcfg.Enabled}
	if !vcfg.Enabled {
		return c.JSON(http.StatusOK, out)
	}
	if st, err := services.ReadVarnishStats(c.Request().Context()); err != nil {
		out["stats_error"] = err.Error()
	} else {
		out["stats"] = map[string]any{
			"ratio": cacheRatio(st.Hits, st.Misses), "objects": st.Objects,
			"used": fmtMiB(st.BytesUsed), "total": fmtMiB(st.BytesUsed + st.BytesFree), "evicted": st.Evicted,
		}
	}
	results, err := h.db.CacheResultsSince(time.Now().Add(-24 * time.Hour))
	if err != nil {
		return err
	}
	rows := make([]cacheRowJSON, len(results))
	for i, r := range results {
		rows[i] = cacheRowJSON{r.App, int64(r.Hits), int64(r.Misses), int64(r.Passes), int64(r.Errors), cacheRatio(uint64(r.Hits), uint64(r.Misses))} //nolint:gosec // G115: counts are never negative
	}
	out["services"] = rows
	return c.JSON(http.StatusOK, out)
}

// SetServiceBot answers PUT /api/services/:id/bot: the bot challenge mode,
// AI crawler overrides (issue #187), login protection (issue #132) and the
// leaked password check (issue #188).
func (h *Handler) SetServiceBot(c *echo.Context) error {
	s, err := h.serviceFor(c)
	if err != nil {
		return err
	}
	var v svcBot
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	if v.Mode != "inherit" && v.Mode != "always" && v.Mode != "off" {
		return fieldError("mode", "Pick inherit, always or off.")
	}
	ai := bot.AIPolicy{}
	for _, cat := range bot.AICategories {
		switch a := v.AI[cat]; {
		case a == "":
		case bot.ValidAIAction(a):
			ai[cat] = a
		default:
			return fieldError("ai_"+cat, "Pick allow, challenge or block.")
		}
	}
	var paths []string
	for _, p := range v.LoginPaths {
		if p = strings.TrimSpace(p); p == "" || slices.Contains(paths, p) {
			continue
		}
		if !strings.HasPrefix(p, "/") || p == "/" {
			return fieldError("login_paths", fmt.Sprintf("%q is not a path: start it with / and name the login page, e.g. /login.", p))
		}
		paths = append(paths, p)
	}
	if len(paths) > loginPathsMax {
		return fieldError("login_paths", fmt.Sprintf("At most %d login paths.", loginPathsMax))
	}
	if v.BreachAction != "" && v.BreachAction != "log" && v.BreachAction != "block" {
		return fieldError("breach_action", "Pick off, log or block.")
	}
	var fields []string
	for _, f := range v.BreachFields {
		for _, f := range splitList(f) {
			if len(f) > 64 {
				return fieldError("breach_fields", "Field names are at most 64 characters.")
			}
			if !slices.Contains(fields, f) {
				fields = append(fields, f)
			}
		}
	}
	if len(fields) > 10 {
		return fieldError("breach_fields", "At most 10 field names.")
	}
	for _, err := range []error{
		h.db.SetServiceBotMode(s.ID, v.Mode),
		h.db.SetServiceAICrawlerPolicy(s.ID, ai.String()),
		h.db.SetServiceLoginPaths(s.ID, paths),
		h.db.SetServiceBreachCheck(s.ID, v.BreachAction, fields),
	} {
		if err != nil {
			return err
		}
	}
	return h.applied(c, false)
}

// SetServiceGateJSON answers PUT /api/services/:id/gate: maintenance mode
// and the waiting room (issue #198). Turning maintenance on mints a bypass
// token if there is none; new_bypass replaces it, revoking shared links.
func (h *Handler) SetServiceGateJSON(c *echo.Context) error {
	s, err := h.serviceFor(c)
	if err != nil {
		return err
	}
	var v struct {
		svcGate
		NewBypass bool `json:"new_bypass"`
	}
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	stored, err := h.db.ListServiceGates() // GetService leaves Gate empty
	if err != nil {
		return err
	}
	g := storage.ServiceGate{
		Maintenance: v.Maintenance, MaintMsg: strings.TrimSpace(v.Message), BypassToken: stored[s.ID].BypassToken,
		WaitingRoom: v.WaitingRoom, WaitMsg: strings.TrimSpace(v.WaitMessage), Crawlers: v.Crawlers,
		MaxActive: v.MaxActive, IdleSecs: v.IdleMins * 60,
	}
	for _, f := range []struct {
		name, in string
		dst      *time.Time
	}{{"start", v.Start, &g.MaintStart}, {"end", v.End, &g.MaintEnd}} {
		if f.in != "" {
			if *f.dst, err = time.Parse(gateTimeLayout, f.in); err != nil {
				return fieldError(f.name, "Enter a date and time.")
			}
		}
	}
	if !g.MaintStart.IsZero() && !g.MaintEnd.IsZero() && !g.MaintEnd.After(g.MaintStart) {
		return fieldError("end", "The end must be after the start.")
	}
	if len(g.MaintMsg) > 500 {
		return fieldError("message", "At most 500 characters.")
	}
	if len(g.WaitMsg) > 500 {
		return fieldError("wait_message", "At most 500 characters.")
	}
	if g.Crawlers != "deny" {
		g.Crawlers = "bypass"
	}
	if g.WaitingRoom {
		rc := rangeCheck{}
		rc.num("max_active", float64(v.MaxActive), 1, 1_000_000)
		rc.num("idle_mins", float64(v.IdleMins), 1, 1440)
		if err := rc.err(); err != nil {
			return err
		}
	}
	if (g.Maintenance && g.BypassToken == "") || v.NewBypass {
		b := make([]byte, 16)
		rand.Read(b) //nolint:errcheck // never errors on modern platforms
		g.BypassToken = hex.EncodeToString(b)
	}
	if err := h.db.SetServiceGate(s.ID, g); err != nil {
		return err
	}
	return h.applied(c, false)
}

// SetServiceUploads answers PUT /api/services/:id/uploads: streaming large
// JavaScript bodies, the multipart limit (issue #319) and the malware scan
// (issue #340). The first two feed the WAF engines.
func (h *Handler) SetServiceUploads(c *echo.Context) error {
	s, err := h.serviceFor(c)
	if err != nil {
		return err
	}
	var v svcUploads
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	if !validMultipartMB(v.MultipartMB) {
		return fieldError("multipart_mb", "Between 0 (the 12.5 MiB default) and 256 MiB.")
	}
	if !validMalwareScan(v.MalwareScan) {
		return fieldError("malware_scan", "Pick off, log or block.")
	}
	for _, err := range []error{
		h.db.SetServiceLargeJSUploads(s.ID, v.LargeJS),
		h.db.SetServiceMultipartLimit(s.ID, v.MultipartMB),
		h.db.SetServiceMalwareScan(s.ID, v.MalwareScan),
	} {
		if err != nil {
			return err
		}
	}
	return h.applied(c, true)
}

// fields trims a JSON list and drops blank or repeated entries.
func fields(in []string) []string {
	var out []string
	for _, s := range in {
		for _, s := range strings.Fields(s) {
			if !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	return out
}

// SetServiceSchemaJSON answers PUT /api/services/:id/schema: the JSON
// Schema request bodies are checked against (issue #75).
func (h *Handler) SetServiceSchemaJSON(c *echo.Context) error {
	s, err := h.serviceFor(c)
	if err != nil {
		return err
	}
	var v svcSchema
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	v.Schema = strings.TrimSpace(v.Schema)
	if v.Mode != "log" && v.Mode != "enforce" {
		v.Mode = "off"
	}
	if v.Schema != "" && v.Mode != "off" {
		if err := waf.ValidateSchema(v.Schema); err != nil {
			return fieldError("schema", "Not a valid JSON Schema: "+err.Error())
		}
	}
	if err := h.db.SetServiceSchema(s.ID, v.Schema, v.Mode); err != nil {
		return err
	}
	return h.applied(c, true)
}

type svcOpenAPI struct {
	Mode string `json:"mode"`
	Spec string `json:"spec"`
}

// ServiceOpenAPIJSON answers GET /api/services/:id/openapi. The spec can be
// large, so the page list carries only its mode.
func (h *Handler) ServiceOpenAPIJSON(c *echo.Context) error {
	s, err := h.serviceFor(c)
	if err != nil {
		return err
	}
	o, err := h.db.GetServiceOpenAPI(s.ID)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, svcOpenAPI{cmp.Or(o.Mode, "off"), o.Spec})
}

// SetServiceOpenAPIJSON answers PUT /api/services/:id/openapi (issue #190).
// An empty spec removes it.
func (h *Handler) SetServiceOpenAPIJSON(c *echo.Context) error {
	s, err := h.serviceFor(c)
	if err != nil {
		return err
	}
	var v svcOpenAPI
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	v.Spec = strings.TrimSpace(v.Spec)
	if v.Mode != "log" && v.Mode != "enforce" {
		v.Mode = "off"
	}
	if len(v.Spec) > openAPIMaxBytes {
		return fieldError("spec", "The spec is larger than 2 MiB.")
	}
	if v.Spec != "" {
		if err := waf.ValidateOpenAPI(v.Spec); err != nil {
			return fieldError("spec", "Not a valid OpenAPI spec: "+err.Error())
		}
	}
	if err := h.db.SetServiceOpenAPI(s.ID, v.Spec, v.Mode); err != nil {
		return err
	}
	return h.applied(c, true)
}

// SetServiceMCPJSON answers PUT /api/services/:id/mcp (issue #234).
func (h *Handler) SetServiceMCPJSON(c *echo.Context) error {
	s, err := h.serviceFor(c)
	if err != nil {
		return err
	}
	var v svcMCP
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	m := storage.ServiceMCP{
		Mode: v.Mode, Path: strings.TrimSpace(v.Path),
		Origins: strings.Join(fields(v.Origins), "\n"), Methods: strings.Join(fields(v.Methods), "\n"), Tools: strings.Join(fields(v.Tools), "\n"),
	}
	switch m.Mode {
	case "log", "enforce":
		if !strings.HasPrefix(m.Path, "/") {
			return fieldError("path", "Start the endpoint path with /, e.g. /mcp.")
		}
		for _, o := range strings.Fields(m.Origins) {
			if u, err := neturl.Parse(o); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.TrimSuffix(u.Path, "/") != "" || u.RawQuery != "" || u.User != nil {
				return fieldError("origins", o+" must look like https://app.example.com.")
			}
		}
	case "off":
	default:
		return fieldError("mode", "Pick off, log or enforce.")
	}
	if err := h.db.SetServiceMCP(s.ID, m); err != nil {
		return err
	}
	return h.applied(c, true)
}

// SetServiceJWTJSON answers PUT /api/services/:id/jwt (issue #279). The
// verifier is built once here so a bad key or URL never reaches a reload.
func (h *Handler) SetServiceJWTJSON(c *echo.Context) error {
	s, err := h.serviceFor(c)
	if err != nil {
		return err
	}
	var v svcJWT
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	j := storage.ServiceJWT{
		Mode: v.Mode, JWKSURL: strings.TrimSpace(v.JWKSURL), PublicKey: strings.TrimSpace(v.PublicKey),
		Issuer: strings.TrimSpace(v.Issuer), Audience: strings.TrimSpace(v.Audience),
		Algorithms: strings.Join(fields(v.Algorithms), " "), Prefixes: strings.Join(fields(v.Prefixes), "\n"),
	}
	switch j.Mode {
	case "log", "enforce":
		if _, err := jwtauth.New(services.JWTConfig(j)); err != nil {
			return badBody(err.Error())
		}
	case "off":
	default:
		return fieldError("mode", "Pick off, log or enforce.")
	}
	if err := h.db.SetServiceJWT(s.ID, j); err != nil {
		return err
	}
	return h.applied(c, false)
}

// SetServiceCSPJSON answers PUT /api/services/:id/csp: the script inventory
// policy (issue #235) and enforcement with approved sources (issue #283).
// Approvals must be in the service's inventory; off keeps them.
func (h *Handler) SetServiceCSPJSON(c *echo.Context) error {
	s, err := h.serviceFor(c)
	if err != nil {
		return err
	}
	var v svcCSP
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	policy := ""
	switch v.Mode {
	case "report", "enforce":
		policy = cmp.Or(strings.Join(strings.Fields(v.Policy), " "), defaultCSP)
		lower := strings.ToLower(policy)
		switch {
		case len(policy) > 4096:
			return fieldError("policy", "At most 4096 characters.")
		case strings.Contains(lower, "report-uri") || strings.Contains(lower, "report-to"):
			return fieldError("policy", "Leave out report-uri and report-to; Palisade adds them.")
		case strings.IndexFunc(policy, func(r rune) bool { return r < 0x20 || r > 0x7e }) >= 0:
			return fieldError("policy", "Only printable ASCII.")
		}
		policy = strings.TrimSuffix(policy, ";")
	case "off":
	default:
		return fieldError("mode", "Pick off, report or enforce.")
	}
	var approved []string
	if policy == "" {
		cur, err := h.db.ListCSPEnforcement()
		if err != nil {
			return err
		}
		approved = cur[s.ID].Approved
	} else {
		all, err := h.db.ListCSPScripts()
		if err != nil {
			return err
		}
		for _, o := range v.Approved {
			if slices.ContainsFunc(all[s.ID], func(sc storage.CSPScript) bool { return sc.Origin == o }) && !slices.Contains(approved, o) {
				approved = append(approved, o)
			}
		}
	}
	if err := h.db.SetServiceCSP(s.ID, policy); err != nil {
		return err
	}
	if err := h.db.SetCSPEnforcement(s.ID, storage.CSPEnforcement{Enforce: v.Mode == "enforce", Approved: approved}); err != nil {
		return err
	}
	return h.applied(c, false)
}

// SetServiceCookiesJSON answers PUT /api/services/:id/cookies (issue #281).
func (h *Handler) SetServiceCookiesJSON(c *echo.Context) error {
	s, err := h.serviceFor(c)
	if err != nil {
		return err
	}
	var v svcCookies
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	var exempt []string
	for _, e := range v.Exempt {
		exempt = append(exempt, splitList(e)...)
	}
	exempt = fields(exempt)
	if len(exempt) > 50 {
		return fieldError("exempt", "At most 50 cookie names.")
	}
	for _, n := range exempt {
		if len(n) > 128 || !cookieName.MatchString(n) {
			return fieldError("exempt", "Not a cookie name: "+n)
		}
	}
	if err := h.db.SetServiceCookiePolicy(s.ID, v.Enabled, exempt); err != nil {
		return err
	}
	return h.applied(c, false)
}

// SetServicePolicyJSON answers PUT /api/services/:id/policy: the methods,
// Content-Types and body size a service accepts (issue #282).
func (h *Handler) SetServicePolicyJSON(c *echo.Context) error {
	s, err := h.serviceFor(c)
	if err != nil {
		return err
	}
	var v svcPolicy
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	p := storage.RequestPolicy{Mode: v.Mode}
	switch p.Mode {
	case "off":
		p.Mode = ""
	case "log", "enforce":
		for _, m := range fields(v.Methods) {
			if m = strings.ToUpper(m); !methodToken.MatchString(m) {
				return fieldError("methods", "Not an HTTP method: "+m)
			}
			p.Methods = append(p.Methods, m)
		}
		for _, t := range fields(v.ContentTypes) {
			if t = strings.ToLower(t); len(t) > 127 || !mediaType.MatchString(t) {
				return fieldError("content_types", "Not a media type: "+t)
			}
			p.ContentTypes = append(p.ContentTypes, t)
		}
		if len(p.Methods) > 20 {
			return fieldError("methods", "At most 20 methods.")
		}
		if len(p.ContentTypes) > 30 {
			return fieldError("content_types", "At most 30 content types.")
		}
		if v.MaxBodyKiB < 0 || v.MaxBodyKiB > 1<<20 {
			return fieldError("max_body_kib", "Between 0 and 1048576 KiB (1 GiB).")
		}
		p.MaxBodyKiB = v.MaxBodyKiB
		if len(p.Methods) == 0 && len(p.ContentTypes) == 0 && p.MaxBodyKiB == 0 {
			return badBody("Set methods, content types or a body size, or turn the policy off.")
		}
	default:
		return fieldError("mode", "Pick off, log or enforce.")
	}
	if err := h.db.SetServiceRequestPolicy(s.ID, p); err != nil {
		return err
	}
	return h.applied(c, false)
}

// SetServiceResponsesJSON answers PUT /api/services/:id/responses: response
// inspection (issue #192), "" off, "log" or "block".
func (h *Handler) SetServiceResponsesJSON(c *echo.Context) error {
	s, err := h.serviceFor(c)
	if err != nil {
		return err
	}
	var v struct {
		Mode string `json:"mode"`
	}
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	if v.Mode != "" && v.Mode != "log" && v.Mode != "block" {
		return fieldError("mode", "Pick off, log or block.")
	}
	if err := h.db.SetServiceResponseInspect(s.ID, v.Mode); err != nil {
		return err
	}
	return h.applied(c, false)
}

// SetServiceCacheJSON answers PUT /api/services/:id/cache: Varnish caching,
// per-session caching, TTL tuning, path rules (issue #212) and compression,
// which doesn't need Varnish.
func (h *Handler) SetServiceCacheJSON(c *echo.Context) error {
	s, err := h.serviceFor(c)
	if err != nil {
		return err
	}
	var v struct {
		svcCache
		Compress bool `json:"compress"`
	}
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	v.SessionCookie = strings.TrimSpace(v.SessionCookie)
	if v.BySession && v.SessionCookie == "" {
		return fieldError("session_cookie", "Name the session cookie, or turn caching by session off.")
	}
	rc := rangeCheck{}
	for _, f := range []struct {
		name string
		n    int
	}{{"ttl_floor", v.TTLFloor}, {"ttl_ceiling", v.TTLCeiling}, {"grace", v.Grace}, {"keep", v.Keep}} {
		rc.num(f.name, float64(f.n), 0, 365*24*3600)
	}
	if err := rc.err(); err != nil {
		return err
	}
	if v.TTLCeiling > 0 && v.TTLFloor > v.TTLCeiling {
		return fieldError("ttl_floor", "The floor can't be above the ceiling.")
	}
	rules := strings.TrimSpace(strings.ReplaceAll(v.Rules, "\r\n", "\n"))
	if _, err := services.ParseCacheRules(rules); err != nil {
		return fieldError("rules", err.Error())
	}
	for _, err := range []error{
		h.db.SetServiceCache(s.ID, v.Enabled),
		h.db.SetServiceCacheSession(s.ID, v.BySession, v.SessionCookie),
		h.db.SetServiceCacheTuning(s.ID, v.TTLFloor, v.TTLCeiling, v.Grace, v.Keep, rules),
		h.db.SetServiceCompress(s.ID, v.Compress),
	} {
		if err != nil {
			return err
		}
	}
	return h.applied(c, false)
}

// PurgeServiceCacheJSON answers POST /api/services/:id/purge: evict what
// Varnish holds for the service, or only under path. 502 when varnishd
// can't be reached.
func (h *Handler) PurgeServiceCacheJSON(c *echo.Context) error {
	s, err := h.serviceFor(c)
	if err != nil {
		return err
	}
	var v struct {
		Path string `json:"path"`
	}
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	vcfg, err := h.db.GetVarnishConfig()
	if err != nil {
		return err
	}
	if !vcfg.Enabled {
		return &jsonError{Status: http.StatusConflict, Code: "varnish_off", Message: "The Varnish integration is off. Turn it on in Settings first."}
	}
	v.Path = strings.TrimSpace(v.Path)
	if v.Path != "" && !services.ValidPurgePath(v.Path) {
		return fieldError("path", "Start with / and use only letters, digits and / _ . ~ % -.")
	}
	if err := services.Purge(vcfg, s, v.Path); err != nil {
		return &jsonError{Status: http.StatusBadGateway, Code: "purge_failed", Message: "Varnish didn't take the purge: " + err.Error()}
	}
	return c.NoContent(http.StatusNoContent)
}

// tlsFor is serviceFor for the TLS tab, which needs a host to serve on.
func (h *Handler) tlsFor(c *echo.Context) (storage.Service, error) {
	s, err := h.serviceFor(c)
	if err == nil && s.Host == "" {
		return s, &jsonError{Status: http.StatusConflict, Code: "no_host", Message: "TLS needs a host-matched service; this one matches by path prefix."}
	}
	return s, err
}

// SetServiceTLSJSON answers PUT /api/services/:id/tls. mode is "pool" (a
// certificate from the pool, cert_id), "custom" (cert_pem and key_pem, the
// key written to disk only), "auto" (Let's Encrypt; acme_email is saved
// first when none is stored) or "none". A certificate must cover the host.
func (h *Handler) SetServiceTLSJSON(c *echo.Context) error {
	s, err := h.tlsFor(c)
	if err != nil {
		return err
	}
	var v struct {
		Mode      string `json:"mode"`
		CertID    int64  `json:"cert_id"`
		CertPEM   string `json:"cert_pem"`
		KeyPEM    string `json:"key_pem"`
		AcmeEmail string `json:"acme_email"`
	}
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	switch v.Mode {
	case "pool":
		cert, err := h.db.GetCertificate(v.CertID)
		if err != nil {
			return fieldError("cert_id", "Pick a certificate from the pool.")
		}
		pem, err := os.ReadFile(cert.CertPath)
		if err != nil {
			return err
		}
		if err := services.CertCoversHost(pem, s.Host); err != nil {
			return fieldError("cert_id", err.Error())
		}
		err = h.db.SetServiceCertID(s.ID, v.CertID)
		if err != nil {
			return err
		}
	case "custom":
		certPEM, keyPEM := []byte(strings.TrimSpace(v.CertPEM)+"\n"), []byte(strings.TrimSpace(v.KeyPEM)+"\n")
		switch {
		case strings.TrimSpace(v.CertPEM) == "":
			return fieldError("cert_pem", "Paste the certificate.")
		case strings.TrimSpace(v.KeyPEM) == "":
			return fieldError("key_pem", "Paste the private key.")
		}
		if err := services.CertCoversHost(certPEM, s.Host); err != nil {
			return fieldError("cert_pem", err.Error())
		}
		if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
			return fieldError("key_pem", "This key doesn't match the certificate, or isn't a PEM private key.")
		}
		certPath, keyPath, expires, err := services.SaveCustomCert(s.ID, certPEM, keyPEM)
		if err != nil {
			return err
		}
		if err := h.db.ClearServiceTLS(s.ID); err != nil { // drops a pool link
			return err
		}
		if err := h.db.SetServiceTLS(s.ID, "custom", certPath, keyPath, expires.UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	case "auto":
		stored, err := h.db.GetAcmeEmail()
		if err != nil {
			return err
		}
		if email := strings.TrimSpace(v.AcmeEmail); email != "" {
			if !storage.ValidEmail(email) {
				return fieldError("acme_email", "Enter a valid email address.")
			}
			if err := h.db.SetAcmeEmail(email); err != nil {
				return err
			}
		} else if stored == "" {
			return fieldError("acme_email", "Let's Encrypt needs a contact email before it can issue.")
		}
		if err := h.db.ClearServiceTLS(s.ID); err != nil {
			return err
		}
		if err := h.db.SetServiceTLS(s.ID, "auto", "", "", ""); err != nil {
			return err
		}
	case "none":
		if err := h.db.ClearServiceTLS(s.ID); err != nil {
			return err
		}
	default:
		return fieldError("mode", "Pick pool, custom, auto or none.")
	}
	return h.applied(c, false)
}

// SetServiceHTTP3JSON answers PUT /api/services/:id/http3.
func (h *Handler) SetServiceHTTP3JSON(c *echo.Context) error {
	s, err := h.tlsFor(c)
	if err != nil {
		return err
	}
	var v struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	if err := h.db.SetServiceHTTP3(s.ID, v.Enabled); err != nil {
		return err
	}
	return h.applied(c, false)
}

// SetServiceMTLSJSON answers PUT /api/services/:id/mtls: the client
// certificate policy (issue #191). An empty ca keeps the stored bundle, and
// off keeps it for later.
func (h *Handler) SetServiceMTLSJSON(c *echo.Context) error {
	s, err := h.tlsFor(c)
	if err != nil {
		return err
	}
	var v struct {
		Mode  string   `json:"mode"`
		CA    string   `json:"ca"`
		Allow []string `json:"allow"`
	}
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	if v.Mode != "off" && v.Mode != "optional" && v.Mode != "required" {
		return fieldError("mode", "Pick off, optional or required.")
	}
	all, err := h.db.ListServiceMTLS()
	if err != nil {
		return err
	}
	m := all[s.ID]
	m.Mode = v.Mode
	if m.Allow = strings.Join(fields(v.Allow), "\n"); len(m.Allow) > 64<<10 {
		return fieldError("allow", "At most 64 KiB.")
	}
	if ca := strings.TrimSpace(v.CA); ca != "" {
		if m.CAPath, err = services.SaveClientCA(s.ID, []byte(ca+"\n")); err != nil {
			return fieldError("ca", err.Error())
		}
	}
	if m.CAPath == "" {
		if m.Mode != "off" {
			return fieldError("ca", "Paste the CA certificate(s) that issue your client certificates.")
		}
		return c.NoContent(http.StatusNoContent)
	}
	if err := h.db.SetServiceMTLS(s.ID, m); err != nil {
		return err
	}
	return h.applied(c, false)
}
