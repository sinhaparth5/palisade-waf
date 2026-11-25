package ui

import (
	"cmp"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"net/http"
	neturl "net/url"
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

func (h *Handler) ServicesPage(c *echo.Context) error {
	poolCerts, _ := h.db.ListCertificates()
	return h.render(c, "services", map[string]any{
		"Services":      h.serviceViews(),
		"PoolCerts":     poolCerts,
		"HTTP3Listener": h.cfg.ListenAddrH3 != "",
	})
}

// ServicesRows re-renders just the services table body, polled periodically
// by the page so the reachability dot updates live.
func (h *Handler) ServicesRows(c *echo.Context) error {
	return h.servicesRows(c)
}

// servicesRows renders the service table fragment every service write swaps in.
func (h *Handler) servicesRows(c *echo.Context) error {
	return h.renderPartial(c, "services", "services-rows", h.servicesRowsData(c))
}

// servicesRowsData is the services-rows input: the rows plus the viewer's
// role, which picks the Edit or the read-only View button.
func (h *Handler) servicesRowsData(c *echo.Context) map[string]any {
	role := ""
	if u := currentUser(c); u != nil {
		role = u.Role
	}
	return map[string]any{"Services": h.serviceViews(), "Role": role}
}

// wizardError redirects the swap to the wizard's own error box (instead of
// the services table) via HTMX response headers, so a failed add doesn't
// clobber the existing rows.
func (h *Handler) wizardError(c *echo.Context, msg string) error {
	c.Response().Header().Set("HX-Retarget", "#wizard-error")
	c.Response().Header().Set("HX-Reswap", "innerHTML")
	return c.String(http.StatusOK, msg)
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

func (h *Handler) dockerManaged(id int) bool {
	s, err := h.db.GetService(id)
	return err == nil && s.DockerManaged
}

// AddService creates a new backend service from the add-service wizard.
// matchType picks which of host/prefix gets saved; the wizard only ever
// collects one of the two from the user. The backend must pass a live
// reachability probe before it's saved.
func (h *Handler) AddService(c *echo.Context) error {
	name := strings.TrimSpace(c.FormValue("name"))
	matchType := c.FormValue("match_type") // "host" | "prefix"
	matchValue := strings.TrimSpace(c.FormValue("match_value"))
	backend := strings.TrimSpace(c.FormValue("backend"))

	if name == "" || matchValue == "" || (matchType != "host" && matchType != "prefix") {
		return h.wizardError(c, "Please fill in all required fields.")
	}
	if err := services.Validate(backend); err != nil {
		return h.wizardError(c, err.Error())
	}
	if err := services.Probe(backend); err != nil {
		return h.wizardError(c, err.Error()+". Fix the backend and try again.")
	}

	var host, prefix string
	if matchType == "host" {
		host = sanitizeHost(matchValue)
		if _, _, err := services.ValidateHosts(0, host, nil, "", h.registry.List()); err != nil {
			return h.wizardError(c, err.Error())
		}
	} else {
		prefix = matchValue
	}

	var rps float64
	if v := strings.TrimSpace(c.FormValue("rps")); v != "" {
		var err error
		if rps, err = strconv.ParseFloat(v, 64); err != nil {
			return h.wizardError(c, "Requests/second must be a number.")
		}
	}
	var burst int
	if v := strings.TrimSpace(c.FormValue("burst")); v != "" {
		var err error
		if burst, err = strconv.Atoi(v); err != nil {
			return h.wizardError(c, "Burst must be a whole number.")
		}
	}
	if rps < 0 {
		rps = 0
	}
	if burst < 0 {
		burst = 0
	}

	if err := h.db.AddService(name, host, prefix, backend, rps, burst); err != nil {
		return err
	}
	if err := h.registry.Reload(h.db); err != nil {
		return err
	}
	w := c.Response()
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<div id="wizard-error" hx-swap-oob="true"></div>`)
	return h.tmpls["services"].ExecuteTemplate(w, "services-rows", h.servicesRowsData(c))
}

func (h *Handler) DeleteService(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	if err := h.db.RemoveService(id); err != nil {
		return err
	}
	if err := h.registry.Reload(h.db); err != nil {
		return err
	}
	return h.servicesRows(c)
}

// rlError mirrors tlsModalError but targets the Rate Limit tab's own error box.
func (h *Handler) rlError(c *echo.Context, msg string) error {
	c.Response().Header().Set("HX-Retarget", "#rl-error")
	c.Response().Header().Set("HX-Reswap", "innerHTML")
	return c.String(http.StatusOK, msg)
}

func (h *Handler) SetServiceRateLimit(c *echo.Context) error {
	id, err := strconv.Atoi(c.FormValue("service_id"))
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid service")
	}
	var rps float64
	if v := strings.TrimSpace(c.FormValue("rps")); v != "" {
		if rps, err = strconv.ParseFloat(v, 64); err != nil {
			return h.rlError(c, "Requests/second must be a number.")
		}
	}
	var burst int
	if v := strings.TrimSpace(c.FormValue("burst")); v != "" {
		if burst, err = strconv.Atoi(v); err != nil {
			return h.rlError(c, "Burst must be a whole number.")
		}
	}
	if rps < 0 {
		rps = 0
	}
	if burst < 0 {
		burst = 0
	}
	pathRules := strings.TrimSpace(strings.ReplaceAll(c.FormValue("path_rules"), "\r\n", "\n"))
	if _, err := services.ParseRateRules(pathRules); err != nil {
		return h.rlError(c, "Path limits: "+err.Error())
	}
	if err := h.db.SetServiceRateLimit(id, rps, burst); err != nil {
		return err
	}
	if err := h.db.SetServiceRateRules(id, pathRules); err != nil {
		return err
	}
	if err := h.registry.Reload(h.db); err != nil {
		return err
	}
	w := c.Response()
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Response().Header().Set("HX-Trigger", "rl-saved")
	fmt.Fprint(w, `<div id="rl-error" hx-swap-oob="true"></div>`)
	return h.tmpls["services"].ExecuteTemplate(w, "services-rows", h.servicesRowsData(c))
}

// SetServiceBotMode sets the per-service bot protection override (inherit / always / off).
func (h *Handler) SetServiceBotMode(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	mode := c.FormValue("bot_mode")
	if mode != "inherit" && mode != "always" && mode != "off" {
		mode = "inherit"
	}
	if err := h.db.SetServiceBotMode(id, mode); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if err := h.registry.Reload(h.db); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	w := c.Response()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return h.tmpls["services"].ExecuteTemplate(w, "services-rows", h.servicesRowsData(c))
}

const multipartRangeErr = "multipart limit must be 0 (default 12.5 MiB) to 256 MiB"

// validMultipartMB checks a service's multipart limit in MiB (issue #319):
// 0 keeps the default, the rest are capped at waf.MaxMultipartLimit.
func validMultipartMB(mb int) bool { return mb >= 0 && mb <= waf.MaxMultipartLimit>>20 }

const malwareScanErr = `malware scan must be "", "log" or "block"`

// validMalwareScan checks a service's upload malware scan mode (issue #340).
func validMalwareScan(mode string) bool { return mode == "" || mode == "log" || mode == "block" }

// SetServiceLargeJSUploads opts one service into streaming JavaScript request
// bodies. This avoids the small, deliberately conservative limit applied to
// non-file bodies while leaving all header-phase WAF checks active.
func (h *Handler) SetServiceLargeJSUploads(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	enabled := c.FormValue("enabled") == "1"
	mb := 0
	if v := strings.TrimSpace(c.FormValue("multipart_mb")); v != "" {
		if mb, err = strconv.Atoi(v); err != nil || !validMultipartMB(mb) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": multipartRangeErr})
		}
	}
	scan := c.FormValue("malware_scan")
	if !validMalwareScan(scan) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": malwareScanErr})
	}
	if err := h.db.SetServiceLargeJSUploads(id, enabled); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if err := h.db.SetServiceMultipartLimit(id, mb); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if err := h.db.SetServiceMalwareScan(id, scan); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if err := h.registry.Reload(h.db); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if h.reloadWAF != nil {
		h.reloadWAF()
	}
	w := c.Response()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return h.tmpls["services"].ExecuteTemplate(w, "services-rows", h.servicesRowsData(c))
}

// SetServiceHTTP3 opts one service's Host into HTTP/3. Takes effect on the
// next request via the registry reload; no-op until --listen-h3 is set.
func (h *Handler) SetServiceHTTP3(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	if err := h.db.SetServiceHTTP3(id, c.FormValue("enabled") == "1"); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if err := h.registry.Reload(h.db); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	w := c.Response()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return h.tmpls["services"].ExecuteTemplate(w, "services-rows", h.servicesRowsData(c))
}

// SetServiceBackends saves a service's backend list (one URL per line, the
// first is the primary), balancing policy and active health check. Errors
// are swapped into the tab's error box; success fires backends-saved, which
// closes the modal.
func (h *Handler) SetServiceBackends(c *echo.Context) error {
	fail := func(msg string) error {
		c.Response().Header().Set("HX-Retarget", "#svc-backends-error")
		c.Response().Header().Set("HX-Reswap", "innerHTML")
		return c.String(http.StatusOK, html.EscapeString(msg))
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return fail("invalid service id")
	}
	if h.dockerManaged(id) {
		return fail(errDockerManaged)
	}
	var backends []string
	for _, line := range strings.Split(c.FormValue("backends"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			backends = append(backends, line)
		}
	}
	healthPath := strings.TrimSpace(c.FormValue("health_path"))
	interval := 0
	if v := strings.TrimSpace(c.FormValue("health_interval")); v != "" {
		if interval, err = strconv.Atoi(v); err != nil {
			return fail("Health check interval must be a whole number of seconds.")
		}
	}
	if err := services.ValidateBackends(backends, healthPath, interval); err != nil {
		return fail(err.Error())
	}
	backendCA := strings.TrimSpace(strings.ReplaceAll(c.FormValue("backend_ca"), "\r\n", "\n"))
	if err := services.ValidateBackendCA(backendCA); err != nil {
		return fail("Trusted backend certificate: " + err.Error())
	}
	if err := h.db.SetServiceBackends(id, backends, c.FormValue("lb_policy"), healthPath, interval); err != nil {
		return fail(err.Error())
	}
	if err := h.db.SetServiceBackendCA(id, backendCA); err != nil {
		return fail(err.Error())
	}
	if err := h.registry.Reload(h.db); err != nil {
		return fail(err.Error())
	}
	c.Response().Header().Set("HX-Trigger", "backends-saved")
	return h.servicesRows(c)
}

// RenameService changes a service's name (issue #320). Rules keyed on the
// name move with it (storage.UpdateService); the per-service WAF engines are
// keyed on it too, so they are rebuilt.
func (h *Handler) RenameService(c *echo.Context) error {
	fail := func(msg string) error {
		c.Response().Header().Set("HX-Retarget", "#svc-name-error")
		c.Response().Header().Set("HX-Reswap", "innerHTML")
		return c.String(http.StatusOK, html.EscapeString(msg))
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return fail("invalid service id")
	}
	if h.dockerManaged(id) {
		return fail(errDockerManaged)
	}
	svc, err := h.db.GetService(id)
	if err != nil {
		return fail("service not found")
	}
	name := strings.TrimSpace(c.FormValue("name"))
	switch name {
	case "":
		return fail("name cannot be empty")
	case svc.Name:
		c.Response().Header().Set("HX-Trigger", "name-saved")
		return h.servicesRows(c)
	}
	for _, s := range h.registry.List() {
		if s.Name == name {
			return fail("another service is already called " + name)
		}
	}
	if err := h.db.UpdateService(id, name, svc.Host, svc.Prefix, svc.Backend); err != nil {
		return fail(err.Error())
	}
	if err := h.registry.Reload(h.db); err != nil {
		return fail(err.Error())
	}
	if h.reloadWAF != nil {
		h.reloadWAF()
	}
	c.Response().Header().Set("HX-Trigger", "name-saved")
	return h.servicesRows(c)
}

// SetServiceHosts saves a host-matched service's extra hostnames (one per
// line, e.g. www.example.com) and which name the others redirect to.
func (h *Handler) SetServiceHosts(c *echo.Context) error {
	fail := func(msg string) error {
		c.Response().Header().Set("HX-Retarget", "#svc-hosts-error")
		c.Response().Header().Set("HX-Reswap", "innerHTML")
		return c.String(http.StatusOK, html.EscapeString(msg))
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return fail("invalid service id")
	}
	if h.dockerManaged(id) {
		return fail(errDockerManaged)
	}
	svc, err := h.db.GetService(id)
	if err != nil {
		return fail("service not found")
	}
	aliases, canonical, err := services.ValidateHosts(id, svc.Host, strings.Split(c.FormValue("aliases"), "\n"), c.FormValue("canonical"), h.registry.List())
	if err != nil {
		return fail(err.Error())
	}
	if err := h.db.SetServiceHosts(id, aliases, canonical); err != nil {
		return fail(err.Error())
	}
	if err := h.registry.Reload(h.db); err != nil {
		return fail(err.Error())
	}
	c.Response().Header().Set("HX-Trigger", "hosts-saved")
	return h.servicesRows(c)
}

// aiPolicyForm reads the ai_<category> selects; anything else is dropped.
func aiPolicyForm(c *echo.Context) bot.AIPolicy {
	p := bot.AIPolicy{}
	for _, cat := range bot.AICategories {
		if a := c.FormValue("ai_" + cat); bot.ValidAIAction(a) {
			p[cat] = a
		}
	}
	return p
}

// SetServiceAICrawlers saves a service's AI crawler policy overrides
// (issue #187); a category left on inherit takes the global default.
func (h *Handler) SetServiceAICrawlers(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	if err := h.db.SetServiceAICrawlerPolicy(id, aiPolicyForm(c).String()); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if err := h.registry.Reload(h.db); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return h.servicesRows(c)
}

// SetServiceBreachCheck saves a service's leaked-password check (issue #188).
func (h *Handler) SetServiceBreachCheck(c *echo.Context) error {
	fail := func(msg string) error {
		c.Response().Header().Set("HX-Retarget", "#svc-breach-error")
		c.Response().Header().Set("HX-Reswap", "innerHTML")
		return c.String(http.StatusOK, html.EscapeString(msg))
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return fail("invalid service id")
	}
	action := c.FormValue("breach_action")
	if action != "" && action != "log" && action != "block" {
		return fail("Unknown action.")
	}
	var fields []string
	for _, f := range strings.Fields(strings.ReplaceAll(c.FormValue("breach_fields"), ",", " ")) {
		if len(f) > 64 {
			return fail("Field names are at most 64 characters.")
		}
		if !slices.Contains(fields, f) {
			fields = append(fields, f)
		}
	}
	if len(fields) > 10 {
		return fail("At most 10 field names.")
	}
	if err := h.db.SetServiceBreachCheck(id, action, fields); err != nil {
		return fail(err.Error())
	}
	if err := h.registry.Reload(h.db); err != nil {
		return fail(err.Error())
	}
	c.Response().Header().Set("HX-Trigger", "breach-saved")
	return h.servicesRows(c)
}

// loginPathsMax caps a service's login protection list.
const loginPathsMax = 20

// SetServiceLoginPaths saves the paths that get the login protection preset
// (issue #132). An empty list turns it off.
func (h *Handler) SetServiceLoginPaths(c *echo.Context) error {
	fail := func(msg string) error {
		c.Response().Header().Set("HX-Retarget", "#svc-login-error")
		c.Response().Header().Set("HX-Reswap", "innerHTML")
		return c.String(http.StatusOK, html.EscapeString(msg))
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return fail("invalid service id")
	}
	var paths []string
	for _, p := range strings.Fields(c.FormValue("login_paths")) {
		if !strings.HasPrefix(p, "/") || p == "/" {
			return fail(fmt.Sprintf("%q is not a path: start it with / and name the login page, e.g. /login.", p))
		}
		if !slices.Contains(paths, p) {
			paths = append(paths, p)
		}
	}
	if len(paths) > loginPathsMax {
		return fail(fmt.Sprintf("At most %d login paths.", loginPathsMax))
	}
	if err := h.db.SetServiceLoginPaths(id, paths); err != nil {
		return fail(err.Error())
	}
	if err := h.registry.Reload(h.db); err != nil {
		return fail(err.Error())
	}
	c.Response().Header().Set("HX-Trigger", "login-saved")
	return h.servicesRows(c)
}

// SetServiceCompress turns response compression on or off for one service.
func (h *Handler) SetServiceCompress(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	if err := h.db.SetServiceCompress(id, c.FormValue("enabled") == "1"); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if err := h.registry.Reload(h.db); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	w := c.Response()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return h.tmpls["services"].ExecuteTemplate(w, "services-rows", h.servicesRowsData(c))
}

// SetServiceSchema attaches (or clears) a JSON Schema used to validate this
// service's JSON request bodies (issue #75). mode "off" (or an empty schema)
// disables validation, "log" records violations without blocking, "enforce"
// rejects a mismatching body with 400 — see waf.Engine.SetRequestSchema. A
// malformed schema is rejected here, before it ever reaches the DB, so a bad
// save can't later break a WAF reload.
func (h *Handler) SetServiceSchema(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	schemaJSON := strings.TrimSpace(c.FormValue("schema"))
	mode := c.FormValue("mode")
	if mode != "log" && mode != "enforce" {
		mode = "off"
	}
	if schemaJSON != "" && mode != "off" {
		if err := waf.ValidateSchema(schemaJSON); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON Schema: " + err.Error()})
		}
	}
	if err := h.db.SetServiceSchema(id, schemaJSON, mode); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if err := h.registry.Reload(h.db); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if h.reloadWAF != nil {
		h.reloadWAF()
	}
	w := c.Response()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return h.tmpls["services"].ExecuteTemplate(w, "services-rows", h.servicesRowsData(c))
}

// openAPIMaxBytes caps an uploaded OpenAPI document.
const openAPIMaxBytes = 2 << 20

// ServiceOpenAPI returns a service's stored OpenAPI spec as plain text, for
// the edit modal.
func (h *Handler) ServiceOpenAPI(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	o, err := h.db.GetServiceOpenAPI(id)
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}
	return c.String(http.StatusOK, o.Spec)
}

// SetServiceOpenAPI uploads, replaces or removes a service's OpenAPI spec
// (issue #190): a positive security model where only declared operations
// reach the backend. See waf.Engine.SetOpenAPI.
func (h *Handler) SetServiceOpenAPI(c *echo.Context) error {
	fail := func(msg string) error {
		c.Response().Header().Set("HX-Retarget", "#svc-openapi-error")
		c.Response().Header().Set("HX-Reswap", "innerHTML")
		return c.String(http.StatusOK, html.EscapeString(msg))
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return fail("invalid service id")
	}
	spec := strings.TrimSpace(c.FormValue("openapi_spec"))
	mode := c.FormValue("openapi_mode")
	if mode != "log" && mode != "enforce" {
		mode = "off"
	}
	if len(spec) > openAPIMaxBytes {
		return fail("The spec is larger than 2 MiB.")
	}
	if spec != "" {
		if err := waf.ValidateOpenAPI(spec); err != nil {
			return fail("Invalid OpenAPI spec: " + err.Error())
		}
	}
	if err := h.db.SetServiceOpenAPI(id, spec, mode); err != nil {
		return fail(err.Error())
	}
	if h.reloadWAF != nil {
		h.reloadWAF()
	}
	c.Response().Header().Set("HX-Trigger", "openapi-saved")
	return h.servicesRows(c)
}

// SetServiceMCP saves a service's MCP endpoint guard (issue #234). See
// waf.Engine.SetMCP.
func (h *Handler) SetServiceMCP(c *echo.Context) error {
	fail := func(msg string) error {
		c.Response().Header().Set("HX-Retarget", "#svc-mcp-error")
		c.Response().Header().Set("HX-Reswap", "innerHTML")
		return c.String(http.StatusOK, html.EscapeString(msg))
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return fail("invalid service id")
	}
	m := storage.ServiceMCP{
		Mode:    c.FormValue("mcp_mode"),
		Path:    strings.TrimSpace(c.FormValue("mcp_path")),
		Origins: strings.Join(strings.Fields(c.FormValue("mcp_origins")), "\n"),
		Methods: strings.Join(strings.Fields(c.FormValue("mcp_methods")), "\n"),
		Tools:   strings.Join(strings.Fields(c.FormValue("mcp_tools")), "\n"),
	}
	if m.Mode == "log" || m.Mode == "enforce" {
		if !strings.HasPrefix(m.Path, "/") {
			return fail("The endpoint path must start with /.")
		}
		for _, o := range strings.Fields(m.Origins) {
			if u, err := neturl.Parse(o); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.TrimSuffix(u.Path, "/") != "" || u.RawQuery != "" || u.User != nil {
				return fail("Origin " + o + " must look like https://app.example.com.")
			}
		}
	}
	if err := h.db.SetServiceMCP(id, m); err != nil {
		return fail(err.Error())
	}
	if h.reloadWAF != nil {
		h.reloadWAF()
	}
	c.Response().Header().Set("HX-Trigger", "mcp-saved")
	return h.servicesRows(c)
}

// SetServiceJWT saves a service's edge JWT check (issue #279). See
// jwtauth.Verifier.
func (h *Handler) SetServiceJWT(c *echo.Context) error {
	fail := func(msg string) error {
		c.Response().Header().Set("HX-Retarget", "#svc-jwt-error")
		c.Response().Header().Set("HX-Reswap", "innerHTML")
		return c.String(http.StatusOK, html.EscapeString(msg))
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return fail("invalid service id")
	}
	j := storage.ServiceJWT{
		Mode:       c.FormValue("jwt_mode"),
		JWKSURL:    strings.TrimSpace(c.FormValue("jwt_jwks_url")),
		PublicKey:  strings.TrimSpace(c.FormValue("jwt_public_key")),
		Issuer:     strings.TrimSpace(c.FormValue("jwt_issuer")),
		Audience:   strings.TrimSpace(c.FormValue("jwt_audience")),
		Algorithms: strings.Join(strings.Fields(c.FormValue("jwt_algorithms")), " "),
		Prefixes:   strings.Join(strings.Fields(c.FormValue("jwt_prefixes")), "\n"),
	}
	if j.Mode == "log" || j.Mode == "enforce" {
		if _, err := jwtauth.New(services.JWTConfig(j)); err != nil {
			return fail(err.Error())
		}
	}
	if err := h.db.SetServiceJWT(id, j); err != nil {
		return fail(err.Error())
	}
	if err := h.registry.Reload(h.db); err != nil {
		return fail(err.Error())
	}
	c.Response().Header().Set("HX-Trigger", "jwt-saved")
	return h.servicesRows(c)
}

// defaultCSP reports every script not served from the page's own origin.
const defaultCSP = "script-src 'self'"

// SetServiceCSP saves a service's report-only CSP (issue #235). The report
// directives are appended by services.Registry, so the policy can't carry
// its own.
func (h *Handler) SetServiceCSP(c *echo.Context) error {
	fail := func(msg string) error {
		c.Response().Header().Set("HX-Retarget", "#svc-csp-error")
		c.Response().Header().Set("HX-Reswap", "innerHTML")
		return c.String(http.StatusOK, html.EscapeString(msg))
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return fail("invalid service id")
	}
	policy := ""
	mode := c.FormValue("csp_mode")
	if mode == "report" || mode == "enforce" {
		policy = strings.Join(strings.Fields(c.FormValue("csp_policy")), " ")
		if policy == "" {
			policy = defaultCSP
		}
		lower := strings.ToLower(policy)
		switch {
		case len(policy) > 4096:
			return fail("The policy is too long (4096 characters max).")
		case strings.Contains(lower, "report-uri") || strings.Contains(lower, "report-to"):
			return fail("Leave out report-uri and report-to; Palisade adds them.")
		case strings.IndexFunc(policy, func(r rune) bool { return r < 0x20 || r > 0x7e }) >= 0:
			return fail("The policy may only contain printable ASCII.")
		}
		policy = strings.TrimSuffix(policy, ";")
	}
	// Approvals (issue #283) must name entries of this service's inventory.
	var approved []string
	if policy == "" { // off keeps approvals, like the inventory
		cur, err := h.db.ListCSPEnforcement()
		if err != nil {
			return fail(err.Error())
		}
		approved = cur[id].Approved
	} else {
		all, err := h.db.ListCSPScripts()
		if err != nil {
			return fail(err.Error())
		}
		for _, o := range c.Request().PostForm["csp_approved"] {
			if slices.ContainsFunc(all[id], func(s storage.CSPScript) bool { return s.Origin == o }) && !slices.Contains(approved, o) {
				approved = append(approved, o)
			}
		}
	}
	if err := h.db.SetServiceCSP(id, policy); err != nil {
		return fail(err.Error())
	}
	if err := h.db.SetCSPEnforcement(id, storage.CSPEnforcement{Enforce: mode == "enforce", Approved: approved}); err != nil {
		return fail(err.Error())
	}
	if err := h.registry.Reload(h.db); err != nil {
		return fail(err.Error())
	}
	c.Response().Header().Set("HX-Trigger", "csp-saved")
	return h.servicesRows(c)
}

// cookieName matches an RFC 6265 cookie name (a token).
var cookieName = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")

// SetServiceCookies turns Set-Cookie hardening on or off for a service
// (issue #281), with the cookie names to leave alone.
func (h *Handler) SetServiceCookies(c *echo.Context) error {
	fail := func(msg string) error {
		c.Response().Header().Set("HX-Retarget", "#svc-cookies-error")
		c.Response().Header().Set("HX-Reswap", "innerHTML")
		return c.String(http.StatusOK, html.EscapeString(msg))
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return fail("invalid service id")
	}
	exempt := splitList(c.FormValue("cookie_exempt"))
	if len(exempt) > 50 {
		return fail("At most 50 cookie names.")
	}
	for _, n := range exempt {
		if len(n) > 128 || !cookieName.MatchString(n) {
			return fail("Not a cookie name: " + n)
		}
	}
	if err := h.db.SetServiceCookiePolicy(id, c.FormValue("cookie_mode") == "on", exempt); err != nil {
		return fail(err.Error())
	}
	if err := h.registry.Reload(h.db); err != nil {
		return fail(err.Error())
	}
	c.Response().Header().Set("HX-Trigger", "cookies-saved")
	return h.servicesRows(c)
}

var (
	methodToken = regexp.MustCompile(`^[A-Z]{1,20}$`)
	mediaType   = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]*/([a-z0-9][a-z0-9!#$&^_.+-]*|\*)$`)
)

// splitList splits a form list on commas and whitespace.
func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' })
}

// SetServiceRequestPolicy saves the methods, Content-Types and body size a
// service accepts (issue #282). The presets only fill the form, in JS.
func (h *Handler) SetServiceRequestPolicy(c *echo.Context) error {
	fail := func(msg string) error {
		c.Response().Header().Set("HX-Retarget", "#svc-policy-error")
		c.Response().Header().Set("HX-Reswap", "innerHTML")
		return c.String(http.StatusOK, html.EscapeString(msg))
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return fail("invalid service id")
	}
	p := storage.RequestPolicy{Mode: c.FormValue("policy_mode")}
	switch p.Mode {
	case "off":
		p.Mode = ""
	case "log", "enforce":
		for _, m := range splitList(strings.ToUpper(c.FormValue("policy_methods"))) {
			if !methodToken.MatchString(m) {
				return fail("Not an HTTP method: " + m)
			}
			p.Methods = append(p.Methods, m)
		}
		for _, t := range splitList(strings.ToLower(c.FormValue("policy_types"))) {
			if len(t) > 127 || !mediaType.MatchString(t) {
				return fail("Not a media type: " + t)
			}
			p.ContentTypes = append(p.ContentTypes, t)
		}
		if len(p.Methods) > 20 || len(p.ContentTypes) > 30 {
			return fail("At most 20 methods and 30 content types.")
		}
		if s := strings.TrimSpace(c.FormValue("policy_max_kib")); s != "" {
			if p.MaxBodyKiB, err = strconv.Atoi(s); err != nil || p.MaxBodyKiB < 0 || p.MaxBodyKiB > 1<<20 {
				return fail("Maximum body size must be 0 to 1048576 KiB (1 GiB).")
			}
		}
		if len(p.Methods) == 0 && len(p.ContentTypes) == 0 && p.MaxBodyKiB == 0 {
			return fail("Set methods, content types or a body size, or turn the policy off.")
		}
	default:
		return fail("invalid mode")
	}
	if err := h.db.SetServiceRequestPolicy(id, p); err != nil {
		return fail(err.Error())
	}
	if err := h.registry.Reload(h.db); err != nil {
		return fail(err.Error())
	}
	c.Response().Header().Set("HX-Trigger", "policy-saved")
	return h.servicesRows(c)
}

// SetServiceMTLS saves a service's client-certificate policy (issue #191).
// An empty CA field keeps the stored bundle; "off" keeps it for later.
func (h *Handler) SetServiceMTLS(c *echo.Context) error {
	fail := func(msg string) error {
		c.Response().Header().Set("HX-Retarget", "#svc-mtls-error")
		c.Response().Header().Set("HX-Reswap", "innerHTML")
		return c.String(http.StatusOK, html.EscapeString(msg))
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return fail("invalid service id")
	}
	svc, err := h.db.GetService(id)
	if err != nil {
		return fail("service not found")
	}
	if svc.Host == "" {
		return fail("Client certificates need a host-matched service (this one matches by path prefix).")
	}
	all, err := h.db.ListServiceMTLS()
	if err != nil {
		return fail(err.Error())
	}
	m := all[id]
	m.Mode = c.FormValue("mtls_mode")
	m.Allow = strings.Join(strings.Fields(c.FormValue("mtls_allow")), "\n")
	if len(m.Allow) > 64<<10 {
		return fail("The allowlist is larger than 64 KiB.")
	}
	if caPEM := strings.TrimSpace(c.FormValue("mtls_ca")); caPEM != "" {
		if m.CAPath, err = services.SaveClientCA(svc.ID, []byte(caPEM+"\n")); err != nil {
			return fail(err.Error())
		}
	}
	if m.CAPath == "" {
		if m.Mode != "optional" && m.Mode != "required" {
			c.Response().Header().Set("HX-Trigger", "mtls-saved")
			return h.servicesRows(c)
		}
		return fail("Paste the CA certificate(s) that issue your client certificates.")
	}
	if err := h.db.SetServiceMTLS(id, m); err != nil {
		return fail(err.Error())
	}
	if err := h.registry.Reload(h.db); err != nil {
		return fail(err.Error())
	}
	c.Response().Header().Set("HX-Trigger", "mtls-saved")
	return h.servicesRows(c)
}

// SetServiceResponseInspect sets a service's response inspection mode
// (issue #192): "" off, "log" or "block".
func (h *Handler) SetServiceResponseInspect(c *echo.Context) error {
	fail := func(msg string) error {
		c.Response().Header().Set("HX-Retarget", "#svc-responses-error")
		c.Response().Header().Set("HX-Reswap", "innerHTML")
		return c.String(http.StatusOK, html.EscapeString(msg))
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return fail("invalid service id")
	}
	mode := c.FormValue("response_inspect")
	if mode != "" && mode != "log" && mode != "block" {
		return fail("Unknown mode.")
	}
	if err := h.db.SetServiceResponseInspect(id, mode); err != nil {
		return fail(err.Error())
	}
	if err := h.registry.Reload(h.db); err != nil {
		return fail(err.Error())
	}
	c.Response().Header().Set("HX-Trigger", "responses-saved")
	return h.servicesRows(c)
}

// SetServiceCache toggles routing one service's clean traffic through the
// local Varnish cache and rebuilds the registry so it applies immediately.
func (h *Handler) SetServiceCache(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	enabled := c.FormValue("enabled") == "1"
	if err := h.db.SetServiceCache(id, enabled); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if err := h.registry.Reload(h.db); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	w := c.Response()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return h.tmpls["services"].ExecuteTemplate(w, "services-rows", h.servicesRowsData(c))
}

// SetServiceCacheSession configures opt-in session-aware Varnish caching for
// one service: cached objects are partitioned by the named session cookie's
// value instead of Varnish refusing to cache any cookie-bearing request.
// Requires both the checkbox and a non-empty cookie name to take effect.
func (h *Handler) SetServiceCacheSession(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	enabled := c.FormValue("session_enabled") == "1"
	cookieName := strings.TrimSpace(c.FormValue("session_cookie_name"))
	if enabled && cookieName == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "session cookie name is required"})
	}
	if err := h.db.SetServiceCacheSession(id, enabled, cookieName); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if err := h.registry.Reload(h.db); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	w := c.Response()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return h.tmpls["services"].ExecuteTemplate(w, "services-rows", h.servicesRowsData(c))
}

// parseOptionalSeconds parses a form field as a non-negative whole number of
// seconds, treating a blank value as 0 ("unset" for cache-tuning fields).
func parseOptionalSeconds(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("must be a non-negative whole number of seconds")
	}
	return n, nil
}

// SetServiceCacheTuning configures per-service Varnish TTL floor/ceiling and
// grace/keep overrides. Each field is optional seconds; blank means "use the
// VCL's own default" (see deploy/varnish/default.vcl's vcl_backend_response).
func (h *Handler) SetServiceCacheTuning(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	ttlFloor, err := parseOptionalSeconds(c.FormValue("ttl_floor"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "TTL floor " + err.Error()})
	}
	ttlCeiling, err := parseOptionalSeconds(c.FormValue("ttl_ceiling"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "TTL ceiling " + err.Error()})
	}
	grace, err := parseOptionalSeconds(c.FormValue("grace"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "grace " + err.Error()})
	}
	keep, err := parseOptionalSeconds(c.FormValue("keep"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "keep " + err.Error()})
	}
	if ttlCeiling > 0 && ttlFloor > ttlCeiling {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "TTL floor cannot be greater than the ceiling"})
	}
	rules := strings.TrimSpace(strings.ReplaceAll(c.FormValue("cache_rules"), "\r\n", "\n"))
	if _, err := services.ParseCacheRules(rules); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "cache rules " + err.Error()})
	}
	if err := h.db.SetServiceCacheTuning(id, ttlFloor, ttlCeiling, grace, keep, rules); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if err := h.registry.Reload(h.db); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	w := c.Response()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return h.tmpls["services"].ExecuteTemplate(w, "services-rows", h.servicesRowsData(c))
}

// PurgeServiceCache invalidates the objects Varnish holds for one service —
// all of them, or only those under the optional "path" prefix (e.g. /blog/
// after a content deploy). Returns a small
// status fragment rather than the services list, since purging doesn't
// change any row's displayed state.
func (h *Handler) PurgeServiceCache(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return c.HTML(http.StatusOK, `<span class="text-red-600">invalid service id</span>`)
	}
	svc, err := h.db.GetService(id)
	if err != nil {
		return c.HTML(http.StatusOK, `<span class="text-red-600">service not found</span>`)
	}
	vcfg, err := h.db.GetVarnishConfig()
	if err != nil {
		return c.HTML(http.StatusOK, `<span class="text-red-600">`+html.EscapeString(err.Error())+`</span>`)
	}
	path := strings.TrimSpace(c.FormValue("path"))
	if err := services.Purge(vcfg, svc, path); err != nil {
		return c.HTML(http.StatusOK, `<span class="text-red-600">`+html.EscapeString(err.Error())+`</span>`)
	}
	if path != "" {
		return c.HTML(http.StatusOK, `<span class="text-green-600">Purged `+html.EscapeString(path)+`*.</span>`)
	}
	return c.HTML(http.StatusOK, `<span class="text-green-600">Purged.</span>`)
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

// ServicesCacheStats renders the Services page's "Cache performance" card:
// Varnish-wide counters from varnishstat (best-effort — an error is shown,
// not fatal) plus per-service hit ratios from the request log's
// cache_status, which varnishstat can't split by service.
func (h *Handler) ServicesCacheStats(c *echo.Context) error {
	vcfg, err := h.db.GetVarnishConfig()
	if err != nil {
		return err
	}
	data := map[string]any{"AdminPath": h.cfg.Admin.Path, "Enabled": vcfg.Enabled}
	if !vcfg.Enabled {
		return h.renderPartial(c, "services", "cache-stats", data)
	}
	if st, err := services.ReadVarnishStats(c.Request().Context()); err != nil {
		data["StatsErr"] = err.Error()
	} else {
		data["Stats"] = map[string]any{
			"Ratio":   cacheRatio(st.Hits, st.Misses),
			"Objects": st.Objects,
			"Used":    fmtMiB(st.BytesUsed),
			"Total":   fmtMiB(st.BytesUsed + st.BytesFree),
			"Evicted": st.Evicted,
		}
	}
	results, err := h.db.CacheResultsSince(time.Now().Add(-24 * time.Hour))
	if err != nil {
		return err
	}
	rows := make([]map[string]any, 0, len(results))
	for _, r := range results {
		rows = append(rows, map[string]any{
			"App": r.App, "Hits": r.Hits, "Misses": r.Misses, "Passes": r.Passes, "Errors": r.Errors,
			"Ratio": cacheRatio(uint64(r.Hits), uint64(r.Misses)), //nolint:gosec // G115: varnishstat counters are never negative
		})
	}
	data["Services"] = rows
	return h.renderPartial(c, "services", "cache-stats", data)
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
