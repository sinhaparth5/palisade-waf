package ui

import (
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

// SetServiceLargeJSUploads opts one service into streaming JavaScript request
// bodies. This avoids the small, deliberately conservative limit applied to
// non-file bodies while leaving all header-phase WAF checks active.
func (h *Handler) SetServiceLargeJSUploads(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	enabled := c.FormValue("enabled") == "1"
	if err := h.db.SetServiceLargeJSUploads(id, enabled); err != nil {
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
		if m.CAPath, err = services.SaveClientCA(svc.Name, []byte(caPEM+"\n")); err != nil {
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
