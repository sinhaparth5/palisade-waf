package ui

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"palisade/internal/config"
	"palisade/internal/notify/metrics"
	"palisade/internal/proxy"
	"palisade/internal/security/blocklist"
	"palisade/internal/security/bot"
	"palisade/internal/security/breach"
	"palisade/internal/security/challenge"
	"palisade/internal/security/geo"
	"palisade/internal/security/passkey"
	"palisade/internal/security/threatscore"
	"palisade/internal/services"
	"palisade/internal/storage"
	"slices"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

//go:embed templates
var templateFS embed.FS

// vendorFS holds the third-party admin assets (htmx, Chart.js, fonts, icons,
// flags), served from the binary so the admin CSP can be 'self' only and the
// UI works air-gapped (issue #195). See THIRD_PARTY_NOTICES.md.
//
//go:embed vendor
var vendorFS embed.FS

// adminCSP is the Content-Security-Policy on every admin response (issue
// #195). No inline script or style and no external origin: an XSS in a
// rendered log row can't run script with the admin's session.
const adminCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// setCSP adds adminCSP. It runs after hostGuard, so admin paths proxied
// for a service host keep the backend's own headers.
func setCSP(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		c.Response().Header().Set("Content-Security-Policy", adminCSP)
		return next(c)
	}
}

var funcs = template.FuncMap{
	// can reports whether role may use routes declared for need, by the
	// same order requireRole enforces (issue #216): {{if can $.Role "admin"}}.
	// A missing role (nil) has no rank, so it gets read-only markup.
	"can": func(role any, need string) bool {
		r, _ := role.(string)
		return roleRank[r] >= roleRank[need]
	},
	"flagClass":   func(code string) string { return "fi fi-" + strings.ToLower(code) },
	"fmtTime":     func(t time.Time) string { return t.Format("02 Jan 15:04:05") },
	"fmtTimeFull": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") },
	"fmtDur":      func(ms int64) string { return fmt.Sprintf("%dms", ms) },
	"fmtLastUsed": func(t *time.Time) string {
		if t == nil {
			return "Never"
		}
		return t.Format("02 Jan 15:04:05")
	},
	"today": func() string { return time.Now().Format("2 January 2006") },
	// truncate counts runes, not bytes: slicing bytes could cut a multi-byte
	// character in half and render U+FFFD.
	"truncate": func(s string, n int) string {
		r := []rune(s)
		if len(r) <= n {
			return s
		}
		return string(r[:n]) + "…"
	},
	"shortDate": func(s string) string {
		if len(s) < 10 {
			return s
		}
		return s[:10]
	},
	"add":      func(a, b int) int { return a + b },
	"sub":      func(a, b int) int { return a - b },
	"isOdd":    func(i int) bool { return i%2 == 1 },
	"contains": strings.Contains,
	"aiPolicy": bot.ParseAIPolicy,
	"join":     strings.Join,
	"has":      slices.Contains[[]string, string],
	"splitComma": func(s string) []string {
		var out []string
		for _, p := range strings.Split(s, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	},
	"map": func(pairs ...any) (map[string]any, error) {
		if len(pairs)%2 != 0 {
			return nil, fmt.Errorf("map: odd number of args")
		}
		m := make(map[string]any, len(pairs)/2)
		for i := 0; i < len(pairs); i += 2 {
			k, ok := pairs[i].(string)
			if !ok {
				return nil, fmt.Errorf("map: key must be string")
			}
			m[k] = pairs[i+1]
		}
		return m, nil
	},
}

// Handler holds all UI dependencies.
type Handler struct {
	cfg             *config.Config
	db              *storage.DB
	ipbl            *blocklist.IPBlocklist
	geoBl           *geo.Blocker
	registry        *services.Registry
	broadcaster     *LogBroadcaster
	tmpls           map[string]*template.Template
	sections        []section // page cards for the top bar search, see search.go
	staticJS        fs.FS
	staticCSS       fs.FS
	assetVer        string // cache-busting stamp for the embedded CSS/JS URLs
	staticImgs      fs.FS
	reloadBot       func(*challenge.Challenger)
	buildChallenger func(enabled bool, threshold, ttl int) *challenge.Challenger
	reloadRateLimit func()
	reloadWAF       func()
	syncThreatIntel func(id int64)
	sendReportNow   func() error
	sendTestWebhook func() error
	sendLoginCode   func(code string) error
	sendInvite      func(to, inviter, role, link string) error
	reloadAutoban   func()
	reloadAdaptive  func()
	scorer          *threatscore.Scorer
	loginLimiter    *loginLimiter
	apiKeyLimiter   *loginLimiter
	twoFA           *twoFAStore
	passkeys        *passkey.Manager
	pkEnroll        *pkEnrollStore
	pwBreach        *breach.Checker // HIBP lookup for new admin passwords
	trustedNets     []*net.IPNet
	adminAllow      []*net.IPNet // --admin-allow; empty = any client
	proxyHandle     echo.HandlerFunc
	accountLimiter  *loginLimiter     // per-account login throttle, next to the per-IP loginLimiter
	routeRoles      map[string]string // "METHOD /admin/path" → minimum role, filled by Register
}

// NewHandler builds the UI handler. jsFS must contain the minified JS
// assets at "static/js/dist/*" (see assets.go in the repo root); it's
// served under /<admin_path>/static/js/. cssFS must contain the compiled
// Tailwind stylesheet at "static/css/dist/*" (built by `make css`, committed,
// embedded — no CDN); it's served under /<admin_path>/static/css/. imgsFS
// must contain "static/imgs/*"; it's served under /<admin_path>/static/imgs/.
// proxyHandle is the reverse-proxy pipeline's own route handler
// (proxy.Handler.Handle, the same func registered for the catch-all "/*"
// route in internal/app); see hostGuard for why the admin/API routes need to be
// able to hand a request off to it.
func NewHandler(cfg *config.Config, db *storage.DB, ipbl *blocklist.IPBlocklist, geoBl *geo.Blocker, registry *services.Registry, bc *LogBroadcaster, jsFS embed.FS, cssFS embed.FS, imgsFS embed.FS, reloadBot func(*challenge.Challenger), buildChallenger func(bool, int, int) *challenge.Challenger, reloadRateLimit func(), reloadWAF func(), syncThreatIntel func(int64), sendReportNow func() error, sendTestWebhook func() error, sendLoginCode func(string) error, sendInvite func(to, inviter, role, link string) error, reloadAutoban func(), scorer *threatscore.Scorer, reloadAdaptive func(), proxyHandle echo.HandlerFunc) (*Handler, error) {
	sub, err := fs.Sub(jsFS, "static/js/dist")
	if err != nil {
		return nil, fmt.Errorf("sub static/js/dist: %w", err)
	}
	cssSub, err := fs.Sub(cssFS, "static/css/dist")
	if err != nil {
		return nil, fmt.Errorf("sub static/css/dist: %w", err)
	}
	imgsSub, err := fs.Sub(imgsFS, "static/imgs")
	if err != nil {
		return nil, fmt.Errorf("sub static/imgs: %w", err)
	}

	// Embedded assets only change with the binary, and StaticFS sends no
	// validators, so the ?v= stamp is what moves browsers to a new build.
	assetVer := assetStamp(sub, cssSub, imgsSub, vendorFS)
	h := &Handler{cfg: cfg, db: db, ipbl: ipbl, geoBl: geoBl, registry: registry, broadcaster: bc, staticJS: sub, staticCSS: cssSub, staticImgs: imgsSub, assetVer: assetVer, reloadBot: reloadBot, buildChallenger: buildChallenger, reloadRateLimit: reloadRateLimit, reloadWAF: reloadWAF, syncThreatIntel: syncThreatIntel, sendReportNow: sendReportNow, sendTestWebhook: sendTestWebhook, sendLoginCode: sendLoginCode, sendInvite: sendInvite, reloadAutoban: reloadAutoban, scorer: scorer, reloadAdaptive: reloadAdaptive, loginLimiter: newLoginLimiter(), accountLimiter: newLoginLimiter(), apiKeyLimiter: newLoginLimiter(), twoFA: newTwoFAStore(), passkeys: passkey.New(db), pkEnroll: newPkEnrollStore(), pwBreach: breach.New(""), trustedNets: proxy.ParseTrustedProxyCIDRs(cfg.TrustedProxies), adminAllow: proxy.ParseTrustedProxyCIDRs(cfg.Admin.Allow), proxyHandle: proxyHandle}
	if err := h.parseTemplates(); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *Handler) parseTemplates() error {
	// Standalone login page, doesn't use base.html.
	login, err := template.New("login").Funcs(funcs).ParseFS(templateFS, "templates/login.html")
	if err != nil {
		return fmt.Errorf("parse template login: %w", err)
	}

	h.tmpls = make(map[string]*template.Template, len(adminPages)+1)
	h.tmpls["login"] = login
	for _, page := range adminPages {
		t, err := template.New("").Funcs(funcs).ParseFS(templateFS,
			"templates/components/*.html",
			"templates/log_row.html",
			"templates/base.html",
			"templates/"+page+".html",
		)
		if err != nil {
			return fmt.Errorf("parse template %s: %w", page, err)
		}
		h.tmpls[page] = t
	}
	// log-row partial used by the SSE stream handler
	t, err := template.New("log-row").Funcs(funcs).ParseFS(templateFS, "templates/log_row.html")
	if err != nil {
		return fmt.Errorf("parse log-row: %w", err)
	}
	h.tmpls["log-row"] = t

	// notifications partial used by the bell dropdown
	notif, err := template.New("notifications-panel").Funcs(funcs).ParseFS(templateFS, "templates/notifications.html")
	if err != nil {
		return fmt.Errorf("parse notifications: %w", err)
	}
	h.tmpls["notifications"] = notif
	// Before any Execute: html/template rewrites the trees on first use.
	h.sections = h.searchSections()
	return nil
}

const sessionCookie = "cz_session"

// sessionAuth is the session-cookie middleware that guards every admin route.
// Unauthenticated requests are redirected to the login page.
func (h *Handler) sessionAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		login := h.cfg.Admin.Path + "/login"
		cookie, err := c.Cookie(sessionCookie)
		if err != nil || cookie.Value == "" {
			return c.Redirect(http.StatusFound, login)
		}
		sess, err := h.db.GetSession(cookie.Value)
		if err != nil || sess == nil {
			return c.Redirect(http.StatusFound, login)
		}
		if !sess.Live() {
			// Say which of the two happened. A revoked session means
			// someone logged in elsewhere (or revoked this device from the
			// Settings page); an expired one is just the 24h TTL.
			if sess.Revoked() {
				return c.Redirect(http.StatusFound, login+"?reason=revoked")
			}
			return c.Redirect(http.StatusFound, login)
		}
		// A disabled user's sessions are revoked when they're disabled;
		// checking here too keeps a stale row from ever authenticating.
		u, err := h.db.GetAdminUser(sess.UserID)
		if err != nil {
			return c.Redirect(http.StatusFound, login)
		}
		if u == nil || u.Disabled {
			// Drop the row too: LoginPage would otherwise see a live
			// session and bounce straight back here.
			h.db.DeleteSession(sess.ID) //nolint — best effort, it can't authenticate either way
			return c.Redirect(http.StatusFound, login)
		}
		c.Set(ctxUser, u)
		// Record last-seen off the hot path, throttled like TouchAPIKey so
		// a busy dashboard doesn't write on every request.
		if time.Since(sess.LastActiveAt) > sessionTouchThrottle {
			id := sess.ID
			h.db.Go(func() {
				if err := h.db.TouchSession(id); err != nil {
					log.Printf("session touch: %v", err)
				}
			})
		}
		return next(c)
	}
}

// sessionTouchThrottle bounds how often a session's last-active timestamp is
// rewritten, mirroring apiKeyTouchThrottle.
const sessionTouchThrottle = time.Minute

// hostGuard keeps the admin dashboard and REST API from being reachable on
// a service's own domain. Echo routes purely by path and knows nothing
// about Host, so without this check "https://example-api.com/admin/login"
// would serve the WAF's own login page whenever example-api.com's DNS
// points at this server, even though it's configured as an unrelated
// proxied service. Any request whose Host matches a configured service is
// handed to the reverse-proxy pipeline instead (registry.IsServiceHost),
// where it gets routed, WAF-checked, rate-limited, and logged like any
// other request to that service, landing on the real backend's own
// /admin/login if it has one. The admin UI and API stay reachable on any
// Host nothing else claims, e.g. this server's bare listen IP.
//
// It also enforces --admin-allow and --admin-listen (issue #271). A request
// those rule out goes to the proxy pipeline too, so the admin UI looks like
// it isn't there: an unmatched host gets a logged 404 that autoban counts.
func (h *Handler) hostGuard(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		r := c.Request()
		if r.Context().Value(adminListenerKey{}) != nil {
			// The admin listener never proxies.
			if !h.adminAllowed(r) {
				return echo.ErrNotFound
			}
			return next(c)
		}
		if h.cfg.Admin.Listen != "" || !h.adminAllowed(r) || h.registry.IsServiceHost(r.Host) {
			return h.proxyHandle(c)
		}
		return next(c)
	}
}

// adminAllowed applies --admin-allow to the resolved client IP.
func (h *Handler) adminAllowed(r *http.Request) bool {
	if len(h.adminAllow) == 0 {
		return true
	}
	ip := net.ParseIP(h.clientIP(r))
	for _, n := range h.adminAllow {
		if ip != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

type adminListenerKey struct{}

// AdminListener wraps the Echo handler for the --admin-listen server: it
// marks requests as arriving there and serves nothing outside the admin path.
func AdminListener(base string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != base && !strings.HasPrefix(r.URL.Path, base+"/") {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), adminListenerKey{}, true)))
	})
}

// Register mounts all admin routes on e under cfg.Admin.Path.
// Login/logout are public; everything else is behind sessionAuth.
func (h *Handler) Register(e *echo.Echo) {
	base := h.cfg.Admin.Path

	// Cap request bodies before anything reads them: the WAF's
	// SecRequestBodyLimit only covers proxied traffic, never these routes,
	// and LoginPost is reachable unauthenticated. 1 MiB is far above any
	// admin form or PEM chain upload, and Echo returns 413 without buffering
	// past the cap.
	bodyLimit := middleware.BodyLimit(1 << 20)

	// admin is the parent group for every route under cfg.Admin.Path.
	// hostGuard runs first for all of them, public or not; see hostGuard.
	admin := e.Group(base)
	admin.Use(h.hostGuard, setCSP)

	// Public routes, no session required.
	admin.GET("/login", h.LoginPage)
	admin.POST("/login", h.LoginPost, bodyLimit)
	// Second login step when 2FA is on: code entry + emailed recovery code.
	admin.POST("/login/totp", h.LoginTOTPPost, bodyLimit)
	admin.POST("/login/totp/email", h.LoginTOTPEmail, bodyLimit)
	// Passkey alternative to the code form above, same pending-login stage.
	admin.POST("/login/webauthn/begin", h.BeginPasskeyLogin, bodyLimit)
	admin.POST("/login/webauthn/finish", h.FinishPasskeyLogin, bodyLimit)
	// OIDC single sign-on: redirect to the IdP, and its redirect back.
	admin.GET("/login/sso", h.SSOStart)
	admin.GET("/login/sso/callback", h.SSOCallback)
	// Set-password page from an invite email (issue #229).
	admin.GET("/invite/:token", h.InvitePage)
	admin.POST("/invite/:token", h.InvitePost, bodyLimit)
	// Static assets are public so the login page can load spirals/JS before auth.
	static := admin.Group("/static", staticGzip, h.staticCache)
	static.StaticFS("/js", h.staticJS)
	static.StaticFS("/css", h.staticCSS)
	static.StaticFS("/imgs", h.staticImgs)
	static.StaticFS("/vendor", echo.MustSubFS(vendorFS, "vendor"))

	g := admin.Group("")
	// bodyLimit must run ahead of csrfProtect, which parses the form body.
	g.Use(bodyLimit, h.sessionAuth, h.requireRole, h.csrfProtect, h.auditLog)

	// as declares the minimum role for routes (issue #196); requireRole
	// enforces it. Every mutating route is listed under one of the three
	// roles, which TestRouteRoles checks. GETs default to viewer.
	h.routeRoles = map[string]string{}
	as := func(role string, routes ...echo.RouteInfo) {
		for _, r := range routes {
			h.routeRoles[r.Method+" "+r.Path] = role
		}
	}

	g.GET("/metrics", echo.WrapHandler(metrics.Handler()))
	g.GET("", h.Dashboard)
	g.GET("/api/notifications", h.NotificationsPanel)
	g.GET("/api/notifications/stream", h.NotificationsStream)
	g.GET("/api/traffic", h.TrafficSeries)
	g.GET("/api/threats", h.ThreatsSeries)
	g.GET("/logs", h.Logs)
	g.GET("/logs/stream", h.LogsStream)
	g.GET("/logs/stats", h.LogStatsSeed)
	g.GET("/logs/:id", h.LogDetail)
	g.GET("/ip-rules", h.IPRulesPage)
	g.GET("/ip-rules/rows", h.IPRulesRows)
	g.GET("/geo-rules", h.GeoRulesPage)
	g.GET("/services", h.ServicesPage)
	g.GET("/services/rows", h.ServicesRows)
	g.GET("/services/openapi/:id", h.ServiceOpenAPI)
	g.GET("/services/cache-stats", h.ServicesCacheStats)
	g.GET("/certificates", h.CertificatesPage)
	g.GET("/waf-rules", h.WAFRulesPage)
	g.GET("/threat-intel", h.ThreatIntelPage)
	g.GET("/settings", h.SettingsPage)
	g.GET("/settings/audit", h.AuditRows)
	g.GET("/search", h.Search)

	// Every role: the user's own session, credentials and second factors.
	as(storage.RoleViewer,
		g.POST("/logout", h.Logout),
		g.POST("/api/notifications/seen", h.MarkNotificationsSeen),
		g.POST("/settings/credentials", h.ChangeCredentials),
		g.POST("/settings/2fa/start", h.StartTOTPEnrollment),
		g.POST("/settings/2fa/confirm", h.ConfirmTOTPEnrollment),
		g.POST("/settings/2fa/disable", h.DisableTOTP),
		g.POST("/settings/passkeys/begin", h.BeginPasskeyEnrollment),
		g.POST("/settings/passkeys/finish", h.FinishPasskeyEnrollment),
		g.DELETE("/settings/passkeys/:id", h.DeletePasskey),
		g.DELETE("/settings/devices/:token", h.RevokeDevice),
		g.POST("/settings/devices/revoke-others", h.RevokeOtherDevices),
	)

	as(storage.RoleAdmin,
		// Full request headers leave the UI here, so viewers can't export.
		g.GET("/logs/export", h.ExportLogs),
		g.POST("/logs/feedback/:id", h.MarkLogFeedback),
		g.POST("/logs/exception/:id", h.CreateLogException),
		g.POST("/ip-rules", h.AddIPRule),
		g.POST("/ip-rules/autoban", h.SaveAutobanSettings),
		g.POST("/ip-rules/adaptive", h.SaveAdaptiveSettings),
		g.POST("/ip-rules/honeypots", h.SaveHoneypots),
		g.DELETE("/ip-rules/:id", h.DeleteIPRule),
		g.POST("/geo-rules", h.AddGeoRule),
		g.DELETE("/geo-rules/:id", h.DeleteGeoRule),
		g.POST("/services", h.AddService),
		g.DELETE("/services/:id", h.DeleteService),
		g.POST("/services/tls/upload", h.UploadServiceTLS),
		g.POST("/services/tls/auto", h.EnableServiceAutoTLS),
		g.POST("/services/tls/pool", h.AssignPoolCert),
		g.POST("/services/tls/clear", h.ClearServiceTLS),
		g.POST("/certificates", h.AddCertificate),
		g.DELETE("/certificates/:id", h.DeleteCertificate),
		g.POST("/services/ratelimit", h.SetServiceRateLimit),
		g.POST("/services/bot/:id", h.SetServiceBotMode),
		g.POST("/services/uploads/:id", h.SetServiceLargeJSUploads),
		g.POST("/services/http3/:id", h.SetServiceHTTP3),
		g.POST("/services/mtls/:id", h.SetServiceMTLS),
		g.POST("/services/login/:id", h.SetServiceLoginPaths),
		g.POST("/services/ai/:id", h.SetServiceAICrawlers),
		g.POST("/services/breach/:id", h.SetServiceBreachCheck),
		g.POST("/services/responses/:id", h.SetServiceResponseInspect),
		g.POST("/services/gate/:id", h.SetServiceGate),
		g.POST("/services/compress/:id", h.SetServiceCompress),
		g.POST("/services/backends/:id", h.SetServiceBackends),
		g.POST("/services/hosts/:id", h.SetServiceHosts),
		g.POST("/services/name/:id", h.RenameService),
		g.POST("/services/schema/:id", h.SetServiceSchema),
		g.POST("/services/openapi/:id", h.SetServiceOpenAPI),
		g.POST("/services/mcp/:id", h.SetServiceMCP),
		g.POST("/services/jwt/:id", h.SetServiceJWT),
		g.POST("/services/csp/:id", h.SetServiceCSP),
		g.POST("/services/cookies/:id", h.SetServiceCookies),
		g.POST("/services/policy/:id", h.SetServiceRequestPolicy),
		g.POST("/services/cache/:id", h.SetServiceCache),
		g.POST("/services/cache-session/:id", h.SetServiceCacheSession),
		g.POST("/services/cache-tuning/:id", h.SetServiceCacheTuning),
		g.POST("/services/cache-purge/:id", h.PurgeServiceCache),
		g.POST("/settings/varnish", h.SaveVarnishConfig),
		g.POST("/settings/acme-email", h.SaveAcmeEmail),
		g.POST("/settings/bot", h.SaveBotSettings),
		g.POST("/settings/ratelimit", h.SaveRateLimitConfig),
		g.POST("/settings/trusted-ips", h.SaveTrustedIPs),
		g.POST("/waf-rules/disable", h.DisableWAFRule),
		g.POST("/waf-rules/dry-run", h.WAFDryRun),
		g.POST("/waf-rules/custom", h.SaveCustomRule),
		g.POST("/waf-rules/custom/:id/toggle", h.ToggleCustomRule),
		g.DELETE("/waf-rules/custom/:id", h.DeleteCustomRule),
		g.DELETE("/waf-rules/:id", h.EnableWAFRule),
		g.DELETE("/waf-rules/service/:id", h.EnableWAFRuleForService),
		g.POST("/waf-rules/feedback-config", h.SaveWAFFeedbackConfig),
		g.POST("/threat-intel", h.AddThreatIntelSource),
		g.POST("/threat-intel/crowdsec", h.AddCrowdSecSource),
		g.DELETE("/threat-intel/:id", h.DeleteThreatIntelSource),
		g.POST("/threat-intel/:id/toggle", h.ToggleThreatIntelSource),
		g.POST("/threat-intel/:id/sync", h.SyncThreatIntelSource),
	)

	// Owner: users, the DB connection, secrets and API keys.
	as(storage.RoleOwner,
		g.POST("/settings/users", h.CreateUser),
		g.POST("/settings/users/:id", h.UpdateUser),
		g.POST("/settings/users/:id/invite", h.ResendUserInvite),
		g.DELETE("/settings/users/:id", h.DeleteUser),
		g.POST("/settings/users/invites", h.CreateSSOInvite),
		g.POST("/settings/users/invites/:id", h.RenewSSOInvite),
		g.DELETE("/settings/users/invites/:id", h.RevokeSSOInvite),
		g.POST("/settings/sso", h.SaveSSOSettings),
		g.POST("/settings/webhook", h.SaveWebhookConfig),
		g.POST("/settings/webhook/test", h.TestWebhook),
		g.POST("/settings/email", h.SaveEmailSettings),
		g.POST("/settings/email/test", h.TestEmailReport),
		g.POST("/settings/api-keys", h.CreateAPIKey),
		g.DELETE("/settings/api-keys/:id", h.DeleteAPIKey),
		// POST, not GET: this streams the full DB (password hashes,
		// challenge secret), so it must never be reachable via cross-site
		// top-level navigation.
		g.POST("/settings/backup", h.BackupDB),
		// POST for the same reason: users, password hashes and sealed secrets.
		g.POST("/settings/config-export", h.ExportConfig),
		// Profiles expose memory contents and the command line (issue #267).
		g.GET("/debug/pprof/*", h.Pprof),
	)
}

func (h *Handler) render(c *echo.Context, page string, data map[string]any) error {
	t, ok := h.tmpls[page]
	if !ok {
		return fmt.Errorf("template %q not found", page)
	}
	markAuditFailure(c, data)
	if data == nil {
		data = map[string]any{}
	}
	data["Page"] = page
	if _, ok := data["Heading"]; !ok {
		data["Heading"] = pageHeadings[page]
	}
	if _, ok := data["AdminPath"]; !ok {
		data["AdminPath"] = h.cfg.Admin.Path
	}
	if _, ok := data["Asset"]; !ok {
		data["Asset"] = h.assetVer
	}
	if _, ok := data["AlertCount"]; !ok {
		data["AlertCount"] = h.unreadAlertCount()
	}
	// The signed-in user, for the sidebar and role-gated cards. Always
	// set, so templates can compare .Role without a nil check.
	data["UserEmail"], data["Role"] = "", ""
	if u := currentUser(c); u != nil {
		data["UserEmail"], data["Role"] = u.Email, u.Role
	}
	// Shell chrome: sidebar status box and bottom status bar.
	data["Version"], data["WAFOn"] = h.cfg.Version, h.cfg.WAF.Enabled
	// CSRF token for this session: picked up by hx-headers on <body> for all
	// HTMX requests and by hidden _csrf inputs in plain HTML forms.
	if _, ok := data["CSRF"]; !ok {
		data["CSRF"] = h.csrfFromContext(c)
	}
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	// no-store keeps these pages out of the browser's back/forward cache.
	// Without it, navigating away leaves the previous page (and its live
	// notifications/logs EventSource, see notify.js and logs.html) frozen in
	// bfcache instead of torn down, so each connection stays open for as long
	// as that bfcache entry survives. A few quick page navigations can pile
	// up more open SSE connections than Chrome's ~6-per-origin HTTP/1.1 limit
	// allows, stalling every other request behind them for as long as it
	// takes bfcache to evict an old entry. It's also the right call for an
	// authenticated admin panel anyway: these pages shouldn't be restorable
	// from cache after logout.
	c.Response().Header().Set("Cache-Control", "no-store")
	return t.ExecuteTemplate(c.Response(), "base", data)
}

// renderPartial executes a named sub-template from a page template (used for HTMX swaps).
func (h *Handler) renderPartial(c *echo.Context, page, tmplName string, data any) error {
	t, ok := h.tmpls[page]
	if !ok {
		return fmt.Errorf("template %q not found", page)
	}
	markAuditFailure(c, data)
	// Swapped fragments gate their controls with can, like full pages.
	if m, ok := data.(map[string]any); ok && m["Role"] == nil {
		if u := currentUser(c); u != nil {
			m["Role"] = u.Role
		}
	}
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	return t.ExecuteTemplate(c.Response(), tmplName, data)
}
