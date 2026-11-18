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
	"palisade/internal/ext"
	"palisade/internal/notify/metrics"
	"palisade/internal/proxy"
	"palisade/internal/security/blocklist"
	"palisade/internal/security/breach"
	"palisade/internal/security/challenge"
	"palisade/internal/security/geo"
	"palisade/internal/security/passkey"
	"palisade/internal/security/threatscore"
	"palisade/internal/services"
	"palisade/internal/storage"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

//go:embed templates
var templateFS embed.FS

// vendorFS holds the third-party admin assets (htmx for the Pro page, fonts, icons,
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

// Handler holds all UI dependencies.
type Handler struct {
	cfg             *config.Config
	db              *storage.DB
	ipbl            *blocklist.IPBlocklist
	geoBl           *geo.Blocker
	registry        *services.Registry
	broadcaster     *LogBroadcaster
	pro             *template.Template // templates/pro.html, the add-on cards page
	staticJS        fs.FS
	staticCSS       fs.FS
	assetVer        string // cache-busting stamp for the embedded CSS/JS URLs
	staticImgs      fs.FS
	appIndex        *template.Template // React admin index.html (app.go); nil when not built
	appFS           fs.FS
	loginIndex      *template.Template // the public sign-in page (web/login.html)
	loginFS         fs.FS              // its own build: no app code before sign-in
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
	extCards        []ext.Card        // Settings cards from ext.Mounts, filled by Register
}

// NewHandler builds the UI handler. jsFS must contain the theme script at
// "js/*.js" (see package static); it's served under
// /<admin_path>/static/js/. cssFS must contain the compiled Tailwind
// stylesheet at "css/dist/*" (built by `make css`, committed, embedded — no
// CDN); it's served under /<admin_path>/static/css/. imgsFS must contain
// "imgs/*"; it's served under /<admin_path>/static/imgs/.
// proxyHandle is the reverse-proxy pipeline's own route handler
// (proxy.Handler.Handle, the same func registered for the catch-all "/*"
// route in internal/app); see hostGuard for why the admin/API routes need to be
// able to hand a request off to it.
func NewHandler(cfg *config.Config, db *storage.DB, ipbl *blocklist.IPBlocklist, geoBl *geo.Blocker, registry *services.Registry, bc *LogBroadcaster, jsFS embed.FS, cssFS embed.FS, imgsFS embed.FS, reloadBot func(*challenge.Challenger), buildChallenger func(bool, int, int) *challenge.Challenger, reloadRateLimit func(), reloadWAF func(), syncThreatIntel func(int64), sendReportNow func() error, sendTestWebhook func() error, sendLoginCode func(string) error, sendInvite func(to, inviter, role, link string) error, reloadAutoban func(), scorer *threatscore.Scorer, reloadAdaptive func(), proxyHandle echo.HandlerFunc) (*Handler, error) {
	sub, err := fs.Sub(jsFS, "js")
	if err != nil {
		return nil, fmt.Errorf("sub static/js: %w", err)
	}
	cssSub, err := fs.Sub(cssFS, "css/dist")
	if err != nil {
		return nil, fmt.Errorf("sub static/css/dist: %w", err)
	}
	imgsSub, err := fs.Sub(imgsFS, "imgs")
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
	pro, err := template.ParseFS(templateFS, "templates/pro.html")
	if err != nil {
		return fmt.Errorf("parse pro.html: %w", err)
	}
	h.pro = pro
	return nil
}

const sessionCookie = "cz_session"

// signIn sends a request without a live session to the login page. The
// React app gets a 401 instead: fetch would follow the redirect into HTML.
func (h *Handler) signIn(c *echo.Context, query string) error {
	if wantsJSON(c) {
		return &jsonError{Status: http.StatusUnauthorized, Code: "unauthenticated", Message: "Your session has ended. Sign in again."}
	}
	return c.Redirect(http.StatusFound, h.cfg.Admin.Path+"/login"+query)
}

// sessionAuth is the session-cookie middleware that guards every admin route.
// Unauthenticated requests are sent to the login page (signIn).
func (h *Handler) sessionAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		cookie, err := c.Cookie(sessionCookie)
		if err != nil || cookie.Value == "" {
			return h.signIn(c, "")
		}
		sess, err := h.db.GetSession(cookie.Value)
		if err != nil || sess == nil {
			return h.signIn(c, "")
		}
		if !sess.Live() {
			// Say which of the two happened. A revoked session means
			// someone logged in elsewhere (or revoked this device from the
			// Settings page); an expired one is just the 24h TTL.
			if sess.Revoked() {
				return h.signIn(c, "?reason=revoked")
			}
			return h.signIn(c, "")
		}
		// A disabled user's sessions are revoked when they're disabled;
		// checking here too keeps a stale row from ever authenticating.
		u, err := h.db.GetAdminUser(sess.UserID)
		if err != nil {
			return h.signIn(c, "")
		}
		if u == nil || u.Disabled {
			// Drop the row too: LoginPage would otherwise see a live
			// session and bounce straight back here.
			h.db.DeleteSession(sess.ID) //nolint — best effort, it can't authenticate either way
			return h.signIn(c, "")
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
	// The sign-in page's own bundle, public; the app's stays behind a session.
	admin.GET("/login/assets/*", h.LoginAsset)
	admin.POST("/invite/:token", h.InvitePost, bodyLimit)
	// Static assets are public so the login page can load spirals/JS before auth.
	static := admin.Group("/static", staticGzip, h.staticCache)
	static.StaticFS("/js", h.staticJS)
	static.StaticFS("/css", h.staticCSS)
	static.StaticFS("/imgs", h.staticImgs)
	static.StaticFS("/vendor", echo.MustSubFS(vendorFS, "vendor"))

	g := admin.Group("")
	// jsonErrors wraps the rest so the React app gets its error body from
	// every one of them; the body limit must run ahead of csrfProtect,
	// which parses the form body.
	// The OpenAPI tab takes a spec up to openAPIMaxBytes, as a JSON string
	// (escaping can double it), so that one route gets its own cap.
	openAPIPath := base + "/api/services/:id/openapi"
	sessionLimit := middleware.BodyLimitWithConfig(middleware.BodyLimitConfig{
		LimitBytes: 1 << 20,
		Skipper:    func(c *echo.Context) bool { return c.Path() == openAPIPath },
	})
	g.Use(jsonErrors, sessionLimit, h.sessionAuth, h.requireRole, h.csrfProtect, h.auditLog)

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
	g.GET("/api/dashboard", h.Dashboard)
	g.GET("/api/logs", h.APIListLogs)
	g.GET("/api/logs/apps", h.LogApps)
	g.GET("/api/notifications", h.NotificationsPanel)
	g.GET("/api/notifications/stream", h.NotificationsStream)
	g.GET("/logs/stream", h.LogsStream)
	g.GET("/logs/stats", h.LogStatsSeed)
	g.GET("/logs/:id", h.LogDetail)
	g.GET("/api/ip-rules", h.ListIPRules)
	g.GET("/api/ip-rules/settings", h.IPRulesSettings)
	g.GET("/api/geo-rules", h.APIListGeoRules)
	g.GET("/api/services", h.ListServices)
	g.GET("/api/services/cache-stats", h.CacheStats)
	g.GET("/api/services/:id/openapi", h.ServiceOpenAPIJSON)
	g.GET("/api/certificates", h.ListCertificates)
	g.GET("/api/waf-rules", h.ListWAFRules)
	g.GET("/api/threat-intel", h.ListThreatIntel)
	// Add-on cards (ext.Card) render on the server.
	g.GET("/settings/pro", h.SettingsPro)
	g.GET("/api/settings/account", h.Account)
	g.GET("/api/settings/protection", h.Protection)
	g.GET("/api/settings/audit", h.Audit)
	g.GET("/search", h.Search)
	// The React app (issue #357): every other GET renders it, so the client
	// router handles deep links. /app/* is where it lived before.
	g.GET("", h.AppPage)
	g.GET("/*", h.AppPage)
	g.GET("/app", h.fromApp)
	g.GET("/app/*", h.fromApp)

	// Every role: the user's own session, credentials and second factors.
	as(storage.RoleViewer,
		g.POST("/logout", h.Logout),
		g.POST("/api/notifications/seen", h.MarkNotificationsSeen),
		g.PUT("/api/settings/credentials", h.SetCredentials),
		g.POST("/api/settings/2fa/start", h.StartTOTP),
		g.POST("/api/settings/2fa/confirm", h.ConfirmTOTP),
		g.POST("/api/settings/2fa/disable", h.DisableTOTPJSON),
		g.POST("/api/settings/passkeys/begin", h.BeginPasskey),
		g.POST("/api/settings/passkeys/finish", h.FinishPasskey),
		g.DELETE("/api/settings/passkeys/:id", h.RemovePasskey),
		g.DELETE("/api/settings/devices/:id", h.SignOutDevice),
		g.POST("/api/settings/devices/sign-out-others", h.SignOutOthers),
	)

	as(storage.RoleAdmin,
		// Full request headers leave the UI here, so viewers can't export.
		g.GET("/logs/export", h.ExportLogs),
		g.POST("/logs/feedback/:id", h.MarkLogFeedback),
		g.POST("/logs/exception/:id", h.CreateLogException),
		g.POST("/api/ip-rules", h.AddIPRules),
		g.POST("/api/ip-rules/remove", h.RemoveIPRules),
		g.PUT("/api/ip-rules/autoban", h.SaveAutobanSettings),
		g.PUT("/api/ip-rules/adaptive", h.SaveAdaptiveSettings),
		g.PUT("/api/ip-rules/honeypots", h.SaveHoneypots),
		g.POST("/api/geo-rules", h.AddGeoRules),
		g.POST("/api/geo-rules/remove", h.RemoveGeoRules),
		g.POST("/api/services", h.APICreateService),
		g.DELETE("/api/services/:id", h.APIDeleteService),
		g.PUT("/api/services/:id/name", h.SetServiceName),
		g.PUT("/api/services/:id/hosts", h.SetServiceHostsJSON),
		g.PUT("/api/services/:id/backends", h.SetServiceBackendsJSON),
		g.PUT("/api/services/:id/rate-limit", h.SetServiceRateLimitJSON),
		g.PUT("/api/services/:id/bot", h.SetServiceBot),
		g.PUT("/api/services/:id/gate", h.SetServiceGateJSON),
		g.PUT("/api/services/:id/uploads", h.SetServiceUploads),
		g.PUT("/api/services/:id/schema", h.SetServiceSchemaJSON),
		g.PUT("/api/services/:id/openapi", h.SetServiceOpenAPIJSON, middleware.BodyLimit(2*openAPIMaxBytes)),
		g.PUT("/api/services/:id/mcp", h.SetServiceMCPJSON),
		g.PUT("/api/services/:id/jwt", h.SetServiceJWTJSON),
		g.PUT("/api/services/:id/csp", h.SetServiceCSPJSON),
		g.PUT("/api/services/:id/cookies", h.SetServiceCookiesJSON),
		g.PUT("/api/services/:id/policy", h.SetServicePolicyJSON),
		g.PUT("/api/services/:id/responses", h.SetServiceResponsesJSON),
		g.PUT("/api/services/:id/cache", h.SetServiceCacheJSON),
		g.POST("/api/services/:id/purge", h.PurgeServiceCacheJSON),
		g.PUT("/api/services/:id/tls", h.SetServiceTLSJSON),
		g.PUT("/api/services/:id/http3", h.SetServiceHTTP3JSON),
		g.PUT("/api/services/:id/mtls", h.SetServiceMTLSJSON),
		g.POST("/api/certificates", h.AddCertificate),
		g.DELETE("/api/certificates/:id", h.DeleteCertificate),
		g.PUT("/api/settings/bot", h.SetBot),
		g.PUT("/api/settings/rate-limit", h.SetRateLimit),
		g.PUT("/api/settings/trusted-ips", h.SetTrustedIPs),
		g.PUT("/api/settings/varnish", h.SetVarnish),
		g.POST("/api/waf-rules/exceptions", h.AddWAFException),
		g.DELETE("/api/waf-rules/exceptions/global/:id", h.DeleteWAFException),
		g.DELETE("/api/waf-rules/exceptions/services/:id", h.DeleteWAFException),
		g.PUT("/api/waf-rules/feedback", h.SetWAFFeedback),
		g.POST("/api/waf-rules/dry-run", h.WAFDryRun),
		g.POST("/api/waf-rules/custom", h.AddCustomRule),
		g.PUT("/api/waf-rules/custom/:id", h.UpdateCustomRule),
		g.PUT("/api/waf-rules/custom/:id/enabled", h.SetCustomRuleEnabled),
		g.DELETE("/api/waf-rules/custom/:id", h.DeleteCustomRule),
		g.POST("/api/threat-intel", h.AddThreatIntelSource),
		g.POST("/api/threat-intel/crowdsec", h.AddCrowdSecSource),
		g.PUT("/api/threat-intel/:id", h.SetThreatIntelSource),
		g.DELETE("/api/threat-intel/:id", h.DeleteThreatIntelSource),
		g.POST("/api/threat-intel/:id/sync", h.SyncThreatIntelSource),
	)

	// Owner: users, the DB connection, secrets and API keys.
	as(storage.RoleOwner,
		g.GET("/api/settings/team", h.Team),
		g.POST("/api/settings/users", h.AddUser),
		g.PUT("/api/settings/users/:id", h.UpdateUserJSON),
		g.POST("/api/settings/users/:id/invite", h.ResendInvite),
		g.POST("/api/settings/users/:id/reset-2fa", h.ResetUser2FA),
		g.DELETE("/api/settings/users/:id", h.RemoveUser),
		g.POST("/api/settings/sso-invites", h.AddSSOInvite),
		g.POST("/api/settings/sso-invites/:id/renew", h.RenewSSOInviteJSON),
		g.DELETE("/api/settings/sso-invites/:id", h.RemoveSSOInvite),
		g.PUT("/api/settings/sso", h.SetSSO),
		g.POST("/api/settings/api-keys", h.AddAPIKey),
		g.DELETE("/api/settings/api-keys/:id", h.RemoveAPIKey),
		g.GET("/api/settings/alerts", h.Alerts),
		g.PUT("/api/settings/webhook", h.SetWebhook),
		g.POST("/api/settings/webhook/test", h.TestWebhookJSON),
		g.PUT("/api/settings/email", h.SetEmail),
		g.POST("/api/settings/email/test", h.TestEmailJSON),
		// POST, not GET: this streams the full DB (password hashes,
		// challenge secret), so it must never be reachable via cross-site
		// top-level navigation.
		g.POST("/settings/backup", h.BackupDB),
		// POST for the same reason: users, password hashes and sealed secrets.
		g.POST("/settings/config-export", h.ExportConfig),
		// Profiles expose memory contents and the command line (issue #267).
		g.GET("/debug/pprof/*", h.Pprof),
	)

	// Add-ons from a binary built on palisade (palisade-pro). A route
	// without a valid role would be open to every user, so refuse to start.
	h.extCards = nil
	ext.CurrentUser = currentUser
	for _, mount := range ext.Mounts {
		f := mount(ext.Env{DB: h.db, AdminPath: base, Reload: h.reloadAll})
		for _, r := range f.Open {
			admin.Add(r.Method, r.Path, r.Handler, bodyLimit)
		}
		for _, r := range f.Routes {
			if !storage.ValidRole(r.Role) {
				panic("ext route " + r.Method + " " + r.Path + " has no valid role")
			}
			as(r.Role, g.Add(r.Method, r.Path, r.Handler))
		}
		if f.Card != nil {
			h.extCards = append(h.extCards, f.Card)
		}
	}
}
