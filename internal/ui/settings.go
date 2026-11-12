package ui

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"palisade/internal/notify/mailer"
	"palisade/internal/security/bot"
	"palisade/internal/security/challenge"
	"palisade/internal/security/passkey"
	"palisade/internal/storage"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

// ── Settings ──────────────────────────────────────────────────────────────────

func (h *Handler) SettingsPage(c *echo.Context) error {
	me := currentUser(c)
	botEnabled, botThreshold, botTTL, _ := h.db.GetBotSettings()
	aiPolicy, _ := h.db.GetAICrawlerPolicy()
	rlEnabled, rlRPS, rlBurst, _ := h.db.GetRateLimitSettings()
	wh, _ := h.db.GetWebhookConfig()
	ec, _ := h.db.GetEmailConfig()
	tc, _ := h.db.GetTypeSafeConfig()
	vc, _ := h.db.GetVarnishConfig()
	captcha, _ := h.db.GetCaptchaConfig()
	audit, _ := h.auditRowsData(1)
	apiKeys, _ := h.db.ListAPIKeys()
	totpEnabled, _ := h.db.TOTPEnabled(me.ID)
	dbConnCfg, _ := h.db.GetDBConnConfig()
	if dbConnCfg.Driver == "" {
		// Never configured through this page yet — default the form to
		// reflect what's actually running (see ActiveDBDriver/ActiveDBPath
		// below) rather than starting blank. Only sqlite's Path doubles
		// safely as a form field value here; a mysql/postgres DSN isn't
		// picked apart into host/user/password since it may not have come
		// from this page at all (e.g. set directly via --db at the CLI).
		dbConnCfg.Driver = h.cfg.DB.Driver
		if dbConnCfg.Driver == "sqlite" || dbConnCfg.Driver == "" {
			dbConnCfg.Host = h.cfg.DB.Path
		}
	}
	passkeyRows, _ := h.db.ListWebAuthnCredentials(me.ID)
	trustedIPs, _ := h.db.GetTrustedIPs()
	var users []storage.AdminUser
	var invites []storage.SSOInvite
	var sso storage.SSOConfig
	if me.Role == storage.RoleOwner {
		users, _ = h.db.ListAdminUsers()
		invites, _ = h.db.ListSSOInvites()
		sso, _ = h.db.GetSSOConfig()
	}
	return h.render(c, "settings", h.dbConnCardData(dbConnCfg, false, "", map[string]any{
		"AdminEmail":             me.Email,
		"Users":                  users,
		"Invites":                invites,
		"SSOOn":                  sso.Issuer != "",
		"SSOIssuer":              sso.Issuer,
		"SSOClientID":            sso.ClientID,
		"SSOSecretSet":           sso.ClientSecret != "",
		"SSOGroup":               sso.Group,
		"SSOCallbackURL":         h.ssoCallbackURL(c),
		"MyID":                   me.ID,
		"TOTPEnabled":            totpEnabled,
		"Passkeys":               passkeyRows,
		"SecureContext":          passkey.IsSecureContext(c.Request()),
		"BotEnabled":             botEnabled,
		"BotThreshold":           botThreshold,
		"BotTTL":                 botTTL,
		"AIPolicy":               bot.ParseAIPolicy(aiPolicy),
		"CaptchaProvider":        captcha.Provider,
		"CaptchaSiteKey":         captcha.SiteKey,
		"CaptchaSecretSet":       captcha.Secret != "",
		"RLEnabled":              rlEnabled,
		"RLRPS":                  rlRPS,
		"RLBurst":                rlBurst,
		"TrustedIPs":             trustedIPs,
		"WebhookURL":             wh.URL,
		"WebhookSecret":          wh.Secret,
		"WebhookEnabled":         wh.Enabled,
		"WebhookEvents":          wh.Events,
		"WebhookDestinationType": wh.DestinationType,
		"EmailEnabled":           ec.Enabled,
		"EmailSender":            mailer.Sender,
		"EmailTo":                ec.To,
		"EmailTokenSet":          ec.Token != "",
		"TypeSafeEnabled":        tc.Enabled,
		"TypeSafeAPIKeySet":      tc.APIKey != "",
		"VarnishEnabled":         vc.Enabled,
		"VarnishAddr":            vc.Addr,
		"APIKeys":                apiKeys,
		"Devices":                h.deviceRows(me.ID, sessionCookieValue(c)),
		"Audit":                  audit,
	}))
}

// CreateAPIKey generates a new bearer token for the REST API and shows it to
// the admin exactly once; only its SHA-256 hash and a display prefix are
// persisted (see newAPIKey, ui/api.go).
func (h *Handler) CreateAPIKey(c *echo.Context) error {
	name := strings.TrimSpace(c.FormValue("name"))
	readOnly := c.FormValue("read_only") == "1"
	apiKeys, _ := h.db.ListAPIKeys()

	if name == "" {
		return h.renderPartial(c, "settings", "api-keys-card", map[string]any{
			"AdminPath":     h.cfg.Admin.Path,
			"APIKeys":       apiKeys,
			"APIKeySaveErr": "Name is required.",
		})
	}

	raw, prefix, hash, err := newAPIKey()
	if err != nil {
		return h.renderPartial(c, "settings", "api-keys-card", map[string]any{
			"AdminPath":     h.cfg.Admin.Path,
			"APIKeys":       apiKeys,
			"APIKeySaveErr": "Could not generate a key: " + err.Error(),
		})
	}
	if _, err := h.db.CreateAPIKey(name, prefix, hash, readOnly); err != nil {
		return h.renderPartial(c, "settings", "api-keys-card", map[string]any{
			"AdminPath":     h.cfg.Admin.Path,
			"APIKeys":       apiKeys,
			"APIKeySaveErr": err.Error(),
		})
	}

	apiKeys, _ = h.db.ListAPIKeys()
	return h.renderPartial(c, "settings", "api-keys-card", map[string]any{
		"AdminPath": h.cfg.Admin.Path,
		"APIKeys":   apiKeys,
		"NewAPIKey": raw,
	})
}

// DeleteAPIKey revokes a key by deleting its row. Any request already using
// it fails its next auth check immediately, no cache or TTL to wait out.
func (h *Handler) DeleteAPIKey(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	if err := h.db.RemoveAPIKey(id); err != nil {
		return err
	}
	apiKeys, _ := h.db.ListAPIKeys()
	return h.renderPartial(c, "settings", "api-keys-rows", map[string]any{
		"AdminPath": h.cfg.Admin.Path,
		"Keys":      apiKeys,
	})
}

// SaveBotSettings persists global bot-protection settings and hot-reloads the
// challenger so changes take effect without a server restart.
func (h *Handler) SaveBotSettings(c *echo.Context) error {
	enabled := c.FormValue("bot_enabled") == "1"
	threshold, _ := strconv.Atoi(c.FormValue("bot_threshold"))
	ttl, _ := strconv.Atoi(c.FormValue("bot_ttl"))
	if threshold <= 0 {
		threshold = 8
	}
	if ttl <= 0 {
		ttl = 3600
	}

	// CAPTCHA fallback. A blank secret keeps the stored one, like the email
	// token, and the secret is never echoed back into the page.
	stored, _ := h.db.GetCaptchaConfig()
	cc := storage.CaptchaConfig{
		Provider: c.FormValue("captcha_provider"),
		SiteKey:  strings.TrimSpace(c.FormValue("captcha_site_key")),
		Secret:   strings.TrimSpace(c.FormValue("captcha_secret")),
	}
	if cc.Secret == "" {
		cc.Secret = stored.Secret
	}
	botErr := ""
	switch {
	case cc.Provider == "":
	case !challenge.ValidCaptchaProvider(cc.Provider):
		botErr = "Unknown CAPTCHA provider."
	case cc.SiteKey == "" || cc.Secret == "":
		botErr = "The CAPTCHA fallback needs both a site key and a secret key."
	}

	aiPolicy := aiPolicyForm(c)

	data := map[string]any{
		"AdminPath":        h.cfg.Admin.Path,
		"BotEnabled":       enabled,
		"BotThreshold":     threshold,
		"BotTTL":           ttl,
		"AIPolicy":         aiPolicy,
		"CaptchaProvider":  cc.Provider,
		"CaptchaSiteKey":   cc.SiteKey,
		"CaptchaSecretSet": cc.Secret != "",
	}
	if botErr != "" {
		data["BotError"] = botErr
		return h.renderPartial(c, "settings", "bot-card", data)
	}
	if err := h.db.SetBotSettings(enabled, threshold, ttl); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if err := h.db.SetCaptchaConfig(cc); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if err := h.db.SetAICrawlerPolicy(aiPolicy.String()); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if err := h.registry.Reload(h.db); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	if h.reloadBot != nil && h.buildChallenger != nil {
		h.reloadBot(h.buildChallenger(enabled, threshold, ttl))
	}

	data["BotSaveOK"] = true
	return h.renderPartial(c, "settings", "bot-card", data)
}

// SaveVarnishConfig persists the global Varnish accelerator settings and
// rebuilds the service registry so cache-enabled services are re-targeted
// (or pointed back at their backends) without a restart. The listen address
// must be loopback: Varnish sits behind the WAF, and a non-local address
// would let clients hit the cache with unscrubbed traffic.
func (h *Handler) SaveVarnishConfig(c *echo.Context) error {
	enabled := c.FormValue("varnish_enabled") == "1"
	addr := strings.TrimSpace(c.FormValue("varnish_addr"))
	if addr == "" {
		addr = storage.DefaultVarnishAddr
	}

	vErr := ""
	if host, _, err := net.SplitHostPort(addr); err != nil {
		vErr = "Address must be host:port, e.g. 127.0.0.1:6081."
	} else if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		vErr = "Varnish must listen on a loopback address, otherwise clients could bypass the WAF and reach the cache directly."
	}
	if vErr == "" {
		// Preserve the stored cache-return address: it's not exposed on the
		// form (it must match the installed VCL, and the listener binds it at
		// startup), so a save must never reset it.
		stored, _ := h.db.GetVarnishConfig()
		if err := h.db.SetVarnishConfig(storage.VarnishConfig{Enabled: enabled, Addr: addr, ReturnAddr: stored.ReturnAddr}); err != nil {
			vErr = "Failed to save: " + err.Error()
		} else if err := h.registry.Reload(h.db); err != nil {
			vErr = "Saved, but applying to services failed: " + err.Error()
		}
	}

	if vErr != "" {
		// Revert the displayed state to what is actually stored.
		if stored, err := h.db.GetVarnishConfig(); err == nil {
			enabled, addr = stored.Enabled, stored.Addr
		}
	}
	return h.renderPartial(c, "settings", "varnish-card", map[string]any{
		"AdminPath":      h.cfg.Admin.Path,
		"VarnishEnabled": enabled,
		"VarnishAddr":    addr,
		"VarnishSaveOK":  vErr == "",
		"VarnishError":   vErr,
	})
}

// SaveRateLimitConfig persists the global rate-limit settings (enabled/rps/
// burst), then hot-reloads the limiter in the proxy handler.
func (h *Handler) SaveRateLimitConfig(c *echo.Context) error {
	enabled := c.FormValue("rl_enabled") == "1"
	rps, _ := strconv.ParseFloat(strings.TrimSpace(c.FormValue("rl_rps")), 64)
	burst, _ := strconv.Atoi(strings.TrimSpace(c.FormValue("rl_burst")))

	rlErr := ""
	if enabled && (rps <= 0 || burst < 1) {
		rlErr = "Requests per second and burst must be positive numbers."
	}
	if rlErr == "" {
		// Limiter off with blank/invalid numbers: keep the stored values
		// instead of persisting zeros that would fall back to defaults.
		if rps <= 0 || burst < 1 {
			_, storedRPS, storedBurst, _ := h.db.GetRateLimitSettings()
			if rps <= 0 {
				rps = storedRPS
			}
			if burst < 1 {
				burst = storedBurst
			}
		}
		if err := h.db.SetRateLimitSettings(enabled, rps, burst); err != nil {
			rlErr = "Failed to save: " + err.Error()
		}
	}
	if rlErr == "" && h.reloadRateLimit != nil {
		h.reloadRateLimit()
	}

	rlEnabled, rlRPS, rlBurst := enabled, rps, burst
	if rlErr != "" {
		// Revert display to the stored config on error.
		rlEnabled, rlRPS, rlBurst, _ = h.db.GetRateLimitSettings()
	}
	return h.renderPartial(c, "settings", "ratelimit-card", map[string]any{
		"AdminPath": h.cfg.Admin.Path,
		"RLEnabled": rlEnabled,
		"RLRPS":     rlRPS,
		"RLBurst":   rlBurst,
		"RLSaveOK":  rlErr == "",
		"RLError":   rlErr,
	})
}

// SaveWebhookConfig persists the webhook delivery settings.
func (h *Handler) SaveWebhookConfig(c *echo.Context) error {
	url := strings.TrimSpace(c.FormValue("webhook_url"))
	secret := strings.TrimSpace(c.FormValue("webhook_secret"))
	enabled := c.FormValue("webhook_enabled") == "1"
	destType := c.FormValue("webhook_destination_type")
	// webhook_events is a multi-value checkbox; collect all checked values.
	eventVals := c.Request().PostForm["webhook_events"]
	events := strings.Join(eventVals, ",")
	if events == "" {
		events = "blocked"
	}
	cfg := storage.WebhookConfig{URL: url, Secret: secret, Enabled: enabled && url != "", Events: events, DestinationType: destType}
	saveErr := ""
	if url != "" {
		if err := validateOutboundURL(url); err != nil {
			saveErr = err.Error()
		}
	}
	if saveErr == "" {
		if err := h.db.SetWebhookConfig(cfg); err != nil {
			saveErr = err.Error()
		}
	}
	// Re-read so the re-rendered card shows the normalized destination type
	// (SetWebhookConfig falls back an unrecognized value to "generic").
	saved, _ := h.db.GetWebhookConfig()
	return h.renderPartial(c, "settings", "webhook-card", map[string]any{
		"AdminPath":              h.cfg.Admin.Path,
		"WebhookURL":             url,
		"WebhookSecret":          secret,
		"WebhookEnabled":         cfg.Enabled,
		"WebhookEvents":          events,
		"WebhookDestinationType": saved.DestinationType,
		"WebhookSaveOK":          saveErr == "",
		"WebhookSaveErr":         saveErr,
	})
}

// TestWebhook sends a single synthetic "blocked" event to the currently
// saved webhook URL/destination type, mirroring TestEmailReport's pattern
// (test against saved settings, ignoring the enabled toggle).
func (h *Handler) TestWebhook(c *echo.Context) error {
	if h.sendTestWebhook == nil {
		return c.HTML(http.StatusOK,
			`<span class="text-red-600 text-[13px]">Webhook delivery is not available.</span>`)
	}
	if err := h.sendTestWebhook(); err != nil {
		return c.HTML(http.StatusOK,
			`<span class="text-red-600 text-[13px]">Send failed: `+template.HTMLEscapeString(err.Error())+`</span>`)
	}
	return c.HTML(http.StatusOK,
		`<span class="text-green-600 text-[13px] font-medium">Test alert sent.</span>`)
}

// SaveEmailSettings persists the daily-report email settings (recipients and
// Cloudflare API token; everything else is hardcoded in the mailer package).
// A blank token field keeps the stored token, so re-saving other fields never
// wipes the credential, and the token is never echoed back into the page.
func (h *Handler) SaveEmailSettings(c *echo.Context) error {
	stored, _ := h.db.GetEmailConfig()

	cfg := storage.EmailConfig{
		Enabled: c.FormValue("email_enabled") == "1",
		Token:   strings.TrimSpace(c.FormValue("email_token")),
		To:      strings.TrimSpace(c.FormValue("email_to")),
	}
	if cfg.Token == "" {
		cfg.Token = stored.Token
	}

	saveErr := ""
	if cfg.Enabled && (cfg.To == "" || cfg.Token == "") {
		saveErr = "A recipient address and the API token are required to enable email alerts."
		cfg.Enabled = false
	}
	if saveErr == "" {
		if err := h.db.SetEmailConfig(cfg); err != nil {
			saveErr = err.Error()
		}
	}

	return h.renderPartial(c, "settings", "email-card", map[string]any{
		"AdminPath":     h.cfg.Admin.Path,
		"EmailEnabled":  cfg.Enabled,
		"EmailSender":   mailer.Sender,
		"EmailTo":       cfg.To,
		"EmailTokenSet": cfg.Token != "",
		"EmailSaveOK":   saveErr == "",
		"EmailSaveErr":  saveErr,
	})
}

// SaveTypeSafeSettings persists the TypeSafe ASN-classification opt-in (see
// internal/security/threatscore/typesafeclassify.go) and hot-reloads the
// scorer's classifier via h.scorer, the same "Reload after save" pattern
// used for geo rules. A blank key field keeps the stored one, mirroring
// SaveEmailSettings, and the key is never echoed back into the page.
func (h *Handler) SaveTypeSafeSettings(c *echo.Context) error {
	stored, _ := h.db.GetTypeSafeConfig()

	cfg := storage.TypeSafeConfig{
		Enabled: c.FormValue("typesafe_enabled") == "1",
		APIKey:  strings.TrimSpace(c.FormValue("typesafe_api_key")),
	}
	if cfg.APIKey == "" {
		cfg.APIKey = stored.APIKey
	}

	saveErr := ""
	if cfg.Enabled && cfg.APIKey == "" {
		saveErr = "An API key is required to enable AI-assisted ASN classification."
		cfg.Enabled = false
	}
	if saveErr == "" {
		if err := h.db.SetTypeSafeConfig(cfg); err != nil {
			saveErr = err.Error()
		}
	}
	h.scorer.ReloadTypeSafeConfig(cfg.Enabled, cfg.APIKey)

	return h.renderPartial(c, "settings", "typesafe-card", map[string]any{
		"AdminPath":         h.cfg.Admin.Path,
		"TypeSafeEnabled":   cfg.Enabled,
		"TypeSafeAPIKeySet": cfg.APIKey != "",
		"TypeSafeSaveOK":    saveErr == "",
		"TypeSafeSaveErr":   saveErr,
	})
}

// TestEmailReport sends a report for the last 24 hours right now, using the
// saved settings. Returns an inline HTML fragment for HTMX.
func (h *Handler) TestEmailReport(c *echo.Context) error {
	if h.sendReportNow == nil {
		return c.HTML(http.StatusOK,
			`<span class="text-red-600 text-[13px]">Email reporting is not available.</span>`)
	}
	if err := h.sendReportNow(); err != nil {
		return c.HTML(http.StatusOK,
			`<span class="text-red-600 text-[13px]">Send failed: `+template.HTMLEscapeString(err.Error())+`</span>`)
	}
	return c.HTML(http.StatusOK,
		`<span class="text-green-600 text-[13px] font-medium">Report sent. Check the inbox.</span>`)
}

// dbConnCardData builds the "Database connection" card's rendering state.
// cfg.Password/cfg.DSN are deliberately never placed in the returned map —
// only the derived *Set booleans are, matching the "never echo a stored
// secret back to the browser" convention EmailConfig.Token already
// established (see CLAUDE.md's secrets-at-rest section) — so a future
// template change can't accidentally leak them into a value= attribute.
func (h *Handler) dbConnCardData(cfg storage.DBConnConfig, saveOK bool, saveErr string, extra map[string]any) map[string]any {
	data := map[string]any{
		"AdminPath":         h.cfg.Admin.Path,
		"ActiveDBDriver":    h.cfg.DB.Driver,
		"ActiveDBPath":      h.cfg.DB.Path,
		"DBConnDriver":      cfg.Driver,
		"DBConnMode":        cfg.Mode,
		"DBConnHost":        cfg.Host,
		"DBConnPort":        cfg.Port,
		"DBConnUsername":    cfg.Username,
		"DBConnDBName":      cfg.DBName,
		"DBConnSSLMode":     cfg.SSLMode,
		"DBConnExtra":       cfg.Extra,
		"DBConnPasswordSet": cfg.Password != "",
		"DBConnDSNSet":      cfg.DSN != "",
		"DBConnSaveOK":      saveOK,
		"DBConnSaveErr":     saveErr,
	}
	for k, v := range extra {
		data[k] = v
	}
	return data
}

// resolveDBConnInput turns the "Database connection" card's submitted form
// fields into a driver name + final DSN, used by both SaveDBConnConfig (to
// validate before persisting) and TestDBConnection (to actually dial it).
// sqlite has no host/port/credentials, so its Host field doubles as the
// database file path — the same convention storage.DBConnFields.Host uses.
func resolveDBConnInput(c *echo.Context) (driver, dsn string, err error) {
	driver = strings.TrimSpace(c.FormValue("dbconn_driver"))
	if driver == "" {
		return "", "", fmt.Errorf("select a database driver")
	}
	host := strings.TrimSpace(c.FormValue("dbconn_host"))
	if driver == "sqlite" {
		if host == "" {
			return "", "", fmt.Errorf("database file path is required")
		}
		return driver, host, nil
	}
	if c.FormValue("dbconn_mode") == "dsn" {
		dsn = strings.TrimSpace(c.FormValue("dbconn_dsn"))
		if dsn == "" {
			return "", "", fmt.Errorf("connection string is required")
		}
		return driver, dsn, nil
	}
	if host == "" {
		return "", "", fmt.Errorf("host is required")
	}
	dsn, err = storage.BuildDSN(storage.DBConnFields{
		Driver:   driver,
		Host:     host,
		Port:     strings.TrimSpace(c.FormValue("dbconn_port")),
		Username: strings.TrimSpace(c.FormValue("dbconn_username")),
		Password: c.FormValue("dbconn_password"),
		DBName:   strings.TrimSpace(c.FormValue("dbconn_dbname")),
		SSLMode:  c.FormValue("dbconn_sslmode"),
		Extra:    strings.TrimSpace(c.FormValue("dbconn_extra")),
	})
	return driver, dsn, err
}

// SaveDBConnConfig persists the admin-entered database connection to the
// meta table purely for this page's own convenience — pre-filling the form
// on the next visit. It has no effect on the live server: the DB connection
// this process actually uses is fixed at startup via the --db-driver/--db
// CLI flags (see internal/app's serve) and only changes
// after a restart with the flags TestDBConnection shows on a successful
// test. Saving here never touches that live connection or requires a
// successful test first, so an admin can save a draft mid-edit.
func (h *Handler) SaveDBConnConfig(c *echo.Context) error {
	cfg := storage.DBConnConfig{
		Driver:   strings.TrimSpace(c.FormValue("dbconn_driver")),
		Mode:     c.FormValue("dbconn_mode"),
		DSN:      strings.TrimSpace(c.FormValue("dbconn_dsn")),
		Host:     strings.TrimSpace(c.FormValue("dbconn_host")),
		Port:     strings.TrimSpace(c.FormValue("dbconn_port")),
		Username: strings.TrimSpace(c.FormValue("dbconn_username")),
		Password: c.FormValue("dbconn_password"),
		DBName:   strings.TrimSpace(c.FormValue("dbconn_dbname")),
		SSLMode:  c.FormValue("dbconn_sslmode"),
		Extra:    strings.TrimSpace(c.FormValue("dbconn_extra")),
	}
	if cfg.Mode != "dsn" {
		cfg.Mode = "fields"
	}

	saveErr := ""
	if cfg.Driver == "" {
		saveErr = "Select a database driver."
	}
	if saveErr == "" {
		if err := h.db.SetDBConnConfig(cfg); err != nil {
			saveErr = "Failed to save: " + err.Error()
		}
	}

	display := cfg
	if saveErr == "" {
		// Reload for the canonical roundtrip (e.g. a blank password field
		// resolved to "keep the stored one" inside SetDBConnConfig/
		// GetDBConnConfig) rather than trusting the just-submitted values.
		if stored, err := h.db.GetDBConnConfig(); err == nil {
			display = stored
		}
	}
	return h.renderPartial(c, "settings", "dbconn-card", h.dbConnCardData(display, saveErr == "", saveErr, nil))
}

// TestDBConnection dials the connection described by the card's current
// (not necessarily saved) form fields and reports reachability, and, on
// success, shows the --db-driver/--db flag values needed to actually switch
// the running server over, since that always requires a restart (see
// SaveDBConnConfig's doc comment).
func (h *Handler) TestDBConnection(c *echo.Context) error {
	driver, dsn, err := resolveDBConnInput(c)
	if err != nil {
		return c.HTML(http.StatusOK,
			`<span class="text-red-600 text-[13px]">`+template.HTMLEscapeString(err.Error())+`</span>`)
	}
	if err := storage.TestConnection(driver, dsn); err != nil {
		return c.HTML(http.StatusOK,
			`<span class="text-red-600 text-[13px]">Connection failed: `+template.HTMLEscapeString(err.Error())+`</span>`)
	}
	flags := fmt.Sprintf("--db-driver %s --db '%s'", driver, dsn)
	return c.HTML(http.StatusOK, ""+
		`<div class="flex flex-col gap-2">`+
		`<span class="text-green-600 text-[13px] font-medium">Connected successfully.</span>`+
		`<p class="text-[12px] text-slate-500">Not applied yet — restart the server with these flags to switch to it:</p>`+
		`<pre class="bg-slate-900 text-green-600 text-[11px] font-mono rounded-md px-3 py-2 overflow-x-auto">`+template.HTMLEscapeString(flags)+`</pre>`+
		`</div>`)
}

// MigrateDBConfig copies this server's configuration (see
// storage.MigrateConfigTo's doc comment for the exact table list and what's
// deliberately excluded, e.g. the request log) into the connection
// described by the card's current form fields — the same
// resolveDBConnInput TestDBConnection uses. The source (this server's
// actual live database) is never modified, so this is safe to run more
// than once against different targets; it is NOT safe to run twice against
// the same already-migrated target, which fails on duplicate keys rather
// than overwriting (the confirm dialog on the button says this). Like
// Save/Test, this never switches the live connection — that still needs a
// restart with the flags TestDBConnection shows.
func (h *Handler) MigrateDBConfig(c *echo.Context) error {
	driver, dsn, err := resolveDBConnInput(c)
	if err != nil {
		return c.HTML(http.StatusOK,
			`<span class="text-red-600 text-[13px]">`+template.HTMLEscapeString(err.Error())+`</span>`)
	}
	report, err := h.db.MigrateConfigTo(driver, dsn)
	if err != nil {
		return c.HTML(http.StatusOK, ""+
			`<div class="flex flex-col gap-2">`+
			`<span class="text-red-600 text-[13px]">Migration failed: `+template.HTMLEscapeString(err.Error())+`</span>`+
			migrationReportHTML(report)+
			`</div>`)
	}
	return c.HTML(http.StatusOK, ""+
		`<div class="flex flex-col gap-2">`+
		`<span class="text-green-600 text-[13px] font-medium">Migrated `+fmt.Sprintf("%d", report.TotalRows)+` rows. Your current database is untouched.</span>`+
		migrationReportHTML(report)+
		`<p class="text-[12px] text-slate-500">Not applied yet — restart the server with the flags above (from "Test connection") to switch to it.</p>`+
		`</div>`)
}

// migrationReportHTML renders a per-table row-count list for
// MigrateDBConfig's result fragment. Table names come from a fixed Go
// literal list in storage.MigrateConfigTo, never user input, but escaped
// anyway on general principle for anything written via string
// concatenation into an HTML response.
func migrationReportHTML(report storage.MigrationReport) string {
	var b strings.Builder
	b.WriteString(`<ul class="text-[12px] text-slate-500 font-mono list-disc list-inside">`)
	for _, t := range report.Tables {
		fmt.Fprintf(&b, "<li>%s: %d</li>", template.HTMLEscapeString(t.Table), t.Rows)
	}
	b.WriteString(`</ul>`)
	return b.String()
}

func (h *Handler) ChangeCredentials(c *echo.Context) error {
	currentPassword := c.FormValue("current_password")
	newEmail := strings.TrimSpace(c.FormValue("new_email"))
	newPassword := c.FormValue("new_password")
	confirmPassword := c.FormValue("confirm_password")

	me := currentUser(c)

	renderErr := func(msg string) error {
		return h.render(c, "settings", map[string]any{
			"AdminEmail":    me.Email,
			"CredentialErr": msg,
		})
	}

	ok, _ := h.db.CheckAdminPassword(me.ID, currentPassword)
	if !ok {
		return renderErr("Current password is incorrect.")
	}
	if newPassword != "" && newPassword != confirmPassword {
		return renderErr("New passwords do not match.")
	}
	if newPassword != "" {
		email := newEmail
		if email == "" {
			email = me.Email
		}
		if err := ValidateAdminPassword(c.Request().Context(), h.pwBreach, email, newPassword); err != nil {
			return renderErr(err.Error())
		}
	}
	if err := h.db.UpdateAdminCredentials(me.ID, newEmail, newPassword); errors.Is(err, storage.ErrUserExists) {
		return renderErr("Another user already has that email.")
	} else if err != nil {
		return renderErr("Failed to update credentials. Please try again.")
	}
	// Credentials changed: UpdateAdminCredentials deleted this user's
	// sessions, so clear the cookie and force a re-login.
	c.SetCookie(&http.Cookie{Name: sessionCookie, Value: "", HttpOnly: true, Path: "/", MaxAge: -1, Secure: secureCookie(c)}) //nolint:gosec // G124: Secure only over TLS so plain-HTTP setups (loopback, --admin-listen) still work
	return c.Redirect(http.StatusFound, h.cfg.Admin.Path+"/login")
}

func (h *Handler) BackupDB(c *echo.Context) error {
	tmp := fmt.Sprintf("%s/palisade-backup-%d.db", os.TempDir(), time.Now().UnixNano())
	if err := h.db.BackupTo(tmp); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	defer os.Remove(tmp)
	filename := fmt.Sprintf("palisade-%s.db", time.Now().Format("2006-01-02"))
	// Echo v5 reads files through an fs.FS, which rejects absolute paths.
	c.Response().Header().Set(echo.HeaderContentDisposition, `attachment; filename="`+filename+`"`)
	return c.FileFS(filepath.Base(tmp), os.DirFS(filepath.Dir(tmp)))
}

// ExportConfig downloads the configuration as JSON (issue #263).
func (h *Handler) ExportConfig(c *echo.Context) error {
	var buf bytes.Buffer
	if err := h.db.ExportConfig(&buf); err != nil {
		return fmt.Errorf("config export: %w", err)
	}
	filename := fmt.Sprintf("palisade-config-%s.json", time.Now().Format("2006-01-02"))
	c.Response().Header().Set(echo.HeaderContentDisposition, `attachment; filename="`+filename+`"`)
	return c.Blob(http.StatusOK, "application/json", buf.Bytes())
}
