package ui

import (
	"bytes"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"palisade/internal/notify/mailer"
	"palisade/internal/security/bot"
	"palisade/internal/security/challenge"
	"palisade/internal/services"
	"palisade/internal/storage"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

// ── Settings ──────────────────────────────────────────────────────────────────

// SettingsPro shows the cards add-ons (internal/ext) render as HTML. The
// rest of Settings lives in the React app (issue #355), which links here.
func (h *Handler) SettingsPro(c *echo.Context) error {
	var cards []template.HTML
	for _, card := range h.extCards {
		if html := card(c, currentUser(c).Role); html != "" {
			cards = append(cards, html)
		}
	}
	return h.render(c, "settings", map[string]any{"ExtCards": cards})
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

// ── Settings JSON (issue #355): protection and infrastructure ────────────────

// botView is the Bot Protection card. The CAPTCHA secret is write-only: a
// read says only whether one is stored, and a blank one keeps it. Flat keys,
// so the audit summary picks up the ai_* and captcha_provider fields.
type botView struct {
	Enabled          bool   `json:"enabled"`
	Threshold        int    `json:"threshold"`
	TTL              int    `json:"ttl"`
	CaptchaProvider  string `json:"captcha_provider"`
	CaptchaSiteKey   string `json:"captcha_site_key"`
	CaptchaSecret    string `json:"captcha_secret,omitempty"`
	CaptchaSecretSet bool   `json:"captcha_secret_set"`
	AITraining       string `json:"ai_training"`
	AISearch         string `json:"ai_search"`
	AIUser           string `json:"ai_user"`
}

type rateLimitView struct {
	Enabled bool    `json:"enabled"`
	RPS     float64 `json:"rps"`
	Burst   int     `json:"burst"`
}

type varnishView struct {
	Enabled bool   `json:"enabled"`
	Addr    string `json:"addr"`
}

// Protection returns the protection and infrastructure cards' settings.
func (h *Handler) Protection(c *echo.Context) error {
	botOn, threshold, ttl, err := h.db.GetBotSettings()
	if err != nil {
		return err
	}
	ai, err := h.db.GetAICrawlerPolicy()
	if err != nil {
		return err
	}
	captcha, err := h.db.GetCaptchaConfig()
	if err != nil {
		return err
	}
	rlOn, rps, burst, err := h.db.GetRateLimitSettings()
	if err != nil {
		return err
	}
	trusted, err := h.db.GetTrustedIPs()
	if err != nil {
		return err
	}
	vc, err := h.db.GetVarnishConfig()
	if err != nil {
		return err
	}
	p := bot.ParseAIPolicy(ai)
	return c.JSON(http.StatusOK, map[string]any{
		"bot": botView{Enabled: botOn, Threshold: threshold, TTL: ttl, CaptchaProvider: captcha.Provider, CaptchaSiteKey: captcha.SiteKey,
			CaptchaSecretSet: captcha.Secret != "", AITraining: p[bot.AITraining], AISearch: p[bot.AISearch], AIUser: p[bot.AIUser]},
		"rate_limit":  rateLimitView{rlOn, rps, burst},
		"trusted_ips": nonNil(trusted),
		"varnish":     varnishView{vc.Enabled, vc.Addr},
	})
}

// SetBot saves bot protection, the CAPTCHA fallback and the AI crawler
// defaults, then reloads the registry and the challenger.
func (h *Handler) SetBot(c *echo.Context) error {
	var v botView
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	rc := rangeCheck{}
	rc.num("threshold", float64(v.Threshold), 1, 100)
	rc.num("ttl", float64(v.TTL), 60, 30*86400)
	stored, err := h.db.GetCaptchaConfig()
	if err != nil {
		return err
	}
	cc := storage.CaptchaConfig{Provider: v.CaptchaProvider, SiteKey: strings.TrimSpace(v.CaptchaSiteKey), Secret: strings.TrimSpace(v.CaptchaSecret)}
	if cc.Secret == "" {
		cc.Secret = stored.Secret
	}
	if cc.Provider != "" {
		switch {
		case !challenge.ValidCaptchaProvider(cc.Provider):
			rc["captcha_provider"] = "Unknown CAPTCHA provider."
		case cc.SiteKey == "":
			rc["captcha_site_key"] = "Enter the site key."
		case cc.Secret == "":
			rc["captcha_secret"] = "Enter the secret key."
		}
	}
	ai := bot.AIPolicy{}
	for cat, a := range map[string]string{bot.AITraining: v.AITraining, bot.AISearch: v.AISearch, bot.AIUser: v.AIUser} {
		switch {
		case a == "":
		case bot.ValidAIAction(a):
			ai[cat] = a
		default:
			rc["ai_"+cat] = "Pick allow, challenge or block."
		}
	}
	if err := rc.err(); err != nil {
		return err
	}
	if err := h.db.SetBotSettings(v.Enabled, v.Threshold, v.TTL); err != nil {
		return err
	}
	if err := h.db.SetCaptchaConfig(cc); err != nil {
		return err
	}
	if err := h.db.SetAICrawlerPolicy(ai.String()); err != nil {
		return err
	}
	if err := h.registry.Reload(h.db); err != nil {
		return err
	}
	if h.reloadBot != nil && h.buildChallenger != nil {
		h.reloadBot(h.buildChallenger(v.Enabled, v.Threshold, v.TTL))
	}
	return c.NoContent(http.StatusNoContent)
}

// SetRateLimit saves the global per-IP limit and reloads the limiter. With
// the limiter off, numbers left blank keep the stored ones.
func (h *Handler) SetRateLimit(c *echo.Context) error {
	var v rateLimitView
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	if v.Enabled {
		rc := rangeCheck{}
		rc.num("rps", v.RPS, 0.1, 1e6)
		rc.num("burst", float64(v.Burst), 1, 1e6)
		if err := rc.err(); err != nil {
			return err
		}
	}
	if v.RPS <= 0 || v.Burst < 1 {
		_, rps, burst, err := h.db.GetRateLimitSettings()
		if err != nil {
			return err
		}
		if v.RPS <= 0 {
			v.RPS = rps
		}
		if v.Burst < 1 {
			v.Burst = burst
		}
	}
	if err := h.db.SetRateLimitSettings(v.Enabled, v.RPS, v.Burst); err != nil {
		return err
	}
	if h.reloadRateLimit != nil {
		h.reloadRateLimit()
	}
	return c.NoContent(http.StatusNoContent)
}

// SetTrustedIPs replaces the trusted IP list and swaps it into the registry.
func (h *Handler) SetTrustedIPs(c *echo.Context) error {
	var req struct {
		IPs string `json:"trusted_ips"`
	}
	if err := c.Bind(&req); err != nil {
		return badBody("Send a JSON body.")
	}
	var entries []string
	for _, e := range strings.Fields(req.IPs) {
		if !slices.Contains(entries, e) {
			entries = append(entries, e)
		}
	}
	nets, err := services.ParseTrustedIPs(entries)
	if err != nil {
		return fieldError("trusted_ips", err.Error()+".")
	}
	if len(entries) > trustedIPsMax {
		return fieldError("trusted_ips", fmt.Sprintf("At most %d entries.", trustedIPsMax))
	}
	if err := h.db.SetTrustedIPs(entries); err != nil {
		return err
	}
	h.registry.SetTrustedIPs(nets)
	return c.NoContent(http.StatusNoContent)
}

// SetVarnish saves the Varnish switch and address. The address must be
// loopback, or clients could reach the cache without passing the WAF. The
// cache-return address isn't editable (it must match the installed VCL), so
// a save keeps the stored one.
func (h *Handler) SetVarnish(c *echo.Context) error {
	var v varnishView
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	if v.Addr = strings.TrimSpace(v.Addr); v.Addr == "" {
		v.Addr = storage.DefaultVarnishAddr
	}
	if host, _, err := net.SplitHostPort(v.Addr); err != nil {
		return fieldError("addr", "Enter host:port, e.g. 127.0.0.1:6081.")
	} else if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fieldError("addr", "Use a loopback address, or clients could reach the cache without passing the WAF.")
	}
	stored, err := h.db.GetVarnishConfig()
	if err != nil {
		return err
	}
	if err := h.db.SetVarnishConfig(storage.VarnishConfig{Enabled: v.Enabled, Addr: v.Addr, ReturnAddr: stored.ReturnAddr}); err != nil {
		return err
	}
	if err := h.registry.Reload(h.db); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Settings JSON: alerts and activity ───────────────────────────────────────

// webhookView is the Webhook card. The secret goes back to the owner, as
// it always has: blank means no X-WAF-Secret header, not "keep".
type webhookView struct {
	Enabled         bool     `json:"enabled"`
	URL             string   `json:"url"`
	Secret          string   `json:"secret"`
	Events          []string `json:"events"`
	DestinationType string   `json:"destination_type"`
}

// emailView is the Email Alerts card. The token is write-only: a read says
// only whether one is stored, and a blank one keeps it.
type emailView struct {
	Enabled  bool   `json:"enabled"`
	Sender   string `json:"sender,omitempty"`
	To       string `json:"to"`
	Token    string `json:"token,omitempty"`
	TokenSet bool   `json:"token_set"`
}

var webhookEvents = []string{"blocked", "challenged", "scripts"}

// Alerts returns the webhook and email settings (owner only).
func (h *Handler) Alerts(c *echo.Context) error {
	wh, err := h.db.GetWebhookConfig()
	if err != nil {
		return err
	}
	ec, err := h.db.GetEmailConfig()
	if err != nil {
		return err
	}
	var events []string
	for e := range strings.SplitSeq(wh.Events, ",") {
		if e = strings.TrimSpace(e); slices.Contains(webhookEvents, e) {
			events = append(events, e)
		}
	}
	return c.JSON(http.StatusOK, map[string]any{
		"webhook": webhookView{wh.Enabled, wh.URL, wh.Secret, nonNil(events), wh.DestinationType},
		"email":   emailView{Enabled: ec.Enabled, Sender: mailer.Sender, To: ec.To, TokenSet: ec.Token != ""},
	})
}

// SetWebhook saves the webhook. An empty URL turns it off; no events
// selected means blocked requests only, as before.
func (h *Handler) SetWebhook(c *echo.Context) error {
	var v webhookView
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	v.URL, v.Secret = strings.TrimSpace(v.URL), strings.TrimSpace(v.Secret)
	if v.URL != "" {
		if err := validateOutboundURL(v.URL); err != nil {
			return fieldError("url", err.Error())
		}
	}
	for _, e := range v.Events {
		if !slices.Contains(webhookEvents, e) {
			return fieldError("events", "Unknown event "+strconv.Quote(e)+".")
		}
	}
	events := strings.Join(v.Events, ",")
	if events == "" {
		events = "blocked"
	}
	return h.saved(c, h.db.SetWebhookConfig(storage.WebhookConfig{URL: v.URL, Secret: v.Secret, Enabled: v.Enabled && v.URL != "", Events: events, DestinationType: v.DestinationType}))
}

// SetEmail saves the daily report email. A blank token keeps the stored one.
func (h *Handler) SetEmail(c *echo.Context) error {
	var v emailView
	if err := c.Bind(&v); err != nil {
		return badBody("Send a JSON body.")
	}
	stored, err := h.db.GetEmailConfig()
	if err != nil {
		return err
	}
	cfg := storage.EmailConfig{Enabled: v.Enabled, To: strings.TrimSpace(v.To), Token: strings.TrimSpace(v.Token)}
	if cfg.Token == "" {
		cfg.Token = stored.Token
	}
	if cfg.Enabled {
		rc := rangeCheck{}
		if cfg.To == "" {
			rc["to"] = "Enter at least one recipient."
		}
		if cfg.Token == "" {
			rc["token"] = "Enter the Cloudflare API token."
		}
		if err := rc.err(); err != nil {
			return err
		}
	}
	return h.saved(c, h.db.SetEmailConfig(cfg))
}

// saved answers a write: 204, or the error for jsonErrors to log as a 500.
func (h *Handler) saved(c *echo.Context, err error) error {
	if err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// sendTest runs a test send: 204, or a 502 that says why it failed.
func sendTest(c *echo.Context, send func() error, what string) error {
	if send == nil {
		return &jsonError{Status: http.StatusServiceUnavailable, Code: "unavailable", Message: what + " isn't available."}
	}
	if err := send(); err != nil {
		return &jsonError{Status: http.StatusBadGateway, Code: "send_failed", Message: "Send failed: " + err.Error()}
	}
	return c.NoContent(http.StatusNoContent)
}

// TestWebhookJSON sends one synthetic event with the saved settings.
func (h *Handler) TestWebhookJSON(c *echo.Context) error {
	return sendTest(c, h.sendTestWebhook, "Webhook delivery")
}

// TestEmailJSON sends the last 24 hours' report with the saved settings.
func (h *Handler) TestEmailJSON(c *echo.Context) error {
	return sendTest(c, h.sendReportNow, "Email reporting")
}

type auditJSON struct {
	TS      string `json:"ts"`
	Actor   string `json:"actor"`
	IP      string `json:"ip"`
	Action  string `json:"action"`
	Target  string `json:"target"`
	Summary string `json:"summary"`
}

// Audit returns one page of the audit log (?page=, clamped to the last).
func (h *Handler) Audit(c *echo.Context) error {
	page, _ := strconv.Atoi(c.QueryParam("page"))
	d, err := h.auditRowsData(page)
	if err != nil {
		return err
	}
	entries := []auditJSON{}
	for _, e := range d["Entries"].([]storage.AuditEntry) {
		entries = append(entries, auditJSON{rfc3339(e.TS), e.Actor, e.IP, e.Action, e.Target, e.Summary})
	}
	return c.JSON(http.StatusOK, map[string]any{"entries": entries, "page": d["CurPage"], "pages": d["TotalPages"], "total": d["Total"]})
}
