package storage

import (
	"strconv"
	"strings"
	"time"
)

// ── Autoban config ───────────────────────────────────────────────────────────

// AutobanConfig controls the automatic IP banner (autoban package). Stored in
// the meta table and managed from the IP Rules page.
type AutobanConfig struct {
	Enabled       bool
	Threshold     int // points within the window that trigger a ban
	WindowMinutes int // sliding window size
	BanHours      int // how long a ban lasts; 0 = never expires (issue #156)

	// Bad-status scoring (issue #193): a backend response with one of these
	// codes to a request Palisade let through scores BadStatusPoints.
	BadStatusEnabled bool
	BadStatusCodes   []int
	BadStatusPoints  int
}

// DefaultAutobanConfig is used when nothing is stored yet: enabled, ban for
// 24 hours at 10 points in 10 minutes (≈2 critical WAF hits, 4 generic WAF
// hits, or 10 rate-limited requests — see autoban's scoring).
func DefaultAutobanConfig() AutobanConfig {
	return AutobanConfig{Enabled: true, Threshold: 10, WindowMinutes: 10, BanHours: 24,
		BadStatusCodes: []int{400, 401, 403, 404, 405, 444}, BadStatusPoints: 1}
}

// ParseStatusCodes reads a comma- or space-separated list of HTTP status
// codes, dropping anything outside 100–599.
func ParseStatusCodes(s string) []int {
	var codes []int
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if n, err := strconv.Atoi(f); err == nil && n >= 100 && n <= 599 {
			codes = append(codes, n)
		}
	}
	return codes
}

// FormatStatusCodes is the inverse of ParseStatusCodes.
func FormatStatusCodes(codes []int) string {
	parts := make([]string, len(codes))
	for i, c := range codes {
		parts[i] = strconv.Itoa(c)
	}
	return strings.Join(parts, ", ")
}

func (db *DB) GetAutobanConfig() (AutobanConfig, error) {
	cfg := DefaultAutobanConfig()
	if v, err := db.getMeta("autoban_enabled"); err != nil {
		return cfg, err
	} else if v != "" {
		cfg.Enabled = v == "1"
	}
	if v, _ := db.getMeta("autoban_threshold"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.Threshold = n
		}
	}
	if v, _ := db.getMeta("autoban_window_min"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.WindowMinutes = n
		}
	}
	if v, _ := db.getMeta("autoban_ban_hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.BanHours = n
		}
	}
	if v, _ := db.getMeta("autoban_bad_status"); v != "" {
		cfg.BadStatusEnabled = v == "1"
	}
	if v, _ := db.getMeta("autoban_bad_status_codes"); v != "" {
		cfg.BadStatusCodes = ParseStatusCodes(v)
	}
	if v, _ := db.getMeta("autoban_bad_status_points"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.BadStatusPoints = n
		}
	}
	return cfg, nil
}

func (db *DB) SetAutobanConfig(cfg AutobanConfig) error {
	enabled := "0"
	if cfg.Enabled {
		enabled = "1"
	}
	if err := db.setMeta("autoban_enabled", enabled); err != nil {
		return err
	}
	if err := db.setMeta("autoban_threshold", strconv.Itoa(cfg.Threshold)); err != nil {
		return err
	}
	if err := db.setMeta("autoban_window_min", strconv.Itoa(cfg.WindowMinutes)); err != nil {
		return err
	}
	if err := db.setMeta("autoban_ban_hours", strconv.Itoa(cfg.BanHours)); err != nil {
		return err
	}
	bad := "0"
	if cfg.BadStatusEnabled {
		bad = "1"
	}
	if err := db.setMeta("autoban_bad_status", bad); err != nil {
		return err
	}
	if err := db.setMeta("autoban_bad_status_codes", FormatStatusCodes(cfg.BadStatusCodes)); err != nil {
		return err
	}
	return db.setMeta("autoban_bad_status_points", strconv.Itoa(cfg.BadStatusPoints))
}

// ExpireAutobans deletes automatic ban rules created before cutoff and
// returns how many were removed. Only autoban's own global rules match, so
// admin and API rules never expire.
func (db *DB) ExpireAutobans(cutoff time.Time) (int64, error) {
	res, err := db.exec(
		`DELETE FROM ip_rules WHERE app_name = '' AND rule_type = 'block' AND note LIKE 'Auto-banned%' AND created_at < ?`,
		cutoff.UTC(),
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// GetHoneypotPaths returns the honeypot path list (issue #130); see
// services.Registry.Honeypot for how an entry matches.
func (db *DB) GetHoneypotPaths() ([]string, error) {
	v, err := db.getMeta("honeypot_paths")
	return strings.Fields(v), err
}

func (db *DB) SetHoneypotPaths(paths []string) error {
	return db.setMeta("honeypot_paths", strings.Join(paths, "\n"))
}

// GetTrustedIPs returns the IPs and CIDRs that skip every blocking stage
// (issue #179); see services.Registry.Trusted.
func (db *DB) GetTrustedIPs() ([]string, error) {
	v, err := db.getMeta("trusted_ips")
	return strings.Fields(v), err
}

func (db *DB) SetTrustedIPs(entries []string) error {
	return db.setMeta("trusted_ips", strings.Join(entries, "\n"))
}

// ── Adaptive enforcement config ──────────────────────────────────────────────

// AdaptiveEnforcementConfig controls threat-score-driven adaptive
// enforcement (the adaptive package, issue #16): dynamically scaling the
// global rate limit and forcing a bot challenge based on a client's current
// composite threat score (threatscore package, issue #12). Stored in the
// meta table and managed from the IP Rules page, next to Autoban.
type AdaptiveEnforcementConfig struct {
	Enabled                 bool
	HighRiskThreshold       int     // score >= this: tighten the rate limit
	LowRiskThreshold        int     // score <= this: relax the rate limit
	HighRiskRateScale       float64 // multiplies rate+burst for high-risk IPs, e.g. 0.3
	LowRiskRateScale        float64 // multiplies rate+burst for low-risk IPs, e.g. 1.5
	ForceChallengeThreshold int     // score >= this: force a bot challenge regardless of per-service bot_mode
}

// DefaultAdaptiveEnforcementConfig is used when nothing is stored yet.
// Disabled by default — unlike autoban, this is a brand-new mechanism
// driven by a heuristic composite score (see threatscore's ASN/hosting
// classification) and includes a security-*loosening* action (relaxing
// rate limits for low-risk IPs); an admin should see real scores on the IP
// Rules page before opting in, rather than have enforcement silently start
// adjusting traffic on upgrade.
func DefaultAdaptiveEnforcementConfig() AdaptiveEnforcementConfig {
	return AdaptiveEnforcementConfig{
		Enabled: false, HighRiskThreshold: 70, LowRiskThreshold: 10,
		HighRiskRateScale: 0.3, LowRiskRateScale: 1.5, ForceChallengeThreshold: 70,
	}
}

func (db *DB) GetAdaptiveEnforcementConfig() (AdaptiveEnforcementConfig, error) {
	cfg := DefaultAdaptiveEnforcementConfig()
	if v, err := db.getMeta("adaptive_enabled"); err != nil {
		return cfg, err
	} else if v != "" {
		cfg.Enabled = v == "1"
	}
	if v, _ := db.getMeta("adaptive_high_threshold"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.HighRiskThreshold = n
		}
	}
	if v, _ := db.getMeta("adaptive_low_threshold"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.LowRiskThreshold = n
		}
	}
	if v, _ := db.getMeta("adaptive_high_rate_scale"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			cfg.HighRiskRateScale = f
		}
	}
	if v, _ := db.getMeta("adaptive_low_rate_scale"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			cfg.LowRiskRateScale = f
		}
	}
	if v, _ := db.getMeta("adaptive_force_challenge_threshold"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.ForceChallengeThreshold = n
		}
	}
	return cfg, nil
}

func (db *DB) SetAdaptiveEnforcementConfig(cfg AdaptiveEnforcementConfig) error {
	enabled := "0"
	if cfg.Enabled {
		enabled = "1"
	}
	if err := db.setMeta("adaptive_enabled", enabled); err != nil {
		return err
	}
	if err := db.setMeta("adaptive_high_threshold", strconv.Itoa(cfg.HighRiskThreshold)); err != nil {
		return err
	}
	if err := db.setMeta("adaptive_low_threshold", strconv.Itoa(cfg.LowRiskThreshold)); err != nil {
		return err
	}
	if err := db.setMeta("adaptive_high_rate_scale", strconv.FormatFloat(cfg.HighRiskRateScale, 'f', -1, 64)); err != nil {
		return err
	}
	if err := db.setMeta("adaptive_low_rate_scale", strconv.FormatFloat(cfg.LowRiskRateScale, 'f', -1, 64)); err != nil {
		return err
	}
	return db.setMeta("adaptive_force_challenge_threshold", strconv.Itoa(cfg.ForceChallengeThreshold))
}

// ── Varnish cache config ─────────────────────────────────────────────────────

// VarnishConfig controls the optional Varnish accelerator sitting between the
// WAF and cache-enabled backends. Stored in the meta table and managed from
// the Settings page. Traffic makes a loopback round trip:
//
//	client → WAF (:80/:443) → varnishd (Addr) → WAF cache-return (ReturnAddr) → backend
//
// Cache misses come back to the WAF's cache-return listener, which routes to
// the real backend from the services table — so the Varnish VCL needs exactly
// one static backend (ReturnAddr) and never changes when services do. Both
// addresses must stay loopback-only so nothing reaches the cache, or the
// return listener's direct-to-backend path, without passing the WAF first.
type VarnishConfig struct {
	Enabled    bool
	Addr       string // host:port of varnishd, e.g. "127.0.0.1:6081"
	ReturnAddr string // host:port the WAF's cache-return listener binds, e.g. "127.0.0.1:6082"
}

// DefaultVarnishAddr and DefaultVarnishReturnAddr match the deploy/varnish
// systemd configuration and the VCL's single backend.
const (
	DefaultVarnishAddr       = "127.0.0.1:6081"
	DefaultVarnishReturnAddr = "127.0.0.1:6082"
)

func (db *DB) GetVarnishConfig() (VarnishConfig, error) {
	cfg := VarnishConfig{Addr: DefaultVarnishAddr, ReturnAddr: DefaultVarnishReturnAddr}
	v, err := db.getMeta("varnish_enabled")
	if err != nil {
		return cfg, err
	}
	cfg.Enabled = v == "1"
	if addr, _ := db.getMeta("varnish_addr"); addr != "" {
		cfg.Addr = addr
	}
	if addr, _ := db.getMeta("varnish_return_addr"); addr != "" {
		cfg.ReturnAddr = addr
	}
	return cfg, nil
}

func (db *DB) SetVarnishConfig(cfg VarnishConfig) error {
	enabled := "0"
	if cfg.Enabled {
		enabled = "1"
	}
	if err := db.setMeta("varnish_enabled", enabled); err != nil {
		return err
	}
	if err := db.setMeta("varnish_addr", cfg.Addr); err != nil {
		return err
	}
	if cfg.ReturnAddr == "" {
		cfg.ReturnAddr = DefaultVarnishReturnAddr
	}
	return db.setMeta("varnish_return_addr", cfg.ReturnAddr)
}

// GetBotSettings reads global bot protection settings from the meta table.
// Returns defaults (disabled, threshold=8, ttl=3600) if not yet configured.
func (db *DB) GetBotSettings() (enabled bool, threshold, ttl int, err error) {
	threshold, ttl = 8, 3600
	if v, e := db.getMeta("bot_enabled"); e == nil {
		enabled = v == "1"
	}
	if v, e := db.getMeta("bot_threshold"); e == nil && v != "" {
		if n, e2 := strconv.Atoi(v); e2 == nil && n > 0 {
			threshold = n
		}
	}
	if v, e := db.getMeta("bot_ttl"); e == nil && v != "" {
		if n, e2 := strconv.Atoi(v); e2 == nil && n > 0 {
			ttl = n
		}
	}
	return
}

// SetBotSettings persists global bot protection settings to the meta table.
func (db *DB) SetBotSettings(enabled bool, threshold, ttl int) error {
	v := "0"
	if enabled {
		v = "1"
	}
	if err := db.setMeta("bot_enabled", v); err != nil {
		return err
	}
	if err := db.setMeta("bot_threshold", strconv.Itoa(threshold)); err != nil {
		return err
	}
	return db.setMeta("bot_ttl", strconv.Itoa(ttl))
}

// CaptchaConfig is the optional CAPTCHA fallback on the bot challenge page
// (issue #133). Provider is "" (off), "turnstile" or "hcaptcha".
type CaptchaConfig struct {
	Provider, SiteKey, Secret string
}

func (db *DB) GetCaptchaConfig() (CaptchaConfig, error) {
	var c CaptchaConfig
	var err error
	if c.Provider, err = db.getMeta("captcha_provider"); err != nil {
		return CaptchaConfig{}, err
	}
	if c.SiteKey, err = db.getMeta("captcha_site_key"); err != nil {
		return CaptchaConfig{}, err
	}
	if c.Secret, err = db.getSecretMeta("captcha_secret"); err != nil {
		return CaptchaConfig{}, err
	}
	return c, nil
}

func (db *DB) SetCaptchaConfig(c CaptchaConfig) error {
	if err := db.setMeta("captcha_provider", c.Provider); err != nil {
		return err
	}
	if err := db.setMeta("captcha_site_key", c.SiteKey); err != nil {
		return err
	}
	return db.setSecretMeta("captcha_secret", c.Secret)
}
