package ui

import (
	"fmt"
	"net"
	"net/http"
	"palisade/internal/storage"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/labstack/echo/v5"
)

// ── IP Rules ───────────────────────────────────────────────────────────────────
// The page lives in the React app (issue #351); these are its JSON endpoints.

// ipRulesPageSize caps how many rows one page of the list pulls into
// memory. Autoban can grow ip_rules into the thousands.
const ipRulesPageSize = 16

// bulkMax caps how many IPs, countries or ids one bulk add or remove takes.
const bulkMax = 500

// fieldError is a 400 for one form field.
func fieldError(field, msg string) *jsonError {
	return &jsonError{Status: http.StatusBadRequest, Code: "invalid", Message: msg, Fields: map[string]string{field: msg}}
}

type ipRuleView struct {
	ID        int       `json:"id"`
	AppName   string    `json:"app_name"`
	IP        string    `json:"ip"`
	RuleType  string    `json:"rule_type"`
	Note      string    `json:"note"`
	Auto      bool      `json:"auto"`
	Score     int       `json:"score"`
	CreatedAt time.Time `json:"created_at"`
}

// ListIPRules returns one page of rules (newest first) with their threat
// scores, plus whole-table block/allow counts. A page past the end falls
// back to the last one, so a page emptied by a delete never shows nothing.
func (h *Handler) ListIPRules(c *echo.Context) error {
	page, _ := strconv.Atoi(c.QueryParam("page"))
	page = max(page, 1)
	rules, total, err := h.db.ListIPRulesPaginated(ipRulesPageSize, (page-1)*ipRulesPageSize)
	if err != nil {
		return err
	}
	totalPages := max(1, (total+ipRulesPageSize-1)/ipRulesPageSize)
	if page > totalPages {
		page = totalPages
		if rules, _, err = h.db.ListIPRulesPaginated(ipRulesPageSize, (page-1)*ipRulesPageSize); err != nil {
			return err
		}
	}
	ips := make([]string, len(rules))
	for i, r := range rules {
		ips[i] = r.IP
	}
	scores, err := h.db.GetIPThreatScores(ips)
	if err != nil {
		return err
	}
	blockCount, allowCount, err := h.db.CountIPRulesByType()
	if err != nil {
		return err
	}
	views := make([]ipRuleView, len(rules))
	for i, r := range rules {
		views[i] = ipRuleView{r.ID, r.AppName, r.IP, r.RuleType, r.Note, r.Auto(), scores[r.IP], r.CreatedAt}
	}
	return c.JSON(http.StatusOK, map[string]any{
		"rules": views, "page": page, "total_pages": totalPages, "total": total,
		"block_count": blockCount, "allow_count": allowCount,
	})
}

type ruleAddRequest struct {
	AppName  string `json:"app_name"`
	RuleType string `json:"rule_type"`
}

func (h *Handler) checkRuleAdd(r ruleAddRequest) error {
	if r.RuleType != "block" && r.RuleType != "allow" {
		return fieldError("rule_type", "Choose block or allow.")
	}
	if r.AppName != "" && !h.serviceExists(r.AppName) {
		return fieldError("app_name", "No service has that name.")
	}
	return nil
}

// canonicalIP accepts an IP or CIDR range and returns its canonical form
// ("10.0.1.5/24" → "10.0.1.0/24", "::ffff:1.2.3.4" → "1.2.3.4").
func canonicalIP(s string) (string, bool) {
	if _, network, err := net.ParseCIDR(s); err == nil {
		return network.String(), true
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", false
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), true
	}
	return ip.String(), true
}

// AddIPRules adds one rule per IP or CIDR in ip (separated by whitespace or
// commas), all or none: one bad entry refuses the lot.
func (h *Handler) AddIPRules(c *echo.Context) error {
	var req struct {
		ruleAddRequest
		IP string `json:"ip"`
	}
	if err := c.Bind(&req); err != nil {
		return fieldError("ip", "Send a JSON body.")
	}
	if err := h.checkRuleAdd(req.ruleAddRequest); err != nil {
		return err
	}
	var ips []string
	for _, f := range strings.FieldsFunc(req.IP, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
		ip, ok := canonicalIP(f)
		if !ok {
			return fieldError("ip", fmt.Sprintf("%q is not an IP or CIDR range (e.g. 1.2.3.4, ::1, 10.0.0.0/8).", f))
		}
		if !slices.Contains(ips, ip) {
			ips = append(ips, ip)
		}
	}
	switch {
	case len(ips) == 0:
		return fieldError("ip", "Enter an IP or CIDR range.")
	case len(ips) > bulkMax:
		return fieldError("ip", fmt.Sprintf("At most %d entries at once.", bulkMax))
	}
	for _, ip := range ips {
		if err := h.db.AddIPRule(req.AppName, ip, req.RuleType); err != nil {
			return err
		}
	}
	if err := h.ipbl.Reload(h.db); err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, map[string]int{"added": len(ips)})
}

// removeIDs reads {"ids": [...]} for a bulk remove.
func removeIDs(c *echo.Context) ([]int, error) {
	var req struct {
		IDs []int `json:"ids"`
	}
	if err := c.Bind(&req); err != nil || len(req.IDs) == 0 || len(req.IDs) > bulkMax {
		return nil, &jsonError{Status: http.StatusBadRequest, Code: "invalid", Message: fmt.Sprintf("Select between 1 and %d rules.", bulkMax)}
	}
	return req.IDs, nil
}

// RemoveIPRules deletes the rules with the given ids. An id that's already
// gone is not an error.
func (h *Handler) RemoveIPRules(c *echo.Context) error {
	ids, err := removeIDs(c)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := h.db.RemoveIPRule(id); err != nil {
			return err
		}
	}
	if err := h.ipbl.Reload(h.db); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

type autobanView struct {
	Enabled   bool   `json:"enabled"`
	Threshold int    `json:"threshold"`
	Window    int    `json:"window"`
	BanHours  int    `json:"ban_hours"`
	BadStatus bool   `json:"bad_status"`
	BadCodes  string `json:"bad_codes"`
	BadPoints int    `json:"bad_points"`
}

type adaptiveView struct {
	Enabled        bool    `json:"enabled"`
	HighThreshold  int     `json:"high_threshold"`
	LowThreshold   int     `json:"low_threshold"`
	HighScale      float64 `json:"high_scale"`
	LowScale       float64 `json:"low_scale"`
	ForceChallenge int     `json:"force_challenge"`
}

// IPRulesSettings returns the automatic banning, adaptive enforcement and
// honeypot cards' settings.
func (h *Handler) IPRulesSettings(c *echo.Context) error {
	ab, err := h.db.GetAutobanConfig()
	if err != nil {
		return err
	}
	ad, err := h.db.GetAdaptiveEnforcementConfig()
	if err != nil {
		return err
	}
	honeypots, err := h.db.GetHoneypotPaths()
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{
		"autoban":        autobanView{ab.Enabled, ab.Threshold, ab.WindowMinutes, ab.BanHours, ab.BadStatusEnabled, storage.FormatStatusCodes(ab.BadStatusCodes), ab.BadStatusPoints},
		"adaptive":       adaptiveView{ad.Enabled, ad.HighRiskThreshold, ad.LowRiskThreshold, ad.HighRiskRateScale, ad.LowRiskRateScale, ad.ForceChallengeThreshold},
		"honeypot_paths": nonNil(honeypots),
	})
}

// rangeCheck collects a field error for each value outside its range.
type rangeCheck map[string]string

func (rc rangeCheck) num(field string, v, lo, hi float64) {
	if v < lo || v > hi {
		rc[field] = fmt.Sprintf("Between %v and %v.", lo, hi)
	}
}

func (rc rangeCheck) err() error {
	if len(rc) == 0 {
		return nil
	}
	return &jsonError{Status: http.StatusBadRequest, Code: "invalid", Message: "Fix the highlighted fields.", Fields: rc}
}

// SaveAutobanSettings persists the automatic banning settings and
// hot-reloads the banner so they apply immediately.
func (h *Handler) SaveAutobanSettings(c *echo.Context) error {
	var v autobanView
	if err := c.Bind(&v); err != nil {
		return &jsonError{Status: http.StatusBadRequest, Code: "invalid", Message: "Send a JSON body."}
	}
	rc := rangeCheck{}
	rc.num("threshold", float64(v.Threshold), 1, 1000)
	rc.num("window", float64(v.Window), 1, 1440)
	rc.num("ban_hours", float64(v.BanHours), 0, 8760)
	rc.num("bad_points", float64(v.BadPoints), 1, 1000)
	codes := storage.ParseStatusCodes(v.BadCodes)
	if len(codes) == 0 {
		rc["bad_codes"] = "List at least one status code from 100 to 599."
	}
	if err := rc.err(); err != nil {
		return err
	}
	cfg := storage.AutobanConfig{Enabled: v.Enabled, Threshold: v.Threshold, WindowMinutes: v.Window, BanHours: v.BanHours,
		BadStatusEnabled: v.BadStatus, BadStatusCodes: codes, BadStatusPoints: v.BadPoints}
	if err := h.db.SetAutobanConfig(cfg); err != nil {
		return err
	}
	if h.reloadAutoban != nil {
		h.reloadAutoban()
	}
	return c.NoContent(http.StatusNoContent)
}

// SaveAdaptiveSettings persists the adaptive enforcement settings and
// hot-reloads the policy so they apply immediately.
func (h *Handler) SaveAdaptiveSettings(c *echo.Context) error {
	var v adaptiveView
	if err := c.Bind(&v); err != nil {
		return &jsonError{Status: http.StatusBadRequest, Code: "invalid", Message: "Send a JSON body."}
	}
	rc := rangeCheck{}
	rc.num("high_threshold", float64(v.HighThreshold), 1, 100)
	rc.num("low_threshold", float64(v.LowThreshold), 0, 99)
	rc.num("high_scale", v.HighScale, 0.05, 1)
	rc.num("low_scale", v.LowScale, 1, 5)
	rc.num("force_challenge", float64(v.ForceChallenge), 1, 100)
	if err := rc.err(); err != nil {
		return err
	}
	cfg := storage.AdaptiveEnforcementConfig{Enabled: v.Enabled, HighRiskThreshold: v.HighThreshold, LowRiskThreshold: v.LowThreshold,
		HighRiskRateScale: v.HighScale, LowRiskRateScale: v.LowScale, ForceChallengeThreshold: v.ForceChallenge}
	if err := h.db.SetAdaptiveEnforcementConfig(cfg); err != nil {
		return err
	}
	if h.reloadAdaptive != nil {
		h.reloadAdaptive()
	}
	return c.NoContent(http.StatusNoContent)
}

// honeypotMax caps the honeypot list; every proxied 404 scans it.
const honeypotMax = 200

// SaveHoneypots replaces the honeypot path list (issue #130) and swaps it
// into the registry, which the proxy checks on every 404.
func (h *Handler) SaveHoneypots(c *echo.Context) error {
	var req struct {
		Paths string `json:"honeypot_paths"`
	}
	if err := c.Bind(&req); err != nil {
		return fieldError("honeypot_paths", "Send a JSON body.")
	}
	var paths []string
	for _, p := range strings.Fields(req.Paths) {
		if !strings.HasPrefix(p, "/") || p == "/" {
			return fieldError("honeypot_paths", fmt.Sprintf("%q is not a path: start it with / and name something under the root.", p))
		}
		if !slices.Contains(paths, p) {
			paths = append(paths, p)
		}
	}
	if len(paths) > honeypotMax {
		return fieldError("honeypot_paths", fmt.Sprintf("At most %d paths.", honeypotMax))
	}
	if err := h.db.SetHoneypotPaths(paths); err != nil {
		return err
	}
	h.registry.SetHoneypots(paths)
	return c.NoContent(http.StatusNoContent)
}

// trustedIPsMax caps the trusted list; every proxied request scans it.
const trustedIPsMax = 200
