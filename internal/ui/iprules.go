package ui

import (
	"fmt"
	"net"
	"net/http"
	"palisade/internal/services"
	"palisade/internal/storage"
	"slices"
	"strconv"
	"strings"

	"github.com/labstack/echo/v5"
)

// ── IP Rules ───────────────────────────────────────────────────────────────────

// ipRulesPageSize caps how many rows the IP Rules admin page pulls into
// memory per request. Autoban can grow ip_rules into the thousands, and the
// page used to load the whole table on every view and every add/delete.
const ipRulesPageSize = 16

// ipRulesRowsData fetches one page of rules for the ip-rules-rows partial,
// clamping page into range so a page that just emptied out (e.g. the last
// row on it was deleted) falls back to the new last page instead of
// rendering nothing. Shared by the full page render and every HTMX action
// that re-renders just the rows (add, delete, Prev/Next).
func (h *Handler) ipRulesRowsData(page int) (map[string]any, error) {
	if page < 1 {
		page = 1
	}
	rules, total, err := h.db.ListIPRulesPaginated(ipRulesPageSize, (page-1)*ipRulesPageSize)
	if err != nil {
		return nil, err
	}
	totalPages := max(1, (total+ipRulesPageSize-1)/ipRulesPageSize)
	if page > totalPages {
		page = totalPages
		if rules, _, err = h.db.ListIPRulesPaginated(ipRulesPageSize, (page-1)*ipRulesPageSize); err != nil {
			return nil, err
		}
	}

	// Bulk-fetch this page's threat scores in one query rather than one
	// lookup per row; see internal/security/threatscore.
	ips := make([]string, len(rules))
	for i, r := range rules {
		ips[i] = r.IP
	}
	threatScores, err := h.db.GetIPThreatScores(ips)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"AdminPath":    h.cfg.Admin.Path,
		"Rules":        rules,
		"ThreatScores": threatScores,
		"CurPage":      page, // matches the Logs page's pagination fields; can't use "Page" because h.render overwrites that key with the template name for nav highlighting
		"TotalPages":   totalPages,
		"Total":        total,
	}, nil
}

func (h *Handler) IPRulesPage(c *echo.Context) error {
	page, _ := strconv.Atoi(c.QueryParam("page"))
	data, err := h.ipRulesRowsData(page)
	if err != nil {
		return err
	}

	// Block/allow counts and percentages must reflect the whole table, not
	// just the current page, so they're a separate query rather than derived
	// from the paginated rows.
	blockCount, allowCount, err := h.db.CountIPRulesByType()
	if err != nil {
		return err
	}
	blockPct, allowPct := 0, 0
	if grandTotal := blockCount + allowCount; grandTotal > 0 {
		blockPct = blockCount * 100 / grandTotal
		allowPct = allowCount * 100 / grandTotal
	}

	ab, _ := h.db.GetAutobanConfig()
	ad, _ := h.db.GetAdaptiveEnforcementConfig()
	data["Apps"] = h.registry.List()
	data["BlockCount"] = blockCount
	data["AllowCount"] = allowCount
	data["BlockPct"] = blockPct
	data["AllowPct"] = allowPct
	data["AutobanEnabled"] = ab.Enabled
	data["AutobanThresh"] = ab.Threshold
	data["AutobanWindow"] = ab.WindowMinutes
	data["AutobanBanHours"] = ab.BanHours
	data["AutobanBadStatus"] = ab.BadStatusEnabled
	data["AutobanBadCodes"] = storage.FormatStatusCodes(ab.BadStatusCodes)
	data["AutobanBadPoints"] = ab.BadStatusPoints
	data["AdaptiveEnabled"] = ad.Enabled
	data["AdaptiveHighThresh"] = ad.HighRiskThreshold
	data["AdaptiveLowThresh"] = ad.LowRiskThreshold
	data["AdaptiveHighScale"] = ad.HighRiskRateScale
	data["AdaptiveLowScale"] = ad.LowRiskRateScale
	data["AdaptiveForceChallenge"] = ad.ForceChallengeThreshold
	data["HoneypotPaths"], _ = h.db.GetHoneypotPaths()
	return h.render(c, "ip_rules", data)
}

// IPRulesRows renders just the paginated rows partial. The Prev/Next
// buttons hx-get this so paging never reloads the whole page.
func (h *Handler) IPRulesRows(c *echo.Context) error {
	page, _ := strconv.Atoi(c.QueryParam("page"))
	data, err := h.ipRulesRowsData(page)
	if err != nil {
		return err
	}
	return h.renderPartial(c, "ip_rules", "ip-rules-rows", data)
}

// SaveAutobanSettings persists the automatic-banning knobs shown on the IP
// Rules page and hot-reloads the banner so they apply immediately.
func (h *Handler) SaveAutobanSettings(c *echo.Context) error {
	cfg := storage.DefaultAutobanConfig()
	cfg.Enabled = c.FormValue("autoban_enabled") == "1"
	if n, err := strconv.Atoi(c.FormValue("autoban_threshold")); err == nil && n >= 1 && n <= 1000 {
		cfg.Threshold = n
	}
	if n, err := strconv.Atoi(c.FormValue("autoban_window")); err == nil && n >= 1 && n <= 1440 {
		cfg.WindowMinutes = n
	}
	if n, err := strconv.Atoi(c.FormValue("autoban_ban_hours")); err == nil && n >= 0 && n <= 8760 {
		cfg.BanHours = n
	}
	cfg.BadStatusEnabled = c.FormValue("autoban_bad_status") == "1"
	if codes := storage.ParseStatusCodes(c.FormValue("autoban_bad_codes")); len(codes) > 0 {
		cfg.BadStatusCodes = codes
	}
	if n, err := strconv.Atoi(c.FormValue("autoban_bad_points")); err == nil && n >= 1 && n <= 1000 {
		cfg.BadStatusPoints = n
	}
	saveErr := ""
	if err := h.db.SetAutobanConfig(cfg); err != nil {
		saveErr = "Could not save: " + err.Error()
	} else if h.reloadAutoban != nil {
		h.reloadAutoban()
	}
	return h.renderPartial(c, "ip_rules", "autoban-card", map[string]any{
		"AutobanEnabled":   cfg.Enabled,
		"AutobanThresh":    cfg.Threshold,
		"AutobanWindow":    cfg.WindowMinutes,
		"AutobanBanHours":  cfg.BanHours,
		"AutobanBadStatus": cfg.BadStatusEnabled,
		"AutobanBadCodes":  storage.FormatStatusCodes(cfg.BadStatusCodes),
		"AutobanBadPoints": cfg.BadStatusPoints,
		"AutobanSaveOK":    saveErr == "",
		"AutobanSaveErr":   saveErr,
	})
}

// honeypotMax caps the honeypot list; every proxied 404 scans it.
const honeypotMax = 200

// SaveHoneypots replaces the honeypot path list (issue #130) and swaps it
// into the registry, which the proxy checks on every 404.
func (h *Handler) SaveHoneypots(c *echo.Context) error {
	var paths []string
	saveErr := ""
	raw := strings.Fields(c.FormValue("honeypot_paths"))
	for _, p := range raw {
		switch {
		case !strings.HasPrefix(p, "/") || p == "/":
			saveErr = fmt.Sprintf("%q is not a path: start it with / and name something under the root.", p)
		case !slices.Contains(paths, p):
			paths = append(paths, p)
		}
	}
	if saveErr == "" && len(paths) > honeypotMax {
		saveErr = fmt.Sprintf("At most %d paths.", honeypotMax)
	}
	if saveErr == "" {
		if err := h.db.SetHoneypotPaths(paths); err != nil {
			saveErr = "Could not save: " + err.Error()
		} else {
			h.registry.SetHoneypots(paths)
		}
	}
	if saveErr != "" {
		paths = raw // give the admin their input back to fix
	}
	return h.renderPartial(c, "ip_rules", "honeypot-card", map[string]any{
		"HoneypotPaths":   paths,
		"HoneypotSaveOK":  saveErr == "",
		"HoneypotSaveErr": saveErr,
	})
}

// trustedIPsMax caps the trusted list; every proxied request scans it.
const trustedIPsMax = 200

// SaveTrustedIPs replaces the trusted IP list (issue #179) and swaps it into
// the registry, so its requests skip every blocking stage straight away.
func (h *Handler) SaveTrustedIPs(c *echo.Context) error {
	var entries []string
	for _, e := range strings.Fields(c.FormValue("trusted_ips")) {
		if !slices.Contains(entries, e) {
			entries = append(entries, e)
		}
	}
	nets, err := services.ParseTrustedIPs(entries)
	saveErr := ""
	switch {
	case err != nil:
		saveErr = err.Error() + "."
	case len(entries) > trustedIPsMax:
		saveErr = fmt.Sprintf("At most %d entries.", trustedIPsMax)
	default:
		if err := h.db.SetTrustedIPs(entries); err != nil {
			saveErr = "Could not save: " + err.Error()
		} else {
			h.registry.SetTrustedIPs(nets)
		}
	}
	return h.renderPartial(c, "settings", "trusted-ips-card", map[string]any{
		"AdminPath":      h.cfg.Admin.Path,
		"TrustedIPs":     entries,
		"TrustedSaveOK":  saveErr == "",
		"TrustedSaveErr": saveErr,
	})
}

// SaveAdaptiveSettings persists the adaptive-enforcement knobs shown on the
// IP Rules page and hot-reloads the policy so they apply immediately.
func (h *Handler) SaveAdaptiveSettings(c *echo.Context) error {
	cfg := storage.DefaultAdaptiveEnforcementConfig()
	cfg.Enabled = c.FormValue("adaptive_enabled") == "1"
	if n, err := strconv.Atoi(c.FormValue("adaptive_high_threshold")); err == nil && n >= 1 && n <= 100 {
		cfg.HighRiskThreshold = n
	}
	if n, err := strconv.Atoi(c.FormValue("adaptive_low_threshold")); err == nil && n >= 0 && n <= 99 {
		cfg.LowRiskThreshold = n
	}
	if f, err := strconv.ParseFloat(c.FormValue("adaptive_high_rate_scale"), 64); err == nil && f > 0 && f <= 1 {
		cfg.HighRiskRateScale = f
	}
	if f, err := strconv.ParseFloat(c.FormValue("adaptive_low_rate_scale"), 64); err == nil && f >= 1 && f <= 5 {
		cfg.LowRiskRateScale = f
	}
	if n, err := strconv.Atoi(c.FormValue("adaptive_force_challenge_threshold")); err == nil && n >= 1 && n <= 100 {
		cfg.ForceChallengeThreshold = n
	}
	saveErr := ""
	if err := h.db.SetAdaptiveEnforcementConfig(cfg); err != nil {
		saveErr = "Could not save: " + err.Error()
	} else if h.reloadAdaptive != nil {
		h.reloadAdaptive()
	}
	return h.renderPartial(c, "ip_rules", "adaptive-card", map[string]any{
		"AdaptiveEnabled":        cfg.Enabled,
		"AdaptiveHighThresh":     cfg.HighRiskThreshold,
		"AdaptiveLowThresh":      cfg.LowRiskThreshold,
		"AdaptiveHighScale":      cfg.HighRiskRateScale,
		"AdaptiveLowScale":       cfg.LowRiskRateScale,
		"AdaptiveForceChallenge": cfg.ForceChallengeThreshold,
		"AdaptiveSaveOK":         saveErr == "",
		"AdaptiveSaveErr":        saveErr,
	})
}

func (h *Handler) AddIPRule(c *echo.Context) error {
	appName := c.FormValue("app_name")
	ip := strings.TrimSpace(c.FormValue("ip"))
	ruleType := c.FormValue("rule_type")

	if ip == "" || (ruleType != "block" && ruleType != "allow") {
		return c.String(http.StatusBadRequest, "invalid input")
	}

	// Accept plain IPs and CIDR ranges. Try CIDR first so "10.0.0.0/8" is
	// handled correctly (net.ParseIP rejects the slash). net.ParseCIDR
	// canonicalises host bits (e.g. "10.0.1.5/24" → "10.0.1.0/24").
	if _, network, err := net.ParseCIDR(ip); err == nil {
		ip = network.String()
	} else if parsed := net.ParseIP(ip); parsed != nil {
		if v4 := parsed.To4(); v4 != nil {
			ip = v4.String()
		} else {
			ip = parsed.String()
		}
	} else {
		return c.String(http.StatusBadRequest, "invalid IP or CIDR (e.g. 1.2.3.4, ::1, or 10.0.0.0/8)")
	}

	if err := h.db.AddIPRule(appName, ip, ruleType); err != nil {
		return err
	}
	if err := h.ipbl.Reload(h.db); err != nil {
		return err
	}
	// A new rule sorts newest-first, so it always lands on page 1. Show that
	// page regardless of where the admin's list view happened to be.
	data, err := h.ipRulesRowsData(1)
	if err != nil {
		return err
	}
	return h.renderPartial(c, "ip_rules", "ip-rules-rows", data)
}

func (h *Handler) DeleteIPRule(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	if err := h.db.RemoveIPRule(id); err != nil {
		return err
	}
	if err := h.ipbl.Reload(h.db); err != nil {
		return err
	}
	// Stay on whichever page the admin was viewing (carried as ?page= on the
	// delete URL, see the remove-btn call in ip-rules-rows); ipRulesRowsData
	// clamps back a page if this delete just emptied the last one.
	page, _ := strconv.Atoi(c.QueryParam("page"))
	data, err := h.ipRulesRowsData(page)
	if err != nil {
		return err
	}
	return h.renderPartial(c, "ip_rules", "ip-rules-rows", data)
}
