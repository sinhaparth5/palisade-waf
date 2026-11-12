package ui

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v5"
)

// ── Geo Rules ─────────────────────────────────────────────────────────────────

func (h *Handler) GeoRulesPage(c *echo.Context) error {
	rules, err := h.db.ListGeoRules()
	if err != nil {
		return err
	}
	blockCount, allowCount := 0, 0
	for _, r := range rules {
		if r.RuleType == "block" {
			blockCount++
		} else {
			allowCount++
		}
	}
	blockPct, allowPct := 0, 0
	if total := len(rules); total > 0 {
		blockPct = blockCount * 100 / total
		allowPct = allowCount * 100 / total
	}
	return h.render(c, "geo_rules", map[string]any{
		"Rules":      rules,
		"Apps":       h.registry.List(),
		"BlockCount": blockCount,
		"AllowCount": allowCount,
		"BlockPct":   blockPct,
		"AllowPct":   allowPct,
	})
}

func (h *Handler) AddGeoRule(c *echo.Context) error {
	appName := c.FormValue("app_name")
	code := strings.ToUpper(strings.TrimSpace(c.FormValue("country_code")))
	ruleType := c.FormValue("rule_type")

	if len(code) != 2 || (ruleType != "block" && ruleType != "allow") {
		return c.String(http.StatusBadRequest, "invalid input")
	}
	if err := h.db.AddGeoRule(appName, code, ruleType); err != nil {
		return err
	}
	if err := h.geoBl.Reload(h.db); err != nil {
		return err
	}
	rules, _ := h.db.ListGeoRules()
	h.scorer.ReloadGeoRules(rules)
	return h.renderPartial(c, "geo_rules", "geo-rules-rows", map[string]any{"Rules": rules})
}

func (h *Handler) DeleteGeoRule(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	if err := h.db.RemoveGeoRule(id); err != nil {
		return err
	}
	if err := h.geoBl.Reload(h.db); err != nil {
		return err
	}
	rules, _ := h.db.ListGeoRules()
	h.scorer.ReloadGeoRules(rules)
	return h.renderPartial(c, "geo_rules", "geo-rules-rows", map[string]any{"Rules": rules})
}
