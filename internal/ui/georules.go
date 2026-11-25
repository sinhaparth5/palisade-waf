package ui

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/labstack/echo/v5"
)

// ── Geo Rules ─────────────────────────────────────────────────────────────────
// The page lives in the React app (issue #351). It lists rules with
// APIListGeoRules, shared with /api/v1.

// AddGeoRules adds one rule per country in country_code, all or none.
func (h *Handler) AddGeoRules(c *echo.Context) error {
	var req struct {
		ruleAddRequest
		Codes []string `json:"country_code"`
	}
	if err := c.Bind(&req); err != nil {
		return fieldError("country_code", "Send a JSON body.")
	}
	if err := h.checkRuleAdd(req.ruleAddRequest); err != nil {
		return err
	}
	var codes []string
	for _, code := range req.Codes {
		code = strings.ToUpper(strings.TrimSpace(code))
		if len(code) != 2 || strings.Trim(code, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
			return fieldError("country_code", fmt.Sprintf("%q is not a two-letter ISO country code.", code))
		}
		if !slices.Contains(codes, code) {
			codes = append(codes, code)
		}
	}
	switch {
	case len(codes) == 0:
		return fieldError("country_code", "Pick at least one country.")
	case len(codes) > bulkMax:
		return fieldError("country_code", fmt.Sprintf("At most %d countries at once.", bulkMax))
	}
	for _, code := range codes {
		if err := h.db.AddGeoRule(req.AppName, code, req.RuleType); err != nil {
			return err
		}
	}
	if err := h.reloadGeo(); err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, map[string]int{"added": len(codes)})
}

// RemoveGeoRules deletes the rules with the given ids.
func (h *Handler) RemoveGeoRules(c *echo.Context) error {
	ids, err := removeIDs(c)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := h.db.RemoveGeoRule(id); err != nil {
			return err
		}
	}
	if err := h.reloadGeo(); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}
