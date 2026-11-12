package ui

import (
	"net/http"
	"palisade/internal/security/waf"
	"palisade/internal/storage"
	"strconv"
	"strings"

	"github.com/labstack/echo/v5"
)

// ── WAF Rules ─────────────────────────────────────────────────────────────────

// wafRulesContentData gathers everything the waf_rules page (and its
// waf-content partial) render: global disabled rules, per-service
// exceptions, the top-firing rules table, and the service list for the
// scope dropdown on the disable form.
func (h *Handler) wafRulesContentData() (map[string]any, error) {
	disabled, err := h.db.ListDisabledWAFRules()
	if err != nil {
		return nil, err
	}
	serviceExceptions, err := h.db.ListWAFServiceExceptions()
	if err != nil {
		return nil, err
	}
	topRules, err := h.db.GetTopFiringRules(20)
	if err != nil {
		return nil, err
	}
	feedbackCfg, err := h.db.GetWAFRuleFeedbackConfig()
	if err != nil {
		return nil, err
	}
	suggestions, err := h.db.GetWAFRuleSuggestions(feedbackCfg)
	if err != nil {
		return nil, err
	}
	customRules, err := h.db.ListWAFCustomRules()
	if err != nil {
		return nil, err
	}
	vpatches, err := h.vpatchViews(disabled, serviceExceptions)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"VPatches":          vpatches,
		"CustomRules":       customRules,
		"Disabled":          disabled,
		"ServiceExceptions": serviceExceptions,
		"TopRules":          topRules,
		"Services":          h.registry.List(),
		"Suggestions":       suggestions,
		"FeedbackThreshold": feedbackCfg.Threshold,
		"FeedbackWindow":    feedbackCfg.WindowDays,
	}, nil
}

// vpatchView is a virtual patch (issue #189) with its hits and where it is
// switched off. Off is an ordinary rule exception for its rule id.
type vpatchView struct {
	waf.VPatch
	Hits      int
	GlobalOff bool
	OffFor    []string
}

func (h *Handler) vpatchViews(disabled []storage.DisabledWAFRule, exceptions []storage.WAFServiceException) ([]vpatchView, error) {
	hits, err := h.db.GetRuleHitCounts(waf.VPatchIDMin, waf.VPatchIDMax)
	if err != nil {
		return nil, err
	}
	out := make([]vpatchView, len(waf.VPatches()))
	for i, p := range waf.VPatches() {
		v := vpatchView{VPatch: p, Hits: hits[p.RuleID]}
		for _, d := range disabled {
			v.GlobalOff = v.GlobalOff || d.RuleID == p.RuleID
		}
		for _, e := range exceptions {
			if e.RuleID == p.RuleID {
				v.OffFor = append(v.OffFor, e.ServiceName)
			}
		}
		out[i] = v
	}
	return out, nil
}

func (h *Handler) WAFRulesPage(c *echo.Context) error {
	data, err := h.wafRulesContentData()
	if err != nil {
		return err
	}
	return h.render(c, "waf_rules", data)
}

func (h *Handler) DisableWAFRule(c *echo.Context) error {
	ruleIDStr := strings.TrimSpace(c.FormValue("rule_id"))
	reason := strings.TrimSpace(c.FormValue("reason"))
	service := strings.TrimSpace(c.FormValue("service"))

	ruleID, err := strconv.Atoi(ruleIDStr)
	if err != nil || ruleID <= 0 {
		return c.String(http.StatusBadRequest, "invalid rule ID")
	}
	if service == "" {
		err = h.db.DisableWAFRule(ruleID, reason)
	} else {
		err = h.db.DisableWAFRuleForService(service, ruleID, reason)
	}
	if err != nil {
		return err
	}
	h.reloadWAF()
	data, err := h.wafRulesContentData()
	if err != nil {
		return err
	}
	return h.renderPartial(c, "waf_rules", "waf-content", data)
}

func (h *Handler) EnableWAFRule(c *echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	if err := h.db.EnableWAFRule(id); err != nil {
		return err
	}
	h.reloadWAF()
	data, err := h.wafRulesContentData()
	if err != nil {
		return err
	}
	return h.renderPartial(c, "waf_rules", "waf-content", data)
}

func (h *Handler) EnableWAFRuleForService(c *echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	if err := h.db.EnableWAFRuleForService(id); err != nil {
		return err
	}
	h.reloadWAF()
	data, err := h.wafRulesContentData()
	if err != nil {
		return err
	}
	return h.renderPartial(c, "waf_rules", "waf-content", data)
}

// SaveWAFFeedbackConfig persists the false-positive-mark threshold/window
// used to surface suggested exceptions (issue #76). No hot-reload needed —
// it only changes which suggestions GetWAFRuleSuggestions returns, not the
// live WAF engine.
func (h *Handler) SaveWAFFeedbackConfig(c *echo.Context) error {
	cfg := storage.DefaultWAFRuleFeedbackConfig()
	if n, err := strconv.Atoi(c.FormValue("feedback_threshold")); err == nil && n >= 1 && n <= 1000 {
		cfg.Threshold = n
	}
	if n, err := strconv.Atoi(c.FormValue("feedback_window")); err == nil && n >= 1 && n <= 90 {
		cfg.WindowDays = n
	}
	if err := h.db.SetWAFRuleFeedbackConfig(cfg); err != nil {
		return err
	}
	data, err := h.wafRulesContentData()
	if err != nil {
		return err
	}
	return h.renderPartial(c, "waf_rules", "waf-content", data)
}
