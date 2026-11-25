package ui

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"palisade/internal/security/waf"
	"palisade/internal/storage"

	"github.com/labstack/echo/v5"
)

// ── WAF Rules ─────────────────────────────────────────────────────────────────

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

// The WAF Rules page's JSON (GET /api/waf-rules). Times are RFC 3339.

type vpatchJSON struct {
	CVE       string   `json:"cve"`
	Product   string   `json:"product"`
	Reference string   `json:"reference"`
	Added     string   `json:"added"`
	RuleID    int      `json:"rule_id"`
	Hits      int      `json:"hits"`
	GlobalOff bool     `json:"global_off"`
	OffFor    []string `json:"off_for"`
}

// exceptionJSON is a rule switched off globally (service "") or for one
// service. The id is the row in its own table.
type exceptionJSON struct {
	ID        int64  `json:"id"`
	RuleID    int    `json:"rule_id"`
	Service   string `json:"service"`
	Reason    string `json:"reason"`
	CreatedAt string `json:"created_at"`
}

type suggestionJSON struct {
	RuleID         int    `json:"rule_id"`
	Service        string `json:"service"`
	FalsePositives int    `json:"false_positives"`
	LastMarked     string `json:"last_marked"`
}

type topRuleJSON struct {
	RuleID   int    `json:"rule_id"`
	Hits     int    `json:"hits"`
	LastSeen string `json:"last_seen"`
	Disabled bool   `json:"disabled"`
}

type customRuleJSON struct {
	ID        int64  `json:"id"`
	Service   string `json:"service"`
	Rule      string `json:"rule"`
	Note      string `json:"note"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"created_at"`
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// ListWAFRules answers GET /api/waf-rules: virtual patches, suggested
// exceptions and their thresholds, the top firing rules of the last 30
// days, custom rules, every exception, and the service names for scopes.
func (h *Handler) ListWAFRules(c *echo.Context) error {
	disabled, err := h.db.ListDisabledWAFRules()
	if err != nil {
		return err
	}
	perService, err := h.db.ListWAFServiceExceptions()
	if err != nil {
		return err
	}
	patches, err := h.vpatchViews(disabled, perService)
	if err != nil {
		return err
	}
	top, err := h.db.GetTopFiringRules(20)
	if err != nil {
		return err
	}
	fb, err := h.db.GetWAFRuleFeedbackConfig()
	if err != nil {
		return err
	}
	suggested, err := h.db.GetWAFRuleSuggestions(fb)
	if err != nil {
		return err
	}
	custom, err := h.db.ListWAFCustomRules()
	if err != nil {
		return err
	}

	vp := make([]vpatchJSON, len(patches))
	for i, p := range patches {
		vp[i] = vpatchJSON{p.CVE, p.Product, p.Reference, p.Added, p.RuleID, p.Hits, p.GlobalOff, append([]string{}, p.OffFor...)}
	}
	exc := make([]exceptionJSON, 0, len(disabled)+len(perService))
	for _, d := range disabled {
		exc = append(exc, exceptionJSON{d.ID, d.RuleID, "", d.Reason, rfc3339(d.CreatedAt)})
	}
	for _, e := range perService {
		exc = append(exc, exceptionJSON{e.ID, e.RuleID, e.ServiceName, e.Reason, rfc3339(e.CreatedAt)})
	}
	sg := make([]suggestionJSON, len(suggested))
	for i, s := range suggested {
		sg[i] = suggestionJSON{s.RuleID, s.ServiceName, s.FalsePositiveCount, rfc3339(s.LastMarked)}
	}
	tr := make([]topRuleJSON, len(top))
	for i, t := range top {
		tr[i] = topRuleJSON{t.RuleID, t.HitCount, rfc3339(t.LastSeen), t.Disabled}
	}
	cr := make([]customRuleJSON, len(custom))
	for i, r := range custom {
		cr[i] = customRuleJSON{r.ID, r.ServiceName, r.Rule, r.Note, r.Enabled, rfc3339(r.CreatedAt)}
	}
	services := []string{}
	for _, s := range h.registry.List() {
		services = append(services, s.Name)
	}
	return c.JSON(http.StatusOK, map[string]any{
		"vpatches":    vp,
		"suggestions": sg,
		"feedback":    map[string]int{"threshold": fb.Threshold, "window_days": fb.WindowDays},
		"top_rules":   tr,
		"custom":      cr,
		"exceptions":  exc,
		"services":    services,
		"waf_enabled": h.cfg.WAF.Enabled,
	})
}

func badBody(msg string) *jsonError {
	return &jsonError{Status: http.StatusBadRequest, Code: "invalid", Message: msg}
}

func pathID(c *echo.Context, what string) (int64, error) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, badBody("Invalid " + what + " id.")
	}
	return id, nil
}

// AddWAFException switches a rule off globally (no service) or for one
// service and reloads the WAF: POST {"rule_id", "service"?, "reason"?}.
func (h *Handler) AddWAFException(c *echo.Context) error {
	var req struct {
		RuleID  int    `json:"rule_id"`
		Service string `json:"service"`
		Reason  string `json:"reason"`
	}
	if err := c.Bind(&req); err != nil {
		return badBody("Send rule_id, service and reason as JSON.")
	}
	service := strings.TrimSpace(req.Service)
	if req.RuleID <= 0 {
		return fieldError("rule_id", "Enter the rule id, a positive number.")
	}
	if service != "" && !h.serviceExists(service) {
		return fieldError("service", "That service no longer exists.")
	}
	if err := h.setRuleOff(req.RuleID, service, strings.TrimSpace(req.Reason)); err != nil {
		return err
	}
	return c.NoContent(http.StatusCreated)
}

// DeleteWAFException turns a rule back on: DELETE .../global/:id or
// .../services/:id, the row id from the list.
func (h *Handler) DeleteWAFException(c *echo.Context) error {
	id, err := pathID(c, "exception")
	if err != nil {
		return err
	}
	if strings.HasSuffix(c.Path(), "/global/:id") {
		err = h.db.EnableWAFRule(id)
	} else {
		err = h.db.EnableWAFRuleForService(id)
	}
	if err != nil {
		return err
	}
	h.reloadWAF()
	return c.NoContent(http.StatusNoContent)
}

// SetWAFFeedback stores when a rule is suggested for an exception (issue
// #76): PUT {"threshold", "window_days"}. Suggestions only, so no reload.
func (h *Handler) SetWAFFeedback(c *echo.Context) error {
	var req struct {
		Threshold  int `json:"threshold"`
		WindowDays int `json:"window_days"`
	}
	if err := c.Bind(&req); err != nil {
		return badBody("Send threshold and window_days as JSON.")
	}
	if req.Threshold < 1 || req.Threshold > 1000 {
		return fieldError("threshold", "Use 1 to 1000 marks.")
	}
	if req.WindowDays < 1 || req.WindowDays > 90 {
		return fieldError("window_days", "Use 1 to 90 days.")
	}
	if err := h.db.SetWAFRuleFeedbackConfig(storage.WAFRuleFeedbackConfig{Threshold: req.Threshold, WindowDays: req.WindowDays}); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}
