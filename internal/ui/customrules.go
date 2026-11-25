package ui

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"palisade/internal/security/waf"
	"palisade/internal/storage"

	"github.com/labstack/echo/v5"
)

// Custom WAF rules (issue #112): SecRules stored in the DB and compiled into
// the live engines by buildWAFAll in internal/app, so saving one takes effect on
// the next request with no restart or SIGHUP.

const customRuleMaxLen = 16 << 10

// checkCustomRule normalizes r and rejects it unless it compiles, uses only
// custom-range IDs no other custom rule already uses, and is scoped to an
// existing service (or globally).
// errCustomRuleStorage marks a checkCustomRule failure that is the DB's
// fault, not the rule's, so the API can answer 500 instead of 400.
var errCustomRuleStorage = errors.New("storage error")

func (h *Handler) checkCustomRule(r *storage.WAFCustomRule) error {
	r.Rule = strings.TrimSpace(r.Rule)
	r.ServiceName = strings.TrimSpace(r.ServiceName)
	r.Note = strings.TrimSpace(r.Note)
	if r.Rule == "" {
		return errors.New("enter a rule")
	}
	if len(r.Rule) > customRuleMaxLen {
		return fmt.Errorf("a rule can be at most %d bytes", customRuleMaxLen)
	}
	if r.ServiceName != "" {
		if !slices.ContainsFunc(h.registry.List(), func(s storage.Service) bool { return s.Name == r.ServiceName }) {
			return fmt.Errorf("no service named %q", r.ServiceName)
		}
	}
	ids, err := waf.ValidateCustomRule(r.Rule)
	if err != nil {
		return err
	}
	others, err := h.db.ListWAFCustomRules()
	if err != nil {
		return fmt.Errorf("%w: %w", errCustomRuleStorage, err)
	}
	for _, o := range others {
		if o.ID == r.ID {
			continue
		}
		for _, id := range waf.CustomRuleIDs(o.Rule) {
			if slices.Contains(ids, id) {
				return fmt.Errorf("rule id %d is already used by custom rule #%d", id, o.ID)
			}
		}
	}
	return nil
}

type customRuleRequest struct {
	Rule    string `json:"rule"`
	Service string `json:"service"`
	Note    string `json:"note"`
}

// saveCustomRule backs POST /api/waf-rules/custom (id 0, answers 201) and
// PUT /api/waf-rules/custom/:id (204). A rule that doesn't compile or
// reuses an id is a field error on rule.
func (h *Handler) saveCustomRule(c *echo.Context, id int64) error {
	var req customRuleRequest
	if err := c.Bind(&req); err != nil {
		return badBody("Send rule, service and note as JSON.")
	}
	r := storage.WAFCustomRule{ID: id, Rule: req.Rule, ServiceName: strings.TrimSpace(req.Service), Note: req.Note, Enabled: true}
	if r.ServiceName != "" && !h.serviceExists(r.ServiceName) {
		return fieldError("service", "That service no longer exists.")
	}
	if err := h.checkCustomRule(&r); errors.Is(err, errCustomRuleStorage) {
		return err
	} else if err != nil {
		msg := err.Error()
		return fieldError("rule", strings.ToUpper(msg[:1])+msg[1:])
	}
	if err := h.db.SaveWAFCustomRule(r); errors.Is(err, sql.ErrNoRows) {
		return &jsonError{Status: http.StatusNotFound, Code: "not_found", Message: "That custom rule no longer exists."}
	} else if err != nil {
		return err
	}
	h.reloadWAF()
	if id == 0 {
		return c.NoContent(http.StatusCreated)
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) AddCustomRule(c *echo.Context) error { return h.saveCustomRule(c, 0) }

func (h *Handler) UpdateCustomRule(c *echo.Context) error {
	id, err := pathID(c, "custom rule")
	if err != nil {
		return err
	}
	return h.saveCustomRule(c, id)
}

// SetCustomRuleEnabled turns a custom rule on or off: PUT {"enabled"}.
func (h *Handler) SetCustomRuleEnabled(c *echo.Context) error {
	id, err := pathID(c, "custom rule")
	if err != nil {
		return err
	}
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := c.Bind(&req); err != nil || req.Enabled == nil {
		return badBody(`Send {"enabled": true|false}.`)
	}
	if err := h.db.SetWAFCustomRuleEnabled(id, *req.Enabled); err != nil {
		return err
	}
	h.reloadWAF()
	return c.NoContent(http.StatusNoContent)
}

// DeleteCustomRule handles DELETE /api/waf-rules/custom/:id.
func (h *Handler) DeleteCustomRule(c *echo.Context) error {
	id, err := pathID(c, "custom rule")
	if err != nil {
		return err
	}
	if err := h.db.DeleteWAFCustomRule(id); err != nil {
		return err
	}
	h.reloadWAF()
	return c.NoContent(http.StatusNoContent)
}

// ── REST API ─────────────────────────────────────────────────────────────────

type apiCustomRuleRequest struct {
	ServiceName string `json:"service_name"`
	Rule        string `json:"rule"`
	Note        string `json:"note"`
	Enabled     *bool  `json:"enabled"` // default true
}

func (h *Handler) APIListCustomRules(c *echo.Context) error {
	rules, err := h.db.ListWAFCustomRules()
	if err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, rules)
}

// apiSaveCustomRule backs both POST (id 0) and PUT /waf-rules/custom/:id.
func (h *Handler) apiSaveCustomRule(c *echo.Context, id int64) error {
	var req apiCustomRuleRequest
	if err := c.Bind(&req); err != nil {
		return apiError(c, http.StatusBadRequest, "invalid JSON body")
	}
	r := storage.WAFCustomRule{ID: id, ServiceName: req.ServiceName, Rule: req.Rule, Note: req.Note, Enabled: req.Enabled == nil || *req.Enabled}
	if err := h.checkCustomRule(&r); errors.Is(err, errCustomRuleStorage) {
		return apiError(c, http.StatusInternalServerError, err.Error())
	} else if err != nil {
		return apiError(c, http.StatusBadRequest, err.Error())
	}
	if err := h.db.SaveWAFCustomRule(r); errors.Is(err, sql.ErrNoRows) {
		return apiError(c, http.StatusNotFound, "custom rule not found")
	} else if err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	if id != 0 && req.Enabled != nil {
		if err := h.db.SetWAFCustomRuleEnabled(id, *req.Enabled); err != nil {
			return apiError(c, http.StatusInternalServerError, err.Error())
		}
	}
	h.reloadWAF()
	// Custom rule IDs are unique across rows (checkCustomRule), so the
	// rule's first SecRule id finds the saved row, new id included.
	first := waf.CustomRuleIDs(r.Rule)[0]
	rules, err := h.db.ListWAFCustomRules()
	if err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	status := http.StatusOK
	if id == 0 {
		status = http.StatusCreated
	}
	for _, o := range rules {
		if waf.CustomRuleIDs(o.Rule)[0] == first {
			return c.JSON(status, o)
		}
	}
	return c.NoContent(status)
}

func (h *Handler) APICreateCustomRule(c *echo.Context) error { return h.apiSaveCustomRule(c, 0) }

func (h *Handler) APIUpdateCustomRule(c *echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		return apiError(c, http.StatusBadRequest, "invalid id")
	}
	return h.apiSaveCustomRule(c, id)
}

func (h *Handler) APIDeleteCustomRule(c *echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return apiError(c, http.StatusBadRequest, "invalid id")
	}
	if err := h.db.DeleteWAFCustomRule(id); err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
	}
	h.reloadWAF()
	return c.NoContent(http.StatusNoContent)
}
