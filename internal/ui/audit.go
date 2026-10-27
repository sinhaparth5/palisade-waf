package ui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"palisade/internal/storage"
)

// auditSkip lists mutating routes that change no configuration: connection
// tests, previews and UI bookkeeping. Keyed like AuditEntry.Action.
var auditSkip = map[string]bool{
	"POST /logout":                 true, // the sessions table already records it
	"POST /api/notifications/seen": true,
	"POST /settings/webhook/test":  true,
	"POST /settings/email/test":    true,
	"POST /settings/dbconn/test":   true,
	"POST /waf-rules/dry-run":      true,
}

// auditFields is the allowlist of form/JSON fields copied into an entry's
// summary: names of the thing being changed, never its secrets. An allowlist
// rather than a denylist so a field added later (a password, a token, a URL
// with credentials in it) stays out until someone decides it's safe.
var auditFields = []string{
	"ai_search", "ai_training", "ai_user", "aliases", "app_name", "bot_mode", "canonical", "canonical_host", "captcha_provider", "cert_id",
	"country_code", "enabled", "honeypot_paths", "host", "host_aliases", "ip", "label", "lb_policy", "login_paths",
	"match_type", "mode", "name", "note", "path", "prefix", "read_only", "reason",
	"rule_id", "rule_type", "service", "service_id", "trusted_ips",
}

const auditValueMax = 120

// auditPageSize is how many entries one page of the Settings card shows.
// The whole log is kept for a year, so the card pages through it rather
// than growing the Settings page with every change.
const auditPageSize = 10

// auditLog records every successful (status < 400) non-GET request on the
// group it wraps. It runs after authentication, so the actor is known: the
// admin session by default, or the API key apiKeyAuth stored in the context.
func (h *Handler) auditLog(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		r := c.Request()
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			return next(c)
		}
		// Route pattern relative to the admin path: "/ip-rules/:id" or
		// "/api/v1/ip-rules/:id".
		action := r.Method + " " + strings.TrimPrefix(c.Path(), h.cfg.Admin.Path)
		if auditSkip[action] {
			return next(c)
		}

		// JSON bodies are consumed by Bind, so read them first. BodyLimit
		// has already capped the size.
		var jsonBody map[string]any
		if strings.HasPrefix(r.Header.Get(echo.HeaderContentType), echo.MIMEApplicationJSON) && r.Body != nil {
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				return err
			}
			r.Body = io.NopCloser(bytes.NewReader(raw))
			_ = json.Unmarshal(raw, &jsonBody) // a malformed body fails in the handler instead
		}

		if err := next(c); err != nil || c.Response().Status >= 400 || auditFailed(c) {
			return err
		}

		actor, _ := c.Get("audit_actor").(string)
		if actor == "" {
			actor = "admin"
		}
		var target []string
		for i, name := range c.ParamNames() {
			target = append(target, name+"="+auditValue(c.ParamValues()[i]))
		}
		e := storage.AuditEntry{
			Actor:   actor,
			IP:      h.clientIP(r),
			Action:  action,
			Target:  strings.Join(target, " "),
			Summary: auditSummary(r, jsonBody),
		}
		if err := h.db.InsertAudit(e); err != nil {
			log.Printf("audit log: %v", err)
		}
		return nil
	}
}

// auditSummary renders the allowlisted fields the handler read, from the
// parsed form (r.PostForm, filled by FormValue/ParseMultipartForm) or the
// JSON body.
func auditSummary(r *http.Request, jsonBody map[string]any) string {
	var parts []string
	for _, k := range auditFields {
		var v string
		if vs, ok := r.PostForm[k]; ok && len(vs) > 0 {
			v = vs[0]
		} else if jv, ok := jsonBody[k]; ok && jv != nil {
			v = fmt.Sprint(jv)
		} else {
			continue
		}
		if v = strings.TrimSpace(v); v != "" {
			parts = append(parts, k+"="+auditValue(v))
		}
	}
	slices.Sort(parts)
	return strings.Join(parts, " ")
}

// auditValue truncates v and quotes it when it holds whitespace or quotes,
// so "k=v k2=v2" stays unambiguous.
func auditValue(v string) string {
	if len(v) > auditValueMax {
		v = strings.ToValidUTF8(v[:auditValueMax], "") + "…"
	}
	if strings.ContainsAny(v, " \t\r\n\"") {
		return strconv.Quote(v)
	}
	return v
}

const auditFailedKey = "audit_failed"

// markAuditFailure flags a request whose handler answered 200 with an inline
// validation error instead of a 4xx, which by this package's convention is a
// non-empty "...Err"/"...Error" string in the template data. Called from
// render/renderPartial so new handlers are covered without remembering to.
// ponytail: a "Saved, but applying failed" message also counts as a failure,
// so that rare half-applied save goes unrecorded.
func markAuditFailure(c echo.Context, data any) {
	m, ok := data.(map[string]any)
	if !ok {
		return
	}
	for k, v := range m {
		if s, ok := v.(string); ok && s != "" && (strings.HasSuffix(k, "Err") || strings.HasSuffix(k, "Error")) {
			c.Set(auditFailedKey, true)
			return
		}
	}
}

// auditFailed reports whether the handler rejected the request while still
// answering 200: flagged by markAuditFailure, or an htmx error box swap
// (HX-Retarget, the fail() helpers in the service handlers).
func auditFailed(c echo.Context) bool {
	failed, _ := c.Get(auditFailedKey).(bool)
	return failed || c.Response().Header().Get("HX-Retarget") != ""
}

// auditRowsData fetches one page of the audit log for the audit-rows
// partial, clamping page into range like ipRulesRowsData.
func (h *Handler) auditRowsData(page int) (map[string]any, error) {
	page = max(page, 1)
	entries, total, err := h.db.ListAudit(auditPageSize, (page-1)*auditPageSize)
	if err != nil {
		return nil, err
	}
	totalPages := max(1, (total+auditPageSize-1)/auditPageSize)
	if page > totalPages {
		page = totalPages
		if entries, _, err = h.db.ListAudit(auditPageSize, (page-1)*auditPageSize); err != nil {
			return nil, err
		}
	}
	return map[string]any{
		"AdminPath":  h.cfg.Admin.Path,
		"Entries":    entries,
		"CurPage":    page,
		"TotalPages": totalPages,
		"Total":      total,
	}, nil
}

// AuditRows renders one page of the audit card for its Prev/Next buttons.
func (h *Handler) AuditRows(c echo.Context) error {
	page, _ := strconv.Atoi(c.QueryParam("page"))
	data, err := h.auditRowsData(page)
	if err != nil {
		return err
	}
	return h.renderPartial(c, "settings", "audit-rows", data)
}
