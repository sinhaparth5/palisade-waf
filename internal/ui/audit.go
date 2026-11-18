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

	"github.com/labstack/echo/v5"

	"palisade/internal/ext"
	"palisade/internal/storage"
)

// auditSkip lists mutating routes that change no configuration: connection
// tests, previews and UI bookkeeping. Keyed like AuditEntry.Action.
var auditSkip = map[string]bool{
	"POST /logout":                 true, // the sessions table already records it
	"POST /api/notifications/seen": true,
	"POST /settings/webhook/test":  true,
	"POST /settings/email/test":    true,
	"POST /api/waf-rules/dry-run":  true,
	"POST /api/v1/mcp":             true, // read-only tool calls
}

// auditFields is the allowlist of form/JSON fields copied into an entry's
// summary: names of the thing being changed, never its secrets. An allowlist
// rather than a denylist so a field added later (a password, a token, a URL
// with credentials in it) stays out until someone decides it's safe.
var auditFields = []string{
	"action", "addr", "ai_search", "ai_training", "ai_user", "algorithms", "aliases", "app_name", "approved", "audience", "bot_mode", "breach_action", "breach_fields", "burst", "by_session",
	"canonical", "canonical_host", "captcha_provider", "cert_id", "client_id", "compress", "content_types", "cookie_exempt", "cookie_mode", "country_code", "crawlers", "destination_type",
	"disabled", "email", "enabled", "events", "exempt", "grace", "group", "health_interval", "health_path", "honeypot_paths", "host", "host_aliases", "ids", "ip", "issuer", "jwks_url",
	"jwt_mode", "keep", "label", "large_js", "lb_policy", "login_paths", "maintenance", "malware_scan", "match_type", "max_active", "max_body_kib", "methods", "mode", "mtls_mode",
	"multipart_mb", "name", "note", "openapi_mode", "origins", "path", "path_rules", "policy_max_kib", "policy_methods", "policy_mode", "policy_types", "prefix", "prefixes", "read_only",
	"reason", "response_inspect", "role", "rps", "rule_id", "rule_type", "service", "service_id", "session_cookie", "threshold", "tools", "trusted_ips", "ttl", "ttl_ceiling", "ttl_floor",
	"waiting_room", "window_days", "wr_crawlers", "wr_max",
}

const auditValueMax = 120

// auditPageSize is how many entries one page of the Settings card shows.
// The whole log is kept for a year, so the card pages through it rather
// than growing the Settings page with every change.
const auditPageSize = 10

// auditLog records every successful (status < 400) non-GET request on the
// group it wraps. It runs after authentication, so the actor is known: the
// signed-in user's email, or the API key apiKeyAuth stored in the context.
func (h *Handler) auditLog(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
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
		if ro, _ := c.Get("api_key_read_only").(bool); ext.Hold != nil && !ro && replayOf(r) == nil && ext.Hold(c, action) {
			return nil
		}

		if err := next(c); err != nil || responseStatus(c) >= 400 || auditFailed(c) {
			return err
		}

		actor, _ := c.Get("audit_actor").(string)
		if u := currentUser(c); actor == "" && u != nil {
			actor = u.Email
		}
		if actor == "" {
			actor = "admin"
		}
		var target []string
		for _, pv := range c.PathValues() {
			target = append(target, pv.Name+"="+auditValue(pv.Value))
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

// replayKey marks a request run by ext.Replay. Only in-process code can set
// a context value, so no client can claim it.
type replayKey struct{}

type replay struct {
	user  *storage.AdminUser
	actor string
}

func replayOf(r *http.Request) *replay {
	p, _ := r.Context().Value(replayKey{}).(*replay)
	return p
}

// auditFailed reports whether a handler rejected the request while still
// answering 200 with an htmx error box swap (HX-Retarget), which add-on
// cards on the Pro page may do.
func auditFailed(c *echo.Context) bool {
	return c.Response().Header().Get("HX-Retarget") != ""
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

// responseStatus is the status echo recorded for c's response (0 when its
// writer isn't echo's *Response).
func responseStatus(c *echo.Context) int {
	if r, err := echo.UnwrapResponse(c.Response()); err == nil {
		return r.Status
	}
	return 0
}
