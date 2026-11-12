package ui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"palisade/internal/storage"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
)

// ── Live Logs ──────────────────────────────────────────────────────────────────

const logsPageSize = 50

// Logs serves the logs page. The row data always comes from the database
// (so it survives restarts, unlike the in-memory broadcast ring buffer).
// In "live" mode (no filters, page 1) the page also keeps an SSE connection
// open so brand-new requests get prepended in real time. Any filter, or
// paging past page 1, freezes the view into a static "history" page.
func (h *Handler) Logs(c *echo.Context) error {
	q := c.QueryParams()

	filter := storage.LogFilter{
		AppName:     q.Get("app"),
		StatusClass: q.Get("status"),
	}
	fromStr := q.Get("from")
	toStr := q.Get("to")
	if fromStr != "" {
		if t, err := time.Parse("2006-01-02T15:04", fromStr); err == nil {
			filter.From = t
		}
	}
	if toStr != "" {
		if t, err := time.Parse("2006-01-02T15:04", toStr); err == nil {
			filter.To = t
		}
	}

	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	filter.Limit = logsPageSize
	filter.Offset = (page - 1) * logsPageSize

	hasFilter := filter.AppName != "" || filter.StatusClass != "" || fromStr != "" || toStr != ""
	live := !hasFilter && page == 1 && q.Get("mode") != "history"

	rows, total, err := h.db.ListRequestsFiltered(filter)
	if err != nil {
		return err
	}

	return h.render(c, "logs", map[string]any{
		"Apps":         h.registry.List(),
		"History":      !live,
		"Recent":       rows,
		"Total":        total,
		"CurPage":      page,
		"TotalPages":   max(1, (total+logsPageSize-1)/logsPageSize),
		"FilterApp":    filter.AppName,
		"FilterStatus": filter.StatusClass,
		"FilterFrom":   fromStr,
		"FilterTo":     toStr,
	})
}

// LogsStream is an SSE endpoint that pushes pre-rendered HTML log rows, each
// followed by a JSON "stat" event for the Stats view.
func (h *Handler) LogsStream(c *echo.Context) error {
	w := c.Response()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	ch := h.broadcaster.Subscribe()
	defer h.broadcaster.Unsubscribe(ch)

	for {
		select {
		case entry, ok := <-ch:
			if !ok {
				return nil
			}
			var buf bytes.Buffer
			if err := h.tmpls["log-row"].ExecuteTemplate(&buf, "log-row", entry); err != nil {
				continue
			}
			// SSE format: each line prefixed with "data:", blank line to end event
			for _, line := range strings.Split(buf.String(), "\n") {
				fmt.Fprintf(w, "data: %s\n", line)
			}
			fmt.Fprint(w, "\n")
			// The Stats view counts these; same connection, so it never lags the table.
			if stat, err := json.Marshal(newStatEvent(entry)); err == nil {
				fmt.Fprintf(w, "event: stat\ndata: %s\n\n", stat)
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-c.Request().Context().Done():
			return nil
		}
	}
}

// LogDetail returns the full detail of one request log entry as JSON,
// including the proxy IP and captured request headers. Used by the
// client-side detail modal on the Logs page.
func (h *Handler) LogDetail(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	d, err := h.db.GetRequestByID(id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "not found"})
	}

	// Parse headers_json into a plain map for the response.
	var headers map[string]string
	if d.HeadersJSON != "" {
		if err := json.Unmarshal([]byte(d.HeadersJSON), &headers); err != nil {
			log.Printf("ui: log detail %d: unmarshal headers_json: %v", d.ID, err)
		}
	}

	// Unified threat score (issue #12), absent until the log-worker's
	// threat-score hook has processed at least one event for this IP.
	threat, hasThreat, err := h.db.GetIPThreatScore(d.RealIP)
	if err != nil {
		log.Printf("ui: log detail %d: threat score for %s: %v", d.ID, d.RealIP, err)
	}

	return c.JSON(http.StatusOK, map[string]any{
		"id":               d.ID,
		"request_id":       d.RequestID,
		"timestamp":        d.Timestamp.UTC().Format(time.RFC3339),
		"app_name":         d.AppName,
		"real_ip":          d.RealIP,
		"proxy_ip":         d.ProxyIP,
		"country":          d.Country,
		"method":           d.Method,
		"host":             d.Host,
		"path":             d.Path,
		"query":            d.Query,
		"status":           d.Status,
		"blocked":          d.Blocked,
		"rule_id":          d.RuleID,
		"action":           d.Action,
		"user_agent":       d.UserAgent,
		"duration_ms":      d.Duration,
		"proto":            d.Proto,
		"tls_version":      d.TLSVersion,
		"tls_cipher":       d.TLSCipher,
		"tls_sni":          d.TLSSNI,
		"asn":              d.ASN,
		"org":              d.Org,
		"ja4":              d.JA4,
		"visitor_id":       d.VisitorID,
		"bot_score":        d.BotScore,
		"cache_status":     d.CacheStatus,
		"headers":          headers,
		"has_threat_score": hasThreat,
		"threat_score":     threat.Total,
		"threat_autoban":   threat.AutobanScore,
		"threat_bot":       threat.BotScore,
		"threat_asn":       threat.ASNScore,
		"threat_geo":       threat.GeoScore,
		"threat_ja4":       threat.JA4Score,
	})
}

// MarkLogFeedback records a false/true-positive mark on a blocked log
// entry's WAF rule (issue #76) — signal collection only, consumed by
// GetWAFRuleSuggestions on the WAF Rules page; it never disables anything
// itself.
func (h *Handler) MarkLogFeedback(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	d, err := h.db.GetRequestByID(id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "not found"})
	}
	if !d.Blocked || d.RuleID == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "log entry has no WAF rule to mark"})
	}
	falsePositive := c.FormValue("false_positive") == "1"
	if err := h.db.MarkWAFRuleFeedback(d.AppName, d.RuleID, falsePositive); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

// CreateLogException disables the rule that blocked a log entry for that
// entry's service only (issue #7), reloading the WAF live. Rule and service
// come from the stored row, never the client, so this can't be aimed at an
// arbitrary rule/service pair.
func (h *Handler) CreateLogException(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	d, err := h.db.GetRequestByID(id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "not found"})
	}
	if !d.Blocked || d.RuleID == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "log entry has no WAF rule"})
	}
	if _, ok := h.registry.Proxy(d.AppName); !ok {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "service " + d.AppName + " no longer exists"})
	}
	reason := fmt.Sprintf("From log #%d: %s %s", d.ID, d.Method, d.Path)
	if err := h.db.DisableWAFRuleForService(d.AppName, d.RuleID, reason); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	h.reloadWAF()
	return c.JSON(http.StatusOK, map[string]string{"status": "ok", "service": d.AppName})
}

// ExportLogs streams the filtered request log as NDJSON (one JSON object per
// line). Accepts the same from/to/app/status query parameters as the Logs page.
func (h *Handler) ExportLogs(c *echo.Context) error {
	q := c.QueryParams()
	filter := storage.LogFilter{
		AppName:     q.Get("app"),
		StatusClass: q.Get("status"),
	}
	if t, err := time.Parse("2006-01-02T15:04", q.Get("from")); err == nil {
		filter.From = t
	}
	if t, err := time.Parse("2006-01-02T15:04", q.Get("to")); err == nil {
		filter.To = t
	}

	filename := "waf-logs-" + time.Now().UTC().Format("2006-01-02") + ".ndjson"
	w := c.Response()
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(w)
	flusher, canFlush := w.(http.Flusher)
	n := 0
	if err := h.db.ExportRequests(filter, func(r storage.RequestLog) bool {
		_ = enc.Encode(r) // each Encode call appends a newline
		n++
		if canFlush && n%500 == 0 {
			flusher.Flush()
		}
		return true
	}); err != nil {
		return err
	}
	if canFlush {
		flusher.Flush()
	}
	return nil
}
