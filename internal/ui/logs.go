package ui

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"palisade/internal/storage"
	"strconv"
	"time"

	"github.com/labstack/echo/v5"
)

// ── Live Logs ──────────────────────────────────────────────────────────────────

// LogsStream sends each new request to the React Logs page as a JSON
// server-sent event (statEvent): the live table and the Stats view both read
// it. A comment line every apiStreamPing keeps idle proxies from closing it.
func (h *Handler) LogsStream(c *echo.Context) error {
	w := c.Response()
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering
	ch := h.broadcaster.Subscribe()
	defer h.broadcaster.Unsubscribe(ch)
	w.WriteHeader(http.StatusOK)
	_ = rc.Flush()
	ping := time.NewTicker(apiStreamPing)
	defer ping.Stop()
	s := scopeOf(c)

	for {
		select {
		case entry, ok := <-ch:
			if !ok {
				return nil
			}
			if !s.hasName(entry.AppName) {
				continue
			}
			if b, err := json.Marshal(newStatEvent(entry)); err == nil {
				fmt.Fprintf(w, "data: %s\n\n", b)
			}
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
		case <-c.Request().Context().Done():
			return nil
		}
		_ = rc.Flush()
	}
}

// LogApps lists the service names for the Logs page's app filter. Names
// only: the full service list carries settings a viewer doesn't get.
func (h *Handler) LogApps(c *echo.Context) error {
	scope := scopeOf(c)
	names := []string{}
	for _, s := range h.registry.List() {
		if scope.hasName(s.Name) {
			names = append(names, s.Name)
		}
	}
	return c.JSON(http.StatusOK, names)
}

// LogDetail returns the full detail of one request log entry as JSON,
// including the proxy IP and captured request headers. Used by the
// client-side detail modal on the Logs page.
func (h *Handler) LogDetail(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return apiError(c, http.StatusBadRequest, "invalid id")
	}
	d, err := h.db.GetRequestByID(id)
	if err != nil {
		return lookupError(c, err, "not found")
	}
	if !scopeOf(c).hasName(d.AppName) {
		return apiError(c, http.StatusNotFound, "not found")
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
		"node":             d.Node,
		"headers":          headers,
		"has_threat_score": hasThreat,
		"threat_score":     threat.Total,
		"threat_autoban":   threat.AutobanScore,
		"threat_bot":       threat.BotScore,
		"threat_asn":       threat.ASNScore,
		"threat_geo":       threat.GeoScore,
		"threat_ja4":       threat.JA4Score,
		"proxy_type":       h.scorer.ProxyType(d.RealIP),
	})
}

// MarkLogFeedback records a false/true-positive mark on a blocked log
// entry's WAF rule (issue #76) — signal collection only, consumed by
// GetWAFRuleSuggestions on the WAF Rules page; it never disables anything
// itself.
func (h *Handler) MarkLogFeedback(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return apiError(c, http.StatusBadRequest, "invalid id")
	}
	d, err := h.db.GetRequestByID(id)
	if err != nil {
		return lookupError(c, err, "not found")
	}
	if !d.Blocked || d.RuleID == 0 {
		return apiError(c, http.StatusBadRequest, "This request has no WAF rule to mark.")
	}
	falsePositive := c.FormValue("false_positive") == "1"
	if err := h.db.MarkWAFRuleFeedback(d.AppName, d.RuleID, falsePositive); err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
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
		return apiError(c, http.StatusBadRequest, "invalid id")
	}
	d, err := h.db.GetRequestByID(id)
	if err != nil {
		return lookupError(c, err, "not found")
	}
	if !d.Blocked || d.RuleID == 0 {
		return apiError(c, http.StatusBadRequest, "This request has no WAF rule to make an exception for.")
	}
	if _, ok := h.registry.Proxy(d.AppName); !ok {
		return apiError(c, http.StatusBadRequest, "Service "+d.AppName+" no longer exists.")
	}
	reason := fmt.Sprintf("From log #%d: %s %s", d.ID, d.Method, d.Path)
	if err := h.db.DisableWAFRuleForService(d.AppName, d.RuleID, reason); err != nil {
		return apiError(c, http.StatusInternalServerError, err.Error())
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
