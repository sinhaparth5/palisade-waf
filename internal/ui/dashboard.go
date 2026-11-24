package ui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"palisade/internal/storage"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

// dashboardService is one service card on the dashboard.
type dashboardService struct {
	Name    string `json:"name"`
	Route   string `json:"route"`
	TLS     string `json:"tls"`
	Healthy bool   `json:"healthy"`
	Known   bool   `json:"known"`
	Cache   bool   `json:"cache"`
}

type dashboardCount struct {
	Code  string `json:"code"`
	Name  string `json:"name,omitempty"`
	Count int    `json:"count"`
}

// glanceCard is one cell of the dashboard's live strip.
type glanceCard struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Trend string `json:"trend"`
}

// enforcementRow is one defense layer in "Enforcement today".
type enforcementRow struct {
	Label string `json:"label"`
	Icon  string `json:"icon"`
	Count int    `json:"count"`
}

// ── Dashboard ──────────────────────────────────────────────────────────────────

// Dashboard answers GET /api/dashboard: everything the React dashboard shows,
// in one request.
func (h *Handler) Dashboard(c *echo.Context) error {
	stats, err := h.db.GetStats()
	if err != nil {
		return err
	}
	recent, err := h.db.ListRequests(false, "", 10, 0)
	if err != nil {
		return err
	}
	blocked, err := h.db.ListRequests(true, "", 8, 0)
	if err != nil {
		return err
	}
	hourly, err := h.db.GetHourlyTraffic(24)
	if err != nil {
		return err
	}
	labels, allowedSeries, blockedSeries := hourlySeries(hourly, 24)
	countries, err := h.db.GetTopCountries(5, 24)
	if err != nil {
		return err
	}
	threats, err := h.db.GetTopBlockedCountries(6, 24)
	if err != nil {
		return err
	}
	glance, err := h.db.GetAtAGlanceStats()
	if err != nil {
		return err
	}
	// Per-stage enforcement counts since UTC midnight, the same window
	// GetStats and GetBotStats use.
	nowUTC := time.Now().UTC()
	startOfDay := time.Date(nowUTC.Year(), nowUTC.Month(), nowUTC.Day(), 0, 0, 0, 0, time.UTC)
	report, err := h.db.GetDailyReport(startOfDay, startOfDay.Add(24*time.Hour))
	if err != nil {
		return err
	}
	changes, _, err := h.db.ListAudit(6, 0)
	if err != nil {
		return err
	}
	apps := h.registry.List()
	svcs := make([]dashboardService, 0, len(apps))
	for _, s := range apps {
		route := s.Host
		if route == "" {
			route = s.Prefix
		}
		healthy, known := h.registry.IsHealthy(s.Name)
		svcs = append(svcs, dashboardService{Name: s.Name, Route: route, TLS: s.TLSMode, Healthy: healthy, Known: known, Cache: s.CacheEnabled})
	}
	blockRate := 0
	if stats.TotalToday > 0 {
		blockRate = stats.BlockedToday * 100 / stats.TotalToday
	}
	bots := h.db.GetBotStats()
	return c.JSON(http.StatusOK, map[string]any{
		"requests_today": stats.TotalToday,
		"blocked_today":  stats.BlockedToday,
		"blocked_all":    stats.BlockedAll,
		"block_rate":     blockRate,
		"challenged":     bots.ChallengedToday,
		"passed":         bots.PassedToday,
		"visitors":       glance.UniqueVisitorsToday,
		"glance":         dashboardGlance(glance),
		"traffic":        map[string]any{"labels": labels, "allowed": allowedSeries, "blocked": blockedSeries},
		"countries":      countryCounts(countries, true),
		"threats":        countryCounts(threats, false),
		"enforcement":    dashboardEnforcement(report),
		"services":       svcs,
		"recent":         nonNil(recent),
		"blocked":        nonNil(blocked),
		"changes":        nonNil(changes),
	})
}

// nonNil keeps an empty list a JSON [] rather than null.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func countryCounts(rows []storage.CountryCount, named bool) []dashboardCount {
	out := make([]dashboardCount, 0, len(rows))
	for _, row := range rows {
		code := strings.ToUpper(strings.TrimSpace(row.Country))
		if code == "" {
			continue
		}
		d := dashboardCount{Code: code, Count: row.Count}
		if named {
			d.Name = countryName(code)
		}
		out = append(out, d)
	}
	return out
}

func countryName(code string) string {
	region, err := language.ParseRegion(code)
	if err != nil {
		return code
	}
	name := display.English.Regions().Name(region)
	if name == "" {
		return code
	}
	return name
}

func dashboardGlance(s storage.AtAGlanceStats) []glanceCard {
	return []glanceCard{
		{Label: "Requests/sec", Value: fmt.Sprintf("%.1f", float64(s.RequestsLastMinute)/60), Trend: trendLabel(s.RequestsLastMinute, s.RequestsPrevMinute)},
		{Label: "Avg latency", Value: fmt.Sprintf("%dms", s.AvgLatencyMS), Trend: trendLabel(s.AvgLatencyMS, s.PrevAvgLatencyMS)},
		{Label: "Blocked/min", Value: strconv.Itoa(s.BlockedLastMinute), Trend: trendLabel(s.BlockedLastMinute, s.BlockedPrevMinute)},
		{Label: "WAF rule hits", Value: strconv.Itoa(s.WAFRuleHitsToday), Trend: trendLabel(s.WAFRuleHitsToday, s.WAFRuleHitsPreviousDay)},
	}
}

func dashboardEnforcement(rep storage.DailyReport) []enforcementRow {
	return []enforcementRow{
		{Label: "WAF rules", Icon: "hgi-security-block", Count: rep.WAFBlocked},
		{Label: "IP blocklist", Icon: "hgi-cancel-circle", Count: rep.IPBlocked},
		{Label: "Geo rules", Icon: "hgi-earth", Count: rep.GeoBlocked},
		{Label: "Rate limit", Icon: "hgi-time-04", Count: rep.RateLimited},
		{Label: "Bot challenge", Icon: "hgi-bot", Count: rep.BotChallenged},
	}
}

func trendLabel(current, previous int) string {
	if previous == 0 {
		if current == 0 {
			return "0.0%"
		}
		return "+100%"
	}
	delta := float64(current-previous) * 100 / float64(previous)
	if delta > 0 {
		return fmt.Sprintf("+%.1f%%", delta)
	}
	return fmt.Sprintf("%.1f%%", delta)
}

// unreadAlertCount returns how many blocked requests happened since the
// admin last marked notifications as read.
func (h *Handler) unreadAlertCount() int {
	seenAt, err := h.db.NotificationsSeenAt()
	if err != nil {
		return 0
	}
	n, err := h.db.CountBlockedSince(seenAt)
	if err != nil {
		return 0
	}
	return n
}

// NotificationsStream is an SSE endpoint that pushes the updated unread
// notification count whenever a new request is blocked, so the bell badge
// updates live without a page reload.
func (h *Handler) NotificationsStream(c *echo.Context) error {
	w := c.Response()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
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
			if !entry.Blocked {
				continue
			}
			fmt.Fprintf(w, "event: count\ndata: %d\n\n", h.unreadAlertCount())
			toastData, _ := json.Marshal(map[string]string{
				"action":  entry.Action,
				"ip":      entry.RealIP,
				"country": entry.Country,
				"method":  entry.Method,
				"path":    entry.Path,
			})
			fmt.Fprintf(w, "event: toast\ndata: %s\n\n", toastData)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-c.Request().Context().Done():
			return nil
		}
	}
}

// NotificationsPanel renders the bell dropdown contents: the most recent
// real blocked requests, newest first.
func (h *Handler) NotificationsPanel(c *echo.Context) error {
	rows, err := h.db.ListRequests(true, "", 6, 0)
	if err != nil {
		return err
	}
	if wantsJSON(c) {
		type block struct {
			Time    time.Time `json:"time"`
			IP      string    `json:"ip"`
			Country string    `json:"country"`
			Method  string    `json:"method"`
			Path    string    `json:"path"`
			App     string    `json:"app"`
			RuleID  int       `json:"rule_id"`
			Action  string    `json:"action"`
		}
		blocks := make([]block, 0, len(rows))
		for _, r := range rows {
			blocks = append(blocks, block{r.Timestamp, r.RealIP, r.Country, r.Method, r.Path, r.AppName, r.RuleID, r.Action})
		}
		return c.JSON(http.StatusOK, map[string]any{"unread": h.unreadAlertCount(), "blocks": blocks})
	}
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	return h.tmpls["notifications"].ExecuteTemplate(c.Response(), "notifications-panel", map[string]any{
		"Rows":      rows,
		"AdminPath": h.cfg.Admin.Path,
	})
}

// MarkNotificationsSeen clears the unread notification badge.
func (h *Handler) MarkNotificationsSeen(c *echo.Context) error {
	if err := h.db.MarkNotificationsSeen(); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// hourlySeries lays GetHourlyTraffic's sparse points onto the last `hours`
// UTC hours, oldest first, zero-filling gaps so charts stay continuous.
func hourlySeries(points []storage.HourlyPoint, hours int) (labels []string, allowed, blocked []int) {
	byHour := make(map[int64]storage.HourlyPoint, len(points))
	for _, p := range points {
		byHour[p.Hour.Unix()] = p
	}
	now := time.Now().UTC().Truncate(time.Hour)
	for i := hours - 1; i >= 0; i-- {
		t := now.Add(-time.Duration(i) * time.Hour)
		p := byHour[t.Unix()]
		labels = append(labels, t.Format("15:00"))
		allowed = append(allowed, p.Total-p.Blocked)
		blocked = append(blocked, p.Blocked)
	}
	return labels, allowed, blocked
}
