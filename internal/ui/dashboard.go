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

type dashboardCountry struct {
	Code     string
	Name     string
	Count    int
	Segments []bool // meter cells, filled relative to the top country
}

// atAGlanceCard is one cell of the dashboard's live strip.
type atAGlanceCard struct {
	Label string
	Value string
	Trend string
}

// sparkBar is one bar of an inline-SVG sparkline (viewBox 0 0 96 32).
type sparkBar struct{ X, Y, H int }

// dashboardService is one service card on the dashboard.
type dashboardService struct {
	Name, Route, TLS string
	Healthy, Known   bool
	Cache            bool
}

// ── Dashboard ──────────────────────────────────────────────────────────────────

func (h *Handler) Dashboard(c *echo.Context) error {
	stats, err := h.db.GetStats()
	if err != nil {
		return err
	}
	recent, err := h.db.ListRequests(false, "", 10, 0)
	if err != nil {
		return err
	}
	topBlocked, err := h.db.ListRequests(true, "", 8, 0)
	if err != nil {
		return err
	}
	blockRate := 0
	if stats.TotalToday > 0 {
		blockRate = stats.BlockedToday * 100 / stats.TotalToday
	}
	hourly, err := h.db.GetHourlyTraffic(24)
	if err != nil {
		return err
	}
	_, allowed, blocked := hourlySeries(hourly, 24)
	total := make([]int, len(allowed))
	for i := range allowed {
		total[i] = allowed[i] + blocked[i]
	}
	botStats := h.db.GetBotStats()
	apps := h.registry.List()
	topCountryCounts, err := h.db.GetTopCountries(5, 24)
	if err != nil {
		return err
	}
	atAGlance, err := h.db.GetAtAGlanceStats()
	if err != nil {
		return err
	}
	// Per-stage enforcement counts for the right panel, since UTC midnight —
	// the same window and query GetStats/GetBotStats already use.
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
	svcs := make([]dashboardService, 0, len(apps))
	for _, s := range apps {
		route := s.Host
		if route == "" {
			route = s.Prefix
		}
		healthy, known := h.registry.IsHealthy(s.Name)
		svcs = append(svcs, dashboardService{Name: s.Name, Route: route, TLS: s.TLSMode, Healthy: healthy, Known: known, Cache: s.CacheEnabled})
	}
	return h.render(c, "dashboard", map[string]any{
		"Stats":        stats,
		"Recent":       recent,
		"TopBlocked":   topBlocked,
		"TopCountries": dashboardCountries(topCountryCounts),
		"AtAGlance":    dashboardAtAGlance(atAGlance),
		"Enforcement":  dashboardEnforcement(report),
		"BlockRate":    blockRate,
		"SparkTotal":   sparkBars(total),
		"SparkBlocked": sparkBars(blocked),
		"Apps":         apps,
		"Services":     svcs,
		"Changes":      changes,
		"BotStats":     botStats,
		"Visitors":     atAGlance.UniqueVisitorsToday,
	})
}

func dashboardCountries(rows []storage.CountryCount) []dashboardCountry {
	top := 0
	for _, row := range rows {
		top = max(top, row.Count)
	}
	out := make([]dashboardCountry, 0, len(rows))
	for _, row := range rows {
		code := strings.ToUpper(strings.TrimSpace(row.Country))
		if code == "" {
			continue
		}
		out = append(out, dashboardCountry{
			Code:     code,
			Name:     countryName(code),
			Count:    row.Count,
			Segments: meterSegments(row.Count, top),
		})
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

func dashboardAtAGlance(s storage.AtAGlanceStats) []atAGlanceCard {
	return []atAGlanceCard{
		{Label: "Requests/sec", Value: fmt.Sprintf("%.1f", float64(s.RequestsLastMinute)/60), Trend: trendLabel(s.RequestsLastMinute, s.RequestsPrevMinute)},
		{Label: "Avg latency", Value: fmt.Sprintf("%dms", s.AvgLatencyMS), Trend: trendLabel(s.AvgLatencyMS, s.PrevAvgLatencyMS)},
		{Label: "Blocked/min", Value: strconv.Itoa(s.BlockedLastMinute), Trend: trendLabel(s.BlockedLastMinute, s.BlockedPrevMinute)},
		{Label: "WAF rule hits", Value: strconv.Itoa(s.WAFRuleHitsToday), Trend: trendLabel(s.WAFRuleHitsToday, s.WAFRuleHitsPreviousDay)},
	}
}

// sparkBars scales an hourly series into SVG bars for a 96x32 viewBox, 4
// units per bar. A zero hour keeps a 1-unit stub so the baseline reads.
func sparkBars(vals []int) []sparkBar {
	top := 1
	for _, v := range vals {
		top = max(top, v)
	}
	out := make([]sparkBar, len(vals))
	for i, v := range vals {
		h := max(1, v*32/top)
		out[i] = sparkBar{X: i * 4, Y: 32 - h, H: h}
	}
	return out
}

// enforcementRow is one defense layer in the right panel's "Enforcement
// today" card: a label, today's hit count, and a meter bar sized relative to
// the busiest layer. WidthClass comes from fixed buckets, like the Top
// countries WidthClass — runtime-computed widths would need a style
// attribute, which the templates don't use.
type enforcementRow struct {
	Label    string
	Icon     string
	Count    int
	Segments []bool
}

func dashboardEnforcement(rep storage.DailyReport) []enforcementRow {
	rows := []enforcementRow{
		{Label: "WAF rules", Icon: "hgi-security-block", Count: rep.WAFBlocked},
		{Label: "IP blocklist", Icon: "hgi-cancel-circle", Count: rep.IPBlocked},
		{Label: "Geo rules", Icon: "hgi-earth", Count: rep.GeoBlocked},
		{Label: "Rate limit", Icon: "hgi-time-04", Count: rep.RateLimited},
		{Label: "Bot challenge", Icon: "hgi-bot", Count: rep.BotChallenged},
	}
	max := 0
	for _, r := range rows {
		if r.Count > max {
			max = r.Count
		}
	}
	for i := range rows {
		rows[i].Segments = meterSegments(rows[i].Count, max)
	}
	return rows
}

// meterSegments fills a 12-cell segmented meter with count/max, rounded up
// so any nonzero count shows at least one cell. Cells are server-computed:
// a runtime width would need a style attribute, which the CSP forbids.
func meterSegments(count, max int) []bool {
	const cells = 12
	out := make([]bool, cells)
	if count <= 0 || max <= 0 {
		return out
	}
	n := min(cells, (count*cells+max-1)/max)
	for i := range n {
		out[i] = true
	}
	return out
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

// TrafficSeries returns hourly allowed/blocked request counts for the last
// 24h as JSON, for the dashboard traffic chart. Gaps with no traffic are
// filled with zero so the chart stays continuous.
func (h *Handler) TrafficSeries(c *echo.Context) error {
	const hours = 24
	points, err := h.db.GetHourlyTraffic(hours)
	if err != nil {
		return err
	}
	labels, allowed, blocked := hourlySeries(points, hours)
	return c.JSON(http.StatusOK, map[string]any{
		"labels":  labels,
		"allowed": allowed,
		"blocked": blocked,
	})
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

// ThreatsSeries returns the top blocked-from countries in the last 24h as
// JSON, for the dashboard "Recent threats" bar chart.
func (h *Handler) ThreatsSeries(c *echo.Context) error {
	rows, err := h.db.GetTopBlockedCountries(6, 24)
	if err != nil {
		return err
	}
	labels := make([]string, 0, len(rows))
	counts := make([]int, 0, len(rows))
	for _, r := range rows {
		labels = append(labels, r.Country)
		counts = append(counts, r.Count)
	}
	return c.JSON(http.StatusOK, map[string]any{
		"labels": labels,
		"counts": counts,
	})
}
