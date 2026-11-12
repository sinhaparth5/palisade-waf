package ui

import (
	"fmt"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"

	"github.com/labstack/echo/v5"
)

// ── Threat Intel ─────────────────────────────────────────────────────────────

// Presets are well-known free threat intel block lists shown as quick-add chips.
var threatIntelPresets = []struct {
	Label         string
	URL           string
	IntervalHours int
}{
	{"Tor Exit Nodes", "https://check.torproject.org/torbulkexitlist", 6},
	{"Emerging Threats", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", 24},
	{"Spamhaus DROP", "https://www.spamhaus.org/drop/drop.txt", 24},
	{"Feodo Tracker", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", 12},
	{"CINS Score", "http://cinsscore.com/list/ci-badguys.txt", 24},
}

func (h *Handler) threatIntelData() map[string]any {
	sources, _ := h.db.ListThreatIntelSources()
	ranges, _ := h.db.ThreatIntelRangeCounts()
	for i := range sources {
		sources[i].RangeCount = ranges[sources[i].ID]
	}
	return map[string]any{
		"Sources":   sources,
		"Presets":   threatIntelPresets,
		"AdminPath": h.cfg.Admin.Path,
	}
}

func (h *Handler) ThreatIntelPage(c *echo.Context) error {
	return h.render(c, "threat_intel", h.threatIntelData())
}

// validateOutboundURL checks an admin-supplied URL that the server itself
// will fetch (webhook endpoint, threat-intel source): absolute, http or
// https only, never a scheme like file: or gopher:. Private/loopback hosts
// are deliberately allowed: SIEM webhooks and intel mirrors commonly live on
// the LAN, and the admin can already reach any internal address by pointing
// a service backend at it, so blocking them here would only break legitimate
// configs without removing any capability.
func validateOutboundURL(raw string) error {
	u, err := neturl.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("URL must be absolute http(s)://host[:port]/…")
	}
	return nil
}

func (h *Handler) AddThreatIntelSource(c *echo.Context) error {
	label := strings.TrimSpace(c.FormValue("label"))
	url := strings.TrimSpace(c.FormValue("url"))
	hours, err := strconv.Atoi(c.FormValue("interval_hours"))
	if err != nil || hours < 1 {
		hours = 24
	}
	if label == "" || url == "" {
		return c.String(http.StatusBadRequest, "label and url required")
	}
	if err := validateOutboundURL(url); err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}
	if err := h.db.AddThreatIntelSource(label, url, hours); err != nil {
		return c.String(http.StatusConflict, "source already exists")
	}
	return h.renderPartial(c, "threat_intel", "intel-rows", h.threatIntelData())
}

// AddCrowdSecSource adds a CrowdSec LAPI source (issue #194). The bouncer
// key is stored sealed and never rendered back; the worker's next poll
// (within 30s) does the initial sync.
func (h *Handler) AddCrowdSecSource(c *echo.Context) error {
	label := strings.TrimSpace(c.FormValue("label"))
	url := strings.TrimSpace(c.FormValue("url"))
	key := strings.TrimSpace(c.FormValue("api_key"))
	if label == "" || url == "" || key == "" {
		return c.String(http.StatusBadRequest, "label, LAPI URL and bouncer key required")
	}
	if err := validateOutboundURL(url); err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}
	if err := h.db.AddCrowdSecSource(label, url, key); err != nil {
		return c.String(http.StatusConflict, "source already exists")
	}
	return h.renderPartial(c, "threat_intel", "intel-rows", h.threatIntelData())
}

func (h *Handler) DeleteThreatIntelSource(c *echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	_ = h.db.DeleteThreatIntelSource(id)
	if err := h.ipbl.ReloadIntel(h.db); err != nil {
		return err
	}
	return h.renderPartial(c, "threat_intel", "intel-rows", h.threatIntelData())
}

func (h *Handler) ToggleThreatIntelSource(c *echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	enabled := c.FormValue("enabled") == "1"
	_ = h.db.SetThreatIntelSourceEnabled(id, enabled)
	if err := h.ipbl.ReloadIntel(h.db); err != nil {
		return err
	}
	return h.renderPartial(c, "threat_intel", "intel-rows", h.threatIntelData())
}

func (h *Handler) SyncThreatIntelSource(c *echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	if h.syncThreatIntel != nil {
		h.syncThreatIntel(id)
	}
	return h.renderPartial(c, "threat_intel", "intel-rows", h.threatIntelData())
}
