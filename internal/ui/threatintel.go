package ui

import (
	"fmt"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"time"

	"palisade/internal/storage"

	"github.com/labstack/echo/v5"
)

// ── Threat Intel ─────────────────────────────────────────────────────────────

type intelPreset struct {
	Label         string `json:"label"`
	URL           string `json:"url"`
	IntervalHours int    `json:"interval_hours"`
}

// Presets are well-known free threat intel block lists shown as quick-add chips.
var threatIntelPresets = []intelPreset{
	{"Tor Exit Nodes", "https://check.torproject.org/torbulkexitlist", 6},
	{"Emerging Threats", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", 24},
	{"Spamhaus DROP", "https://www.spamhaus.org/drop/drop.txt", 24},
	{"Feodo Tracker", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", 12},
	{"CINS Score", "http://cinsscore.com/list/ci-badguys.txt", 24},
}

// intelView is a source as the React Threat Intel page shows it. A CrowdSec
// source's URL is its LAPI without the storage prefix; its bouncer key and
// machine credentials never leave the server, Push only says whether
// autobans are sent.
type intelView struct {
	ID            int64  `json:"id"`
	Label         string `json:"label"`
	Kind          string `json:"kind"` // "feed" or "crowdsec"
	URL           string `json:"url"`
	IntervalHours int    `json:"interval_hours"`
	Enabled       bool   `json:"enabled"`
	LastSyncedAt  string `json:"last_synced_at"` // "" = never
	LastError     string `json:"last_error"`
	IPs           int    `json:"ips"` // single addresses
	Ranges        int    `json:"ranges"`
	Push          bool   `json:"push"`
}

func (h *Handler) intelViews() ([]intelView, error) {
	sources, err := h.db.ListThreatIntelSources()
	if err != nil {
		return nil, err
	}
	ranges, err := h.db.ThreatIntelRangeCounts()
	if err != nil {
		return nil, err
	}
	out := make([]intelView, 0, len(sources))
	for _, s := range sources {
		v := intelView{ID: s.ID, Label: s.Label, Kind: "feed", URL: s.URL, IntervalHours: s.IntervalHours, Enabled: s.Enabled,
			LastError: s.LastError, IPs: s.IPCount - ranges[s.ID], Ranges: ranges[s.ID]}
		if !s.LastSyncedAt.IsZero() {
			v.LastSyncedAt = s.LastSyncedAt.UTC().Format(time.RFC3339)
		}
		if s.CrowdSec() {
			v.Kind, v.URL = "crowdsec", strings.TrimPrefix(s.URL, storage.CrowdSecPrefix)
			if _, _, v.Push, err = h.db.CrowdSecMachine(s.ID); err != nil {
				return nil, err
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// ListThreatIntel answers GET /api/threat-intel: every source with its sync
// state, and the quick-add presets.
func (h *Handler) ListThreatIntel(c *echo.Context) error {
	views, err := h.intelViews()
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"sources": views, "presets": threatIntelPresets})
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

// intelURLError checks a source URL and that no other source is already
// stored as stored (the URL itself, or a CrowdSec LAPI with its prefix).
func (h *Handler) intelURLError(url, stored string) error {
	if url == "" {
		return fieldError("url", "Enter the URL to fetch.")
	}
	if err := validateOutboundURL(url); err != nil {
		return fieldError("url", "Use an absolute http:// or https:// URL.")
	}
	sources, err := h.db.ListThreatIntelSources()
	if err != nil {
		return err
	}
	for _, s := range sources {
		if s.URL == stored {
			return &jsonError{Status: http.StatusConflict, Code: "conflict", Message: "A source with this URL already exists.", Fields: map[string]string{"url": "A source with this URL already exists."}}
		}
	}
	return nil
}

type intelAddRequest struct {
	Label         string `json:"label"`
	URL           string `json:"url"`
	IntervalHours int    `json:"interval_hours"`
}

// AddThreatIntelSource adds a plain-text feed; the worker fetches it on its
// next pass (or on Sync now).
func (h *Handler) AddThreatIntelSource(c *echo.Context) error {
	var req intelAddRequest
	if err := c.Bind(&req); err != nil {
		return &jsonError{Status: http.StatusBadRequest, Code: "invalid", Message: "Send label, url and interval_hours as JSON."}
	}
	label, url := strings.TrimSpace(req.Label), strings.TrimSpace(req.URL)
	if label == "" {
		return fieldError("label", "Give the feed a label.")
	}
	if req.IntervalHours < 1 {
		return fieldError("interval_hours", "Sync at least every hour or longer.")
	}
	if err := h.intelURLError(url, url); err != nil {
		return err
	}
	if err := h.db.AddThreatIntelSource(label, url, req.IntervalHours); err != nil {
		return err
	}
	return c.NoContent(http.StatusCreated)
}

type crowdSecAddRequest struct {
	Label           string `json:"label"`
	URL             string `json:"url"`
	APIKey          string `json:"api_key"`
	MachineLogin    string `json:"machine_login"`
	MachinePassword string `json:"machine_password"`
}

// AddCrowdSecSource adds a CrowdSec LAPI source (issue #194). The bouncer
// key and the optional machine credentials (pushing autobans, issue #342)
// are stored sealed and never sent back; the worker's next poll (within
// 30s) does the initial sync.
func (h *Handler) AddCrowdSecSource(c *echo.Context) error {
	var req crowdSecAddRequest
	if err := c.Bind(&req); err != nil {
		return &jsonError{Status: http.StatusBadRequest, Code: "invalid", Message: "Send the CrowdSec source as JSON."}
	}
	label, url := strings.TrimSpace(req.Label), strings.TrimRight(strings.TrimSpace(req.URL), "/")
	key, login, password := strings.TrimSpace(req.APIKey), strings.TrimSpace(req.MachineLogin), req.MachinePassword
	switch {
	case label == "":
		return fieldError("label", "Give the source a label.")
	case key == "":
		return fieldError("api_key", "Paste the bouncer key from cscli bouncers add.")
	case strings.ContainsAny(login, "\r\n"):
		return fieldError("machine_login", "The login can't contain a line break.")
	case login != "" && password == "":
		return fieldError("machine_password", "Enter the machine password, or clear the login.")
	case login == "" && password != "":
		return fieldError("machine_login", "Enter the machine login, or clear the password.")
	}
	if err := h.intelURLError(url, storage.CrowdSecPrefix+url); err != nil {
		return err
	}
	if err := h.db.AddCrowdSecSource(label, url, key, login, password); err != nil {
		return err
	}
	return c.NoContent(http.StatusCreated)
}

func intelID(c *echo.Context) (int64, error) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return 0, &jsonError{Status: http.StatusBadRequest, Code: "invalid", Message: "Invalid source id."}
	}
	return id, nil
}

// DeleteThreatIntelSource removes a source, its sealed keys and its IPs from
// the blocklist.
func (h *Handler) DeleteThreatIntelSource(c *echo.Context) error {
	id, err := intelID(c)
	if err != nil {
		return err
	}
	if err := h.db.DeleteThreatIntelSource(id); err != nil {
		return err
	}
	if err := h.ipbl.ReloadIntel(h.db); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// SetThreatIntelSource pauses or resumes a source: PUT {"enabled": bool}.
// A paused source's IPs stop blocking at once.
func (h *Handler) SetThreatIntelSource(c *echo.Context) error {
	id, err := intelID(c)
	if err != nil {
		return err
	}
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := c.Bind(&req); err != nil || req.Enabled == nil {
		return &jsonError{Status: http.StatusBadRequest, Code: "invalid", Message: `Send {"enabled": true|false}.`}
	}
	if err := h.db.SetThreatIntelSourceEnabled(id, *req.Enabled); err != nil {
		return err
	}
	if err := h.ipbl.ReloadIntel(h.db); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// SyncThreatIntelSource fetches one source now and answers with its new
// state (the fetch runs in the request; a failure is its last_error).
func (h *Handler) SyncThreatIntelSource(c *echo.Context) error {
	id, err := intelID(c)
	if err != nil {
		return err
	}
	if h.syncThreatIntel != nil {
		h.syncThreatIntel(id)
	}
	views, err := h.intelViews()
	if err != nil {
		return err
	}
	for _, v := range views {
		if v.ID == id {
			return c.JSON(http.StatusOK, v)
		}
	}
	return &jsonError{Status: http.StatusNotFound, Code: "not_found", Message: "That source no longer exists."}
}
