package ui

import (
	"crypto/rand"
	"encoding/hex"
	"html"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"palisade/internal/storage"
)

// gateTimeLayout is what <input type="datetime-local"> submits; the form
// labels it UTC.
const gateTimeLayout = "2006-01-02T15:04"

// SetServiceGate saves a service's maintenance mode and waiting room (issue
// #198). Turning maintenance on mints a bypass token if there is none;
// new_bypass replaces it, revoking links already handed out.
func (h *Handler) SetServiceGate(c echo.Context) error {
	fail := func(msg string) error {
		c.Response().Header().Set("HX-Retarget", "#svc-gate-error")
		c.Response().Header().Set("HX-Reswap", "innerHTML")
		return c.String(http.StatusOK, html.EscapeString(msg))
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return fail("invalid service id")
	}
	stored, _ := h.db.ListServiceGates()
	g := storage.ServiceGate{
		Maintenance: c.FormValue("maintenance") == "1",
		MaintMsg:    strings.TrimSpace(c.FormValue("maint_message")),
		BypassToken: stored[id].BypassToken,
		WaitingRoom: c.FormValue("waiting_room") == "1",
		WaitMsg:     strings.TrimSpace(c.FormValue("wr_message")),
		Crawlers:    c.FormValue("wr_crawlers"),
	}
	for _, f := range []struct {
		name string
		dst  *time.Time
	}{{"maint_start", &g.MaintStart}, {"maint_end", &g.MaintEnd}} {
		if v := c.FormValue(f.name); v != "" {
			if *f.dst, err = time.Parse(gateTimeLayout, v); err != nil {
				return fail("Enter start and end as date and time.")
			}
		}
	}
	if !g.MaintStart.IsZero() && !g.MaintEnd.IsZero() && !g.MaintEnd.After(g.MaintStart) {
		return fail("The end must be after the start.")
	}
	if len(g.MaintMsg) > 500 || len(g.WaitMsg) > 500 {
		return fail("Messages are at most 500 characters.")
	}
	if g.Crawlers != "deny" {
		g.Crawlers = "bypass"
	}
	if g.MaxActive, err = strconv.Atoi(c.FormValue("wr_max")); g.WaitingRoom && (err != nil || g.MaxActive < 1 || g.MaxActive > 1_000_000) {
		return fail("Max active visitors must be between 1 and 1,000,000.")
	}
	idleMin, err := strconv.Atoi(c.FormValue("wr_idle"))
	if g.WaitingRoom && (err != nil || idleMin < 1 || idleMin > 1440) {
		return fail("Session length must be between 1 and 1440 minutes.")
	}
	g.IdleSecs = idleMin * 60
	if (g.Maintenance && g.BypassToken == "") || c.FormValue("new_bypass") == "1" {
		b := make([]byte, 16)
		rand.Read(b) //nolint — never errors on modern platforms
		g.BypassToken = hex.EncodeToString(b)
	}
	if err := h.db.SetServiceGate(id, g); err != nil {
		return fail(err.Error())
	}
	if err := h.registry.Reload(h.db); err != nil {
		return fail(err.Error())
	}
	c.Response().Header().Set("HX-Trigger", "gate-saved")
	return h.servicesRows(c)
}
