package ui

import (
	"log"
	"palisade/internal/storage"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
)

// deviceRow is one line of the Settings page's "Registered devices" card.
type deviceRow struct {
	Token     string
	Device    string // "Chrome on Windows"
	IP        string
	Location  string // country name, or "Unknown"
	Flag      string // ISO country code for the flag icon, empty if unknown
	FirstSeen time.Time
	LastSeen  time.Time
	Current   bool // the device viewing this page right now
	Live      bool // still authenticates requests
}

// browserOS turns a User-Agent into a short "Browser on OS" label.
//
// Deliberately a hand-rolled prefix match rather than a UA-parsing
// dependency: this feeds one line of admin UI, and the failure mode of a
// wrong guess is a slightly vague label, not a security decision. Order
// matters — every Chromium browser also says "Chrome", and Chrome and Edge
// both say "Safari", so the more specific brand has to be tested first.
func browserOS(ua string) string {
	if strings.TrimSpace(ua) == "" {
		return "Unknown device"
	}
	browser, os := uaBrowserOS(ua)
	return browser + " on " + os
}

// uaBrowserOS is browserOS's two halves, kept separate for the Logs page
// Stats view, which counts browsers and operating systems in their own panels.
func uaBrowserOS(ua string) (browser, os string) {
	browser = "Unknown browser"
	for _, c := range []struct{ needle, name string }{
		{"Edg/", "Edge"},
		{"OPR/", "Opera"},
		{"Brave", "Brave"},
		{"Vivaldi", "Vivaldi"},
		{"SamsungBrowser", "Samsung Internet"},
		{"Firefox/", "Firefox"},
		{"Chrome/", "Chrome"},
		{"Safari/", "Safari"},
		{"curl/", "curl"},
		{"Wget/", "Wget"},
	} {
		if strings.Contains(ua, c.needle) {
			browser = c.name
			break
		}
	}
	os = "Unknown OS"
	for _, c := range []struct{ needle, name string }{
		{"iPhone", "iPhone"},
		{"iPad", "iPad"},
		{"Android", "Android"},
		{"Windows NT 10.0", "Windows"},
		{"Windows", "Windows"},
		{"Mac OS X", "macOS"},
		{"CrOS", "ChromeOS"},
		{"Linux", "Linux"},
	} {
		if strings.Contains(ua, c.needle) {
			os = c.name
			break
		}
	}
	return browser, os
}

// deviceRows renders user uid's session history for the template, marking the row
// belonging to current (the caller's own session token).
func (h *Handler) deviceRows(uid int64, current string) []deviceRow {
	sessions, err := h.db.ListSessions(uid)
	if err != nil {
		return nil
	}
	rows := make([]deviceRow, 0, len(sessions))
	for _, s := range sessions {
		country := h.geoBl.LookupCountry(s.IP)
		location, flag := "Unknown", ""
		if name := countryName(country); name != "" {
			location, flag = name, country
		}
		rows = append(rows, deviceRow{
			Token:     s.ID,
			Device:    browserOS(s.UserAgent),
			IP:        s.IP,
			Location:  location,
			Flag:      flag,
			FirstSeen: s.CreatedAt,
			LastSeen:  s.LastActiveAt,
			Current:   s.ID == storage.SessionID(current),
			Live:      s.Live(),
		})
	}
	return currentFirst(rows)
}

// currentFirst moves the caller's own device to the top, preserving the
// order of everything else. ListSessions already sorts live sessions first,
// which is enough while the one-live-session rule holds, but a deployment
// upgraded from before that rule can still have a second live row that
// would otherwise outrank "This device".
func currentFirst(rows []deviceRow) []deviceRow {
	for i := range rows {
		if rows[i].Current && i > 0 {
			cur := rows[i]
			copy(rows[1:], rows[:i]) // copy is memmove-safe on overlap
			rows[0] = cur
			break
		}
	}
	return rows
}

// sessionCookieValue returns the caller's own session token, or "".
func sessionCookieValue(c *echo.Context) string {
	cookie, err := c.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// devicesData is the render payload shared by the card and its row list.
func (h *Handler) devicesData(c *echo.Context) map[string]any {
	current := sessionCookieValue(c)
	return map[string]any{
		"AdminPath": h.cfg.Admin.Path,
		"Devices":   h.deviceRows(currentUID(c), current),
	}
}

// RevokeDevice is the one button on each row of the "Registered devices"
// card, and does whichever of the two things that row needs: a still-live
// device is signed out (revoked, so it keeps its place in the history and
// learns why on its next request), while an already-signed-out one is
// dropped from the history entirely. One route rather than two, because the
// row's own state already says which is meant.
//
// The current device is refused either way: the Log out button in the
// sidebar already signs you out, and doing it from a device list is a
// confusing way to get there.
func (h *Handler) RevokeDevice(c *echo.Context) error {
	// The link carries the session's stored id, never its cookie token (#269).
	if id := c.Param("token"); id != storage.SessionID(sessionCookieValue(c)) {
		sess, err := h.db.GetSessionByID(id)
		switch {
		case err != nil:
			log.Printf("revoke device: %v", err)
		case sess == nil || sess.UserID != currentUID(c): // gone, or not this user's
		case sess.Live():
			if err := h.db.RevokeSession(sess.UserID, id); err != nil {
				log.Printf("revoke device: %v", err)
			}
		default:
			if err := h.db.DeleteSession(id); err != nil {
				log.Printf("forget device: %v", err)
			}
		}
	}
	return h.renderPartial(c, "settings", "devices-rows", h.devicesData(c))
}

// RevokeOtherDevices signs out every session except the caller's own.
func (h *Handler) RevokeOtherDevices(c *echo.Context) error {
	if _, err := h.db.RevokeOtherSessions(currentUID(c), storage.SessionID(sessionCookieValue(c))); err != nil {
		log.Printf("revoke other devices: %v", err)
	}
	return h.renderPartial(c, "settings", "devices-card", h.devicesData(c))
}
