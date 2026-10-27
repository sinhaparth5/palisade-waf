package proxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"

	"palisade/internal/security/waitroom"
	"palisade/internal/storage"
)

// ── Maintenance mode and waiting room (issue #198) ───────────────────────────

const (
	bypassParam  = "palisade_bypass"
	bypassCookie = "cz_bypass"
	// waitCookie is suffixed with the service id: prefix-routed services
	// share a host, and so a cookie jar.
	waitCookie      = "cz_wait_"
	defaultIdleSecs = 600
)

// gates holds the waiting rooms by service name. They outlive
// Registry.Reload, which rebuilds services on every save: a settings
// change must not empty the queue.
type gates struct {
	rooms   sync.Map // service name -> *waitroom.Room
	keyOnce sync.Once
	key     []byte
}

// signKey is the challenge secret, so tickets survive a restart like the
// challenge cookie does; a random key if it can't be read (tests, no DB).
func (h *Handler) signKey() []byte {
	h.gates.keyOnce.Do(func() {
		if h.db != nil {
			if s, err := h.db.GetOrCreateChallengeSecret(); err == nil && s != "" {
				h.gates.key = []byte("waitroom|" + s)
				return
			}
		}
		h.gates.key = make([]byte, 32)
		rand.Read(h.gates.key) //nolint — never errors on modern platforms
	})
	return h.gates.key
}

// ticketSig binds a ticket to the service and the client key, so a cookie
// copied to another network is worth nothing.
func (h *Handler) ticketSig(service, ticket, clientKey string) string {
	m := hmac.New(sha256.New, h.signKey())
	m.Write([]byte(service + "|" + ticket + "|" + clientKey))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// gate applies maintenance and the waiting room to a request that passed
// the blocklists, challenge and rate limits. A non-empty reason means it
// answered the request itself (err is the write's result).
func (h *Handler) gate(c echo.Context, app *storage.Service, clientKey string, crawler bool, reqID string) (reason string, err error) {
	g, now := app.Gate, time.Now()
	r := c.Request()

	if g.MaintenanceActive(now) {
		if tok := r.URL.Query().Get(bypassParam); g.BypassToken != "" && tok != "" &&
			subtle.ConstantTimeCompare([]byte(tok), []byte(g.BypassToken)) == 1 {
			c.SetCookie(&http.Cookie{Name: bypassCookie, Value: tok, Path: "/", MaxAge: 12 * 3600,
				HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
			// Strip the token before anything logs or proxies the URL.
			u := *r.URL
			q := u.Query()
			q.Del(bypassParam)
			u.RawQuery = q.Encode()
			return "maintenance_bypass", c.Redirect(http.StatusFound, u.RequestURI())
		}
		ck, _ := r.Cookie(bypassCookie)
		if g.BypassToken == "" || ck == nil || subtle.ConstantTimeCompare([]byte(ck.Value), []byte(g.BypassToken)) != 1 {
			retry := 300
			msg := g.MaintMsg
			if msg == "" {
				msg = "This site is down for scheduled maintenance. Please check back soon."
			}
			if !g.MaintEnd.IsZero() {
				retry = max(1, int(g.MaintEnd.Sub(now).Seconds()))
				msg += " Expected back by " + g.MaintEnd.UTC().Format("2006-01-02 15:04 UTC") + "."
			}
			c.Response().Header().Set("Retry-After", strconv.Itoa(retry))
			return "maintenance", gatePage(c, "maintenance", reqID, "Down for maintenance", msg, 0)
		}
	}

	if !g.WaitingRoom || g.MaxActive < 1 {
		h.gates.rooms.Delete(app.Name)
		return "", nil
	}
	if crawler {
		// Verified crawlers never take or wait for a slot.
		if g.Crawlers != "deny" {
			return "", nil
		}
		c.Response().Header().Set("Retry-After", "600")
		return "waiting_room", gatePage(c, "waiting_room", reqID, "Busy", "This site is busy. Try again later.", 0)
	}
	v, _ := h.gates.rooms.LoadOrStore(app.Name, waitroom.New())
	room := v.(*waitroom.Room)

	name := waitCookie + strconv.Itoa(app.ID)
	ticket := ""
	if ck, err := r.Cookie(name); err == nil {
		if t, sig, ok := strings.Cut(ck.Value, "."); ok && hmac.Equal([]byte(sig), []byte(h.ticketSig(app.Name, t, clientKey))) {
			ticket = t
		}
	}
	idle := time.Duration(g.IdleSecs) * time.Second
	if idle <= 0 {
		idle = defaultIdleSecs * time.Second
	}
	res := room.Visit(ticket, clientKey, g.MaxActive, idle, now)
	if res.Ticket != "" && res.Ticket != ticket {
		c.SetCookie(&http.Cookie{Name: name, Value: res.Ticket + "." + h.ticketSig(app.Name, res.Ticket, clientKey),
			Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	}
	if res.Admitted {
		return "", nil
	}
	c.Response().Header().Set("Retry-After", strconv.Itoa(waitroom.PollSecs))
	if res.Full {
		return "waiting_room", gatePage(c, "waiting_room", reqID, "Busy", "This site is very busy and the queue is full. Try again in a few minutes.", 0)
	}
	msg := g.WaitMsg
	if msg == "" {
		msg = "This site is busy right now. You're in line and will be let in automatically; keep this page open."
	}
	return "waiting_room", gatePage(c, "waiting_room", reqID, "You're in line",
		msg+" Your place in line: "+strconv.Itoa(res.Position)+".", waitroom.PollSecs)
}

// gatePage writes a 503 like deny: the branded page for browsers (with a
// meta refresh when refresh > 0, so the queue works without JavaScript),
// JSON for everything else.
func gatePage(c echo.Context, reason, reqID, title, msg string, refresh int) error {
	c.Response().Header().Set("X-WAF-Block-Reason", reason)
	c.Response().Header().Set("Cache-Control", "no-store")
	if !strings.Contains(c.Request().Header.Get("Accept"), "text/html") {
		return c.JSON(http.StatusServiceUnavailable, map[string]any{"error": msg, "request_id": reqID})
	}
	var buf bytes.Buffer
	if err := blockPageTmpl.Execute(&buf, map[string]any{
		"Status":     http.StatusServiceUnavailable,
		"StatusText": http.StatusText(http.StatusServiceUnavailable),
		"Title":      title,
		"Message":    msg,
		"Refresh":    refresh,
		"Host":       c.Request().Host,
		"Time":       time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		"RequestID":  reqID,
	}); err != nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]any{"error": msg, "request_id": reqID})
	}
	return c.HTMLBlob(http.StatusServiceUnavailable, buf.Bytes())
}
