package ui

import (
	"net/http"
	"net/http/pprof" //nolint:gosec // G108: also registers on http.DefaultServeMux, which no server in internal/app uses; served here behind session + owner (issue #267)
	"strconv"

	"github.com/labstack/echo/v5"
)

// pprofMaxSeconds caps ?seconds= on the CPU profile and trace, which keep
// the runtime busy for that long. The servers set no WriteTimeout, so
// net/http/pprof would otherwise accept any duration.
const pprofMaxSeconds = 60

// Pprof serves net/http/pprof under {admin}/debug/pprof/ (issue #267). It is
// registered in the owner block of the session group, so it is never on the
// REST API, and hostGuard keeps it off service hosts.
func (h *Handler) Pprof(c *echo.Context) error {
	r := c.Request()
	// A GET, so CSRF doesn't apply and the Lax session cookie rides along on
	// a cross-site navigation: refuse that, so another site can't make an
	// owner's browser start profiles.
	if s := r.Header.Get("Sec-Fetch-Site"); s != "" && s != "same-origin" && s != "none" {
		return c.String(http.StatusForbidden, "cross-site request")
	}
	if s := r.URL.Query().Get("seconds"); s != "" {
		if n, err := strconv.Atoi(s); err != nil || n < 1 || n > pprofMaxSeconds {
			return c.String(http.StatusBadRequest, "seconds must be 1-"+strconv.Itoa(pprofMaxSeconds))
		}
	}
	w := c.Response()
	switch name := c.Param("*"); name {
	case "":
		pprof.Index(w, r) // links on the page are relative, so they stay under the admin path
	case "cmdline":
		pprof.Cmdline(w, r)
	case "profile":
		pprof.Profile(w, r)
	case "symbol":
		pprof.Symbol(w, r)
	case "trace":
		pprof.Trace(w, r)
	default:
		pprof.Handler(name).ServeHTTP(w, r) // unknown names answer 404 "Unknown profile"
	}
	return nil
}
