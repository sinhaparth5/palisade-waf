package proxy

import "github.com/labstack/echo/v5"

// SecurityMiddleware sets hardening HTTP headers on every response:
// standard browser security directives (Server: Palisade is set by the handler).
// Applied globally so blocked responses, admin UI pages, and proxied responses
// all carry the same baseline security posture.
func SecurityMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			h := c.Response().Header()

			// ── Browser hardening ─────────────────────────────────────────────────
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "SAMEORIGIN")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			h.Set("Permissions-Policy",
				"camera=(), microphone=(), geolocation=(), payment=(), usb=()")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")

			// HSTS: only advertise over TLS to avoid breaking plain-HTTP dev setups.
			// 63072000 s = 2 years, matching hstspreload.org recommendations.
			if c.Request().TLS != nil {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			}

			return next(c)
		}
	}
}
