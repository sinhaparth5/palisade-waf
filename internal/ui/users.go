package ui

import (
	"log"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"

	"palisade/internal/storage"
)

// ── Roles (issue #196) ───────────────────────────────────────────────────────

// roleRank orders the fixed roles; a route needing role r admits any user
// whose rank is at least roleRank[r].
var roleRank = map[string]int{storage.RoleViewer: 1, storage.RoleAdmin: 2, storage.RoleOwner: 3}

// ctxUser is the *echo.Context key sessionAuth stores the signed-in user under.
const ctxUser = "admin_user"

// currentUser returns the signed-in user, or nil outside sessionAuth.
func currentUser(c *echo.Context) *storage.AdminUser {
	u, _ := c.Get(ctxUser).(*storage.AdminUser)
	return u
}

// currentUID is currentUser's id, 0 when nobody is signed in.
func currentUID(c *echo.Context) int64 {
	if u := currentUser(c); u != nil {
		return u.ID
	}
	return 0
}

// requireRole enforces the minimum role each route declared in Register
// (h.routeRoles). Undeclared GETs are open to every role; an undeclared
// mutating route needs admin, so a route someone forgot to declare is
// still closed to viewers (TestRouteRoles also fails on it).
func (h *Handler) requireRole(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		r := c.Request()
		need, ok := h.routeRoles[r.Method+" "+c.Path()]
		if !ok {
			need = storage.RoleAdmin
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				need = storage.RoleViewer
			}
		}
		u := currentUser(c)
		if u == nil || roleRank[u.Role] < roleRank[need] {
			return denied(c, "forbidden", "Your role can't do this.")
		}
		// The shared demo account can't change its password or second
		// factors, or sign other visitors out: only these writes are left.
		if h.isDemo(u) && r.Method != http.MethodGet && r.Method != http.MethodHead {
			switch strings.TrimPrefix(c.Path(), h.cfg.Admin.Path) {
			case "/logout", "/api/notifications/seen":
			default:
				return denied(c, "demo", "Disabled in the demo.")
			}
		}
		return next(c)
	}
}

// isDemo reports whether u is the --demo account.
func (h *Handler) isDemo(u *storage.AdminUser) bool {
	return u != nil && h.cfg.Admin.DemoEmail != "" && u.Email == h.cfg.Admin.DemoEmail
}

// isDemoUID is isDemo for a user id; free when --demo is off.
func (h *Handler) isDemoUID(uid int64) bool {
	if h.cfg.Admin.DemoEmail == "" {
		return false
	}
	u, _ := h.db.GetAdminUser(uid)
	return h.isDemo(u)
}

// ── Settings: users card (owner only) ────────────────────────────────────────

// ── Invite page (public) ─────────────────────────────────────────────────────

// InvitePage shows the set-password form for a live invite token.
func (h *Handler) InvitePage(c *echo.Context) error {
	return h.renderInvite(c, "")
}

// InvitePost sets the invited user's password and signs them in.
func (h *Handler) InvitePost(c *echo.Context) error {
	password := c.FormValue("password")
	if password != c.FormValue("confirm_password") {
		return h.renderInvite(c, "Passwords do not match.")
	}
	var email string
	if u, _ := h.db.UserInvite(c.Param("token")); u != nil {
		email = u.Email
	}
	if err := ValidateAdminPassword(c.Request().Context(), h.pwBreach, email, password); err != nil {
		return h.renderInvite(c, err.Error())
	}
	ip := h.clientIP(c.Request())
	if _, locked := h.loginLimiter.blocked(ip); locked {
		return h.renderLoginStatus(c, http.StatusTooManyRequests, "Too many failed attempts. Try again later.")
	}
	u, err := h.db.AcceptUserInvite(c.Param("token"), password)
	if err != nil {
		return err
	}
	if u == nil {
		h.loginLimiter.fail(ip)
		return h.renderInvite(c, "")
	}
	log.Printf("admin users: %s set their password from an invite (%s)", u.Email, ip)
	return h.issueSession(c, u.ID)
}

// renderInvite renders the login page's set-password stage, or the dead-link
// message when the token isn't live (unknown, spent and expired look alike).
func (h *Handler) renderInvite(c *echo.Context, errMsg string) error {
	ip := h.clientIP(c.Request())
	if _, locked := h.loginLimiter.blocked(ip); locked {
		return h.renderLoginStatus(c, http.StatusTooManyRequests, "Too many failed attempts. Try again later.")
	}
	// The token is in the URL; keep it out of Referer headers.
	c.Response().Header().Set("Referrer-Policy", "no-referrer")
	data := map[string]any{"AdminPath": h.cfg.Admin.Path, "Asset": h.assetVer, "InviteStage": true, "Error": errMsg}
	status := http.StatusOK
	u, err := h.db.UserInvite(c.Param("token"))
	if err != nil {
		return err
	}
	if u == nil {
		status = http.StatusNotFound
		data["Error"] = "This invite link has expired or was already used. Ask whoever added you to resend it."
	} else {
		data["InviteEmail"] = u.Email
		data["Token"] = c.Param("token")
	}
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Response().WriteHeader(status)
	return h.tmpls["login"].ExecuteTemplate(c.Response(), "login", data)
}
