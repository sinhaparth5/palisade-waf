package ui

import (
	"cmp"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"palisade/internal/storage"
)

// ── Roles (issue #196) ───────────────────────────────────────────────────────

// roleRank orders the fixed roles; a route needing role r admits any user
// whose rank is at least roleRank[r].
var roleRank = map[string]int{storage.RoleViewer: 1, storage.RoleAdmin: 2, storage.RoleOwner: 3}

// ctxUser is the echo.Context key sessionAuth stores the signed-in user under.
const ctxUser = "admin_user"

// currentUser returns the signed-in user, or nil outside sessionAuth.
func currentUser(c echo.Context) *storage.AdminUser {
	u, _ := c.Get(ctxUser).(*storage.AdminUser)
	return u
}

// currentUID is currentUser's id, 0 when nobody is signed in.
func currentUID(c echo.Context) int64 {
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
	return func(c echo.Context) error {
		r := c.Request()
		need, ok := h.routeRoles[r.Method+" "+c.Path()]
		if !ok {
			need = storage.RoleAdmin
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				need = storage.RoleViewer
			}
		}
		if u := currentUser(c); u == nil || roleRank[u.Role] < roleRank[need] {
			return c.String(http.StatusForbidden, "Your role can't do this.")
		}
		return next(c)
	}
}

// ── Settings: users card (owner only) ────────────────────────────────────────

func (h *Handler) usersCardData(c echo.Context, errMsg string) map[string]any {
	users, _ := h.db.ListAdminUsers()
	invites, _ := h.db.ListSSOInvites()
	sso, _ := h.db.GetSSOConfig()
	return map[string]any{
		"AdminPath": h.cfg.Admin.Path,
		"Users":     users,
		"Invites":   invites,
		"SSOOn":     sso.Issuer != "",
		"MyID":      currentUID(c),
		"UserErr":   errMsg,
	}
}

func (h *Handler) renderUsersCard(c echo.Context, err error) error {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	return h.renderPartial(c, "settings", "users-card", h.usersCardData(c, msg))
}

// CreateUser adds a password-less account and emails it a set-password
// link (issue #229).
func (h *Handler) CreateUser(c echo.Context) error {
	email := storage.NormalizeEmail(c.FormValue("email"))
	role := c.FormValue("role")
	switch {
	case !strings.Contains(email, "@"):
		return h.renderUsersCard(c, errors.New("enter a valid email"))
	case !storage.ValidRole(role):
		return h.renderUsersCard(c, errors.New("pick a role"))
	}
	id, token, err := h.db.InviteAdminUser(email, role)
	if err != nil {
		return h.renderUsersCard(c, err)
	}
	log.Printf("admin users: %s invited %s as %s", currentUser(c).Email, email, role)
	return h.sendUserInvite(c, id, token)
}

// ResendUserInvite replaces a pending user's link and sends it again.
func (h *Handler) ResendUserInvite(c echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	token, err := h.db.RenewUserInvite(id)
	if err != nil {
		return h.renderUsersCard(c, err)
	}
	return h.sendUserInvite(c, id, token)
}

// sendUserInvite emails user id their link. When that fails (often: email
// isn't set up) the user still exists, so the card shows the link once for
// the owner to pass on, rather than an error.
func (h *Handler) sendUserInvite(c echo.Context, id int64, token string) error {
	u, err := h.db.GetAdminUser(id)
	if err != nil || u == nil {
		return h.renderUsersCard(c, cmp.Or(err, errors.New("user not found")))
	}
	link := c.Scheme() + "://" + c.Request().Host + h.cfg.Admin.Path + "/invite/" + token
	data := h.usersCardData(c, "")
	if err := h.sendInvite(u.Email, currentUser(c).Email, u.Role, link); err != nil {
		log.Printf("admin users: invite email to %s failed: %v", u.Email, err)
		data["UserNotice"] = "Added " + u.Email + ", but the invite email wasn't sent (" + err.Error() + ")."
		data["InviteLink"] = link
	} else {
		data["UserNotice"] = "Invite sent to " + u.Email + "."
	}
	return h.renderPartial(c, "settings", "users-card", data)
}

// ── Invite page (public) ─────────────────────────────────────────────────────

// InvitePage shows the set-password form for a live invite token.
func (h *Handler) InvitePage(c echo.Context) error {
	return h.renderInvite(c, "")
}

// InvitePost sets the invited user's password and signs them in.
func (h *Handler) InvitePost(c echo.Context) error {
	password := c.FormValue("password")
	switch {
	case len(password) < 8:
		return h.renderInvite(c, "Password must be at least 8 characters.")
	case password != c.FormValue("confirm_password"):
		return h.renderInvite(c, "Passwords do not match.")
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
func (h *Handler) renderInvite(c echo.Context, errMsg string) error {
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

// UpdateUser applies one owner action to a user: change role, disable,
// enable, or reset 2FA. The last-owner guard lives in storage.
func (h *Handler) UpdateUser(c echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	switch action := c.FormValue("action"); action {
	case "role":
		err = h.db.SetAdminUserRole(id, c.FormValue("role"))
	case "disable", "enable":
		err = h.db.SetAdminUserDisabled(id, action == "disable")
	case "reset-2fa":
		// Your own 2FA goes off only with a current code (DisableTOTP), so
		// a hijacked session can't strip it here instead.
		if id == currentUID(c) {
			err = errors.New("turn off your own 2FA from the Two-Factor Authentication card")
			break
		}
		err = h.db.ResetAdminUser2FA(id)
	default:
		err = errors.New("unknown action")
	}
	return h.renderUsersCard(c, err)
}

// DeleteUser removes a user with their sessions and passkeys.
func (h *Handler) DeleteUser(c echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	return h.renderUsersCard(c, h.db.DeleteAdminUser(id))
}
