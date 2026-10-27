package ui

import (
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
	return map[string]any{
		"AdminPath": h.cfg.Admin.Path,
		"Users":     users,
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

// CreateUser adds an account with an initial password the owner hands over
// out of band; the new user changes it under Settings → Account.
func (h *Handler) CreateUser(c echo.Context) error {
	email := storage.NormalizeEmail(c.FormValue("email"))
	password := c.FormValue("password")
	role := c.FormValue("role")
	switch {
	case !strings.Contains(email, "@"):
		return h.renderUsersCard(c, errors.New("enter a valid email"))
	case len(password) < 8:
		return h.renderUsersCard(c, errors.New("initial password must be at least 8 characters"))
	case !storage.ValidRole(role):
		return h.renderUsersCard(c, errors.New("pick a role"))
	}
	if _, err := h.db.CreateAdminUser(email, password, role); err != nil {
		return h.renderUsersCard(c, err)
	}
	log.Printf("admin users: %s added %s as %s", currentUser(c).Email, email, role)
	return h.renderUsersCard(c, nil)
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
