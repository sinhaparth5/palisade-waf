package ui

import (
	"cmp"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/labstack/echo/v5"

	"palisade/internal/storage"
)

// The React Settings page's owner section (issue #355): users and their
// invites, SSO and its invites, and API keys.

type userJSON struct {
	ID        int64  `json:"id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	Disabled  bool   `json:"disabled"`
	TOTP      bool   `json:"totp"`
	SSO       bool   `json:"sso"`
	Invited   bool   `json:"invited"` // hasn't set a password from the link yet
	CreatedAt string `json:"created_at"`
	You       bool   `json:"you"`
}

type ssoInviteJSON struct {
	ID        int64  `json:"id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	ExpiresAt string `json:"expires_at"`
	Expired   bool   `json:"expired"`
}

type apiKeyJSON struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Prefix     string `json:"prefix"`
	ReadOnly   bool   `json:"read_only"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at"` // "" = never
}

// Team answers GET /api/settings/team (owner only).
func (h *Handler) Team(c *echo.Context) error {
	users, err := h.db.ListAdminUsers()
	if err != nil {
		return err
	}
	invites, err := h.db.ListSSOInvites()
	if err != nil {
		return err
	}
	sso, err := h.db.GetSSOConfig()
	if err != nil {
		return err
	}
	keys, err := h.db.ListAPIKeys()
	if err != nil {
		return err
	}
	me := currentUID(c)
	us := make([]userJSON, len(users))
	for i, u := range users {
		us[i] = userJSON{u.ID, u.Email, u.Role, u.Disabled, u.TOTPEnabled, u.SSO, u.Invited, rfc3339(u.CreatedAt), u.ID == me}
	}
	iv := make([]ssoInviteJSON, len(invites))
	for i, v := range invites {
		iv[i] = ssoInviteJSON{v.ID, v.Email, v.Role, rfc3339(v.ExpiresAt), v.Expired()}
	}
	ks := make([]apiKeyJSON, len(keys))
	for i, k := range keys {
		ks[i] = apiKeyJSON{ID: k.ID, Name: k.Name, Prefix: k.Prefix, ReadOnly: k.ReadOnly, CreatedAt: rfc3339(k.CreatedAt)}
		if k.LastUsedAt != nil {
			ks[i].LastUsedAt = rfc3339(*k.LastUsedAt)
		}
	}
	return c.JSON(http.StatusOK, map[string]any{
		"users":    us,
		"invites":  iv,
		"api_keys": ks,
		"sso": map[string]any{
			"issuer": sso.Issuer, "client_id": sso.ClientID, "secret_set": sso.ClientSecret != "",
			"group": sso.Group, "callback_url": h.ssoCallbackURL(c),
		},
		"ext_login": func() string { l, _ := extLogin(); return l }(), // ext.LoginButton, which takes SSO invites too
	})
}

func conflict(msg string) *jsonError {
	return &jsonError{Status: http.StatusConflict, Code: "conflict", Message: msg}
}

// userError maps storage's refusals to answers the page can show.
func userError(err error) error {
	switch {
	case errors.Is(err, storage.ErrLastOwner):
		return conflict("The last owner can't be demoted, disabled or removed.")
	case errors.Is(err, storage.ErrUserExists):
		return &jsonError{Status: http.StatusConflict, Code: "conflict", Message: "A user with that email already exists.", Fields: map[string]string{"email": "A user with that email already exists."}}
	case errors.Is(err, storage.ErrSSOLinked):
		return conflict("That user already signs in with single sign-on.")
	}
	return err
}

type inviteRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

func (r *inviteRequest) check() error {
	r.Email = storage.NormalizeEmail(r.Email)
	if !storage.ValidEmail(r.Email) {
		return fieldError("email", "Enter a valid email address.")
	}
	if !storage.ValidRole(r.Role) {
		return fieldError("role", "Pick a role.")
	}
	return nil
}

func userID(c *echo.Context) (int64, error) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return 0, badBody("Invalid id.")
	}
	return id, nil
}

// AddUser creates a password-less user and emails them a link to set a
// password (issue #229): 201 with the outcome of the email.
func (h *Handler) AddUser(c *echo.Context) error {
	var req inviteRequest
	if err := c.Bind(&req); err != nil {
		return badBody("Send email and role as JSON.")
	}
	if err := req.check(); err != nil {
		return err
	}
	id, token, err := h.db.InviteAdminUser(req.Email, req.Role)
	if err != nil {
		return userError(err)
	}
	log.Printf("admin users: %s invited %s as %s", currentUser(c).Email, req.Email, req.Role)
	return h.mailInvite(c, http.StatusCreated, id, token)
}

// ResendInvite replaces a pending user's link and sends it again.
func (h *Handler) ResendInvite(c *echo.Context) error {
	id, err := userID(c)
	if err != nil {
		return err
	}
	token, err := h.db.RenewUserInvite(id)
	if err != nil {
		return conflict(cmp.Or(err.Error(), "Couldn't renew the invite."))
	}
	return h.mailInvite(c, http.StatusOK, id, token)
}

// mailInvite sends user id their link. When sending fails (often: email
// isn't set up) the user still exists, so the answer carries the link,
// shown once, for the owner to pass on.
func (h *Handler) mailInvite(c *echo.Context, status int, id int64, token string) error {
	u, err := h.db.GetAdminUser(id)
	if err != nil {
		return err
	}
	if u == nil {
		return &jsonError{Status: http.StatusNotFound, Code: "not_found", Message: "That user is gone."}
	}
	link := c.Scheme() + "://" + c.Request().Host + h.cfg.Admin.Path + "/invite/" + token
	if err := h.sendInvite(u.Email, currentUser(c).Email, u.Role, link); err != nil {
		log.Printf("admin users: invite email to %s failed: %v", u.Email, err)
		return c.JSON(status, map[string]any{"email": u.Email, "sent": false, "link": link, "send_error": err.Error()})
	}
	return c.JSON(status, map[string]any{"email": u.Email, "sent": true})
}

// UpdateUserJSON changes a user's role or turns them off and on: PUT
// {"role"} or {"disabled"}. The last-owner guard lives in storage.
func (h *Handler) UpdateUserJSON(c *echo.Context) error {
	id, err := userID(c)
	if err != nil {
		return err
	}
	var req struct {
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
	}
	if err := c.Bind(&req); err != nil {
		return badBody(`Send {"role"} or {"disabled"} as JSON.`)
	}
	switch {
	case req.Role != nil:
		if !storage.ValidRole(*req.Role) {
			return fieldError("role", "Pick a role.")
		}
		err = h.db.SetAdminUserRole(id, *req.Role)
	case req.Disabled != nil:
		err = h.db.SetAdminUserDisabled(id, *req.Disabled)
	default:
		return badBody(`Send {"role"} or {"disabled"} as JSON.`)
	}
	if err != nil {
		return userError(err)
	}
	return c.NoContent(http.StatusNoContent)
}

// ResetUser2FA turns off another user's TOTP and removes their passkeys.
// Your own goes off only with a code, so a hijacked session can't use this.
func (h *Handler) ResetUser2FA(c *echo.Context) error {
	id, err := userID(c)
	if err != nil {
		return err
	}
	if id == currentUID(c) {
		return conflict("Turn off your own 2FA from the Two-Factor Authentication card.")
	}
	if err := h.db.ResetAdminUser2FA(id); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// RemoveUser deletes a user with their sessions and passkeys.
func (h *Handler) RemoveUser(c *echo.Context) error {
	id, err := userID(c)
	if err != nil {
		return err
	}
	if err := h.db.DeleteAdminUser(id); err != nil {
		return userError(err)
	}
	return c.NoContent(http.StatusNoContent)
}

// AddSSOInvite invites an email to sign in with SSO under a role.
func (h *Handler) AddSSOInvite(c *echo.Context) error {
	var req inviteRequest
	if err := c.Bind(&req); err != nil {
		return badBody("Send email and role as JSON.")
	}
	if err := req.check(); err != nil {
		return err
	}
	if sso, err := h.db.GetSSOConfig(); err != nil {
		return err
	} else if sso.Issuer == "" && !hasExtLogin() { // an add-on login spends invites too
		return conflict("Set up single sign-on first.")
	}
	if err := h.db.CreateSSOInvite(req.Email, req.Role); err != nil {
		return userError(err)
	}
	return c.NoContent(http.StatusCreated)
}

// RenewSSOInviteJSON restarts an invite's 7 days.
func (h *Handler) RenewSSOInviteJSON(c *echo.Context) error {
	id, err := userID(c)
	if err != nil {
		return err
	}
	if err := h.db.RenewSSOInvite(id); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// RemoveSSOInvite deletes a pending invite.
func (h *Handler) RemoveSSOInvite(c *echo.Context) error {
	id, err := userID(c)
	if err != nil {
		return err
	}
	if err := h.db.DeleteSSOInvite(id); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

type ssoRequest struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"` // "" keeps the stored one
	Group        string `json:"group"`
}

// SetSSO stores the SSO config after checking discovery works. An empty
// issuer turns SSO off.
func (h *Handler) SetSSO(c *echo.Context) error {
	var req ssoRequest
	if err := c.Bind(&req); err != nil {
		return badBody("Send the SSO settings as JSON.")
	}
	stored, err := h.db.GetSSOConfig()
	if err != nil {
		return err
	}
	cfg := storage.SSOConfig{
		Issuer:       strings.TrimRight(strings.TrimSpace(req.Issuer), "/"),
		ClientID:     strings.TrimSpace(req.ClientID),
		ClientSecret: cmp.Or(strings.TrimSpace(req.ClientSecret), stored.ClientSecret),
		Group:        strings.TrimSpace(req.Group),
	}
	if cfg.Issuer == "" {
		cfg = storage.SSOConfig{}
	} else {
		if err := checkIssuer(cfg); err != nil {
			return err
		}
		ctx, cancel := ssoContext()
		defer cancel()
		// go-oidc rejects a discovery document whose issuer differs from
		// the one entered, which catches a typo now rather than at login.
		if _, err := oidc.NewProvider(ctx, cfg.Issuer); err != nil {
			return fieldError("issuer", "Discovery failed: "+err.Error())
		}
	}
	if err := h.db.SetSSOConfig(cfg); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// AddAPIKey makes a bearer key for /api/v1 and answers with it once; only
// its hash and a display prefix are stored.
func (h *Handler) AddAPIKey(c *echo.Context) error {
	var req struct {
		Name     string `json:"name"`
		ReadOnly bool   `json:"read_only"`
	}
	if err := c.Bind(&req); err != nil {
		return badBody("Send name and read_only as JSON.")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return fieldError("name", "Name the key, e.g. after what uses it.")
	}
	raw, prefix, hash, err := newAPIKey()
	if err != nil {
		return err
	}
	if _, err := h.db.CreateAPIKey(name, prefix, hash, req.ReadOnly); err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, map[string]string{"key": raw})
}

// RemoveAPIKey revokes a key; anything using it gets a 401 on its next call.
func (h *Handler) RemoveAPIKey(c *echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return badBody("Invalid key id.")
	}
	if err := h.db.RemoveAPIKey(id); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}
