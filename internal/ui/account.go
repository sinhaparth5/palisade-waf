package ui

import (
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	qrcode "github.com/skip2/go-qrcode"

	"palisade/internal/security/passkey"
	"palisade/internal/security/totp"
	"palisade/internal/storage"
)

// The React Settings page's own-account section (issue #355): credentials,
// TOTP, passkeys and devices. Every role may use these on its own account.

type passkeyJSON struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at"` // "" = never
}

type deviceJSON struct {
	ID        string `json:"id"` // the session's stored id, never its cookie token
	Device    string `json:"device"`
	IP        string `json:"ip"`
	Location  string `json:"location"`
	Flag      string `json:"flag"` // ISO country code, "" if unknown
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Current   bool   `json:"current"`
	Live      bool   `json:"live"`
}

// Account answers GET /api/settings/account.
func (h *Handler) Account(c *echo.Context) error {
	me := currentUser(c)
	on, err := h.db.TOTPEnabled(me.ID)
	if err != nil {
		return err
	}
	rows, err := h.db.ListWebAuthnCredentials(me.ID)
	if err != nil {
		return err
	}
	keys := make([]passkeyJSON, len(rows))
	for i, r := range rows {
		keys[i] = passkeyJSON{r.ID, r.Name, rfc3339(r.CreatedAt), r.LastUsedAt}
	}
	devs := []deviceJSON{}
	for _, d := range h.deviceRows(me.ID, sessionCookieValue(c)) {
		devs = append(devs, deviceJSON{d.Token, d.Device, d.IP, d.Location, d.Flag, rfc3339(d.FirstSeen), rfc3339(d.LastSeen), d.Current, d.Live})
	}
	return c.JSON(http.StatusOK, map[string]any{
		"email":          me.Email,
		"totp":           on,
		"secure_context": passkey.IsSecureContext(c.Request()),
		"passkeys":       keys,
		"devices":        devs,
	})
}

type credentialsRequest struct {
	CurrentPassword string `json:"current_password"`
	NewEmail        string `json:"new_email"`
	NewPassword     string `json:"new_password"`
	ConfirmPassword string `json:"confirm_password"`
}

// SetCredentials changes the caller's email and/or password. Success signs
// every session of the account out, this one included (204, cookie
// cleared); the page then goes to the login screen.
func (h *Handler) SetCredentials(c *echo.Context) error {
	var req credentialsRequest
	if err := c.Bind(&req); err != nil {
		return badBody("Send the passwords as JSON.")
	}
	me := currentUser(c)
	email := strings.TrimSpace(req.NewEmail)
	if ok, _ := h.db.CheckAdminPassword(me.ID, req.CurrentPassword); !ok {
		return fieldError("current_password", "The current password is wrong.")
	}
	if email == "" && req.NewPassword == "" {
		return fieldError("new_email", "Enter a new email, a new password, or both.")
	}
	if email != "" && !storage.ValidEmail(email) {
		return fieldError("new_email", "Enter a valid email address.")
	}
	if req.NewPassword != "" {
		if req.NewPassword != req.ConfirmPassword {
			return fieldError("confirm_password", "The new passwords don't match.")
		}
		check := email
		if check == "" {
			check = me.Email
		}
		if err := ValidateAdminPassword(c.Request().Context(), h.pwBreach, check, req.NewPassword); err != nil {
			return fieldError("new_password", err.Error())
		}
	}
	if err := h.db.UpdateAdminCredentials(me.ID, email, req.NewPassword); errors.Is(err, storage.ErrUserExists) {
		return fieldError("new_email", "Another user already has that email.")
	} else if err != nil {
		return err
	}
	c.SetCookie(&http.Cookie{Name: sessionCookie, Value: "", HttpOnly: true, Path: "/", MaxAge: -1, Secure: secureCookie(c)}) //nolint:gosec // G124: Secure only over TLS so plain-HTTP setups (loopback, --admin-listen) still work
	return c.NoContent(http.StatusNoContent)
}

// StartTOTP parks a fresh secret and answers with its QR code (a PNG data
// URI) and the key grouped for typing. Nothing is enforced until ConfirmTOTP.
func (h *Handler) StartTOTP(c *echo.Context) error {
	if on, err := h.db.TOTPEnabled(currentUID(c)); err != nil {
		return err
	} else if on {
		return &jsonError{Status: http.StatusConflict, Code: "conflict", Message: "Two-factor authentication is already on."}
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		return err
	}
	if err := h.db.SetPendingTOTPSecret(currentUID(c), secret); err != nil {
		return err
	}
	png, err := qrcode.Encode(totp.ProvisioningURI(secret, currentUser(c).Email, brand().Name), qrcode.Medium, 220)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]string{"qr": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), "key": groupKey(secret)})
}

type codeRequest struct {
	Code string `json:"code"`
}

// ConfirmTOTP turns 2FA on once a code from the pending secret matches, and
// answers with the backup codes: shown once, stored only as hashes.
func (h *Handler) ConfirmTOTP(c *echo.Context) error {
	var req codeRequest
	if err := c.Bind(&req); err != nil {
		return badBody(`Send {"code": "123456"}.`)
	}
	uid := currentUID(c)
	pending, err := h.db.GetPendingTOTPSecret(uid)
	if err != nil {
		return err
	}
	if pending == "" {
		return &jsonError{Status: http.StatusConflict, Code: "conflict", Message: "No setup in progress. Start again."}
	}
	if ok, _ := totp.Validate(pending, strings.TrimSpace(req.Code), time.Now()); !ok {
		return fieldError("code", "That code didn't match. Check the app and try again.")
	}
	codes, hashes, err := newBackupCodes(backupCodeCount)
	if err != nil {
		return err
	}
	if err := h.db.EnableTOTP(uid, hashes); err != nil {
		return err
	}
	log.Printf("admin 2FA: enabled for %s", currentUser(c).Email)
	return c.JSON(http.StatusOK, map[string]any{"backup_codes": codes})
}

// DisableTOTPJSON turns 2FA off with a current authenticator or backup code,
// so a stolen session cookie alone can't remove the second factor.
func (h *Handler) DisableTOTPJSON(c *echo.Context) error {
	var req codeRequest
	if err := c.Bind(&req); err != nil {
		return badBody(`Send {"code": "123456"}.`)
	}
	uid := currentUID(c)
	secret, err := h.db.GetTOTPSecret(uid)
	if err != nil {
		return err
	}
	code := strings.TrimSpace(req.Code)
	ok, _ := totp.Validate(secret, code, time.Now())
	if !ok && code != "" {
		ok, _ = h.db.ConsumeTOTPBackupCode(uid, hashBackupCode(code))
	}
	if !ok {
		return fieldError("code", "Enter a current authenticator code or a backup code.")
	}
	if err := h.db.DisableTOTP(uid); err != nil {
		return err
	}
	log.Printf("admin 2FA: disabled for %s", currentUser(c).Email)
	return c.NoContent(http.StatusNoContent)
}

// BeginPasskey starts registering a passkey: POST {"name"} answers with the
// options for navigator.credentials.create().
func (h *Handler) BeginPasskey(c *echo.Context) error {
	if !passkey.IsSecureContext(c.Request()) {
		return &jsonError{Status: http.StatusConflict, Code: "insecure", Message: "Passkeys need HTTPS with a real hostname (or localhost)."}
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := c.Bind(&req); err != nil {
		return badBody(`Send {"name": "…"}.`)
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "Passkey"
	}
	creation, session, err := h.passkeys.BeginRegistration(c.Request(), currentUID(c))
	if err != nil {
		return err
	}
	h.pkEnroll.begin(currentUID(c), session, name)
	return c.JSON(http.StatusOK, creation)
}

// FinishPasskey checks the browser's attestation and saves the passkey.
func (h *Handler) FinishPasskey(c *echo.Context) error {
	uid := currentUID(c)
	session, name, ok := h.pkEnroll.take(uid)
	if !ok {
		return &jsonError{Status: http.StatusConflict, Code: "conflict", Message: "Registration expired. Start again."}
	}
	if err := h.passkeys.FinishRegistration(c.Request(), uid, *session, name); err != nil {
		log.Printf("passkey enrollment: finish failed: %v", err)
		return badBody("That passkey couldn't be registered.")
	}
	log.Printf("admin passkey: registered %q", name)
	return c.NoContent(http.StatusCreated)
}

// RemovePasskey deletes one of the caller's passkeys.
func (h *Handler) RemovePasskey(c *echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return badBody("Invalid passkey id.")
	}
	if err := h.db.DeleteWebAuthnCredential(currentUID(c), id); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// SignOutDevice signs a live device out, or forgets a signed-out one. The
// caller's own device and other users' sessions are refused.
func (h *Handler) SignOutDevice(c *echo.Context) error {
	id := c.Param("id")
	if id == storage.SessionID(sessionCookieValue(c)) {
		return badBody("Use Log out to sign this device out.")
	}
	sess, err := h.db.GetSessionByID(id)
	if err != nil {
		return err
	}
	if sess == nil || sess.UserID != currentUID(c) {
		return &jsonError{Status: http.StatusNotFound, Code: "not_found", Message: "That device is gone."}
	}
	if sess.Live() {
		err = h.db.RevokeSession(sess.UserID, id)
	} else {
		err = h.db.DeleteSession(id)
	}
	if err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// SignOutOthers signs out every session of the caller but this one.
func (h *Handler) SignOutOthers(c *echo.Context) error {
	if _, err := h.db.RevokeOtherSessions(currentUID(c), storage.SessionID(sessionCookieValue(c))); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}
