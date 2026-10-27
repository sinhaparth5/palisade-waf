package ui

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"palisade/internal/security/passkey"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/labstack/echo/v4"
)

// pkEnrollTTL bounds how long a passkey registration ceremony can take —
// same idea as twoFAPendingTTL, just for the settings-page enrollment flow
// instead of login.
const pkEnrollTTL = 5 * time.Minute

// pkEnrollStore holds the in-flight passkey enrollment of each user. One
// slot per user, like totp_pending_secret: starting again replaces it.
type pkEnrollStore struct {
	mu sync.Mutex
	m  map[int64]pkEnrollment
}

type pkEnrollment struct {
	session *webauthn.SessionData
	name    string
	expires time.Time
}

func newPkEnrollStore() *pkEnrollStore { return &pkEnrollStore{m: map[int64]pkEnrollment{}} }

func (s *pkEnrollStore) begin(uid int64, session *webauthn.SessionData, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[uid] = pkEnrollment{session: session, name: name, expires: time.Now().Add(pkEnrollTTL)}
}

// take returns and clears uid's pending ceremony, or ok=false if none is live.
func (s *pkEnrollStore) take(uid int64) (session *webauthn.SessionData, name string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, found := s.m[uid]
	delete(s.m, uid)
	if !found || time.Now().After(e.expires) {
		return nil, "", false
	}
	return e.session, e.name, true
}

// ── Settings: enrollment ─────────────────────────────────────────────────────

// passkeysCardData builds the settings card's rendering state: the list of
// registered passkeys plus whether this request is even in a context
// WebAuthn can work in (see passkey.IsSecureContext).
func (h *Handler) passkeysCardData(c echo.Context, extra map[string]any) map[string]any {
	rows, _ := h.db.ListWebAuthnCredentials(currentUID(c))
	data := map[string]any{
		"AdminPath":     h.cfg.Admin.Path,
		"Passkeys":      rows,
		"SecureContext": passkey.IsSecureContext(c.Request()),
		"CSRF":          h.csrfFromContext(c),
	}
	for k, v := range extra {
		data[k] = v
	}
	return data
}

// BeginPasskeyEnrollment starts registering a new passkey for the signed-in
// user: builds the WebAuthn challenge, parks the session server-side,
// and returns the JSON options the browser's navigator.credentials.create()
// call needs.
func (h *Handler) BeginPasskeyEnrollment(c echo.Context) error {
	if !passkey.IsSecureContext(c.Request()) {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Passkeys need HTTPS with a real hostname (or localhost). This admin panel isn't being reached that way right now.",
		})
	}
	var body struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(c.Request().Body).Decode(&body)
	name := body.Name
	if name == "" {
		name = "Passkey"
	}

	creation, session, err := h.passkeys.BeginRegistration(c.Request(), currentUID(c))
	if err != nil {
		log.Printf("passkey enrollment: begin failed: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Could not start passkey registration."})
	}
	h.pkEnroll.begin(currentUID(c), session, name)
	return c.JSON(http.StatusOK, creation)
}

// FinishPasskeyEnrollment validates the browser's attestation response and
// saves the new passkey.
func (h *Handler) FinishPasskeyEnrollment(c echo.Context) error {
	uid := currentUID(c)
	session, name, ok := h.pkEnroll.take(uid)
	if !ok {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Enrollment expired. Start again."})
	}
	if err := h.passkeys.FinishRegistration(c.Request(), uid, *session, name); err != nil {
		log.Printf("passkey enrollment: finish failed: %v", err)
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "That passkey couldn't be registered."})
	}
	log.Printf("admin passkey: registered %q", name)
	return h.renderPartial(c, "settings", "passkeys-card", h.passkeysCardData(c, nil))
}

// DeletePasskey removes one registered passkey. No re-auth challenge like
// DisableTOTP demands — a session already controls this account regardless,
// and removing one of possibly several passkeys is far less destructive
// than turning off the entire second factor.
func (h *Handler) DeletePasskey(c echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	if err := h.db.DeleteWebAuthnCredential(currentUID(c), id); err != nil {
		return err
	}
	log.Printf("admin passkey: removed credential id=%d", id)
	return h.renderPartial(c, "settings", "passkeys-card", h.passkeysCardData(c, nil))
}

// ── Login: passkey as the second factor ──────────────────────────────────────

// BeginPasskeyLogin starts a login ceremony for the pending (password
// already verified) login, mirroring LoginTOTPPost's cz_2fa-cookie gate.
func (h *Handler) BeginPasskeyLogin(c echo.Context) error {
	ip := h.clientIP(c.Request())
	if _, locked := h.loginLimiter.blocked(ip); locked {
		return c.JSON(http.StatusTooManyRequests, map[string]string{"error": "Too many failed attempts. Try again later."})
	}
	_, entry := h.pendingEntry(c)
	if entry == nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Sign-in expired. Enter your password again."})
	}
	assertion, session, err := h.passkeys.BeginLogin(c.Request(), entry.uid)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "No passkeys are registered."})
	}
	entry.setSession(session)
	return c.JSON(http.StatusOK, assertion)
}

// FinishPasskeyLogin validates the browser's assertion and, on success,
// completes the login exactly like a correct TOTP code would.
func (h *Handler) FinishPasskeyLogin(c echo.Context) error {
	ip := h.clientIP(c.Request())
	if wait, locked := h.loginLimiter.blocked(ip); locked {
		log.Printf("admin login: rejected passkey attempt from %s (locked out for %s)", ip, wait.Round(time.Second))
		return c.JSON(http.StatusTooManyRequests, map[string]string{"error": "Too many failed attempts. Try again later."})
	}
	token, entry := h.pendingEntry(c)
	var session *webauthn.SessionData
	if entry != nil {
		session = entry.takeSession()
	}
	if session == nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Sign-in expired. Enter your password again."})
	}
	if _, locked := h.accountLimiter.blocked(entry.account); locked {
		return c.JSON(http.StatusTooManyRequests, map[string]string{"error": "Too many failed attempts. Try again later."})
	}

	if err := h.passkeys.FinishLogin(c.Request(), entry.uid, *session); err != nil {
		if h.loginFailed(ip, entry.account) {
			return c.JSON(http.StatusTooManyRequests, map[string]string{"error": "Too many failed attempts. Try again later."})
		}
		log.Printf("admin login: failed passkey attempt from %s", ip)
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "That passkey didn't verify."})
	}

	h.twoFA.delete(token)
	c.SetCookie(&http.Cookie{
		Name: twoFACookie, Value: "", HttpOnly: true, Path: "/", MaxAge: -1,
		Secure: secureCookie(c),
	})
	h.loginSucceeded(ip, entry.account)
	log.Printf("admin login: successful login for %s from %s (passkey)", entry.account, ip)
	// JS-driven flow (fetch, not a form submit): tell the browser where to
	// go instead of issuing an HTTP redirect, which fetch would follow
	// internally without ever navigating the page.
	if err := h.startSession(c, ip, entry.uid); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal error. Please try again."})
	}
	return c.JSON(http.StatusOK, map[string]string{"redirect": h.cfg.Admin.Path})
}
