package ui

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/labstack/echo/v5"
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

// ── Login: passkey as the second factor ──────────────────────────────────────

// BeginPasskeyLogin starts a login ceremony for the pending (password
// already verified) login, mirroring LoginTOTPPost's cz_2fa-cookie gate.
func (h *Handler) BeginPasskeyLogin(c *echo.Context) error {
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
func (h *Handler) FinishPasskeyLogin(c *echo.Context) error {
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
	c.SetCookie(&http.Cookie{ //nolint:gosec // G124: Secure only over TLS so plain-HTTP setups (loopback, --admin-listen) still work
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
