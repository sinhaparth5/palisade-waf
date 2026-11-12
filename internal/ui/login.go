package ui

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"palisade/internal/storage"
	"time"

	"github.com/labstack/echo/v5"
)

// ── Login / logout ────────────────────────────────────────────────────────────

func (h *Handler) LoginPage(c *echo.Context) error {
	// Redirect already-authenticated users straight to the dashboard.
	if cookie, err := c.Cookie(sessionCookie); err == nil && cookie.Value != "" {
		if valid, _ := h.db.ValidateSession(cookie.Value); valid {
			return c.Redirect(http.StatusFound, h.cfg.Admin.Path)
		}
	}
	if c.QueryParam("reason") == "revoked" {
		return h.renderLogin(c, "Your account is currently being used on another device.")
	}
	return h.renderLogin(c, "")
}

func (h *Handler) LoginPost(c *echo.Context) error {
	ip := h.clientIP(c.Request())
	if wait, locked := h.loginLimiter.blocked(ip); locked {
		log.Printf("admin login: rejected attempt from %s (locked out for %s)", ip, wait.Round(time.Second))
		return h.renderLoginStatus(c, http.StatusTooManyRequests,
			"Too many failed attempts. Try again later.")
	}

	account := storage.NormalizeEmail(c.FormValue("email"))
	password := c.FormValue("password")
	// Per account as well as per IP, so guesses spread over many IPs
	// still stop. Unknown emails get an entry too, so a lockout can't
	// reveal which emails exist.
	if wait, locked := h.accountLimiter.blocked(account); locked {
		log.Printf("admin login: rejected attempt for locked account from %s (locked out for %s)", ip, wait.Round(time.Second))
		return h.renderLoginStatus(c, http.StatusTooManyRequests,
			"Too many failed attempts. Try again later.")
	}

	// CheckAdminLogin costs one bcrypt compare whether or not the email
	// exists, so timing can't enumerate accounts either.
	u, _ := h.db.CheckAdminLogin(account, password)
	if u == nil {
		if h.loginFailed(ip, account) {
			return h.renderLoginStatus(c, http.StatusTooManyRequests,
				"Too many failed attempts. Try again later.")
		}
		log.Printf("admin login: failed attempt from %s", ip)
		return h.renderLogin(c, "Invalid email or password.")
	}
	// Password OK. With TOTP or a passkey enrolled, park the login and ask
	// for a second factor — without resetting the limiter yet (see
	// beginTOTPStage).
	totpEnabled, _ := h.db.TOTPEnabled(u.ID)
	passkeysEnabled, _ := h.passkeys.Enabled(u.ID)
	if totpEnabled || passkeysEnabled {
		return h.beginTOTPStage(c, u)
	}

	h.loginSucceeded(ip, account)
	log.Printf("admin login: successful login for %s from %s", u.Email, ip)
	return h.issueSession(c, u.ID)
}

// loginFailed counts a failed password or second-factor attempt against
// both the IP and the account, and reports whether either is now locked.
func (h *Handler) loginFailed(ip, account string) bool {
	ipLocked, accountLocked := h.loginLimiter.fail(ip), h.accountLimiter.fail(account)
	if ipLocked || accountLocked {
		log.Printf("admin login: locked out after %d failed attempts (ip %s locked=%v, account locked=%v)",
			maxLoginFailures, ip, ipLocked, accountLocked)
	}
	return ipLocked || accountLocked
}

func (h *Handler) loginSucceeded(ip, account string) {
	h.loginLimiter.success(ip)
	h.accountLimiter.success(account)
}

// issueSession creates the session row, sets the cookie, and lands on the
// dashboard — the final step of both the password-only and the 2FA flow.
func (h *Handler) issueSession(c *echo.Context, uid int64) error {
	if err := h.startSession(c, h.clientIP(c.Request()), uid); err != nil {
		return h.renderLogin(c, "Internal error. Please try again.")
	}
	return c.Redirect(http.StatusFound, h.cfg.Admin.Path)
}

// deviceCookie is a random per-browser ID that outlives sessions, so a
// re-login from the same browser updates its "Registered devices" row
// rather than adding a new one. It is not a credential: it only picks
// which history row a login replaces.
const deviceCookie = "cz_device"

// startSession creates the session row and sets the session and device
// cookies. Shared by the password/2FA and passkey login flows.
func (h *Handler) startSession(c *echo.Context, ip string, uid int64) error {
	deviceID := ""
	if ck, err := c.Cookie(deviceCookie); err == nil && len(ck.Value) == 32 {
		if _, err := hex.DecodeString(ck.Value); err == nil {
			deviceID = ck.Value
		}
	}
	if deviceID == "" {
		b := make([]byte, 16)
		rand.Read(b) //nolint — never errors on modern platforms
		deviceID = hex.EncodeToString(b)
	}
	// A lost device cookie (cleared cookies, another hostname, private
	// window) mints a new ID, so also replace rows that look like this
	// browser: same IP and same "Browser on OS" label. The label ignores the
	// version, so a browser update doesn't count as a new device either.
	ua := c.Request().UserAgent()
	if sessions, err := h.db.ListSessions(uid); err == nil {
		for _, s := range sessions {
			if s.IP == ip && browserOS(s.UserAgent) == browserOS(ua) {
				h.db.DeleteSession(s.ID) //nolint — best effort, a leftover row is only cosmetic
			}
		}
	}
	token, err := h.db.CreateSession(uid, ip, ua, deviceID)
	if err != nil {
		return err
	}
	c.SetCookie(&http.Cookie{ //nolint:gosec // G124: Secure only over TLS so plain-HTTP setups (loopback, --admin-listen) still work
		Name:     sessionCookie,
		Value:    token,
		HttpOnly: true,
		Path:     "/",
		MaxAge:   int((24 * time.Hour).Seconds()),
		SameSite: http.SameSiteLaxMode,
		Secure:   secureCookie(c),
	})
	c.SetCookie(&http.Cookie{ //nolint:gosec // G124: Secure only over TLS so plain-HTTP setups (loopback, --admin-listen) still work
		Name:     deviceCookie,
		Value:    deviceID,
		HttpOnly: true,
		Path:     "/",
		MaxAge:   int((400 * 24 * time.Hour).Seconds()), // Chrome's cookie lifetime cap
		SameSite: http.SameSiteLaxMode,
		Secure:   secureCookie(c),
	})
	return nil
}

func (h *Handler) Logout(c *echo.Context) error {
	if cookie, err := c.Cookie(sessionCookie); err == nil {
		h.db.DeleteSession(storage.SessionID(cookie.Value)) //nolint
	}
	c.SetCookie(&http.Cookie{ //nolint:gosec // G124: Secure only over TLS so plain-HTTP setups (loopback, --admin-listen) still work
		Name:     sessionCookie,
		Value:    "",
		HttpOnly: true,
		Path:     "/",
		MaxAge:   -1,
		Secure:   secureCookie(c),
	})
	return c.Redirect(http.StatusFound, h.cfg.Admin.Path+"/login")
}

func (h *Handler) renderLogin(c *echo.Context, errMsg string) error {
	return h.renderLoginStatus(c, http.StatusOK, errMsg)
}

func (h *Handler) renderLoginStatus(c *echo.Context, status int, errMsg string) error {
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Response().WriteHeader(status)
	sso, _ := h.db.GetSSOConfig()
	return h.tmpls["login"].ExecuteTemplate(c.Response(), "login", map[string]any{
		"Error":     errMsg,
		"AdminPath": h.cfg.Admin.Path,
		"Asset":     h.assetVer,
		"SSOName":   ssoProviderName(sso),
	})
}
