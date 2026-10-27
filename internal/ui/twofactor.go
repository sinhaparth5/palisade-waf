package ui

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"palisade/internal/security/passkey"
	"palisade/internal/security/totp"
	"palisade/internal/storage"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/labstack/echo/v4"
	qrcode "github.com/skip2/go-qrcode"
)

const (
	// twoFACookie carries the opaque token proving the password step passed.
	// It is not a session: it only unlocks the code-entry form.
	twoFACookie = "cz_2fa"
	// twoFAPendingTTL is how long the admin has to enter a code after the
	// password step before having to sign in again.
	twoFAPendingTTL = 5 * time.Minute
	// emailCodeTTL / emailCodeResendWait bound the emailed recovery code:
	// valid for 10 minutes, re-sendable at most once a minute so the button
	// can't be used to flood the admin inbox.
	emailCodeTTL        = 10 * time.Minute
	emailCodeResendWait = time.Minute
	// backupCodeCount is how many one-time recovery codes enrollment hands out.
	backupCodeCount = 10
	// totpIssuer names this system in authenticator apps.
	totpIssuer = "Palisade"
)

// twoFAEntry is one password-verified login waiting for its second factor.
// Concurrent requests share one entry, so every field but expires (set once
// at create) is read and written under mu, only through the methods below
// (issue #161).
type twoFAEntry struct {
	expires          time.Time
	uid              int64  // the user whose password passed, set once at create
	account          string // their normalized email, for the per-account limiter
	mu               sync.Mutex
	emailCode        string // emailed recovery code, "" until requested
	emailCodeExpires time.Time
	emailSentAt      time.Time
	waSession        *webauthn.SessionData // set between BeginPasskeyLogin and FinishPasskeyLogin
}

// twoFAStore holds pending two-factor logins in memory. In-process state is
// the same tradeoff loginLimiter already makes: one process, and losing
// entries on restart only means signing in again.
type twoFAStore struct {
	mu sync.Mutex
	m  map[string]*twoFAEntry
}

// takeEmailCode reports whether code matches the live emailed code, and
// clears it on a match so it is single use.
func (e *twoFAEntry) takeEmailCode(code string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.emailCode == "" || !time.Now().Before(e.emailCodeExpires) ||
		subtle.ConstantTimeCompare([]byte(e.emailCode), []byte(code)) != 1 {
		return false
	}
	e.emailCode = ""
	return true
}

// setEmailCode stores a freshly sent code, or returns how long until another
// may be sent.
func (e *twoFAEntry) setEmailCode(code string) time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	if since := time.Since(e.emailSentAt); since < emailCodeResendWait {
		return emailCodeResendWait - since
	}
	now := time.Now()
	e.emailCode, e.emailCodeExpires, e.emailSentAt = code, now.Add(emailCodeTTL), now
	return 0
}

func (e *twoFAEntry) clearEmailCode() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.emailCode = ""
}

func (e *twoFAEntry) setSession(s *webauthn.SessionData) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.waSession = s
}

// takeSession returns the passkey ceremony session and clears it, so one
// ceremony is finished at most once.
func (e *twoFAEntry) takeSession() *webauthn.SessionData {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.waSession
	e.waSession = nil
	return s
}

func newTwoFAStore() *twoFAStore { return &twoFAStore{m: make(map[string]*twoFAEntry)} }

// create registers a new pending login for user uid and returns its opaque token.
func (s *twoFAStore) create(uid int64, account string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	// Sweep expired entries while we're here — logins are rare enough that
	// this keeps the map bounded without a janitor goroutine.
	now := time.Now()
	for t, e := range s.m {
		if now.After(e.expires) {
			delete(s.m, t)
		}
	}
	s.m[token] = &twoFAEntry{expires: now.Add(twoFAPendingTTL), uid: uid, account: account}
	return token, nil
}

// get returns the live entry for token, or nil if unknown/expired.
func (s *twoFAStore) get(token string) *twoFAEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[token]
	if !ok {
		return nil
	}
	if time.Now().After(e.expires) {
		delete(s.m, token)
		return nil
	}
	return e
}

func (s *twoFAStore) delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, token)
}

// ── Login: second step ───────────────────────────────────────────────────────

// pendingEntry resolves the cz_2fa cookie to a live pending login, returning
// the token alongside so handlers can delete it on success.
func (h *Handler) pendingEntry(c echo.Context) (string, *twoFAEntry) {
	ck, err := c.Cookie(twoFACookie)
	if err != nil || ck.Value == "" {
		return "", nil
	}
	return ck.Value, h.twoFA.get(ck.Value)
}

// beginTOTPStage is called by LoginPost after the password checks out but a
// second factor is required: it parks the login in twoFA and shows the code
// form. Deliberately does NOT reset loginLimiter — the password is already
// known-correct to whoever got here, so resetting on every password round
// would let an attacker launder TOTP guesses by re-posting the password.
func (h *Handler) beginTOTPStage(c echo.Context, u *storage.AdminUser) error {
	token, err := h.twoFA.create(u.ID, u.Email)
	if err != nil {
		return h.renderLogin(c, "Internal error. Please try again.")
	}
	c.SetCookie(&http.Cookie{
		Name:     twoFACookie,
		Value:    token,
		HttpOnly: true,
		Path:     "/",
		MaxAge:   int(twoFAPendingTTL.Seconds()),
		SameSite: http.SameSiteLaxMode,
		Secure:   secureCookie(c),
	})
	return h.renderLoginTOTP(c, u.ID, http.StatusOK, "", "")
}

// LoginTOTPPost is the second authentication step: it accepts an
// authenticator code, a one-time backup code, or an emailed recovery code,
// in that order. Failures feed the same per-IP and per-account limiters as
// password failures, so 2FA doesn't open a fresh brute-force surface.
func (h *Handler) LoginTOTPPost(c echo.Context) error {
	ip := h.clientIP(c.Request())
	if wait, locked := h.loginLimiter.blocked(ip); locked {
		log.Printf("admin login: rejected 2FA attempt from %s (locked out for %s)", ip, wait.Round(time.Second))
		return h.renderLoginStatus(c, http.StatusTooManyRequests,
			"Too many failed attempts. Try again later.")
	}

	token, entry := h.pendingEntry(c)
	if entry == nil {
		return h.renderLogin(c, "Sign-in expired. Enter your password again.")
	}
	if _, locked := h.accountLimiter.blocked(entry.account); locked {
		return h.renderLoginStatus(c, http.StatusTooManyRequests,
			"Too many failed attempts. Try again later.")
	}

	code := strings.TrimSpace(c.FormValue("code"))
	if !h.verifySecondFactor(entry, code) {
		if h.loginFailed(ip, entry.account) {
			return h.renderLoginStatus(c, http.StatusTooManyRequests,
				"Too many failed attempts. Try again later.")
		}
		log.Printf("admin login: failed 2FA attempt from %s", ip)
		return h.renderLoginTOTP(c, entry.uid, http.StatusOK, "Invalid code. Try again.", "")
	}

	h.twoFA.delete(token)
	c.SetCookie(&http.Cookie{
		Name: twoFACookie, Value: "", HttpOnly: true, Path: "/", MaxAge: -1,
		Secure: secureCookie(c),
	})
	h.loginSucceeded(ip, entry.account)
	log.Printf("admin login: successful login for %s from %s (2FA)", entry.account, ip)
	return h.issueSession(c, entry.uid)
}

// verifySecondFactor tries the three accepted proofs. TOTP replay is blocked
// by persisting the last accepted counter: a code is otherwise valid for its
// whole 30s window even after a successful login with it.
func (h *Handler) verifySecondFactor(entry *twoFAEntry, code string) bool {
	uid := entry.uid
	secret, err := h.db.GetTOTPSecret(uid)
	if err != nil {
		return false
	}
	if secret == "" {
		// No active TOTP secret. If passkeys aren't enrolled either, 2FA
		// was fully disabled between the two steps — the password already
		// passed, let them in. If passkeys ARE enrolled, TOTP was simply
		// never the active factor here: don't treat a blank/guessed code
		// as a pass, the user must use the passkey button instead.
		passkeysEnabled, _ := h.passkeys.Enabled(uid)
		return !passkeysEnabled
	}

	if ok, counter := totp.Validate(secret, code, time.Now()); ok {
		last, err := h.db.GetTOTPLastCounter(uid)
		if err != nil || counter <= last {
			return false
		}
		if err := h.db.SetTOTPLastCounter(uid, counter); err != nil {
			return false
		}
		return true
	}

	if used, _ := h.db.ConsumeTOTPBackupCode(uid, hashBackupCode(code)); used {
		return true
	}

	return entry.takeEmailCode(strings.TrimSpace(code))
}

// LoginTOTPEmail emails a one-time recovery code for the pending login via
// the existing Cloudflare Email Service mailer — the fallback for an admin
// whose authenticator (and backup codes) aren't at hand.
func (h *Handler) LoginTOTPEmail(c echo.Context) error {
	ip := h.clientIP(c.Request())
	if _, locked := h.loginLimiter.blocked(ip); locked {
		return h.renderLoginStatus(c, http.StatusTooManyRequests,
			"Too many failed attempts. Try again later.")
	}
	_, entry := h.pendingEntry(c)
	if entry == nil {
		return h.renderLogin(c, "Sign-in expired. Enter your password again.")
	}
	if h.sendLoginCode == nil || !h.emailRecoveryAvailable() {
		return h.renderLoginTOTP(c, entry.uid, http.StatusOK, "Email recovery is not configured.", "")
	}
	code, err := randomDigits(6)
	if err != nil {
		return h.renderLoginTOTP(c, entry.uid, http.StatusOK, "Internal error. Please try again.", "")
	}
	if wait := entry.setEmailCode(code); wait > 0 {
		return h.renderLoginTOTP(c, entry.uid, http.StatusOK, "", fmt.Sprintf("A code was already sent. You can request another in %s.", wait.Round(time.Second)))
	}
	if err := h.sendLoginCode(code); err != nil {
		entry.clearEmailCode()
		log.Printf("admin login: sending 2FA recovery code failed: %v", err)
		return h.renderLoginTOTP(c, entry.uid, http.StatusOK, "Sending the code failed. Check the email settings.", "")
	}
	log.Printf("admin login: 2FA recovery code emailed (requested from %s)", ip)
	return h.renderLoginTOTP(c, entry.uid, http.StatusOK, "", "Code sent to the configured admin email. It expires in 10 minutes.")
}

// emailRecoveryAvailable reports whether the mailer has enough config to
// deliver a recovery code; the login page only offers the option when true.
func (h *Handler) emailRecoveryAvailable() bool {
	if h.sendLoginCode == nil {
		return false
	}
	cfg, err := h.db.GetEmailConfig()
	return err == nil && cfg.Token != "" && cfg.To != ""
}

func (h *Handler) renderLoginTOTP(c echo.Context, uid int64, status int, errMsg, notice string) error {
	passkeysEnabled, _ := h.passkeys.Enabled(uid)
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Response().WriteHeader(status)
	return h.tmpls["login"].ExecuteTemplate(c.Response(), "login", map[string]any{
		"TOTPStage":         true,
		"Error":             errMsg,
		"Notice":            notice,
		"EmailAvailable":    h.emailRecoveryAvailable(),
		"PasskeysAvailable": passkeysEnabled && passkey.IsSecureContext(c.Request()),
		"AdminPath":         h.cfg.Admin.Path,
		"Asset":             h.assetVer,
	})
}

// ── Settings: enrollment ─────────────────────────────────────────────────────

// twoFACardData builds the settings card's default (no enrollment in
// progress) rendering state.
func (h *Handler) twoFACardData(c echo.Context, extra map[string]any) map[string]any {
	enabled, _ := h.db.TOTPEnabled(currentUID(c))
	data := map[string]any{
		"AdminPath":   h.cfg.Admin.Path,
		"TOTPEnabled": enabled,
	}
	for k, v := range extra {
		data[k] = v
	}
	return data
}

// StartTOTPEnrollment generates a fresh secret and shows the QR code +
// manual key with the confirm form. Nothing is enforced until the admin
// proves their authenticator works (ConfirmTOTPEnrollment).
func (h *Handler) StartTOTPEnrollment(c echo.Context) error {
	secret, err := totp.GenerateSecret()
	if err != nil {
		return err
	}
	if err := h.db.SetPendingTOTPSecret(currentUID(c), secret); err != nil {
		return err
	}
	return h.renderTOTPEnrollment(c, secret, "")
}

func (h *Handler) renderTOTPEnrollment(c echo.Context, secret, errMsg string) error {
	uri := totp.ProvisioningURI(secret, currentUser(c).Email, totpIssuer)
	png, err := qrcode.Encode(uri, qrcode.Medium, 220)
	// template.URL: html/template's URL filter rejects data: URIs from plain
	// strings (rendered as ZgotmplZ); this one is built entirely server-side
	// from our own PNG bytes, never from user input.
	var qr template.URL
	if err == nil {
		qr = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
	}
	return h.renderPartial(c, "settings", "twofa-card", h.twoFACardData(c, map[string]any{
		"Enrolling": true,
		"QRDataURI": qr,
		"ManualKey": groupKey(secret),
		"EnrollErr": errMsg,
	}))
}

// ConfirmTOTPEnrollment checks a code against the pending secret and, on
// match, activates 2FA and hands out the one-time backup codes — shown once,
// stored only as SHA-256 hashes (they're high-entropy random, same reasoning
// as API keys).
func (h *Handler) ConfirmTOTPEnrollment(c echo.Context) error {
	uid := currentUID(c)
	pending, err := h.db.GetPendingTOTPSecret(uid)
	if err != nil {
		return err
	}
	if pending == "" {
		return h.renderPartial(c, "settings", "twofa-card",
			h.twoFACardData(c, map[string]any{"CardErr": "No enrollment in progress. Start again."}))
	}
	code := c.FormValue("code")
	if ok, _ := totp.Validate(pending, code, time.Now()); !ok {
		return h.renderTOTPEnrollment(c, pending,
			"That code didn't match. Check the app and try again.")
	}

	codes, hashes, err := newBackupCodes(backupCodeCount)
	if err != nil {
		return err
	}
	if err := h.db.EnableTOTP(uid, hashes); err != nil {
		return err
	}
	log.Printf("admin 2FA: enabled for %s", currentUser(c).Email)
	return h.renderPartial(c, "settings", "twofa-card", h.twoFACardData(c, map[string]any{
		"BackupCodes": codes,
	}))
}

// DisableTOTP turns 2FA off. It demands a current authenticator or backup
// code, not just the session cookie: a hijacked session shouldn't be able to
// quietly remove the second factor.
func (h *Handler) DisableTOTP(c echo.Context) error {
	uid := currentUID(c)
	secret, err := h.db.GetTOTPSecret(uid)
	if err != nil {
		return err
	}
	code := c.FormValue("code")
	ok, _ := totp.Validate(secret, code, time.Now())
	if !ok {
		if used, _ := h.db.ConsumeTOTPBackupCode(uid, hashBackupCode(code)); used {
			ok = true
		}
	}
	if !ok {
		return h.renderPartial(c, "settings", "twofa-card",
			h.twoFACardData(c, map[string]any{"CardErr": "Enter a valid authenticator or backup code to disable 2FA."}))
	}
	if err := h.db.DisableTOTP(uid); err != nil {
		return err
	}
	log.Printf("admin 2FA: disabled for %s", currentUser(c).Email)
	return h.renderPartial(c, "settings", "twofa-card", h.twoFACardData(c, nil))
}

// ── Code helpers ─────────────────────────────────────────────────────────────

// newBackupCodes returns n one-time codes in display form ("XXXX-XXXX",
// base32 alphabet) plus their storage hashes.
func newBackupCodes(n int) (codes, hashes []string, err error) {
	for i := 0; i < n; i++ {
		b := make([]byte, 5) // 40 bits → 8 base32 chars
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		raw := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
		code := raw[:4] + "-" + raw[4:]
		codes = append(codes, code)
		hashes = append(hashes, hashBackupCode(code))
	}
	return codes, hashes, nil
}

// hashBackupCode normalizes (case, separators) and hashes a backup code the
// same way at generation and login, so re-typing variants still match.
func hashBackupCode(code string) string {
	norm := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte("cz-backup:" + norm))
	return hex.EncodeToString(sum[:])
}

// randomDigits returns n crypto-random decimal digits (the emailed code).
// Bytes ≥ 250 are rejected rather than folded so every digit is equally
// likely (256 % 10 != 0).
func randomDigits(n int) (string, error) {
	out := make([]byte, 0, n)
	buf := make([]byte, 16)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if b >= 250 || len(out) == n {
				continue
			}
			out = append(out, '0'+b%10)
		}
	}
	return string(out), nil
}

// groupKey chunks a base32 secret into 4-char groups for manual entry.
func groupKey(secret string) string {
	var sb strings.Builder
	for i, r := range secret {
		if i > 0 && i%4 == 0 {
			sb.WriteByte(' ')
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
