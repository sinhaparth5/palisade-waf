package ui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/labstack/echo/v5"
	"golang.org/x/oauth2"

	"palisade/internal/security/egress"
	"palisade/internal/storage"
)

// ── OIDC single sign-on (issue #197) ─────────────────────────────────────────
//
// Authorization code flow with PKCE, state and nonce. The three values ride
// in one short-lived HttpOnly cookie rather than server memory: nothing to
// fill up from unauthenticated clicks, and a code minted for someone else's
// browser can't be redeemed without their verifier. Discovery runs on every
// login (logins are rare); go-oidc checks the ID token's signature against
// the provider JWKS, its issuer, audience and expiry.

const ssoCookie = "cz_sso"

// ssoTimeout bounds every call to the IdP during one login step.
const ssoTimeout = 15 * time.Second

func (h *Handler) ssoCallbackURL(c *echo.Context) string {
	return c.Scheme() + "://" + c.Request().Host + h.cfg.Admin.Path + "/login/sso/callback"
}

// ssoContext carries a client with a timeout: go-oidc uses the context's
// client for discovery, JWKS and userinfo, and drops the context's deadline
// for the key set.
func ssoContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), ssoTimeout)
	return oidc.ClientContext(ctx, egress.Client(ssoTimeout)), cancel
}

func (h *Handler) ssoClient(ctx context.Context, c *echo.Context, cfg storage.SSOConfig) (*oidc.Provider, *oauth2.Config, error) {
	p, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, nil, err
	}
	scopes := []string{oidc.ScopeOpenID, "email"}
	if cfg.Group != "" {
		scopes = append(scopes, "groups")
	}
	return p, &oauth2.Config{
		ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
		Endpoint: p.Endpoint(), RedirectURL: h.ssoCallbackURL(c), Scopes: scopes,
	}, nil
}

// ssoProviderName is what the login button says: the issuer's host.
func ssoProviderName(cfg storage.SSOConfig) string {
	if u, err := url.Parse(cfg.Issuer); err == nil && cfg.Issuer != "" {
		return u.Host
	}
	return ""
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b) //nolint — never errors on modern platforms
	return hex.EncodeToString(b)
}

// SSOStart redirects to the IdP's authorization endpoint.
func (h *Handler) SSOStart(c *echo.Context) error {
	cfg, _ := h.db.GetSSOConfig()
	if cfg.Issuer == "" {
		return c.Redirect(http.StatusFound, h.cfg.Admin.Path+"/login")
	}
	ctx, cancel := ssoContext()
	defer cancel()
	_, oc, err := h.ssoClient(ctx, c, cfg)
	if err != nil {
		log.Printf("admin sso: discovery for %s failed: %v", cfg.Issuer, err)
		return h.renderLogin(c, "Couldn't reach the identity provider. Sign in with your password, or try again later.")
	}
	state, nonce, verifier := randHex(16), randHex(16), oauth2.GenerateVerifier()
	c.SetCookie(&http.Cookie{ //nolint:gosec // G124: Secure only over TLS so plain-HTTP setups (loopback, --admin-listen) still work
		Name: ssoCookie, Value: state + "." + nonce + "." + verifier,
		Path: h.cfg.Admin.Path + "/login/sso", MaxAge: 600, HttpOnly: true,
		// Lax, not Strict: the IdP's redirect back is a cross-site top-level GET.
		SameSite: http.SameSiteLaxMode, Secure: secureCookie(c),
	})
	return c.Redirect(http.StatusFound, oc.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)))
}

// parseSSOCookie splits the cz_sso cookie set by SSOStart and checks the
// callback's state against it. Every part must be present: an empty state
// would match a callback without one.
func parseSSOCookie(value, state string) (nonce, verifier string, ok bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 || len(parts[0]) != 32 || len(parts[1]) != 32 || parts[2] == "" ||
		subtle.ConstantTimeCompare([]byte(state), []byte(parts[0])) != 1 {
		return "", "", false
	}
	return parts[1], parts[2], true
}

// ssoClaims are the claims read from the ID token, with gaps filled from
// userinfo (Authelia, for one, keeps email and groups out of the ID token
// by default).
type ssoClaims struct {
	Email         string   `json:"email"`
	EmailVerified *bool    `json:"email_verified"`
	Groups        []string `json:"groups"`
	AMR           []string `json:"amr"`
}

// SSOCallback finishes the login. Every refusal lands on the login page
// with a reason; none creates a user.
func (h *Handler) SSOCallback(c *echo.Context) error {
	ck, _ := c.Cookie(ssoCookie)
	c.SetCookie(&http.Cookie{Name: ssoCookie, Path: h.cfg.Admin.Path + "/login/sso", MaxAge: -1, HttpOnly: true, Secure: secureCookie(c)}) //nolint:gosec // G124: Secure only over TLS so plain-HTTP setups (loopback, --admin-listen) still work
	value := ""
	if ck != nil {
		value = ck.Value
	}
	nonce, verifier, ok := parseSSOCookie(value, c.QueryParam("state"))
	if !ok {
		return h.renderLogin(c, "Single sign-on expired. Try again.")
	}
	if e := c.QueryParam("error"); e != "" {
		log.Printf("admin sso: provider returned error %q: %s", e, c.QueryParam("error_description"))
		return h.renderLogin(c, "The identity provider didn't sign you in.")
	}
	cfg, err := h.db.GetSSOConfig()
	if err != nil || cfg.Issuer == "" {
		return h.renderLogin(c, "Single sign-on is not set up.")
	}

	ctx, cancel := ssoContext()
	defer cancel()
	cl, err := h.ssoVerify(ctx, c, cfg, c.QueryParam("code"), nonce, verifier)
	if err != nil {
		log.Printf("admin sso: %v", err)
		return h.renderLogin(c, "Single sign-on failed. Try again.")
	}

	return h.ssoLogin(c, cl, cfg.Group == "" || slices.Contains(cl.Groups, cfg.Group), "")
}

// ssoLogin lets a verified identity in, or shows the login page with the
// reason. Shared by OIDC and ext.SSOLogin; method ("saml") goes in the audit.
func (h *Handler) ssoLogin(c *echo.Context, cl *verifiedClaims, inGroup bool, method string) error {
	u, refused := h.ssoUser(inGroup, cl)
	if u == nil {
		log.Printf("admin sso: denied %s (sub %s): %s", cl.email, cl.sub, refused)
		return h.renderLogin(c, refused)
	}
	ip := h.clientIP(c.Request())
	var summary []string
	if method != "" {
		summary = append(summary, "via="+method)
	}
	if len(cl.AMR) > 0 {
		summary = append(summary, "amr="+auditValue(strings.Join(cl.AMR, ",")))
	}
	if err := h.db.InsertAudit(storage.AuditEntry{Actor: u.Email, IP: ip, Action: "SSO login", Summary: strings.Join(summary, " ")}); err != nil {
		log.Printf("audit log: %v", err)
	}
	log.Printf("admin login: successful login for %s from %s (sso)", u.Email, ip)
	return h.issueSession(c, u.ID)
}

type verifiedClaims struct {
	ssoClaims
	iss, sub, email string
}

// ssoVerify redeems the code with the PKCE verifier and returns the
// verified ID token's identity and claims.
func (h *Handler) ssoVerify(ctx context.Context, c *echo.Context, cfg storage.SSOConfig, code, nonce, verifier string) (*verifiedClaims, error) {
	p, oc, err := h.ssoClient(ctx, c, cfg)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	tok, err := oc.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("code exchange: %w", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return nil, errors.New("token response has no id_token")
	}
	idt, err := p.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("id token: %w", err)
	}
	if idt.Nonce != nonce {
		return nil, errors.New("id token nonce mismatch")
	}
	var cl ssoClaims
	if err := idt.Claims(&cl); err != nil {
		return nil, fmt.Errorf("id token claims: %w", err)
	}
	if cl.Email == "" || cl.EmailVerified == nil || (cfg.Group != "" && cl.Groups == nil) {
		if info, err := p.UserInfo(ctx, oauth2.StaticTokenSource(tok)); err == nil && info.Subject == idt.Subject {
			var more ssoClaims
			if info.Claims(&more) == nil {
				if cl.Email == "" {
					cl.Email, cl.EmailVerified = more.Email, more.EmailVerified
				}
				if cl.EmailVerified == nil {
					cl.EmailVerified = more.EmailVerified
				}
				if cl.Groups == nil {
					cl.Groups = more.Groups
				}
			}
		}
	}
	return &verifiedClaims{ssoClaims: cl, iss: idt.Issuer, sub: idt.Subject, email: storage.NormalizeEmail(cl.Email)}, nil
}

// ssoUser decides whether the verified identity gets in. A bound identity
// matches by iss+sub; anything else needs a live invite for a verified
// email. A refusal returns the reason shown on the login page.
func (h *Handler) ssoUser(inGroup bool, cl *verifiedClaims) (*storage.AdminUser, string) {
	const notInGroup = "You're not in the group allowed to sign in here."
	u, err := h.db.SSOUser(cl.iss, cl.sub)
	if err != nil {
		return nil, "Internal error. Please try again."
	}
	if u != nil {
		switch {
		case u.Disabled:
			return nil, "Your account is disabled."
		case !inGroup:
			// Removed from the group at the IdP: sign them out here too.
			h.db.RevokeUserSessions(u.ID) //nolint — best effort, the login is refused either way
			return nil, notInGroup
		}
		return u, ""
	}
	switch {
	case cl.EmailVerified == nil || !*cl.EmailVerified:
		return nil, "Your email isn't verified at the identity provider."
	case !inGroup:
		return nil, notInGroup
	}
	if u, err = h.db.AcceptSSOInvite(cl.email, cl.iss, cl.sub); err != nil {
		return nil, "Internal error. Please try again."
	}
	switch {
	case u == nil:
		return nil, cl.email + " hasn't been invited, or the invite expired."
	case u.Disabled: // an existing user linked by the invite (#296)
		return nil, "Your account is disabled."
	}
	return u, ""
}

// ── Settings: SSO card and invites (owner only) ──────────────────────────────

// checkIssuer requires HTTPS (plain HTTP only to loopback, for a local
// IdP), since anyone on the path to a plain-HTTP issuer could swap in their
// own signing keys.
func checkIssuer(cfg storage.SSOConfig) error {
	u, err := url.Parse(cfg.Issuer)
	if err != nil || u.Host == "" {
		return fieldError("issuer", "Enter the issuer URL, e.g. https://auth.example.com.")
	}
	ip := net.ParseIP(u.Hostname())
	loopback := u.Hostname() == "localhost" || ip != nil && ip.IsLoopback()
	if u.Scheme != "https" && (u.Scheme != "http" || !loopback) {
		return fieldError("issuer", "The issuer URL must use https.")
	}
	if cfg.ClientID == "" {
		return fieldError("client_id", "Enter the client ID.")
	}
	if cfg.ClientSecret == "" {
		return fieldError("client_secret", "Enter the client secret.")
	}
	return nil
}
