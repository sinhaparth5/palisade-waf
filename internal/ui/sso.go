package ui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"

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

func (h *Handler) ssoCallbackURL(c echo.Context) string {
	return c.Scheme() + "://" + c.Request().Host + h.cfg.Admin.Path + "/login/sso/callback"
}

// ssoContext carries a client with a timeout: go-oidc uses the context's
// client for discovery, JWKS and userinfo, and drops the context's deadline
// for the key set.
func ssoContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), ssoTimeout)
	return oidc.ClientContext(ctx, &http.Client{Timeout: ssoTimeout}), cancel
}

func (h *Handler) ssoClient(ctx context.Context, c echo.Context, cfg storage.SSOConfig) (*oidc.Provider, *oauth2.Config, error) {
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
func (h *Handler) SSOStart(c echo.Context) error {
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
	c.SetCookie(&http.Cookie{
		Name: ssoCookie, Value: state + "." + nonce + "." + verifier,
		Path: h.cfg.Admin.Path + "/login/sso", MaxAge: 600, HttpOnly: true,
		// Lax, not Strict: the IdP's redirect back is a cross-site top-level GET.
		SameSite: http.SameSiteLaxMode, Secure: secureCookie(c),
	})
	return c.Redirect(http.StatusFound, oc.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)))
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
func (h *Handler) SSOCallback(c echo.Context) error {
	ck, _ := c.Cookie(ssoCookie)
	c.SetCookie(&http.Cookie{Name: ssoCookie, Path: h.cfg.Admin.Path + "/login/sso", MaxAge: -1, HttpOnly: true, Secure: secureCookie(c)})
	var parts []string
	if ck != nil {
		parts = strings.Split(ck.Value, ".")
	}
	if len(parts) != 3 || c.QueryParam("state") != parts[0] {
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
	cl, err := h.ssoVerify(ctx, c, cfg, c.QueryParam("code"), parts[1], parts[2])
	if err != nil {
		log.Printf("admin sso: %v", err)
		return h.renderLogin(c, "Single sign-on failed. Try again.")
	}

	u, refused := h.ssoUser(cfg, cl)
	if u == nil {
		log.Printf("admin sso: denied %s (sub %s): %s", cl.email, cl.sub, refused)
		return h.renderLogin(c, refused)
	}
	ip := h.clientIP(c.Request())
	summary := ""
	if len(cl.AMR) > 0 {
		summary = "amr=" + auditValue(strings.Join(cl.AMR, ","))
	}
	if err := h.db.InsertAudit(storage.AuditEntry{Actor: u.Email, IP: ip, Action: "SSO login", Summary: summary}); err != nil {
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
func (h *Handler) ssoVerify(ctx context.Context, c echo.Context, cfg storage.SSOConfig, code, nonce, verifier string) (*verifiedClaims, error) {
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
func (h *Handler) ssoUser(cfg storage.SSOConfig, cl *verifiedClaims) (*storage.AdminUser, string) {
	const notInGroup = "You're not in the group allowed to sign in here."
	inGroup := cfg.Group == "" || slices.Contains(cl.Groups, cfg.Group)
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
	if u == nil {
		return nil, cl.email + " hasn't been invited, or the invite expired."
	}
	return u, ""
}

// ── Settings: SSO card and invites (owner only) ──────────────────────────────

func (h *Handler) ssoCardData(c echo.Context, cfg storage.SSOConfig, saveErr string) map[string]any {
	return map[string]any{
		"AdminPath":      h.cfg.Admin.Path,
		"SSOIssuer":      cfg.Issuer,
		"SSOClientID":    cfg.ClientID,
		"SSOSecretSet":   cfg.ClientSecret != "",
		"SSOGroup":       cfg.Group,
		"SSOCallbackURL": h.ssoCallbackURL(c),
		"SSOSaveErr":     saveErr,
		"SSOSaved":       c.Request().Method == http.MethodPost && saveErr == "",
	}
}

// SaveSSOSettings stores the SSO config after checking discovery works. An
// empty issuer turns SSO off; existing SSO users then can't sign in until
// it is back.
func (h *Handler) SaveSSOSettings(c echo.Context) error {
	stored, _ := h.db.GetSSOConfig()
	cfg := storage.SSOConfig{
		Issuer:       strings.TrimRight(strings.TrimSpace(c.FormValue("issuer")), "/"),
		ClientID:     strings.TrimSpace(c.FormValue("client_id")),
		ClientSecret: strings.TrimSpace(c.FormValue("client_secret")),
		Group:        strings.TrimSpace(c.FormValue("group")),
	}
	if cfg.ClientSecret == "" {
		cfg.ClientSecret = stored.ClientSecret
	}
	saveErr := ""
	if cfg.Issuer == "" {
		cfg = storage.SSOConfig{}
	} else if err := checkIssuer(cfg); err != nil {
		saveErr = err.Error()
	} else {
		ctx, cancel := ssoContext()
		defer cancel()
		// go-oidc rejects a discovery document whose issuer differs from
		// the one entered, which catches a typo now rather than at login.
		if _, err := oidc.NewProvider(ctx, cfg.Issuer); err != nil {
			saveErr = "discovery failed: " + err.Error()
		}
	}
	if saveErr == "" {
		if err := h.db.SetSSOConfig(cfg); err != nil {
			saveErr = err.Error()
		}
	}
	return h.renderPartial(c, "settings", "sso-card", h.ssoCardData(c, cfg, saveErr))
}

// checkIssuer requires HTTPS (plain HTTP only to loopback, for a local
// IdP), since anyone on the path to a plain-HTTP issuer could swap in their
// own signing keys.
func checkIssuer(cfg storage.SSOConfig) error {
	u, err := url.Parse(cfg.Issuer)
	if err != nil || u.Host == "" {
		return errors.New("enter the issuer URL, e.g. https://auth.example.com")
	}
	ip := net.ParseIP(u.Hostname())
	loopback := u.Hostname() == "localhost" || ip != nil && ip.IsLoopback()
	if u.Scheme != "https" && (u.Scheme != "http" || !loopback) {
		return errors.New("the issuer URL must use https")
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return errors.New("client ID and client secret are required")
	}
	return nil
}

// CreateSSOInvite invites an email to sign in with SSO under a role.
func (h *Handler) CreateSSOInvite(c echo.Context) error {
	email := storage.NormalizeEmail(c.FormValue("email"))
	if !strings.Contains(email, "@") {
		return h.renderUsersCard(c, errors.New("enter a valid email"))
	}
	return h.renderUsersCard(c, h.db.CreateSSOInvite(email, c.FormValue("role")))
}

// RenewSSOInvite restarts an invite's 7 days.
func (h *Handler) RenewSSOInvite(c echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	return h.renderUsersCard(c, h.db.RenewSSOInvite(id))
}

// RevokeSSOInvite deletes a pending invite.
func (h *Handler) RevokeSSOInvite(c echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	return h.renderUsersCard(c, h.db.DeleteSSOInvite(id))
}
