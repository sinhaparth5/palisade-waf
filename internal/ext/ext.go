// Package ext lets a binary built on palisade (palisade-pro) add admin routes
// and Settings cards. The open-source binary registers nothing.
package ext

import (
	"context"
	"html/template"
	"net"
	"net/http"

	"github.com/labstack/echo/v5"

	"palisade/internal/storage"
)

// Env is what a feature gets when the admin UI mounts it.
type Env struct {
	DB        *storage.DB
	AdminPath string
	// Reload re-reads every runtime setting from DB, after something
	// replaced the configuration underneath the server.
	Reload func() error
}

// Route is an admin route under the admin path, behind the session, CSRF,
// audit log and Role (storage.RoleViewer/Admin/Owner; required).
type Route struct {
	Method, Path, Role string
	Handler            echo.HandlerFunc
}

// Card renders a Settings card for the signed-in user's role; "" hides it.
type Card func(c *echo.Context, role string) template.HTML

// Feature is one mounted add-on.
type Feature struct {
	Routes []Route
	// Open routes skip the session, CSRF, audit log and Role: the handler
	// must authenticate the caller itself. --admin-allow still applies.
	Open []Route
	Card Card
}

// Mounts are called once per admin UI, from init functions appending here.
var Mounts []func(Env) Feature

// OnBan are called after autoban adds a new global block rule for ip (an
// IP or CIDR). They run on the ban's goroutine, so return quickly. Append
// from a Mount, before traffic starts.
var OnBan []func(ip, reason string)

// Dial, when set, gets every backend connection first: the service pools,
// Probe and the active health checks (issue #343). handled=false falls
// through to the normal dialer, whose metadata check still applies; a
// handled connection is the hook's responsibility. Set it from a Mount,
// before traffic starts. Outbound clients (webhooks, JWKS, HIBP) never use it.
var Dial func(ctx context.Context, network, addr string) (conn net.Conn, handled bool, err error)

// OnLog are called for every request log entry, on the single log worker
// goroutine, before the DB insert (entry.ID is 0). Queue and return: a slow
// hook delays bans and logging. Append from a Mount, before traffic starts.
var OnLog []func(storage.RequestLog)

// OnAudit are called after an audit entry is stored. They run on the
// request that made the change, so return quickly. Append from a Mount.
var OnAudit []func(storage.AuditEntry)

// CurrentUser returns the signed-in admin of a Route's request (nil for an
// API key). Set by the admin UI before any Mount runs.
var CurrentUser func(c *echo.Context) *storage.AdminUser

// Hold, when set, sees every change the audit log would record (a
// mutating admin UI or REST API request, not from a read-only API key)
// after authentication and CSRF, before its handler. Returning true means
// it answered the request itself and the change didn't run. action is the
// audit action ("POST /ip-rules/:id"); a JSON body is still readable from
// c.Request().Body. Set from a Mount.
var Hold func(c *echo.Context, action string) bool

// Replay runs a request Hold kept, through the admin routes but without
// the session, CSRF, --admin-allow or Hold: as user for an admin UI route
// (nil fails it), and recorded in the audit log as actor. It returns the
// response's status and body. Set by the admin UI before any Mount runs.
var Replay func(r *http.Request, user *storage.AdminUser, actor string) (int, []byte)

// Scope, when set, may limit a signed-in user to some services: ok=false
// means no limit, otherwise ids are the services they may see and change.
// A scoped user reaches only the Services and Logs pages (showing just
// those services), their own account settings, and changes keyed to those
// services; global settings and every other page are closed to them.
// Owners are never limited.
// Called on every admin request, so keep it cheap. Set from a Mount.
var Scope func(u *storage.AdminUser) (ids []int, ok bool)

// LoginVerdict is an add-on's verdict on a login submission.
type LoginVerdict struct {
	Action string // logged as the request's action, e.g. "ato:ip"
	// Status != 0 answers the client with Body instead of the backend.
	Status      int
	ContentType string
	Body        []byte
}

// OnLogin, when set, sees every submission (not GET/HEAD) to a service's
// login paths from an untrusted client, after the WAF. body is the first
// 64 KiB of a form or JSON body (nil otherwise); r.Body stays readable. It
// runs on the request path, so return quickly. Set from a Mount.
var OnLogin func(r *http.Request, body []byte, service, ip string) *LoginVerdict

// SSOIdentity is someone another sign-in protocol (SAML, say) verified.
type SSOIdentity struct {
	// Issuer+Subject bind the user, like OIDC's iss+sub; on first sign-in
	// Email must match a live SSO invite.
	Issuer, Subject, Email string
	// InGroup false refuses the sign-in and signs a bound user out.
	InGroup bool
	Method  string // in the audit log, e.g. "saml"
}

// SSOLogin finishes a sign-in another protocol verified, exactly like OIDC
// (invite-only, disabled users refused, no local 2FA). With refused != ""
// it shows the login page with that reason instead. Set by the admin UI
// before any Mount runs.
var SSOLogin func(c *echo.Context, id *SSOIdentity, refused string) error

// LoginButton, when set, adds "Sign in with <label>" to the login page,
// linking to path under the admin path; label "" hides it. A label also
// shows SSO invites under Users. Set from a Mount.
var LoginButton func() (label, path string)

// Brand renames and reskins the admin UI; a zero field keeps Palisade's.
type Brand struct {
	Name string // replaces "Palisade" in the UI and authenticator apps
	Logo string // image path under the admin path; served without a session
	CSS  string // stylesheet path under the admin path, loaded after the UI's
}

// Branding, when set, is read on every page render, so keep it cheap. Set
// from a Mount.
var Branding func() Brand
