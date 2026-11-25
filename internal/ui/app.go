package ui

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"maps"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/labstack/echo/v5"
)

// The React admin app (web/, issue #348), served at the admin root behind
// the same session, role and CSP middleware as every other admin page, so an
// anonymous visitor gets the login redirect and never the app's JS.

// appCSP is adminCSP plus this response's nonce for <style>: Radix's scroll
// lock injects one through get-nonce (web/src/main.tsx). Scripts stay 'self'.
func appCSP(nonce string) string {
	return strings.Replace(adminCSP, "style-src 'self'", "style-src 'self' 'nonce-"+nonce+"'", 1)
}

// SetApp loads the built app from fsys (static.App: app/dist/...). Without a
// build (only static/app/.gitkeep), the app routes answer 404.
func (h *Handler) SetApp(fsys fs.FS) error {
	if fsys == nil {
		return nil
	}
	dist, _ := fs.Sub(fsys, "app/dist") // only fails on an invalid path
	h.appIndex, h.appFS, h.loginIndex, h.loginFS = nil, nil, nil, nil
	src, err := fs.ReadFile(dist, "index.html")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read app index.html: %w", err)
	}
	t, err := template.New("app").Parse(string(src))
	if err != nil {
		return fmt.Errorf("parse app index.html: %w", err)
	}
	login, _ := fs.Sub(dist, "login")
	src, err = fs.ReadFile(login, "login.html")
	if err != nil {
		return fmt.Errorf("read app login.html: %w", err)
	}
	lt, err := template.New("login").Parse(string(src))
	if err != nil {
		return fmt.Errorf("parse app login.html: %w", err)
	}
	h.appIndex, h.appFS, h.loginIndex, h.loginFS = t, dist, lt, login
	return nil
}

// LoginAsset serves the sign-in page's bundle (web, `vite build --mode
// login`): a separate build, so an anonymous visitor never gets the app's JS.
func (h *Handler) LoginAsset(c *echo.Context) error {
	if h.loginFS == nil {
		return echo.ErrNotFound
	}
	return serveBuilt(c, h.loginFS, "assets/"+c.Param("*"))
}

// renderLoginPage renders the sign-in page with data (stage, messages, ...),
// which the page reads from <body data-*> (web/src/features/login).
func (h *Handler) renderLoginPage(c *echo.Context, status int, data map[string]any) error {
	if h.loginIndex == nil {
		return echo.NewHTTPError(http.StatusNotFound, "admin app not built (make web)")
	}
	page := map[string]any{
		"AdminPath": h.cfg.Admin.Path, "Base": h.cfg.Admin.Path + "/login/", "Asset": h.assetVer,
		"Stage": "", "Error": "", "Notice": "", "SSO": "", "DemoEmail": "", "DemoPass": "",
		"Passkeys": false, "EmailCode": false, "InviteEmail": "", "Token": "",
	}
	maps.Copy(page, data)
	var buf bytes.Buffer
	if err := h.loginIndex.Execute(&buf, page); err != nil {
		return err
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.HTMLBlob(status, buf.Bytes())
}

// AppPage serves every admin GET no other route takes: hashed files from
// assets/, the licence notices, and index.html for the rest so the client
// router handles deep links. An unknown api/ or static/ path stays a 404.
func (h *Handler) AppPage(c *echo.Context) error {
	if h.appIndex == nil {
		return echo.NewHTTPError(http.StatusNotFound, "admin app not built (make web)")
	}
	rel := c.Param("*")
	switch {
	case strings.HasPrefix(rel, "assets/"):
		return h.appAsset(c, rel)
	case rel == "licenses.md":
		return h.appAsset(c, rel)
	case strings.HasPrefix(rel, "api/"), strings.HasPrefix(rel, "static/"):
		return echo.ErrNotFound
	}
	return h.appHTML(c)
}

func (h *Handler) appHTML(c *echo.Context) error {
	nonce := rand.Text() // 128+ bits, base32: nothing for HTML or the CSP to escape
	data := map[string]any{
		"AdminPath": h.cfg.Admin.Path,
		"Base":      h.cfg.Admin.Path + "/",
		"Asset":     h.assetVer,
		"CSRF":      h.csrfFromContext(c),
		"Version":   h.cfg.Version,
		"WAF":       h.cfg.WAF.Enabled,
		"Pro":       len(h.extCards) > 0, // add-on cards: Settings links to /settings/pro
		"Nonce":     nonce,
		"Role":      "",
		"Email":     "",
		"Demo":      false,
	}
	if u := currentUser(c); u != nil {
		data["Role"], data["Email"], data["Demo"] = u.Role, u.Email, h.isDemo(u)
	}
	var buf bytes.Buffer
	if err := h.appIndex.Execute(&buf, data); err != nil {
		return err
	}
	hd := c.Response().Header()
	hd.Set("Content-Security-Policy", appCSP(nonce))
	// It carries the CSRF token and a one-time nonce.
	hd.Set("Cache-Control", "no-store")
	return c.HTMLBlob(http.StatusOK, buf.Bytes())
}

// appAsset serves one built file, as the .br or .gz copy Vite wrote when the
// client takes it (web/build/palisade.ts), so nothing is compressed per
// request. Names carry a content hash, so the browser keeps them a year;
// private, since they're only served to a signed-in session.
func (h *Handler) appAsset(c *echo.Context, rel string) error {
	return serveBuilt(c, h.appFS, rel)
}

func serveBuilt(c *echo.Context, fsys fs.FS, rel string) error {
	// Clean first: assets/../index.html must not reach the raw template.
	name := path.Clean(rel)
	if !strings.HasPrefix(name, "assets/") && name != "licenses.md" ||
		strings.HasSuffix(name, ".br") || strings.HasSuffix(name, ".gz") {
		return echo.ErrNotFound
	}
	body, err := fs.ReadFile(fsys, name)
	if err != nil {
		return echo.ErrNotFound
	}
	hd := c.Response().Header()
	hd.Add("Vary", "Accept-Encoding")
	ae := c.Request().Header.Get("Accept-Encoding")
	for _, enc := range []struct{ token, ext string }{{"br", ".br"}, {"gzip", ".gz"}} {
		if !acceptsEncoding(ae, enc.token) {
			continue
		}
		if z, err := fs.ReadFile(fsys, name+enc.ext); err == nil {
			body = z
			hd.Set("Content-Encoding", enc.token)
			break
		}
	}
	ctype := mime.TypeByExtension(path.Ext(name))
	if path.Ext(name) == ".md" {
		ctype = "text/markdown; charset=utf-8"
	}
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	hd.Set("Content-Type", ctype)
	if strings.HasPrefix(name, "assets/") {
		hd.Set("Cache-Control", "private, max-age=31536000, immutable")
	}
	// ServeContent would range-slice the compressed bytes; send them whole.
	hd.Set("Content-Length", strconv.Itoa(len(body)))
	return c.Blob(http.StatusOK, ctype, body)
}

// acceptsEncoding reports whether an Accept-Encoding header allows token
// (exact coding name, q=0 refuses it).
func acceptsEncoding(header, token string) bool {
	for part := range strings.SplitSeq(header, ",") {
		coding, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(coding), token) {
			continue
		}
		for p := range strings.SplitSeq(params, ";") {
			k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
			if strings.EqualFold(k, "q") {
				if q, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && q <= 0 {
					return false
				}
			}
		}
		return true
	}
	return false
}

// wantsJSON reports whether the React app is asking (lib/api.ts sends
// Accept: application/json) on an endpoint a browser navigation also reaches
// (the sign-in redirect, error pages). Vary keeps a cache from serving one to
// the other.
func wantsJSON(c *echo.Context) bool {
	c.Response().Header().Add("Vary", "Accept")
	return strings.Contains(c.Request().Header.Get("Accept"), "application/json")
}

// jsonError is the error body of every JSON answer to the React app
// (web/src/lib/api.ts reads it): a stable code to branch on, a message to
// show, and per-field messages for a form. A handler returns one; jsonErrors
// writes it. It replaces the HTMX pages' ...Err template fields and
// HX-Retarget with a real 4xx/5xx.
type jsonError struct {
	Status  int               `json:"-"`
	Code    string            `json:"error"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"`
}

func (e *jsonError) Error() string   { return e.Message }
func (e *jsonError) StatusCode() int { return e.Status }

// errorCodes names a status for an error that didn't come as a jsonError.
var errorCodes = map[int]string{
	http.StatusBadRequest:            "invalid",
	http.StatusUnauthorized:          "unauthenticated",
	http.StatusForbidden:             "forbidden",
	http.StatusNotFound:              "not_found",
	http.StatusConflict:              "conflict",
	http.StatusRequestEntityTooLarge: "too_large",
	http.StatusTooManyRequests:       "rate_limited",
}

// jsonErrors answers a JSON caller's failed request with a jsonError body:
// a returned *jsonError as is, a 4xx from Echo (body limit, CSRF) with its
// status and message, anything else (a DB failure) as a logged 500 that
// doesn't echo the error text. HTMX callers keep Echo's default handling.
func jsonErrors(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		err := next(c)
		if err == nil || !wantsJSON(c) {
			return err
		}
		if r, _ := echo.UnwrapResponse(c.Response()); r != nil && r.Committed {
			return err
		}
		var je *jsonError
		if !errors.As(err, &je) {
			je = &jsonError{Status: http.StatusInternalServerError, Code: "internal", Message: "Something went wrong on the server. Try again."}
			var sc echo.HTTPStatusCoder
			if errors.As(err, &sc) && sc.StatusCode() > 0 && sc.StatusCode() < 500 {
				je.Status, je.Message = sc.StatusCode(), http.StatusText(sc.StatusCode())
				var he *echo.HTTPError
				if errors.As(err, &he) && he.Message != "" {
					je.Message = he.Message
				}
				if je.Code = errorCodes[je.Status]; je.Code == "" {
					je.Code = "error"
				}
			} else {
				log.Printf("admin %s %s: %v", c.Request().Method, c.Path(), err)
			}
		}
		return c.JSON(je.Status, je)
	}
}

// denied is a 403: a jsonError for the React app, the plain text the HTMX
// pages show otherwise.
func denied(c *echo.Context, code, msg string) error {
	if wantsJSON(c) {
		return &jsonError{Status: http.StatusForbidden, Code: code, Message: msg}
	}
	return c.String(http.StatusForbidden, msg)
}

// fromApp redirects {admin}/app/... (the app's address before #357) to the
// same page at the admin root, query kept, so bookmarks still work.
func (h *Handler) fromApp(c *echo.Context) error {
	u := h.cfg.Admin.Path + "/" + c.Param("*")
	if q := c.Request().URL.RawQuery; q != "" {
		u += "?" + q
	}
	return c.Redirect(http.StatusFound, u)
}
