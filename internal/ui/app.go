package ui

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/labstack/echo/v5"
)

// The React admin app (web/, issue #348), served under {admin}/app behind
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
	h.appIndex, h.appFS = t, dist
	return nil
}

// AppPage serves {admin}/app and everything under it: hashed files from
// assets/, the licence notices, and index.html for every other path so the
// client router handles deep links.
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
	}
	return h.appHTML(c)
}

func (h *Handler) appHTML(c *echo.Context) error {
	nonce := rand.Text() // 128+ bits, base32: nothing for HTML or the CSP to escape
	data := map[string]any{
		"AdminPath": h.cfg.Admin.Path,
		"Base":      h.cfg.Admin.Path + "/app/",
		"Asset":     h.assetVer,
		"CSRF":      h.csrfFromContext(c),
		"Version":   h.cfg.Version,
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
	// Clean first: assets/../index.html must not reach the raw template.
	name := path.Clean(rel)
	if !strings.HasPrefix(name, "assets/") && name != "licenses.md" ||
		strings.HasSuffix(name, ".br") || strings.HasSuffix(name, ".gz") {
		return echo.ErrNotFound
	}
	body, err := fs.ReadFile(h.appFS, name)
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
		if z, err := fs.ReadFile(h.appFS, name+enc.ext); err == nil {
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
