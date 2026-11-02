package ui

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"path"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// assetStamp hashes every embedded admin asset (paths and contents), so a
// change to any CSS, JS, image or vendor file gives the build new ?v= URLs.
// Hashing only the stylesheet missed JS-only changes, which immutable
// caching would pin in browsers for a year (issue #255).
func assetStamp(fss ...fs.FS) string {
	h := sha256.New()
	for _, f := range fss {
		_ = fs.WalkDir(f, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := fs.ReadFile(f, p)
			if err != nil {
				return err
			}
			_, _ = io.WriteString(h, p)
			_, _ = h.Write(b)
			return nil
		})
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// precompressed formats gain nothing from gzip.
var precompressed = map[string]bool{".woff2": true, ".woff": true, ".png": true, ".jpg": true, ".jpeg": true, ".webp": true, ".gif": true, ".ico": true}

// staticGzip compresses text assets; small files aren't worth the framing.
var staticGzip = middleware.GzipWithConfig(middleware.GzipConfig{
	MinLength: 1024,
	Skipper:   func(c echo.Context) bool { return precompressed[path.Ext(c.Request().URL.Path)] },
})

// staticCache lets the browser keep a stamped asset for a year without
// revalidating: the stamp changes whenever any asset does. Unstamped URLs
// (fonts and flags referenced from vendor CSS) keep the default headers.
func (h *Handler) staticCache(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if c.QueryParam("v") == h.assetVer {
			c.Response().Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		return next(c)
	}
}
