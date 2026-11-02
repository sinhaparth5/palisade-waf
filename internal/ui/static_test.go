package ui

import (
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

func TestStaticAssets(t *testing.T) {
	env := newAdminEnv(t)
	want, err := fs.ReadFile(vendorFS, "vendor/htmx.min.js")
	if err != nil {
		t.Fatal(err)
	}
	font := "/admin/static/vendor/fonts/JetBrainsMono-latin.woff2"

	tests := []struct {
		name, path, enc string
		wantGzip        bool
		wantCache       string
	}{
		{"stamped js gzipped and immutable", "/admin/static/vendor/htmx.min.js?v=" + env.h.assetVer, "gzip", true, "public, max-age=31536000, immutable"},
		{"stale stamp not cached", "/admin/static/vendor/htmx.min.js?v=old", "gzip", true, ""},
		{"no gzip unless asked", "/admin/static/vendor/htmx.min.js", "", false, ""},
		{"fonts never gzipped", font, "gzip", false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.enc != "" {
				req.Header.Set("Accept-Encoding", tc.enc)
			}
			rec := httptest.NewRecorder()
			env.e.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d", rec.Code)
			}
			if got := rec.Header().Get("Cache-Control"); got != tc.wantCache {
				t.Errorf("Cache-Control %q, want %q", got, tc.wantCache)
			}
			gz := rec.Header().Get("Content-Encoding") == "gzip"
			if gz != tc.wantGzip {
				t.Fatalf("gzip %v, want %v", gz, tc.wantGzip)
			}
			if tc.path == font {
				return
			}
			body := rec.Body.Bytes()
			if gz {
				r, err := gzip.NewReader(bytes.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				if body, err = io.ReadAll(r); err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(body, want) {
				t.Errorf("body differs from htmx.min.js (%d vs %d bytes)", len(body), len(want))
			}
		})
	}
}

func TestAssetStampCoversJS(t *testing.T) {
	css := fstest.MapFS{"tailwind.min.css": {Data: []byte("a{}")}}
	js := func(s string) fstest.MapFS { return fstest.MapFS{"admin.min.js": {Data: []byte(s)}} }
	if assetStamp(css, js("one()")) == assetStamp(css, js("two()")) {
		t.Error("a JS-only change kept the same stamp")
	}
}
