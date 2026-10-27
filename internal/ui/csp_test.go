package ui

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// TestAdminCSP pins issue #195: every admin response carries the strict CSP,
// the vendored assets it relies on are served, and rendered pages load
// nothing from another origin.
func TestAdminCSP(t *testing.T) {
	env := newAdminEnv(t)
	external := regexp.MustCompile(`<(script|link|img|iframe)[^>]+(src|href)="(https?:)?//`)
	for _, path := range []string{"/admin", "/admin/logs", "/admin/settings", "/admin/services", "/admin/certificates", "/admin/nope"} {
		rec := env.do("GET", path, nil)
		if got := rec.Header().Get("Content-Security-Policy"); got != adminCSP {
			t.Errorf("%s: CSP = %q, want adminCSP", path, got)
		}
		if m := external.FindString(rec.Body.String()); m != "" {
			t.Errorf("%s loads an external origin: %s", path, m)
		}
	}
	for _, asset := range []string{"htmx.min.js", "chart.umd.min.js", "fonts/fonts.css", "hugeicons/hgi-stroke-rounded.woff2", "flag-icons/flags/4x3/de.svg"} {
		if rec := env.do("GET", "/admin/static/vendor/"+asset, nil); rec.Code != 200 {
			t.Errorf("vendor asset %s = %d, want 200", asset, rec.Code)
		}
	}
}

// TestTemplatesHaveNoInlineCode keeps the CSP enforceable: no inline
// <script>/<style>, no on*= handlers, no hx-on (needs eval), no style="".
func TestTemplatesHaveNoInlineCode(t *testing.T) {
	bad := regexp.MustCompile(`<script>|<script\s+[^>]*>[^<\s]|<style|\son[a-z]+=|hx-on|\sstyle="`)
	err := fs.WalkDir(templateFS, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".html") {
			return err
		}
		b, err := fs.ReadFile(templateFS, path)
		if err != nil {
			return err
		}
		if m := bad.FindString(string(b)); m != "" {
			t.Errorf("%s: inline code %q breaks the admin CSP", path, m)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
