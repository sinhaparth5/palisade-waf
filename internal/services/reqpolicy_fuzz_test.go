package services

import (
	"mime"
	"net/http"
	"slices"
	"strings"
	"testing"

	"palisade/internal/storage"
)

// FuzzRequestPolicy (issue #307): arbitrary method, Content-Type and length
// never panic, and every pass is one the policy allows: the method (HEAD on
// GET) is listed, the declared size fits, and the media type is listed or
// its type part equals a "type/*" wildcard's, never across the slash.
func FuzzRequestPolicy(f *testing.F) {
	f.Add("POST", "application/json", int64(10), "GET,POST", "application/json,text/*", uint16(1))
	f.Add("HEAD", "text/html; charset=utf-8", int64(-1), "GET", "text/*", uint16(0))
	f.Add("PUT", "text/plain", int64(4096), "", "application/*", uint16(2))
	f.Add("POST", "textual/html", int64(5), "", "text/*", uint16(0))
	f.Add("POST", "*/*", int64(5), "", "*/*", uint16(0))
	f.Add("POST", "TEXT/HTML", int64(5), "", "text/html", uint16(0))
	f.Fuzz(func(t *testing.T, method, ctype string, length int64, methods, types string, maxKiB uint16) {
		p := storage.RequestPolicy{Mode: "enforce", MaxBodyKiB: int(maxKiB)}
		if methods != "" {
			p.Methods = strings.Split(methods, ",")
		}
		if types != "" {
			p.ContentTypes = strings.Split(types, ",")
		}
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.Method, r.ContentLength = method, length
		r.Header.Set("Content-Type", ctype)
		if CheckRequestPolicy(p, r) != 0 {
			return
		}
		if len(p.Methods) > 0 && !slices.Contains(p.Methods, method) &&
			(method != http.MethodHead || !slices.Contains(p.Methods, http.MethodGet)) {
			t.Fatalf("method %q passed %q", method, p.Methods)
		}
		if length == 0 {
			return
		}
		if maxKiB > 0 && length > int64(maxKiB)*1024 {
			t.Fatalf("length %d passed a %d KiB cap", length, maxKiB)
		}
		if len(p.ContentTypes) == 0 {
			return
		}
		mt, _, err := mime.ParseMediaType(ctype)
		if err != nil {
			t.Fatalf("unparseable Content-Type %q passed", ctype)
		}
		typ, _, _ := strings.Cut(mt, "/")
		for _, want := range p.ContentTypes {
			if mt == want || (strings.HasSuffix(want, "/*") && typ+"/*" == want) {
				return
			}
		}
		t.Fatalf("Content-Type %q (%q) passed %q", ctype, mt, p.ContentTypes)
	})
}
