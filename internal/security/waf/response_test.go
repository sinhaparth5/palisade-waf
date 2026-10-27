package waf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"palisade/internal/config"
)

const sqlErrorPage = `<html><body><h1>Error</h1>
<p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1</p>
</body></html>`

func TestCheckResponse(t *testing.T) {
	e := newTestEngine(t)
	big := strings.Repeat("a", ResponseInspectLimit) + sqlErrorPage
	cases := []struct {
		name, method, ctype, encoding, body string
		status                              int
		chunked                             bool
		leak                                bool
	}{
		{"SQL error page", "GET", "text/html; charset=utf-8", "", sqlErrorPage, 500, false, true},
		{"SQL error in JSON", "GET", "application/json", "", `{"error":"` + strings.ReplaceAll(sqlErrorPage, "\n", " ") + `"}`, 500, false, true},
		{"clean page", "GET", "text/html", "", "<html><body>Hello, world</body></html>", 200, false, false},
		{"binary skipped", "GET", "application/octet-stream", "", sqlErrorPage, 200, false, false},
		{"SSE skipped", "GET", "text/event-stream", "", sqlErrorPage, 200, false, false},
		{"gzip skipped", "GET", "text/html", "gzip", sqlErrorPage, 200, false, false},
		{"HEAD skipped", "HEAD", "text/html", "", sqlErrorPage, 200, false, false},
		{"over the cap by length", "GET", "text/html", "", big, 200, false, false},
		{"over the cap, chunked", "GET", "text/html", "", big, 200, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "http://shop.test/item?id=1", nil)
			resp := &http.Response{
				StatusCode:    tc.status,
				Proto:         "HTTP/1.1",
				Header:        http.Header{"Content-Type": {tc.ctype}},
				Body:          io.NopCloser(strings.NewReader(tc.body)),
				ContentLength: int64(len(tc.body)),
				Request:       r,
			}
			if tc.encoding != "" {
				resp.Header.Set("Content-Encoding", tc.encoding)
			}
			if tc.chunked {
				resp.ContentLength = -1
			}
			id := e.CheckResponse(r, "203.0.113.9", resp)
			if (id != 0) != tc.leak {
				t.Fatalf("rule %d, want leak=%v", id, tc.leak)
			}
			if tc.leak && (id < 951000 || id >= 952000) {
				t.Errorf("rule %d, want a 951xxx SQL leak rule", id)
			}
			if got, _ := io.ReadAll(resp.Body); string(got) != tc.body {
				t.Fatalf("body not restored: %d bytes, want %d", len(got), len(tc.body))
			}
		})
	}
}

// BenchmarkCheckResponse measures inspecting a 32 KiB clean HTML page.
func BenchmarkCheckResponse(b *testing.B) {
	e, err := New(config.WAFConfig{Enabled: true}, nil)
	if err != nil {
		b.Fatal(err)
	}
	page := "<html><body>" + strings.Repeat("<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p>\n", 512) + "</body></html>"
	r := httptest.NewRequest("GET", "http://shop.test/", nil)
	b.ReportAllocs()
	for b.Loop() {
		resp := &http.Response{StatusCode: 200, Proto: "HTTP/1.1", Request: r, ContentLength: int64(len(page)),
			Header: http.Header{"Content-Type": {"text/html"}, "Content-Length": {strconv.Itoa(len(page))}},
			Body:   io.NopCloser(strings.NewReader(page))}
		if id := e.CheckResponse(r, "203.0.113.9", resp); id != 0 {
			b.Fatalf("clean page matched %d", id)
		}
	}
}
