package services

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"palisade/internal/storage"
)

func TestCheckRequestPolicy(t *testing.T) {
	p := storage.RequestPolicy{Mode: "enforce", Methods: []string{"GET", "POST"}, ContentTypes: []string{"application/json", "image/*"}, MaxBodyKiB: 1}
	for _, tc := range []struct {
		method, ctype, body string
		want                int
	}{
		{"GET", "", "", 0},
		{"HEAD", "", "", 0},
		{"PUT", "", "", http.StatusMethodNotAllowed},
		{"POST", "application/json", "{}", 0},
		{"POST", "Application/JSON; charset=utf-8", "{}", 0},
		{"POST", "image/webp", "x", 0},
		{"POST", "imagex/png", "x", http.StatusUnsupportedMediaType},
		{"POST", "text/plain", "x", http.StatusUnsupportedMediaType},
		{"POST", ";;", "x", http.StatusUnsupportedMediaType},
		{"POST", "", "", 0}, // no body, no type needed
		{"POST", "application/json", strings.Repeat("x", 1025), http.StatusRequestEntityTooLarge},
		{"POST", "application/json", strings.Repeat("x", 1024), 0},
	} {
		r := httptest.NewRequest(tc.method, "/", strings.NewReader(tc.body))
		if tc.ctype != "" {
			r.Header.Set("Content-Type", tc.ctype)
		}
		if got := CheckRequestPolicy(p, r); got != tc.want {
			t.Errorf("%s %q %d bytes = %d, want %d", tc.method, tc.ctype, len(tc.body), got, tc.want)
		}
	}
	if got := CheckRequestPolicy(storage.RequestPolicy{Mode: "enforce"}, httptest.NewRequest("PATCH", "/", strings.NewReader("x"))); got != 0 {
		t.Errorf("empty policy = %d, want 0", got)
	}
}
