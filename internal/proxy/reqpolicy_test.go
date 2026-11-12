package proxy_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"palisade/internal/storage"
)

// TestRequestPolicy pins issue #282: enforce answers 405/415/413 before the
// WAF with action policy_violation; log mode passes with policy_violation:log;
// a chunked body over the limit never reaches the backend whole.
func TestRequestPolicy(t *testing.T) {
	var gotBody atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		gotBody.Store(n)
	}))
	defer backend.Close()

	h, db, reg := newTestHandlerDB(t, backend)
	logs := make(chan storage.RequestLog, 100)
	db.SetWebhookFn(func(l storage.RequestLog) { logs <- l })
	svc := reg.List()[0]
	if err := db.SetServiceBotMode(svc.ID, "off"); err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	jsonAPI := storage.RequestPolicy{Methods: []string{"GET", "POST"}, ContentTypes: []string{"application/json"}, MaxBodyKiB: 1}

	tests := []struct {
		name, mode, method, ctype, body string
		want                            int
		wantAction                      string
	}{
		{"off", "", "OPTIONS", "", "", http.StatusOK, ""},
		{"GET", "enforce", "GET", "", "", http.StatusOK, ""},
		{"HEAD follows GET", "enforce", "HEAD", "", "", http.StatusOK, ""},
		{"method", "enforce", "OPTIONS", "", "", http.StatusMethodNotAllowed, "policy_violation"},
		{"json", "enforce", "POST", "application/json; charset=utf-8", `{"a":1}`, http.StatusOK, ""},
		{"type", "enforce", "POST", "text/xml", "<a/>", http.StatusUnsupportedMediaType, "policy_violation"},
		{"no type", "enforce", "POST", "", "x", http.StatusUnsupportedMediaType, "policy_violation"},
		{"size", "enforce", "POST", "application/json", strings.Repeat("x", 2048), http.StatusRequestEntityTooLarge, "policy_violation"},
		{"log", "log", "OPTIONS", "", "", http.StatusOK, "policy_violation:log"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := jsonAPI
			p.Mode = tt.mode
			if err := db.SetServiceRequestPolicy(svc.ID, p); err != nil {
				t.Fatal(err)
			}
			if err := reg.Reload(db); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(tt.method, "/x", strings.NewReader(tt.body))
			req.RemoteAddr = "203.0.113.9:1234"
			if tt.ctype != "" {
				req.Header.Set("Content-Type", tt.ctype)
			}
			rec := httptest.NewRecorder()
			_ = h.Handle(e.NewContext(req, rec))
			if rec.Code != tt.want {
				t.Fatalf("status %d, want %d: %s", rec.Code, tt.want, rec.Body)
			}
			select {
			case l := <-logs:
				if l.Action != tt.wantAction {
					t.Errorf("logged action %q, want %q", l.Action, tt.wantAction)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("no request logged")
			}
		})
	}

	// Unknown length: capped while it streams.
	gotBody.Store(-1)
	req := httptest.NewRequest(http.MethodPost, "/x", io.NopCloser(strings.NewReader(strings.Repeat("x", 4096))))
	req.ContentLength = -1
	req.RemoteAddr = "203.0.113.9:1234"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	_ = h.Handle(e.NewContext(req, rec))
	if rec.Code == http.StatusOK || gotBody.Load() > 1024 {
		t.Errorf("chunked body over the limit reached the backend: %d bytes, status %d", gotBody.Load(), rec.Code)
	}
}
