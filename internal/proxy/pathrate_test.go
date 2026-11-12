package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"palisade/internal/storage"
)

// TestPathRateLimit pins issue #280: a per-path rule limits only its method
// and prefix, per client, and the 429 row names the rule.
func TestPathRateLimit(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer backend.Close()
	h, db, reg := newTestHandlerDB(t, backend)
	logs := make(chan storage.RequestLog, 100)
	db.SetWebhookFn(func(l storage.RequestLog) { logs <- l })
	svc := reg.List()[0]
	if err := db.SetServiceBotMode(svc.ID, "off"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetServiceRateRules(svc.ID, "POST /reset 1/h 1"); err != nil {
		t.Fatal(err)
	}
	if err := reg.Reload(db); err != nil {
		t.Fatal(err)
	}
	e := echo.New()

	for i, tc := range []struct {
		method, path, ip string
		want             int
		action           string
	}{
		{"POST", "/reset", "203.0.113.9", 200, ""},
		{"POST", "/reset/confirm", "203.0.113.9", 429, "rate_limited:path POST /reset 1/h 1"},
		{"GET", "/reset", "203.0.113.9", 200, ""},
		{"POST", "/other", "203.0.113.9", 200, ""},
		{"POST", "/reset", "203.0.113.10", 200, ""},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.RemoteAddr = tc.ip + ":1234"
		rec := httptest.NewRecorder()
		_ = h.Handle(e.NewContext(req, rec))
		if rec.Code != tc.want {
			t.Fatalf("%d %s %s: status %d, want %d", i, tc.method, tc.path, rec.Code, tc.want)
		}
		if tc.want == 429 && rec.Header().Get("Retry-After") == "" {
			t.Errorf("%d: no Retry-After", i)
		}
		select {
		case l := <-logs:
			if l.Action != tc.action {
				t.Errorf("%d: action %q, want %q", i, l.Action, tc.action)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%d: no request logged", i)
		}
	}
}
