package proxy_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/labstack/echo/v5"
)

// TestCanonicalRedirectStatus: an alias redirect is 301 for GET/HEAD and
// 308 for anything with a body, so a POST to www keeps its method and body.
func TestCanonicalRedirectStatus(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer backend.Close()
	h, db, reg := newTestHandlerDB(t, backend)
	if err := db.AddService("site", "example.com", "", backend.URL, 0, 0); err != nil {
		t.Fatal(err)
	}
	svcs, _ := db.ListServices()
	for _, s := range svcs {
		var err error
		switch s.Name {
		case "site":
			err = db.SetServiceHosts(s.ID, []string{"www.example.com"}, "example.com")
		default: // the harness's "/" prefix service would match first
			err = db.RemoveService(s.ID)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := reg.Reload(db); err != nil {
		t.Fatal(err)
	}
	for method, want := range map[string]int{"GET": 301, "HEAD": 301, "POST": 308, "DELETE": 308} {
		req := httptest.NewRequest(method, "http://www.example.com/form?x=1", nil)
		rec := httptest.NewRecorder()
		_ = h.Handle(echo.New().NewContext(req, rec))
		if rec.Code != want || rec.Header().Get("Location") != "http://example.com/form?x=1" {
			t.Errorf("%s = %d %q, want %d to the canonical host", method, rec.Code, rec.Header().Get("Location"), want)
		}
	}
}

// TestBodyReadFailure: a client whose body breaks off mid-inspection gets a
// 400, never a 500 or a proxied request.
func TestBodyReadFailure(t *testing.T) {
	reached := false
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	defer backend.Close()
	h := newTestHandler(t, backend)
	body := io.MultiReader(strings.NewReader(`{"a":`), iotest.ErrReader(errors.New("connection reset")))
	req := httptest.NewRequest(http.MethodPost, "/api", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "1.2.3.4")
	rec := httptest.NewRecorder()
	_ = h.Handle(echo.New().NewContext(req, rec))
	if rec.Code != http.StatusBadRequest || reached {
		t.Errorf("broken body = %d (backend reached: %v), want 400", rec.Code, reached)
	}
}
