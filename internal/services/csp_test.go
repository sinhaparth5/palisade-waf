package services

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCSPReportOnlyHeader covers issue #235: the report-only policy goes on
// HTML responses of a service that has one, and nowhere else.
func TestCSPReportOnlyHeader(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".json") {
			w.Header().Set("Content-Type", "application/json")
		} else {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		}
	}))
	defer backend.Close()

	db := openTestDB(t)
	for _, n := range []string{"shop", "plain"} {
		if err := db.AddService(n, n+".example.com", "", backend.URL, 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	list, _ := db.ListServices()
	shopID := list[0].ID
	if list[0].Name != "shop" {
		shopID = list[1].ID
	}
	if err := db.SetServiceCSP(shopID, "script-src 'self'"); err != nil {
		t.Fatal(err)
	}
	reg, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	if name, ok := reg.CSPService(shopID); !ok || name != "shop" {
		t.Errorf("CSPService = %q, %v", name, ok)
	}

	get := func(svc, path string) http.Header {
		h, _ := reg.Proxy(svc)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://"+svc+".example.com"+path, nil))
		return rec.Header()
	}
	hdr := get("shop", "/")
	if got := hdr.Get("Content-Security-Policy-Report-Only"); !strings.HasPrefix(got, "script-src 'self'; report-uri /_cz/csp-report?s=") {
		t.Errorf("CSP-RO = %q", got)
	}
	if hdr.Get("Reporting-Endpoints") == "" {
		t.Error("no Reporting-Endpoints")
	}
	if got := get("shop", "/a.json").Get("Content-Security-Policy-Report-Only"); got != "" {
		t.Errorf("JSON response got a policy: %q", got)
	}
	if got := get("plain", "/").Get("Content-Security-Policy-Report-Only"); got != "" {
		t.Errorf("service without a policy got one: %q", got)
	}
}
