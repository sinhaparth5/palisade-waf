package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"palisade/internal/storage"
)

// gateEnv is a proxied service with the given gate, and a client doing
// requests from ip with its own cookie jar.
func gateEnv(t *testing.T, g storage.ServiceGate) (do func(path, ip string, jar map[string]*http.Cookie) *httptest.ResponseRecorder, hits *int) {
	t.Helper()
	n := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if strings.Contains(r.URL.RawQuery, "palisade_bypass") {
			t.Error("bypass token reached the backend")
		}
	}))
	t.Cleanup(backend.Close)
	h, db, reg := newTestHandlerDB(t, backend)
	svc := reg.List()[0]
	if err := db.SetServiceGate(svc.ID, g); err != nil {
		t.Fatal(err)
	}
	if err := reg.Reload(db); err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	return func(path, ip string, jar map[string]*http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = ip + ":1234"
		req.Header.Set("Accept", "text/html")
		for _, ck := range jar {
			req.AddCookie(ck)
		}
		rec := httptest.NewRecorder()
		_ = h.Handle(e.NewContext(req, rec))
		for _, ck := range rec.Result().Cookies() {
			jar[ck.Name] = ck
		}
		return rec
	}, &n
}

func TestMaintenanceMode(t *testing.T) {
	do, hits := gateEnv(t, storage.ServiceGate{Maintenance: true, MaintMsg: "Upgrading the database.", BypassToken: "team-token",
		MaintEnd: time.Now().Add(time.Hour)})

	rec := do("/", "198.51.100.1", map[string]*http.Cookie{})
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "Upgrading the database.") {
		t.Fatalf("maintenance = %d %s", rec.Code, rec.Body)
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" || ra == "300" {
		t.Errorf("Retry-After = %q, want seconds until the scheduled end", ra)
	}
	// Open paths are never put in maintenance.
	if rec := do("/robots.txt", "198.51.100.1", map[string]*http.Cookie{}); rec.Code == http.StatusServiceUnavailable {
		t.Error("robots.txt got the maintenance page")
	}
	if rec := do("/?palisade_bypass=wrong", "198.51.100.1", map[string]*http.Cookie{}); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("wrong token = %d, want 503", rec.Code)
	}

	// The right token sets a cookie and strips itself from the URL.
	jar := map[string]*http.Cookie{}
	rec = do("/page?x=1&palisade_bypass=team-token", "198.51.100.2", jar)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/page?x=1" {
		t.Fatalf("bypass = %d → %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := do("/page?x=1", "198.51.100.2", jar); rec.Code != http.StatusOK || *hits != 2 { // robots.txt + this
		t.Errorf("with bypass cookie = %d (backend hits %d), want the backend", rec.Code, *hits)
	}
}

func TestMaintenanceSchedule(t *testing.T) {
	for name, g := range map[string]storage.ServiceGate{
		"ended":       {Maintenance: true, MaintEnd: time.Now().Add(-time.Minute)},
		"not started": {Maintenance: true, MaintStart: time.Now().Add(time.Hour)},
		"off":         {MaintStart: time.Now().Add(-time.Hour)},
	} {
		do, _ := gateEnv(t, g)
		if rec := do("/", "198.51.100.1", map[string]*http.Cookie{}); rec.Code != http.StatusOK {
			t.Errorf("%s: %d, want proxied", name, rec.Code)
		}
	}
}

func TestWaitingRoom(t *testing.T) {
	do, hits := gateEnv(t, storage.ServiceGate{WaitingRoom: true, MaxActive: 2, IdleSecs: 600})

	jars := make([]map[string]*http.Cookie, 4)
	for i := range jars {
		jars[i] = map[string]*http.Cookie{}
	}
	ip := func(i int) string { return "203.0.113." + string(rune('1'+i)) }
	for i := range 2 {
		if rec := do("/", ip(i), jars[i]); rec.Code != http.StatusOK {
			t.Fatalf("visitor %d = %d, want admitted", i, rec.Code)
		}
	}
	rec := do("/", ip(2), jars[2])
	body := rec.Body.String()
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(body, "place in line: 1") || !strings.Contains(body, `http-equiv="refresh"`) {
		t.Fatalf("third visitor = %d %s", rec.Code, body)
	}
	if rec := do("/", ip(3), jars[3]); !strings.Contains(rec.Body.String(), "place in line: 2") {
		t.Errorf("fourth visitor not second in line")
	}
	// Admitted visitors keep browsing; never more than 2 reach the backend.
	for range 3 {
		for i := range 2 {
			if rec := do("/next", ip(i), jars[i]); rec.Code != http.StatusOK {
				t.Fatalf("admitted visitor %d lost their slot: %d", i, rec.Code)
			}
		}
	}
	if *hits != 8 {
		t.Errorf("backend hits = %d, want 8 (two visitors only)", *hits)
	}

	// The admitted cookie from another network is a new visitor, queued.
	if rec := do("/", "192.0.2.77", jars[0]); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("shared cookie from another IP = %d, want queued", rec.Code)
	}
	// A forged ticket is ignored.
	forged := map[string]*http.Cookie{}
	for k, ck := range jars[0] {
		c := *ck
		c.Value = strings.Repeat("a", 32) + ".forged"
		forged[k] = &c
	}
	if rec := do("/", ip(0), forged); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("forged cookie = %d, want queued", rec.Code)
	}
}
