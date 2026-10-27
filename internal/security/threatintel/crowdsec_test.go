package threatintel

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"palisade/internal/storage"
)

// TestCrowdSecSync pins issue #194's CrowdSec source: initial sync,
// incremental sync, expiry, and keeping decisions while LAPI is down.
func TestCrowdSecSync(t *testing.T) {
	responses := []string{
		// startup: full set
		`{"new":[
			{"duration":"4h","scope":"Ip","type":"ban","value":"1.2.3.4"},
			{"duration":"10m","scope":"Range","type":"ban","value":"10.0.0.7/24"},
			{"duration":"4h","scope":"Ip","type":"captcha","value":"5.5.5.5"},
			{"duration":"4h","scope":"Ip","type":"ban","value":"2001:db8::1"}
		],"deleted":null}`,
		// incremental: one new, one deleted
		`{"new":[{"duration":"4h","scope":"Ip","type":"ban","value":"6.6.6.6"}],
		  "deleted":[{"duration":"-1s","scope":"Ip","type":"ban","value":"1.2.3.4"}]}`,
		// nothing changed
		`{"new":null,"deleted":null}`,
	}
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path+"?"+r.URL.RawQuery+" key="+r.Header.Get("X-Api-Key"))
		if len(calls) > len(responses) {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, responses[len(calls)-1])
	}))
	defer srv.Close()

	db, err := storage.Open(filepath.Join(t.TempDir(), "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.AddCrowdSecSource("cs", srv.URL+"/", "bouncer-key"); err != nil {
		t.Fatal(err)
	}
	srcs, _ := db.ListThreatIntelSources()
	src := srcs[0]

	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	reloads := 0
	w := &Worker{db: db, reloadIPBL: func() { reloads++ }, client: srv.Client(),
		cs: make(map[int64]map[string]time.Time), now: func() time.Time { return now }}

	step := func(want ...string) {
		t.Helper()
		w.SyncSource(src.ID)
		got, _ := db.ListCrowdSecIPs()
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Fatalf("decisions = %v, want %v", got, want)
		}
	}

	step("1.2.3.4", "10.0.0.0/24", "2001:db8::1")
	if calls[0] != "/v1/decisions/stream?scopes=ip,range&startup=true key=bouncer-key" {
		t.Errorf("startup call = %q", calls[0])
	}
	step("10.0.0.0/24", "2001:db8::1", "6.6.6.6")
	if calls[1] != "/v1/decisions/stream?scopes=ip,range&startup=false key=bouncer-key" {
		t.Errorf("incremental call = %q", calls[1])
	}

	reloadsBefore := reloads
	now = now.Add(15 * time.Minute) // the /24's 10m ban has run out
	step("2001:db8::1", "6.6.6.6")
	if reloads != reloadsBefore+1 {
		t.Errorf("expiry reloads = %d, want 1", reloads-reloadsBefore)
	}

	step("2001:db8::1", "6.6.6.6") // LAPI down: last known decisions kept
	srcs, _ = db.ListThreatIntelSources()
	if srcs[0].LastError == "" || srcs[0].IPCount != 2 {
		t.Errorf("down source = %+v, want error and the last count", srcs[0])
	}
	if ips, _ := db.ListThreatIntelIPs(); len(ips) != 0 {
		t.Errorf("CrowdSec decisions leaked into feed IPs: %v", ips)
	}
}
