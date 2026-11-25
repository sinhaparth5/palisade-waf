package threatintel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"palisade/internal/storage"
)

// TestPushBans pins issue #342: autobans reach a LAPI with machine
// credentials as alerts, after a retry while it's down; pulled decisions
// aren't echoed back and a source without credentials gets nothing.
func TestPushBans(t *testing.T) {
	pushRetry = []time.Duration{time.Millisecond}
	var posts int
	var got []alert
	var logins []map[string]any
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/watchers/login":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			logins = append(logins, body)
			_, _ = w.Write([]byte(`{"code":200,"token":"jwt"}`))
		case "/v1/alerts":
			if posts++; posts == 1 {
				http.Error(w, "down", http.StatusServiceUnavailable)
				return
			}
			if r.Header.Get("Authorization") != "Bearer jwt" {
				http.Error(w, "no token", http.StatusUnauthorized)
				return
			}
			_ = json.NewDecoder(r.Body).Decode(&got)
			_, _ = w.Write([]byte(`["1"]`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer lapi.Close()
	pullOnly := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("source without machine credentials got %s", r.URL.Path)
	}))
	defer pullOnly.Close()

	db, err := storage.Open(filepath.Join(t.TempDir(), "waf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.AddCrowdSecSource("push", lapi.URL, "bouncer", "palisade", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddCrowdSecSource("pull", pullOnly.URL, "bouncer", "", ""); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	w := &Worker{db: db, client: http.DefaultClient, stop: make(chan struct{}),
		cs: map[int64]map[string]time.Time{9: {"5.5.5.5": at}}, now: func() time.Time { return at }}

	w.pushBatch([]ban{
		{"1.2.3.4", "10 blocked requests", 24 * time.Hour, at},
		{"2001:db8:1:2:3::/64", "sqli", 0, at},
		{"5.5.5.5", "pulled from CrowdSec", time.Hour, at}, // echo
		{"not-an-ip", "junk", time.Hour, at},
	})

	if posts != 2 || len(logins) != 2 {
		t.Fatalf("posts = %d, logins = %d; want a failed push then a retry", posts, len(logins))
	}
	if logins[0]["machine_id"] != "palisade" || logins[0]["password"] != "s3cret" {
		t.Errorf("login body = %v", logins[0])
	}
	if len(got) != 2 {
		t.Fatalf("pushed %d alerts, want 2: %+v", len(got), got)
	}
	ip, rng := got[0], got[1]
	if ip.Scenario != scenario || ip.Source != (alertSource{Scope: "Ip", Value: "1.2.3.4", IP: "1.2.3.4"}) ||
		ip.StartAt != "2026-11-19T12:00:00Z" || !strings.Contains(ip.Message, "10 blocked requests") {
		t.Errorf("IP alert = %+v", ip)
	}
	if d := ip.Decisions[0]; d.Type != "ban" || d.Value != "1.2.3.4" || d.Duration != "24h0m0s" || d.Scope != "Ip" {
		t.Errorf("IP decision = %+v", d)
	}
	if rng.Source.Scope != "Range" || rng.Source.Range != "2001:db8:1:2::/64" ||
		rng.Decisions[0].Duration != permanentBan.String() {
		t.Errorf("range alert = %+v", rng)
	}
}

// PushBan drops rather than blocks when the queue is full.
func TestPushBanQueueFull(t *testing.T) {
	w := &Worker{bans: make(chan ban, 1), now: time.Now}
	done := make(chan struct{})
	go func() {
		w.PushBan("1.1.1.1", "a", time.Hour)
		w.PushBan("2.2.2.2", "b", time.Hour)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("PushBan blocked on a full queue")
	}
	if b := <-w.bans; b.value != "1.1.1.1" {
		t.Errorf("queued %q, want the first ban", b.value)
	}
}
