package ui

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"palisade/internal/storage"
)

func TestAdminRequiresSession(t *testing.T) {
	env := newAdminEnv(t)
	for _, path := range []string{"/admin", "/admin/settings", "/admin/logs"} {
		rec := env.doWith("GET", path, nil, "")
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/admin/login" {
			t.Errorf("%s without session: %d %q", path, rec.Code, rec.Header().Get("Location"))
		}
		if rec := env.doWith("GET", path, nil, "bogus-token"); rec.Code != http.StatusFound {
			t.Errorf("%s with unknown session: %d", path, rec.Code)
		}
	}

	// A session revoked by a newer login says why.
	old := env.session
	if _, err := env.db.CreateSession(env.uid, "10.0.0.9", "other", ""); err != nil {
		t.Fatal(err)
	}
	rec := env.doWith("GET", "/admin", nil, old)
	if loc := rec.Header().Get("Location"); loc != "/admin/login?reason=revoked" {
		t.Errorf("revoked session redirect = %q", loc)
	}
	rec = env.doWith("GET", "/admin/login?reason=revoked", nil, "")
	if !strings.Contains(rec.Body.String(), "another device") {
		t.Error("login page should explain the revocation")
	}
}

func TestAdminMutationsRequireCSRF(t *testing.T) {
	env := newAdminEnv(t)
	req := httptest.NewRequest("POST", "/admin/api/ip-rules", strings.NewReader("ip=1.2.3.4&rule_type=block"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: env.session})
	rec := httptest.NewRecorder()
	env.e.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without CSRF = %d, want 403", rec.Code)
	}
}

func TestLoginPageAndLogout(t *testing.T) {
	env := newAdminEnv(t)

	if rec := env.doWith("GET", "/admin/login", nil, ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `data-stage=""`) {
		t.Fatalf("login page: %d", rec.Code)
	}
	// Already logged in: straight to the dashboard.
	if rec := env.do("GET", "/admin/login", nil); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/admin" {
		t.Fatalf("logged-in login page: %d %q", rec.Code, rec.Header().Get("Location"))
	}

	rec := env.doWith("POST", "/admin/login", form("email", testAdminEmail, "password", testAdminPassword), "")
	if rec.Code != http.StatusFound || cookieByName(rec, sessionCookie) == nil || cookieByName(rec, deviceCookie) == nil {
		t.Fatalf("password login: %d", rec.Code)
	}
	newSession := cookieByName(rec, sessionCookie).Value

	rec = env.doWith("POST", "/admin/logout", nil, newSession)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/admin/login" {
		t.Fatalf("logout: %d", rec.Code)
	}
	if sess, _ := env.db.GetSession(newSession); sess != nil {
		t.Error("logout should delete the session row")
	}
}

func TestAdminPagesRender(t *testing.T) {
	env := newAdminEnv(t)
	svc := env.seedService("shop", "shop.example.com")
	_ = env.db.AddIPRule("", "1.2.3.4", "block")
	_ = env.db.AddIPRuleWithNote("", "5.6.7.8", "block", "Auto-banned — test")
	_ = env.db.AddIPRule("shop", "10.0.0.0/8", "allow")
	_ = env.db.AddGeoRule("", "CN", "block")
	_ = env.db.AddGeoRule("shop", "US", "allow")
	_ = env.db.DisableWAFRule(942100, "noisy")
	_ = env.db.DisableWAFRuleForService(svc.Name, 920420, "uploads")
	_ = env.db.AddThreatIntelSource("Feed", "https://example.com/list.txt", 24)
	now := time.Now()
	for i, r := range []storage.RequestLog{
		{AppName: "shop", RealIP: "1.2.3.4", Country: "CN", Method: "GET", Path: "/x", Status: 403, Blocked: true, RuleID: 942100, Action: "deny", UserAgent: "sqlmap/1.7"},
		{AppName: "shop", RealIP: "8.8.8.8", Country: "US", Method: "GET", Path: "/", Status: 200, UserAgent: "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0"},
		{AppName: "shop", RealIP: "9.9.9.9", Country: "DE", Method: "POST", Path: "/login", Status: 429, Blocked: true, Action: "rate_limited"},
		{AppName: "VPS", RealIP: "7.7.7.7", Country: "BR", Method: "GET", Path: "/missing", Status: 404, CacheStatus: "MISS"},
	} {
		r.Timestamp = now.Add(-time.Duration(i) * time.Minute)
		env.seedLog(r)
	}

	pages := map[string]string{
		"/admin/settings/pro": "Palisade Pro",
	}
	// The app's address before #357; bookmarks land on the same page.
	for path, to := range map[string]string{
		"/admin/app":                         "/admin/",
		"/admin/app/":                        "/admin/",
		"/admin/app/ip-rules?page=2":         "/admin/ip-rules?page=2",
		"/admin/app/logs?status=blocked&x=1": "/admin/logs?status=blocked&x=1",
	} {
		if rec := env.do("GET", path, nil); rec.Code != http.StatusFound || rec.Header().Get("Location") != to {
			t.Errorf("GET %s = %d %q, want a redirect to %s", path, rec.Code, rec.Header().Get("Location"), to)
		}
	}
	// Unknown API and static paths stay 404s, never the app's page.
	for _, path := range []string{"/admin/api/nope", "/admin/static/nope.js"} {
		if rec := env.do("GET", path, nil); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
	}
	for path, heading := range pages {
		rec := env.do("GET", path, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), heading) {
			t.Errorf("GET %s = %d (heading %q present: %v)", path, rec.Code, heading, strings.Contains(rec.Body.String(), heading))
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("GET %s missing no-store", path)
		}
	}
}

func TestDashboardAPIs(t *testing.T) {
	env := newAdminEnv(t)
	env.seedLog(storage.RequestLog{AppName: "a", RealIP: "1.1.1.1", Country: "CN", Status: 403, Blocked: true, Action: "deny", Method: "GET", Path: "/"})
	env.seedLog(storage.RequestLog{AppName: "a", RealIP: "2.2.2.2", Country: "US", Status: 200, Method: "GET", Path: "/"})

	var dash struct {
		RequestsToday int `json:"requests_today"`
		BlockRate     int `json:"block_rate"`
		Traffic       struct {
			Labels  []string `json:"labels"`
			Allowed []int    `json:"allowed"`
			Blocked []int    `json:"blocked"`
		} `json:"traffic"`
		Threats   []dashboardCount     `json:"threats"`
		Countries []dashboardCount     `json:"countries"`
		Recent    []storage.LogRow     `json:"recent"`
		Blocked   []storage.LogRow     `json:"blocked"`
		Changes   []storage.AuditEntry `json:"changes"`
		Glance    []glanceCard         `json:"glance"`
		Enforce   []enforcementRow     `json:"enforcement"`
	}
	env.doJSON(env.session, "GET", "/admin/api/dashboard", nil, &dash)
	traffic := dash.Traffic
	if len(traffic.Labels) != 24 || traffic.Allowed[23]+traffic.Blocked[23] != 2 || traffic.Blocked[23] != 1 {
		t.Errorf("traffic = %+v", traffic)
	}
	if dash.RequestsToday != 2 || dash.BlockRate != 50 || len(dash.Recent) != 2 || len(dash.Blocked) != 1 ||
		len(dash.Glance) != 4 || len(dash.Enforce) != 5 || dash.Changes == nil {
		t.Errorf("dashboard = %+v", dash)
	}
	if len(dash.Threats) != 1 || dash.Threats[0].Code != "CN" || len(dash.Countries) != 2 || dash.Countries[0].Name == "" {
		t.Errorf("threats %+v countries %+v", dash.Threats, dash.Countries)
	}

	var logs struct {
		Total int              `json:"total"`
		Logs  []storage.LogRow `json:"logs"`
	}
	env.doJSON(env.session, "GET", "/admin/api/logs?status=blocked", nil, &logs)
	if logs.Total != 1 || logs.Logs[0].RealIP != "1.1.1.1" {
		t.Errorf("blocked logs = %+v", logs)
	}
	var bad jsonError
	if rec := env.doJSON(env.session, "GET", "/admin/api/logs?from=yesterday", nil, &bad); rec.Code != http.StatusBadRequest || bad.Code != "invalid" {
		t.Errorf("bad filter = %d %+v", rec.Code, bad)
	}

	if rec := env.do("GET", "/admin/api/notifications", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "1.1.1.1") {
		t.Errorf("notifications panel: %d", rec.Code)
	}
	if n, _ := env.h.unreadAlertCount(); n != 1 {
		t.Errorf("unread before seen = %d", n)
	}
	if rec := env.do("POST", "/admin/api/notifications/seen", nil); rec.Code != http.StatusNoContent {
		t.Errorf("mark seen: %d", rec.Code)
	}
	if n, _ := env.h.unreadAlertCount(); n != 0 {
		t.Errorf("unread after seen = %d", n)
	}

	rec := env.do("GET", "/admin/logs/stats", nil)
	var seed struct {
		Events []statEvent `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &seed); err != nil || len(seed.Events) != 2 {
		t.Errorf("stats seed: %v %s", err, rec.Body)
	}

	rec = env.do("GET", "/admin/logs/export?app=a&from=2020-01-01T00:00&to=2099-01-01T00:00", nil)
	if rec.Code != http.StatusOK || strings.Count(rec.Body.String(), "\n") != 2 ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), ".ndjson") {
		t.Errorf("export: %d %q", rec.Code, rec.Body)
	}

	if rec := env.do("GET", "/admin/metrics", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "palisade_") {
		t.Errorf("metrics: %d", rec.Code)
	}
}

func TestLogDetailFeedbackAndException(t *testing.T) {
	env := newAdminEnv(t)
	env.seedService("shop", "shop.example.com")
	blocked := env.seedLog(storage.RequestLog{AppName: "shop", RealIP: "1.2.3.4", Method: "GET", Path: "/q", Status: 403, Blocked: true, RuleID: 942100, Action: "deny", HeadersJSON: `{"User-Agent":"x"}`})
	clean := env.seedLog(storage.RequestLog{AppName: "shop", RealIP: "1.2.3.5", Method: "GET", Path: "/", Status: 200})
	orphan := env.seedLog(storage.RequestLog{AppName: "gone", RealIP: "1.2.3.6", Status: 403, Blocked: true, RuleID: 1})
	badHeaders := env.seedLog(storage.RequestLog{AppName: "shop", RealIP: "1.2.3.7", HeadersJSON: "{not json"})
	_ = env.db.UpsertIPThreatScore(storage.IPThreatScore{IP: "1.2.3.4", Total: 42, BotScore: 10, UpdatedAt: time.Now()})

	id := func(n int64) string { return strconv.FormatInt(n, 10) }

	rec := env.do("GET", "/admin/logs/"+id(blocked), nil)
	var d map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil || d["path"] != "/q" || d["has_threat_score"] != true {
		t.Fatalf("detail: %v %s", err, rec.Body)
	}
	if h, _ := d["headers"].(map[string]any); h["User-Agent"] != "x" {
		t.Errorf("headers = %v", d["headers"])
	}
	if rec := env.do("GET", "/admin/logs/"+id(badHeaders), nil); rec.Code != http.StatusOK {
		t.Errorf("detail with corrupt headers: %d", rec.Code)
	}
	for path, want := range map[string]int{"/admin/logs/abc": 400, "/admin/logs/0": 400, "/admin/logs/99999": 404} {
		if rec := env.do("GET", path, nil); rec.Code != want {
			t.Errorf("GET %s = %d want %d", path, rec.Code, want)
		}
	}

	for _, tc := range []struct {
		path string
		want int
	}{
		{"/admin/logs/feedback/" + id(blocked), 200},
		{"/admin/logs/feedback/" + id(clean), 400},
		{"/admin/logs/feedback/x", 400},
		{"/admin/logs/feedback/99999", 404},
		{"/admin/logs/exception/" + id(blocked), 200},
		{"/admin/logs/exception/" + id(clean), 400},
		{"/admin/logs/exception/" + id(orphan), 400},
		{"/admin/logs/exception/x", 400},
		{"/admin/logs/exception/99999", 404},
	} {
		if rec := env.do("POST", tc.path, form("false_positive", "1")); rec.Code != tc.want {
			t.Errorf("POST %s = %d want %d: %s", tc.path, rec.Code, tc.want, rec.Body)
		}
	}
	excs, _ := env.db.ListWAFServiceExceptions()
	if len(excs) != 1 || excs[0].RuleID != 942100 || excs[0].ServiceName != "shop" {
		t.Errorf("exceptions = %+v", excs)
	}
	if env.count("waf") != 1 {
		t.Errorf("waf reloads = %d", env.count("waf"))
	}
}

// readSSE drives an SSE handler: it waits until the handler has
// subscribed, broadcasts entries, then cancels and returns the body.
func readSSE(t *testing.T, env *adminEnv, path string, entries ...storage.RequestLog) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", path, nil).WithContext(ctx)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: env.session})
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { env.e.ServeHTTP(rec, req); close(done) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		env.h.broadcaster.mu.RLock()
		n := len(env.h.broadcaster.subs)
		env.h.broadcaster.mu.RUnlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	for _, e := range entries {
		env.h.broadcaster.Broadcast(e)
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	return rec.Body.String()
}

func TestSSEStreams(t *testing.T) {
	env := newAdminEnv(t)
	blocked := storage.RequestLog{ID: 7, AppName: "a", RealIP: "1.2.3.4", Method: "GET", Path: "/evil", Status: 403, Blocked: true, Action: "deny", Timestamp: time.Now()}
	clean := storage.RequestLog{ID: 8, AppName: "a", RealIP: "1.2.3.5", Method: "GET", Path: "/ok", Status: 200, Timestamp: time.Now()}

	body := readSSE(t, env, "/admin/logs/stream", clean, blocked)
	if !strings.Contains(body, `"p":"/evil","s":403,"blk":true,"why":"deny"`) || !strings.Contains(body, `"p":"/ok"`) {
		t.Errorf("logs stream body: %q", body)
	}

	body = readSSE(t, env, "/admin/api/notifications/stream", clean, blocked)
	sc := bufio.NewScanner(strings.NewReader(body))
	var events []string
	for sc.Scan() {
		if after, ok := strings.CutPrefix(sc.Text(), "event: "); ok {
			events = append(events, after)
		}
	}
	if strings.Join(events, ",") != "count,toast" {
		t.Errorf("notification events = %v (only the blocked entry should notify)", events)
	}
}

func TestBroadcasterRingBuffer(t *testing.T) {
	b := NewLogBroadcaster()
	ch := b.Subscribe()
	for i := range recentBufSize + 5 {
		b.Broadcast(storage.RequestLog{ID: i})
	}
	if len(b.recent) != recentBufSize || b.recent[0].ID != 5 {
		t.Errorf("ring buffer len=%d first=%d", len(b.recent), b.recent[0].ID)
	}
	if len(ch) != cap(ch) {
		t.Errorf("slow subscriber should have a full buffer, not block: %d/%d", len(ch), cap(ch))
	}
	b.Unsubscribe(ch)
	if _, ok := <-drain(ch); ok {
		t.Error("channel should be closed after Unsubscribe")
	}
}

func drain(ch chan storage.RequestLog) chan storage.RequestLog {
	for range len(ch) {
		<-ch
	}
	return ch
}

// TestLoginReplacesSameBrowserRow checks that logging in again from the same
// IP and browser replaces its "Registered devices" row even when the device
// cookie is gone and the browser version changed, while another browser on
// that IP keeps its own row.
func TestLoginReplacesSameBrowserRow(t *testing.T) {
	env := newAdminEnv(t)
	const ip = "127.0.0.1"
	oldLinux := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
	newLinux := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
	windows := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
	if _, err := env.db.CreateSession(env.uid, ip, oldLinux, strings.Repeat("a", 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := env.db.CreateSession(env.uid, ip, windows, strings.Repeat("b", 32)); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/admin/login", strings.NewReader(form("email", testAdminEmail, "password", testAdminPassword).Encode()))
	req.RemoteAddr = ip + ":12345"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", newLinux)
	rec := httptest.NewRecorder()
	env.e.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("login: %d", rec.Code)
	}

	sessions, err := env.db.ListSessions(env.uid)
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for _, s := range sessions {
		count[browserOS(s.UserAgent)]++
	}
	if count["Chrome on Linux"] != 1 || count["Chrome on Windows"] != 1 {
		t.Errorf("device rows = %v, want one Chrome on Linux and one Chrome on Windows", count)
	}
}
