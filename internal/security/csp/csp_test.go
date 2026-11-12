package csp

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"palisade/internal/storage"
)

func TestParse(t *testing.T) {
	cases := []struct {
		name, body string
		want       []violation
	}{
		{"report-uri", `{"csp-report":{"document-uri":"https://shop.example/checkout?token=x","blocked-uri":"https://Skimmer.example:8443/a.js","effective-directive":"script-src-elem"}}`,
			[]violation{{"https://skimmer.example:8443", "/checkout"}}},
		{"violated only", `{"csp-report":{"document-uri":"https://shop.example/","blocked-uri":"inline","violated-directive":"script-src 'self'"}}`,
			[]violation{{"inline", "/"}}},
		{"reports+json", `[{"type":"csp-violation","body":{"documentURL":"https://shop.example/p","blockedURL":"eval","effectiveDirective":"script-src"}},
			{"type":"csp-violation","body":{"documentURL":"https://shop.example/p","blockedURL":"https://img.example/x.png","effectiveDirective":"img-src"}},
			{"type":"deprecation","body":{}}]`,
			[]violation{{"eval", "/p"}}},
		{"data uri", `{"csp-report":{"blocked-uri":"data","effective-directive":"script-src-elem"}}`, []violation{{"data:", "/"}}},
		{"not script", `{"csp-report":{"blocked-uri":"https://f.example","effective-directive":"style-src"}}`, nil},
		{"bad scheme", `{"csp-report":{"blocked-uri":"chrome-extension://abc","effective-directive":"script-src"}}`, nil},
		{"garbage", `not json`, nil},
		{"bad array", `[1,2`, nil},
	}
	for _, c := range cases {
		got := parse([]byte(c.body))
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: got %v, want %v", c.name, got[i], c.want[i])
			}
		}
	}
}

type memStore struct {
	mu   sync.Mutex
	rows map[int][]storage.CSPScript
}

func (m *memStore) AddCSPScript(id int, s storage.CSPScript) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows[id] {
		if r.Origin == s.Origin {
			return false, nil
		}
	}
	m.rows[id] = append(m.rows[id], s)
	return true, nil
}

func (m *memStore) ListCSPScripts() (map[int][]storage.CSPScript, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[int][]storage.CSPScript{}
	for k, v := range m.rows {
		out[k] = append([]storage.CSPScript(nil), v...)
	}
	return out, nil
}

func TestCollector(t *testing.T) {
	store := &memStore{rows: map[int][]storage.CSPScript{1: {{Origin: "https://known.example"}}}}
	alerts := make(chan string, 10)
	c := New(store, func(id int) (string, bool) { return "shop", id == 1 },
		func(*http.Request) string { return "203.0.113.9" },
		func(service, source, page string) { alerts <- service + " " + source + " " + page })

	post := func(target, body string) int {
		rec := httptest.NewRecorder()
		c.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, target, strings.NewReader(body)))
		return rec.Code
	}
	report := func(src string) string {
		return `{"csp-report":{"document-uri":"https://shop.example/cart","blocked-uri":"` + src + `","effective-directive":"script-src-elem"}}`
	}

	if code := post("/_cz/csp-report?s=1", report("https://evil.example/x.js")); code != http.StatusNoContent {
		t.Fatalf("code %d", code)
	}
	if got := <-alerts; got != "shop https://evil.example /cart" {
		t.Errorf("alert %q", got)
	}
	post("/_cz/csp-report?s=1", report("https://evil.example/y.js"))  // same origin: no alert
	post("/_cz/csp-report?s=1", report("https://known.example/a.js")) // already in the store
	post("/_cz/csp-report?s=2", report("https://other.example/a.js")) // service without a policy
	post("/_cz/csp-report?s=x", report("https://other.example/a.js"))
	post("/_cz/csp-report?s=1", strings.Repeat(" ", maxBody)+report("https://big.example/a.js"))
	if n := len(store.rows[1]); n != 2 {
		t.Errorf("stored %d sources, want 2: %+v", n, store.rows)
	}
	if len(store.rows[2]) != 0 {
		t.Error("stored a report for a service without a policy")
	}

	rec := httptest.NewRecorder()
	c.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/_cz/csp-report?s=1", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET = %d", rec.Code)
	}

	// One client adds at most 10 new sources per service (issue #311).
	for i := 0; i < 100; i++ {
		post("/_cz/csp-report?s=1", report("https://flood"+string(rune('a'+i%26))+string(rune('a'+i/26))+".example/x.js"))
	}
	if n := len(store.rows[1]); n > 11 {
		t.Errorf("one client added %d sources, want at most 10 new", n)
	}
	select { // alerts run on their own goroutine
	case <-alerts:
	case <-time.After(2 * time.Second):
		t.Error("no alert for flood sources at all")
	}
}

func TestHeader(t *testing.T) {
	h, ep := Header(7, "script-src 'self'")
	if h != "script-src 'self'; report-uri /_cz/csp-report?s=7; report-to palisade-csp" || ep != `palisade-csp="/_cz/csp-report?s=7"` {
		t.Errorf("got %q / %q", h, ep)
	}
}

func TestEnforcePolicy(t *testing.T) {
	for _, tc := range []struct {
		policy   string
		approved []string
		want     string
	}{
		{"script-src 'self'", nil, "script-src 'self'"},
		{"default-src 'none'; Script-Src 'self' https://a.example", []string{"https://cdn.example", "https://a.example"}, "script-src 'self' https://a.example https://cdn.example"},
		{"img-src *", []string{"inline", "eval", "wasm-eval", "data:", "trusted-types-sink"}, "script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval' data:"},
		{"script-src-elem x; script-src https://only.example", nil, "script-src https://only.example"},
	} {
		if got := EnforcePolicy(tc.policy, tc.approved); got != tc.want {
			t.Errorf("EnforcePolicy(%q, %q) = %q, want %q", tc.policy, tc.approved, got, tc.want)
		}
	}
}

// TestCollectorInventoryFull pins issue #311: one report batch can't fill
// the inventory, and a full inventory alerts once instead of going silent.
func TestCollectorInventoryFull(t *testing.T) {
	store := &memStore{rows: map[int][]storage.CSPScript{1: {}}}
	for i := range MaxSources - 1 {
		store.rows[1] = append(store.rows[1], storage.CSPScript{Origin: "https://s" + strconv.Itoa(i) + ".example"})
	}
	alerts := make(chan string, 10)
	c := New(store, func(id int) (string, bool) { return "shop", id == 1 },
		func(r *http.Request) string { return r.Header.Get("X-Test-IP") },
		func(_, source, _ string) { alerts <- source })
	batch := func(ip string, n int) {
		var b strings.Builder
		b.WriteString("[")
		for i := range n {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(`{"type":"csp-violation","body":{"documentURL":"https://shop.example/","blockedURL":"https://` + ip + `-` + strconv.Itoa(i) + `.example/x.js","effectiveDirective":"script-src"}}`)
		}
		b.WriteString("]")
		req := httptest.NewRequest(http.MethodPost, "/_cz/csp-report?s=1", strings.NewReader(b.String()))
		req.Header.Set("X-Test-IP", ip)
		c.ServeHTTP(httptest.NewRecorder(), req)
	}

	batch("203.0.113.1", 5) // one slot left: the first fills it, the rest hit the cap
	batch("203.0.113.2", 5)
	if n := len(store.rows[1]); n != MaxSources {
		t.Fatalf("inventory %d, want %d", n, MaxSources)
	}
	got := map[string]int{}
	for range 2 {
		select {
		case a := <-alerts:
			got[a]++
		case <-time.After(2 * time.Second):
			t.Fatalf("missing alert, got %v", got)
		}
	}
	if got[InventoryFull] != 1 || got["https://203.0.113.1-0.example"] != 1 {
		t.Errorf("alerts %v, want the last recorded source and one InventoryFull", got)
	}
	select {
	case a := <-alerts:
		t.Errorf("extra alert %q", a)
	case <-time.After(100 * time.Millisecond):
	}
}
