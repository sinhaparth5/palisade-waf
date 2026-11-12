package proxy_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"palisade/internal/security/challenge"
	"palisade/internal/storage"

	"github.com/labstack/echo/v5"
)

// TestChallengeJSONForAPICalls pins issue #314: a page navigation is
// redirected to the challenge, a fetch/XHR gets a JSON 403 naming it, and
// both log the same bot_challenge action.
func TestChallengeJSONForAPICalls(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer backend.Close()
	h, db, _ := newTestHandlerDB(t, backend)
	logs := make(chan storage.RequestLog, 100)
	db.SetWebhookFn(func(l storage.RequestLog) { logs <- l })
	h.ReloadBotProtection(challenge.New("test-secret", 3600, 0)) // threshold 0: everyone is challenged
	e := echo.New()

	for _, tc := range []struct {
		name    string
		headers map[string]string
		want    int
		back    string // return path in challenge_url, for a JSON answer
	}{
		{"navigation", map[string]string{"Sec-Fetch-Mode": "navigate", "Accept": "text/html"}, 307, ""},
		{"navigation asking json", map[string]string{"Sec-Fetch-Mode": "navigate", "Accept": "application/json"}, 307, ""},
		{"fetch cors", map[string]string{"Sec-Fetch-Mode": "cors", "Accept": "*/*"}, 403, "/"},
		{"fetch same-origin", map[string]string{"Sec-Fetch-Mode": "same-origin", "Referer": "http://example.com/cart?x=1"}, 403, "/cart?x=1"},
		{"no-cors", map[string]string{"Sec-Fetch-Mode": "no-cors"}, 403, "/"},
		{"foreign referer", map[string]string{"Sec-Fetch-Mode": "cors", "Referer": "https://evil.example/x"}, 403, "/"},
		{"script json", map[string]string{"Accept": "application/json"}, 403, "/"},
		{"xhr", map[string]string{"X-Requested-With": "XMLHttpRequest"}, 403, "/"},
		{"old browser", map[string]string{"Accept": "text/html,application/xhtml+xml,application/json;q=0.9"}, 307, ""},
		{"curl", map[string]string{"Accept": "*/*"}, 307, ""},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/items", nil)
		req.Host = "example.com"
		req.RemoteAddr = "198.23.130.204:1234"
		for k, v := range tc.headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		_ = h.Handle(e.NewContext(req, rec))
		if rec.Code != tc.want {
			t.Fatalf("%s: status %d, want %d", tc.name, rec.Code, tc.want)
		}
		if tc.want == 403 {
			var got map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("%s: %v: %s", tc.name, err, rec.Body)
			}
			if u := got["challenge_url"]; got["error"] != "challenge_required" ||
				!strings.HasPrefix(u, "/_cz/challenge?") || !strings.Contains(u, "&r="+urlQuery(tc.back)+"&") {
				t.Errorf("%s: body %s", tc.name, rec.Body)
			}
		} else if !strings.Contains(rec.Header().Get("Location"), "r=%2Fapi%2Fitems") {
			t.Errorf("%s: Location %q", tc.name, rec.Header().Get("Location"))
		}
		select {
		case l := <-logs:
			if l.Action != "bot_challenge" || l.Status != tc.want || l.Blocked {
				t.Errorf("%s: logged %q status %d blocked %v", tc.name, l.Action, l.Status, l.Blocked)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: nothing logged", tc.name)
		}
	}
}

func urlQuery(s string) string {
	return strings.NewReplacer("/", "%2F", "?", "%3F", "=", "%3D").Replace(s)
}
