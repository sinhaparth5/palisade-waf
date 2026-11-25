package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testCustomRule = `SecRule ARGS "@contains evil" "id:1000001,phase:2,deny,status:403"`

func TestAPICustomRules(t *testing.T) {
	h, e := newTestAPIHandler(t)
	h.reloadWAF = func() {}
	key := createTestKey(t, h, false)
	call := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}
	const base = "/admin/api/v1/waf-rules/custom"
	rule := `{"rule":"SecRule ARGS \"@contains evil\" \"id:1000001,phase:2,deny\""}`

	for _, tc := range []struct {
		method, path, body string
		want               int
	}{
		{"POST", base, "{", 400},
		{"POST", base, `{"rule":"SecRuleEngine Off"}`, 400},
		{"POST", base, rule, 201},
		{"POST", base, rule, 400}, // id already used
		{"PUT", base + "/x", rule, 400},
		{"PUT", base + "/99999", `{"rule":"SecAction \"id:1000002,pass\""}`, 404},
		{"PUT", base + "/1", `{"rule":"SecRule ARGS \"@contains evil\" \"id:1000001,phase:2,deny\"","enabled":false,"note":"n"}`, 200},
		{"GET", base, "", 200},
		{"DELETE", base + "/x", "", 400},
		{"DELETE", base + "/1", "", 204},
	} {
		if rec := call(tc.method, tc.path, tc.body); rec.Code != tc.want {
			t.Errorf("%s %s %s = %d, want %d: %s", tc.method, tc.path, tc.body, rec.Code, tc.want, rec.Body.String())
		}
	}
	if rec := call("POST", base, rule); rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"Enabled":true`) {
		t.Errorf("create response = %d %s", rec.Code, rec.Body.String())
	}
}
