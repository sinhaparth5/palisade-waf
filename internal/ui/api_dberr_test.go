package ui

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// TestAPIStorageFailure: with every table but api_keys gone, each API route
// answers 500 rather than a 2xx with empty data (an empty rule list would
// read as "nothing blocked") or a 4xx blaming the client, and nothing panics.
// The service list and purge read the in-memory registry, so they're not listed.
func TestAPIStorageFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	h, e := newTestAPIHandlerAt(t, path)
	h.reloadWAF = func() {}
	key := createTestKey(t, h, false)
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(backend.Close)

	dropTables(t, path, "name <> 'api_keys'")

	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/admin/api/v1/services", `{"name":"x","match_type":"host","match_value":"x.test","backend":"` + backend.URL + `"}`},
		{"GET", "/admin/api/v1/services/1", ""},
		{"PUT", "/admin/api/v1/services/1", `{"bot_mode":"off"}`},
		{"DELETE", "/admin/api/v1/services/1", ""},
		{"GET", "/admin/api/v1/ip-rules", ""},
		{"POST", "/admin/api/v1/ip-rules", `{"ip":"1.2.3.4","rule_type":"block"}`},
		{"DELETE", "/admin/api/v1/ip-rules/1", ""},
		{"GET", "/admin/api/v1/waf-rules/custom", ""},
		{"POST", "/admin/api/v1/waf-rules/custom", `{"rule":"SecAction \"id:1000001,pass\""}`},
		{"PUT", "/admin/api/v1/waf-rules/custom/1", `{"rule":"SecAction \"id:1000002,pass\""}`},
		{"DELETE", "/admin/api/v1/waf-rules/custom/1", ""},
		{"GET", "/admin/api/v1/bans", ""},
		{"POST", "/admin/api/v1/bans", `{"ip":"1.2.3.4"}`},
		{"DELETE", "/admin/api/v1/bans/1", ""},
		{"GET", "/admin/api/v1/logs", ""},
		{"GET", "/admin/api/v1/logs/1", ""},
		{"GET", "/admin/api/v1/stats", ""},
		{"GET", "/admin/api/v1/geo-rules", ""},
		{"POST", "/admin/api/v1/geo-rules", `{"country_code":"ZZ","rule_type":"block"}`},
		{"DELETE", "/admin/api/v1/geo-rules/1", ""},
		{"GET", "/admin/api/v1/rule-exceptions", ""},
		{"POST", "/admin/api/v1/rule-exceptions", `{"rule_id":942100}`},
		{"DELETE", "/admin/api/v1/rule-exceptions/global/1", ""},
		{"DELETE", "/admin/api/v1/rule-exceptions/services/1", ""},
		{"GET", "/admin/api/v1/vpatches", ""},
		{"PUT", "/admin/api/v1/vpatches/2000070", `{"enabled":false}`},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("%s %s = %d, want 500: %s", tc.method, tc.path, rec.Code, rec.Body)
		}
	}
}

// dropTables drops the tables of the SQLite file at path matching where (a
// condition on sqlite_master.name), through a second connection, so the
// handler's own DB starts failing on them.
func dropTables(t *testing.T, path, where string) {
	t.Helper()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	tables, err := tableNames(raw, where)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range tables {
		if _, err := raw.Exec(`DROP TABLE "` + n + `"`); err != nil {
			t.Fatal(err)
		}
	}
}

// TestAPIKeyLockout: wrong or missing bearer keys from one IP lock it out,
// and while locked even a valid key is refused, so the lockout can't be used
// to confirm a guessed key.
func TestAPIKeyLockout(t *testing.T) {
	h, e := newTestAPIHandler(t)
	key := createTestKey(t, h, true)
	call := func(auth string) int {
		req := httptest.NewRequest("GET", "/admin/api/v1/stats", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec.Code
	}
	codes := []int{}
	for i := range maxLoginFailures {
		auth := "Bearer cwaf_wrong"
		if i%2 == 0 {
			auth = ""
		}
		codes = append(codes, call(auth))
	}
	if codes[0] != http.StatusUnauthorized || codes[len(codes)-1] != http.StatusTooManyRequests {
		t.Fatalf("codes = %v, want 401s ending in 429", codes)
	}
	if got := call("Bearer " + key); got != http.StatusTooManyRequests {
		t.Errorf("valid key during lockout = %d, want 429", got)
	}
}

func tableNames(raw *sql.DB, where string) ([]string, error) {
	rows, err := raw.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND ` + where)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
