package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzOpenAPI compiles arbitrary specs and matches arbitrary requests
// against the test spec (issue #265): neither may panic, and a request
// the spec doesn't declare never gets a status.
func FuzzOpenAPI(f *testing.F) {
	f.Add(testOpenAPI, "GET", "/v1/users?limit=10", "")
	f.Add(testOpenAPI, "POST", "/v1/users", `{"name":"a","age":3}`)
	f.Add(`{"openapi":"3.0.0","paths":{"/a/{id}":{"get":{"parameters":[{"name":"id","in":"path","schema":{"type":"integer"}}]}}}}`, "GET", "/a/%zz", "")
	f.Add("openapi: 3.1.0\npaths: {}", "DELETE", "//x/../y", "[")
	spec, err := compileOpenAPI(testOpenAPI)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, doc, method, target, body string) {
		if s, err := compileOpenAPI(doc); err == nil && s != nil {
			check(s, method, target, body)
		}
		if status, declared := check(spec, method, target, body); !declared && status != 0 && status != http.StatusNotFound && status != http.StatusMethodNotAllowed {
			t.Fatalf("undeclared request got %d", status)
		}
	})
}

func check(s *apiSpec, method, target, body string) (int, bool) {
	if !validMethod(method) || !strings.HasPrefix(target, "/") || strings.ContainsAny(target, " \r\n\t#") {
		return 0, true
	}
	r := newRequest(method, target, body)
	if r == nil {
		return 0, true
	}
	r.Header.Set("Content-Type", "application/json")
	return s.check(r, r.URL.Path, []byte(body), body != "", true)
}

// newRequest returns nil for a target httptest.NewRequest can't parse (it
// panics); only that call is guarded, never the code under test.
func newRequest(method, target, body string) (r *http.Request) {
	defer func() {
		if recover() != nil {
			r = nil
		}
	}()
	return httptest.NewRequest(method, target, strings.NewReader(body))
}

func validMethod(m string) bool {
	if m == "" {
		return false
	}
	for _, c := range m {
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
}

// FuzzMCP runs arbitrary JSON-RPC bodies and Origins through the guard.
func FuzzMCP(f *testing.F) {
	f.Add("POST", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search"}}`)
	f.Add("POST", "https://app.example.com", `[{"jsonrpc":"2.0","id":2,"method":"tools/list"},{"jsonrpc":"2.0","method":"notifications/x"}]`)
	f.Add("POST", "null", `{"jsonrpc":"2.0","id":null,"method":"x"}`)
	f.Add("GET", "http://127.0.0.1", "")
	e := &Engine{}
	e.SetMCP(MCPConfig{Mode: "enforce", Path: "/mcp", Origins: []string{"https://app.example.com"},
		Methods: []string{"initialize", "notifications/*", "tools/list", "tools/call"}, Tools: []string{"search"}})
	f.Fuzz(func(t *testing.T, method, origin, body string) {
		if !validMethod(method) {
			return
		}
		r := httptest.NewRequest(method, "/mcp", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if origin != "" && !strings.ContainsAny(origin, "\r\n") {
			r.Header.Set("Origin", origin)
		}
		switch got := e.mcp.check(r, "/mcp", []byte(body), body != ""); got {
		case 0, http.StatusBadRequest, http.StatusForbidden, http.StatusMethodNotAllowed, http.StatusUnsupportedMediaType:
		default:
			t.Fatalf("unexpected status %d", got)
		}
	})
}
