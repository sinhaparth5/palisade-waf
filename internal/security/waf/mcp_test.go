package waf

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMCPGuard(t *testing.T) {
	e := newTestEngine(t)
	e.SetMCP(MCPConfig{Mode: "enforce", Path: "/mcp", Origins: []string{"https://app.example.com"},
		Methods: []string{"initialize", "notifications/*", "tools/list", "tools/call"}, Tools: []string{"search"}})

	const call = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"q":"x"}}}`
	cases := []struct {
		name, method, path, origin, ctype, body string
		want                                    int
	}{
		{"allowed call", "POST", "/mcp", "", "application/json", call, 0},
		{"trailing slash", "POST", "/mcp/", "", "application/json", call, 0},
		{"listed origin", "POST", "/mcp", "https://APP.example.com", "application/json", call, 0},
		{"notification wildcard", "POST", "/mcp", "", "application/json", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, 0},
		{"client response", "POST", "/mcp", "", "application/json", `{"jsonrpc":"2.0","id":"s1","result":{}}`, 0},
		{"batch", "POST", "/mcp", "", "application/json", `[` + call + `,{"jsonrpc":"2.0","id":2,"method":"tools/list"}]`, 0},
		{"sse stream", "GET", "/mcp", "", "", "", 0},
		{"session end", "DELETE", "/mcp", "", "", "", 0},
		{"other path untouched", "PUT", "/api", "https://evil.test", "text/plain", "x", 0},
		{"rebinding origin", "POST", "/mcp", "https://evil.test", "application/json", call, 403},
		{"origin on GET", "GET", "/mcp", "http://127.0.0.1:8000", "", "", 403},
		{"bad http method", "PUT", "/mcp", "", "application/json", call, 405},
		{"not json", "POST", "/mcp", "", "text/plain", call, 415},
		{"no body", "POST", "/mcp", "", "application/json", "", 415},
		{"wrong version", "POST", "/mcp", "", "application/json", `{"jsonrpc":"1.0","id":1,"method":"tools/list"}`, 400},
		{"null id", "POST", "/mcp", "", "application/json", `{"jsonrpc":"2.0","id":null,"method":"tools/list"}`, 400},
		{"scalar params", "POST", "/mcp", "", "application/json", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":3}`, 400},
		{"result and error", "POST", "/mcp", "", "application/json", `{"jsonrpc":"2.0","id":1,"result":{},"error":{}}`, 400},
		{"empty batch", "POST", "/mcp", "", "application/json", `[]`, 400},
		{"garbage", "POST", "/mcp", "", "application/json", `{"jsonrpc":`, 400},
		{"method not listed", "POST", "/mcp", "", "application/json", `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{}}`, 403},
		{"tool not listed", "POST", "/mcp", "", "application/json", strings.Replace(call, "search", "exec_shell", 1), 403},
		{"bad call in batch", "POST", "/mcp", "", "application/json", `[` + call + `,{"jsonrpc":"2.0","id":2,"method":"sampling/createMessage"}]`, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var r = httptest.NewRequest(tc.method, "http://mcp.example.com"+tc.path, nil)
			if tc.body != "" {
				r = httptest.NewRequest(tc.method, "http://mcp.example.com"+tc.path, strings.NewReader(tc.body))
			}
			if tc.ctype != "" {
				r.Header.Set("Content-Type", tc.ctype)
			}
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			res, err := e.CheckWithOptions(r, "203.0.113.9", CheckOptions{Path: tc.path})
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == 0 && res.Action == "mcp_violation" || tc.want != 0 && (res.Status != tc.want || res.Action != "mcp_violation") {
				t.Fatalf("got %+v, want status %d", res, tc.want)
			}
		})
	}
}

func TestMCPGuardDefaultsAndModes(t *testing.T) {
	e := newTestEngine(t)
	e.SetMCP(MCPConfig{Mode: "log", Path: "/mcp"})
	req := func(origin, body string) *Result {
		t.Helper()
		r := httptest.NewRequest("POST", "http://mcp.example.com/mcp", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		res, err := e.Check(r, "203.0.113.9")
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	// No origins listed: only the request's own host; no method list: any method.
	if res := req("https://mcp.example.com", `{"jsonrpc":"2.0","id":1,"method":"anything/goes"}`); res.Action == "mcp_violation:log" {
		t.Fatalf("same-host origin flagged: %+v", res)
	}
	if res := req("https://evil.test", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); res.Blocked || res.Action != "mcp_violation:log" {
		t.Fatalf("log mode = %+v, want unblocked mcp_violation:log", res)
	}
	e.SetMCP(MCPConfig{Mode: "off", Path: "/mcp"})
	if e.mcp != nil {
		t.Fatal("off did not clear the guard")
	}
}
