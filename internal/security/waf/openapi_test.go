package waf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testOpenAPI = `
openapi: 3.0.3
servers:
  - url: https://api.example.com/v1
paths:
  /users:
    get:
      parameters:
        - name: limit
          in: query
          schema: {type: integer, maximum: 100}
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema: {$ref: '#/components/schemas/User'}
  /users/me:
    get: {}
  /users/{id}:
    parameters:
      - name: id
        in: path
        required: true
        schema: {type: integer}
    get: {}
    delete:
      parameters:
        - $ref: '#/components/parameters/Confirm'
  /files/{name}.json:
    get: {}
components:
  parameters:
    Confirm:
      name: X-Confirm
      in: header
      required: true
      schema: {type: string, enum: ["yes"]}
  schemas:
    User:
      type: object
      required: [email]
      properties:
        email: {type: string}
        nickname: {type: string, nullable: true}
        manager: {$ref: '#/components/schemas/User'}
`

func TestOpenAPICheck(t *testing.T) {
	spec, err := compileOpenAPI(testOpenAPI)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	cases := []struct {
		name, method, target, body string
		header                     [2]string
		want                       int
		declared                   bool
	}{
		{"declared route", "GET", "/v1/users", "", [2]string{}, 0, true},
		{"trailing slash", "GET", "/v1/users/", "", [2]string{}, 0, true},
		{"query type ok", "GET", "/v1/users?limit=10", "", [2]string{}, 0, true},
		{"query not an integer", "GET", "/v1/users?limit=ten", "", [2]string{}, 400, true},
		{"query over maximum", "GET", "/v1/users?limit=500", "", [2]string{}, 400, true},
		{"static beats template", "GET", "/v1/users/me", "", [2]string{}, 0, true},
		{"path param ok", "GET", "/v1/users/42", "", [2]string{}, 0, true},
		{"path param wrong type", "GET", "/v1/users/abc", "", [2]string{}, 400, true},
		{"HEAD falls back to GET", "HEAD", "/v1/users/42", "", [2]string{}, 0, true},
		{"CORS preflight", "OPTIONS", "/v1/users/42", "", [2]string{}, 0, false},
		{"undeclared method", "PUT", "/v1/users/42", "", [2]string{}, 405, false},
		{"undeclared route", "GET", "/v1/actuator/env", "", [2]string{}, 404, false},
		{"server base is optional", "GET", "/users", "", [2]string{}, 0, true},
		{"too deep", "GET", "/v1/users/42/posts", "", [2]string{}, 404, false},
		{"empty segment", "GET", "/v1/users//x", "", [2]string{}, 404, false},
		{"partial template", "GET", "/v1/files/report.json", "", [2]string{}, 0, true},
		{"required header missing", "DELETE", "/v1/users/42", "", [2]string{}, 400, true},
		{"header enum mismatch", "DELETE", "/v1/users/42", "", [2]string{"x-confirm", "no"}, 400, true},
		{"header ok", "DELETE", "/v1/users/42", "", [2]string{"x-confirm", "yes"}, 0, true},
		{"body ok", "POST", "/v1/users", `{"email":"a@b.c","nickname":null,"manager":{"email":"m@b.c"}}`, [2]string{"Content-Type", "application/json"}, 0, true},
		{"body schema mismatch", "POST", "/v1/users", `{"nickname":"x"}`, [2]string{"Content-Type", "application/json"}, 400, true},
		{"nested ref mismatch", "POST", "/v1/users", `{"email":"a","manager":{}}`, [2]string{"Content-Type", "application/json"}, 400, true},
		{"required body missing", "POST", "/v1/users", "", [2]string{}, 400, true},
		{"undeclared media type", "POST", "/v1/users", `a=b`, [2]string{"Content-Type", "application/x-www-form-urlencoded"}, 415, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "http://api.example.com"+tc.target, strings.NewReader(tc.body))
			if tc.header[0] != "" {
				r.Header.Set(tc.header[0], tc.header[1])
			}
			got, declared := spec.check(r, r.URL.Path, []byte(tc.body), tc.body != "", true)
			if got != tc.want || declared != tc.declared {
				t.Fatalf("check = (%d, %v), want (%d, %v)", got, declared, tc.want, tc.declared)
			}
		})
	}
}

func TestValidateOpenAPI(t *testing.T) {
	cases := []struct {
		name, spec, wantErr string
	}{
		{"json", `{"openapi":"3.1.0","paths":{"/a":{"get":{}}}}`, ""},
		{"not a spec", `hello: [`, "not JSON or YAML"},
		{"swagger 2", `{"swagger":"2.0","paths":{"/a":{"get":{}}}}`, "OpenAPI 3.x"},
		{"no paths", `{"openapi":"3.0.0","paths":{}}`, "no paths"},
		{"relative path", `{"openapi":"3.0.0","paths":{"a":{"get":{}}}}`, "must start with /"},
		{"bad schema", `{"openapi":"3.0.0","paths":{"/a":{"get":{"parameters":[{"name":"q","in":"query","schema":{"type":"integer","minimum":"x"}}]}}}}`, "parameter q"},
		{"unresolved parameter", `{"openapi":"3.0.0","paths":{"/a":{"get":{"parameters":[{"$ref":"#/components/parameters/Nope"}]}}}}`, "unresolved"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateOpenAPI(tc.spec)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("error = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestCheckOpenAPIModes runs the spec through a full engine: enforce blocks
// before CRS, log only annotates, opts.Path (prefix stripped) is what gets
// matched, and a declared operation takes over from the plain JSON Schema.
func TestCheckOpenAPIModes(t *testing.T) {
	e := newTestEngine(t)
	if err := e.SetOpenAPI(testOpenAPI, "enforce"); err != nil {
		t.Fatalf("SetOpenAPI: %v", err)
	}
	// The plain schema would reject every body without "name".
	if err := e.SetRequestSchema(`{"type":"object","required":["name"]}`, "enforce"); err != nil {
		t.Fatal(err)
	}
	check := func(r *http.Request, path string) *Result {
		t.Helper()
		res, err := e.CheckWithOptions(r, "203.0.113.9", CheckOptions{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	r := httptest.NewRequest("GET", "http://x/api/v1/.git/config", nil)
	if res := check(r, "/v1/.git/config"); !res.Blocked || res.Status != 404 || res.Action != "openapi_violation" {
		t.Fatalf("undeclared route = %+v, want 404 openapi_violation", res)
	}
	r = httptest.NewRequest("GET", "http://x/api/v1/users/7", nil)
	if res := check(r, "/v1/users/7"); res.Blocked {
		t.Fatalf("declared route blocked: %+v", res)
	}
	// Without opts.Path the raw /api/... path is outside the spec.
	if res := check(r, ""); !res.Blocked {
		t.Fatalf("unstripped prefix path passed: %+v", res)
	}
	r = jsonRequest(`{"email":"a@b.c"}`)
	r.URL.Path = "/v1/users"
	if res := check(r, ""); res.Blocked {
		t.Fatalf("spec-valid body blocked (plain schema should not apply): %+v", res)
	}

	if err := e.SetOpenAPI(testOpenAPI, "log"); err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest("GET", "http://x/v1/actuator/env", nil)
	if res := check(r, ""); res.Blocked || res.Action != "openapi_violation:log" {
		t.Fatalf("log mode = %+v, want unblocked openapi_violation:log", res)
	}

	if err := e.SetOpenAPI(testOpenAPI, "off"); err != nil || e.openapi != nil {
		t.Fatalf("off did not clear the spec: %v", err)
	}
}

func openAPIWithRoutes(n int) string {
	var b strings.Builder
	b.WriteString(`{"openapi":"3.0.3","paths":{`)
	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"/r%d/{id}/items":{"get":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"integer"}},{"name":"q","in":"query","schema":{"type":"string","maxLength":20}}]}}`, i)
	}
	b.WriteString(`}}`)
	return b.String()
}

// BenchmarkOpenAPICheck measures the per-request cost of a 200-route spec.
func BenchmarkOpenAPICheck(b *testing.B) {
	spec, err := compileOpenAPI(openAPIWithRoutes(200))
	if err != nil {
		b.Fatal(err)
	}
	r := httptest.NewRequest("GET", "http://x/r150/42/items?q=hello", nil)
	b.ReportAllocs()
	for b.Loop() {
		if status, _ := spec.check(r, r.URL.Path, nil, false, true); status != 0 {
			b.Fatalf("status %d", status)
		}
	}
}
