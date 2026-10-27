package waf

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/kaptinlin/jsonschema"
)

// apiSpec is a compiled OpenAPI 3.x document (issue #190): a positive
// security model where only the operations the spec declares get through.
// Built once per engine build, so a request only walks the route trie.
type apiSpec struct {
	root    *routeNode
	bases   []string // servers[].url paths, longest first, stripped before matching
	enforce bool
}

type routeNode struct {
	static map[string]*routeNode
	param  *routeNode // any one non-empty segment ({id})
	ops    map[string]*apiOperation
}

type apiOperation struct {
	pathParams   []*apiParam // one per param segment, in order; nil = unchecked
	params       []*apiParam // query and header
	hasBody      bool
	bodyRequired bool
	content      map[string]*jsonschema.Schema // media type -> schema (nil = any body)
}

type apiParam struct {
	in, name string
	required bool
	kind     string // the schema's type, for coercing the raw string
	schema   *jsonschema.Schema
}

// componentsURI is the base URI the spec's components.schemas are compiled
// under, so every operation schema can $ref them without a copy.
const componentsURI = "https://palisade.invalid/openapi/components.json"

// ValidateOpenAPI parses an OpenAPI 3.x document (JSON or YAML) without
// attaching it to an engine, so a save handler can reject a bad spec.
func ValidateOpenAPI(spec string) error {
	_, err := compileOpenAPI(spec)
	return err
}

// SetOpenAPI attaches a compiled spec to the engine. mode "enforce" blocks
// undeclared routes (404), methods (405) and bad parameters or bodies (400);
// "log" only marks the request. An empty spec or mode "off" clears it.
func (e *Engine) SetOpenAPI(spec, mode string) error {
	if spec == "" || mode == "off" {
		e.openapi = nil
		return nil
	}
	s, err := compileOpenAPI(spec)
	if err != nil {
		return err
	}
	s.enforce = mode == "enforce"
	e.openapi = s
	return nil
}

func compileOpenAPI(spec string) (*apiSpec, error) {
	raw := []byte(spec)
	if !json.Valid(raw) {
		var err error
		if raw, err = yaml.YAMLToJSON(raw); err != nil {
			return nil, fmt.Errorf("not JSON or YAML: %w", err)
		}
	}
	var doc struct {
		OpenAPI    string                                `json:"openapi"`
		Servers    []struct{ URL string }                `json:"servers"`
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas    map[string]any            `json:"schemas"`
			Parameters map[string]map[string]any `json:"parameters"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse OpenAPI document: %w", err)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.") {
		return nil, errors.New(`only OpenAPI 3.x is supported (the document needs "openapi": "3.x")`)
	}
	if len(doc.Paths) == 0 {
		return nil, errors.New("the document declares no paths")
	}
	nullable := strings.HasPrefix(doc.OpenAPI, "3.0")

	c := jsonschema.NewCompiler()
	defs := map[string]any{"$id": componentsURI, "$defs": fixSchema(doc.Components.Schemas, nullable)}
	defsJSON, _ := json.Marshal(defs)
	if _, err := c.Compile(defsJSON, componentsURI); err != nil {
		return nil, fmt.Errorf("components.schemas: %w", err)
	}
	compile := func(where string, schema any) (*jsonschema.Schema, error) {
		b, _ := json.Marshal(fixSchema(schema, nullable))
		s, err := c.Compile(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		return s, nil
	}
	param := func(where string, p map[string]any) (*apiParam, error) {
		if ref, _ := p["$ref"].(string); ref != "" {
			p = doc.Components.Parameters[strings.TrimPrefix(ref, "#/components/parameters/")]
			if p == nil {
				return nil, fmt.Errorf("%s: unresolved parameter %s", where, ref)
			}
		}
		ap := &apiParam{}
		ap.in, _ = p["in"].(string)
		ap.name, _ = p["name"].(string)
		ap.required, _ = p["required"].(bool)
		if ap.in == "header" {
			ap.name = http.CanonicalHeaderKey(ap.name)
		}
		if schema, ok := p["schema"].(map[string]any); ok {
			ap.kind = schemaKind(schema)
			if ap.kind != "array" && ap.kind != "object" {
				s, err := compile(where+" parameter "+ap.name, schema)
				if err != nil {
					return nil, err
				}
				ap.schema = s
			}
		}
		return ap, nil
	}

	out := &apiSpec{root: &routeNode{}}
	for _, srv := range doc.Servers {
		if u, err := url.Parse(srv.URL); err == nil {
			if base := strings.TrimRight(u.Path, "/"); base != "" && !slices.Contains(out.bases, base) {
				out.bases = append(out.bases, base)
			}
		}
	}
	slices.SortFunc(out.bases, func(a, b string) int { return len(b) - len(a) })

	for path, item := range doc.Paths {
		if !strings.HasPrefix(path, "/") {
			return nil, fmt.Errorf("path %q must start with /", path)
		}
		var shared []map[string]any
		if raw, ok := item["parameters"]; ok {
			if err := json.Unmarshal(raw, &shared); err != nil {
				return nil, fmt.Errorf("%s parameters: %w", path, err)
			}
		}
		node := out.root
		var segParams []string // the {name} of each param segment, "" when not a plain {name}
		for _, seg := range splitPath(path) {
			if strings.Contains(seg, "{") {
				// ponytail: "{id}.json"-style segments match any segment unchecked
				name := ""
				if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
					name = seg[1 : len(seg)-1]
				}
				segParams = append(segParams, name)
				if node.param == nil {
					node.param = &routeNode{}
				}
				node = node.param
				continue
			}
			if node.static == nil {
				node.static = map[string]*routeNode{}
			}
			if node.static[seg] == nil {
				node.static[seg] = &routeNode{}
			}
			node = node.static[seg]
		}
		for method, raw := range item {
			method = strings.ToUpper(method)
			switch method {
			case "GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE":
			default:
				continue // parameters, summary, servers, x-...
			}
			var o struct {
				Parameters  []map[string]any `json:"parameters"`
				RequestBody *struct {
					Ref      string `json:"$ref"`
					Required bool   `json:"required"`
					Content  map[string]struct {
						Schema any `json:"schema"`
					} `json:"content"`
				} `json:"requestBody"`
			}
			if err := json.Unmarshal(raw, &o); err != nil {
				return nil, fmt.Errorf("%s %s: %w", method, path, err)
			}
			where := method + " " + path
			op := &apiOperation{pathParams: make([]*apiParam, len(segParams))}
			// Operation parameters override path-level ones with the same in+name.
			byKey := map[string]*apiParam{}
			var order []string
			for _, p := range append(slices.Clone(shared), o.Parameters...) {
				ap, err := param(where, p)
				if err != nil {
					return nil, err
				}
				key := ap.in + "\x00" + ap.name
				if byKey[key] == nil {
					order = append(order, key)
				}
				byKey[key] = ap
			}
			for _, key := range order {
				ap := byKey[key]
				switch ap.in {
				case "path":
					if i := slices.Index(segParams, ap.name); i >= 0 {
						op.pathParams[i] = ap
					}
				case "query", "header":
					// The spec says these three are ignored as parameters.
					if ap.in == "header" && (ap.name == "Accept" || ap.name == "Content-Type" || ap.name == "Authorization") {
						continue
					}
					op.params = append(op.params, ap)
				}
			}
			if rb := o.RequestBody; rb != nil {
				if rb.Ref != "" {
					return nil, fmt.Errorf("%s: requestBody $ref is not supported, inline it", where)
				}
				op.hasBody, op.bodyRequired = true, rb.Required
				op.content = map[string]*jsonschema.Schema{}
				for mt, media := range rb.Content {
					mt = normalizedMediaType(mt)
					op.content[mt] = nil
					if media.Schema != nil && isJSONMediaType(mt) {
						s, err := compile(where+" requestBody "+mt, media.Schema)
						if err != nil {
							return nil, err
						}
						op.content[mt] = s
					}
				}
			}
			if node.ops == nil {
				node.ops = map[string]*apiOperation{}
			}
			node.ops[method] = op
		}
	}
	return out, nil
}

// fixSchema rewrites an OpenAPI schema into plain JSON Schema: component
// refs point at the shared components document, and 3.0's nullable and
// boolean exclusiveMinimum/Maximum become their 2020-12 spellings.
func fixSchema(v any, nullable bool) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = fixSchema(val, nullable)
		}
		if ref, ok := out["$ref"].(string); ok {
			if name, ok := strings.CutPrefix(ref, "#/components/schemas/"); ok {
				out["$ref"] = componentsURI + "#/$defs/" + name
			}
		}
		if nullable {
			if n, _ := out["nullable"].(bool); n {
				if typ, ok := out["type"].(string); ok {
					out["type"] = []any{typ, "null"}
				}
			}
			delete(out, "nullable")
			for _, b := range [][2]string{{"exclusiveMinimum", "minimum"}, {"exclusiveMaximum", "maximum"}} {
				if ex, ok := out[b[0]].(bool); ok {
					delete(out, b[0])
					if ex && out[b[1]] != nil {
						out[b[0]] = out[b[1]]
						delete(out, b[1])
					}
				}
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = fixSchema(val, nullable)
		}
		return out
	}
	return v
}

// schemaKind is the schema's non-null type, "" when it has none.
func schemaKind(schema map[string]any) string {
	switch t := schema["type"].(type) {
	case string:
		return t
	case []any:
		for _, v := range t {
			if s, _ := v.(string); s != "null" {
				return s
			}
		}
	}
	return ""
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// match walks the trie, preferring a literal segment over a template one
// (/users/me before /users/{id}), and returns the param segment values.
func (n *routeNode) match(segs, vals []string) (*routeNode, []string) {
	if len(segs) == 0 {
		if n.ops != nil {
			return n, vals
		}
		return nil, nil
	}
	if c := n.static[segs[0]]; c != nil {
		if m, v := c.match(segs[1:], vals); m != nil {
			return m, v
		}
	}
	if n.param != nil && segs[0] != "" {
		return n.param.match(segs[1:], append(vals, segs[0]))
	}
	return nil, nil
}

// check returns the status an undeclared or invalid request gets (0 when
// it conforms) and whether the spec declares its operation. path is the
// request path as the backend sees it, after any service prefix is
// stripped. Trailing slashes are ignored. body is only validated when it
// was buffered in full.
func (s *apiSpec) check(r *http.Request, path string, body []byte, hadBody, buffered bool) (status int, declared bool) {
	for _, base := range s.bases {
		if rest, ok := strings.CutPrefix(path, base); ok && (rest == "" || rest[0] == '/') {
			path = rest
			break
		}
	}
	node, vals := s.root.match(splitPath(path), nil)
	if node == nil {
		return http.StatusNotFound, false
	}
	op := node.ops[r.Method]
	if op == nil && r.Method == http.MethodHead {
		op = node.ops[http.MethodGet]
	}
	if op == nil {
		// CORS preflights are answered by the backend, never declared.
		if r.Method == http.MethodOptions {
			return 0, false
		}
		return http.StatusMethodNotAllowed, false
	}
	for i, p := range op.pathParams {
		if p != nil && !p.valid(vals[i]) {
			return http.StatusBadRequest, true
		}
	}
	var query url.Values
	for _, p := range op.params {
		var v string
		var ok bool
		if p.in == "header" {
			vs := r.Header.Values(p.name)
			ok = len(vs) > 0
			if ok {
				v = vs[0]
			}
		} else {
			if query == nil {
				query = r.URL.Query()
			}
			ok = query.Has(p.name)
			v = query.Get(p.name)
		}
		if !ok {
			if p.required {
				return http.StatusBadRequest, true
			}
			continue
		}
		if !p.valid(v) {
			return http.StatusBadRequest, true
		}
	}
	if !op.hasBody {
		return 0, true
	}
	if !hadBody || (buffered && len(body) == 0) {
		if op.bodyRequired {
			return http.StatusBadRequest, true
		}
		return 0, true
	}
	if len(op.content) == 0 {
		return 0, true
	}
	mt := normalizedMediaType(r.Header.Get("Content-Type"))
	schema, ok := op.content[mt]
	if !ok {
		if major, _, found := strings.Cut(mt, "/"); found {
			schema, ok = op.content[major+"/*"]
		}
	}
	if !ok {
		schema, ok = op.content["*/*"]
	}
	if !ok {
		return http.StatusUnsupportedMediaType, true
	}
	if schema != nil && buffered && isJSONMediaType(mt) && !schema.ValidateJSON(body).IsValid() {
		return http.StatusBadRequest, true
	}
	return 0, true
}

// valid checks one raw parameter string against its schema, read as the
// type the schema declares. Arrays and objects are only checked for presence.
func (p *apiParam) valid(v string) bool {
	if p.schema == nil {
		return true
	}
	var val any = v
	switch p.kind {
	case "integer", "number":
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			val = f
		}
	case "boolean":
		if v == "true" || v == "false" {
			val = v == "true"
		}
	}
	return p.schema.Validate(val).IsValid()
}
