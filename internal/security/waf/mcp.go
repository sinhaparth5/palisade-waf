package waf

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// MCPConfig is a service's MCP endpoint guard (issue #234): structural
// checks on a Model Context Protocol Streamable HTTP endpoint. Origins,
// Methods and Tools are allowlists; an empty Methods or Tools list allows
// any, and an empty Origins list allows only the request's own host.
type MCPConfig struct {
	Mode    string // "off" | "log" | "enforce"
	Path    string // endpoint path after the service prefix is stripped, e.g. /mcp
	Origins []string
	Methods []string // JSON-RPC methods; "prefix/*" matches a whole namespace
	Tools   []string // tool names allowed in tools/call
}

type mcpGuard struct {
	path    string
	origins map[string]bool
	methods []string
	tools   map[string]bool
	enforce bool
}

// SetMCP attaches the MCP guard to the engine; mode "off" or an empty path
// removes it.
func (e *Engine) SetMCP(c MCPConfig) {
	if c.Mode != "log" && c.Mode != "enforce" || c.Path == "" {
		e.mcp = nil
		return
	}
	g := &mcpGuard{path: strings.TrimSuffix(c.Path, "/"), origins: map[string]bool{}, methods: c.Methods, enforce: c.Mode == "enforce"}
	if g.path == "" {
		g.path = "/"
	}
	for _, o := range c.Origins {
		g.origins[strings.ToLower(strings.TrimSuffix(o, "/"))] = true
	}
	if len(c.Tools) > 0 {
		g.tools = map[string]bool{}
		for _, t := range c.Tools {
			g.tools[t] = true
		}
	}
	e.mcp = g
}

// check returns 0 when r passes, or the status to reject it with. Requests
// to other paths always pass. A JSON body is always buffered in full here:
// one over noFilesBodyLimit was already refused with 413.
func (g *mcpGuard) check(r *http.Request, path string, body []byte, hadBody bool) int {
	if path != g.path && path != g.path+"/" {
		return 0
	}
	// The spec requires Origin validation against DNS rebinding. Clients
	// that are not browsers send no Origin and pass.
	if o := r.Header.Get("Origin"); o != "" && !g.originOK(o, r.Host) {
		return http.StatusForbidden
	}
	switch r.Method {
	case http.MethodGet, http.MethodDelete, http.MethodOptions:
		return 0 // SSE stream, session end, CORS preflight
	case http.MethodPost:
	default:
		return http.StatusMethodNotAllowed
	}
	if !hadBody || !isJSONMediaType(r.Header.Get("Content-Type")) {
		return http.StatusUnsupportedMediaType
	}
	var msgs []json.RawMessage
	if b := bytes.TrimSpace(body); len(b) > 0 && b[0] == '[' {
		if json.Unmarshal(b, &msgs) != nil || len(msgs) == 0 {
			return http.StatusBadRequest
		}
	} else {
		msgs = []json.RawMessage{b}
	}
	for _, m := range msgs {
		if s := g.message(m); s != 0 {
			return s
		}
	}
	return 0
}

func (g *mcpGuard) originOK(origin, host string) bool {
	if len(g.origins) > 0 {
		return g.origins[strings.ToLower(origin)]
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host != "" && strings.EqualFold(u.Host, host)
}

// message validates one JSON-RPC 2.0 message: a request or notification
// (method set), or a response to a server request (result or error).
func (g *mcpGuard) message(raw json.RawMessage) int {
	var m struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  *string         `json:"method"`
		ID      json.RawMessage `json:"id"`
		Params  json.RawMessage `json:"params"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &m) != nil || m.JSONRPC != "2.0" {
		return http.StatusBadRequest
	}
	// MCP ids are strings or numbers, never null.
	if len(m.ID) > 0 && m.ID[0] != '"' && m.ID[0] != '-' && (m.ID[0] < '0' || m.ID[0] > '9') {
		return http.StatusBadRequest
	}
	if m.Method == nil {
		if len(m.ID) == 0 || (m.Result == nil) == (m.Error == nil) {
			return http.StatusBadRequest
		}
		return 0
	}
	if *m.Method == "" || (len(m.Params) > 0 && m.Params[0] != '{' && m.Params[0] != '[') {
		return http.StatusBadRequest
	}
	if !g.methodOK(*m.Method) {
		return http.StatusForbidden
	}
	if *m.Method == "tools/call" && g.tools != nil {
		var p struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(m.Params, &p) != nil || !g.tools[p.Name] {
			return http.StatusForbidden
		}
	}
	return 0
}

func (g *mcpGuard) methodOK(method string) bool {
	if len(g.methods) == 0 {
		return true
	}
	for _, a := range g.methods {
		if a == method || strings.HasSuffix(a, "/*") && strings.HasPrefix(method, a[:len(a)-1]) {
			return true
		}
	}
	return false
}
