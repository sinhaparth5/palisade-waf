package waf

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// ResponseInspectLimit caps how much of a response body is buffered for
// outbound inspection (issue #192). A bigger body streams through unread.
// ponytail: CRS's outbound regexes cost ~0.55ms per KiB (BENCHMARKS.md), so
// this stays small: leaked errors and stack traces are short.
const ResponseInspectLimit = 64 << 10

// responseDirectives switch on Coraza's response body for the outbound CRS
// rules. Nothing reads a response unless CheckResponse is called, which the
// proxy only does for services that opted in, so every other request pays
// nothing for it.
var responseDirectives = `
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html text/xml application/json application/xml
SecResponseBodyLimit ` + strconv.Itoa(ResponseInspectLimit) + `
SecResponseBodyLimitAction ProcessPartial
`

// inspectableResponse reports whether resp's body may be buffered: a text
// body (never binary, never SSE) that is identity-encoded and not an upgrade.
// Compressed bodies are skipped, not decoded; the proxy asks the backend for
// identity encoding on inspected services, so only a backend that compresses
// regardless gets past uninspected.
func inspectableResponse(resp *http.Response) bool {
	if resp.StatusCode == http.StatusSwitchingProtocols || resp.StatusCode == http.StatusNoContent ||
		resp.StatusCode == http.StatusNotModified || resp.Body == nil || resp.Body == http.NoBody ||
		(resp.Request != nil && resp.Request.Method == http.MethodHead) ||
		resp.ContentLength > ResponseInspectLimit {
		return false
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		return false
	}
	switch normalizedMediaType(resp.Header.Get("Content-Type")) {
	case "text/html", "text/plain", "text/xml", "application/json", "application/xml":
		return true
	}
	return false
}

// CheckResponse runs CRS's outbound rules over a backend response to r and
// returns the id of the first leak rule that matched (950000–958999: data
// leakage, SQL/Java/PHP/IIS/Ruby errors, web shells), or 0. Only rules with
// the CRS paranoia level in force run, so rule exceptions and the level
// apply as on the request side. Only the leak
// rules count, not CRS's outbound anomaly score, so the caller decides what
// a match means and log mode reports the same rule block mode would.
//
// The body is buffered up to ResponseInspectLimit and always restored, so
// the response forwards byte for byte. A response over the limit, or one
// that isn't inspectable, is left unread and returns 0.
//
// The request's own transaction is long gone by now (the verdict cache may
// not even have run one), so this is a fresh transaction that replays the
// request line and headers through phase 1, which is what initialises CRS's
// settings for the outbound phases.
func (e *Engine) CheckResponse(r *http.Request, clientIP string, resp *http.Response) int {
	if !e.enabled || !inspectableResponse(resp) {
		return 0
	}
	orig := resp.Body
	body, err := io.ReadAll(io.LimitReader(orig, ResponseInspectLimit+1))
	resp.Body = &bodyReplay{Reader: io.MultiReader(bytes.NewReader(body), orig), Closer: orig}
	if err != nil || len(body) > ResponseInspectLimit {
		return 0
	}

	tx := e.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()
	tx.ProcessConnection(clientIP, 0, "", 0)
	tx.ProcessURI(r.RequestURI, r.Method, r.Proto)
	for name, vals := range r.Header {
		for _, v := range vals {
			tx.AddRequestHeader(name, v)
		}
	}
	tx.AddRequestHeader("Host", r.Host)
	tx.ProcessRequestHeaders() // already passed; run for CRS's phase 1 setup
	for name, vals := range resp.Header {
		for _, v := range vals {
			tx.AddResponseHeader(name, v)
		}
	}
	tx.ProcessResponseHeaders(resp.StatusCode, resp.Proto)
	if _, _, err := tx.WriteResponseBody(body); err == nil {
		_, _ = tx.ProcessResponseBody()
	}
	for _, m := range tx.MatchedRules() {
		// Detection rules carry a msg; CRS's flow rules (paranoia-level
		// gates, "no SQL error here" skips) don't, but still "match".
		if id := m.Rule().ID(); id >= 950000 && id < 959000 && m.Message() != "" {
			return id
		}
	}
	return 0
}
