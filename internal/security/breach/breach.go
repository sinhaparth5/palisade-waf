// Package breach checks login passwords against the Have I Been Pwned
// Pwned Passwords range API (issue #188). Only the first 5 hex characters of
// the password's SHA-1 leave the process (k-anonymity); the password and its
// full hash are never stored or logged.
package breach

import (
	"bufio"
	"context"
	"crypto/sha1" //nolint:gosec // the HIBP range API is keyed by SHA-1; not used for security here
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultURL is the public range endpoint; the 5-character prefix is appended.
const DefaultURL = "https://api.pwnedpasswords.com/range/"

const (
	// Timeout bounds the lookup on the request path; past it the login
	// proceeds unchecked (fail open), so an HIBP outage never breaks logins.
	Timeout = 300 * time.Millisecond

	cacheTTL  = 24 * time.Hour
	cacheCap  = 1024 // ~7 KB per prefix
	warnEvery = time.Minute
)

// DefaultFields are the form/JSON keys read as the password when a service
// names none.
var DefaultFields = []string{"password", "passwd", "pass", "pwd"}

type entry struct {
	suffixes []uint64 // first 64 bits of each breached hash suffix, sorted
	exp      time.Time
}

// Checker looks passwords up, caching each prefix's (public) range response.
type Checker struct {
	url    string
	client *http.Client

	mu       sync.Mutex
	cache    map[string]entry
	lastWarn time.Time
}

// New returns a Checker querying baseURL (DefaultURL when empty).
func New(baseURL string) *Checker {
	if baseURL == "" {
		baseURL = DefaultURL
	}
	return &Checker{url: baseURL, client: &http.Client{Timeout: Timeout}, cache: map[string]entry{}}
}

// Leaked reports whether password appears in a known breach. ok is false
// when the lookup failed, in which case the caller lets the login through.
func (c *Checker) Leaked(ctx context.Context, password string) (leaked, ok bool) {
	sum := sha1.Sum([]byte(password)) //nolint:gosec // see import
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix := h[:5]
	want, _ := strconv.ParseUint(h[5:21], 16, 64)

	now := time.Now()
	c.mu.Lock()
	e, hit := c.cache[prefix]
	c.mu.Unlock()
	if !hit || now.After(e.exp) {
		suffixes, err := c.fetch(ctx, prefix)
		if err != nil {
			c.warn(err)
			return false, false
		}
		e = entry{suffixes: suffixes, exp: now.Add(cacheTTL)}
		c.mu.Lock()
		// ponytail: drops the whole cache when full, like the rDNS cache;
		// an LRU if hit rates ever matter.
		if len(c.cache) >= cacheCap {
			clear(c.cache)
		}
		c.cache[prefix] = e
		c.mu.Unlock()
	}
	_, found := slices.BinarySearch(e.suffixes, want)
	return found, true
}

func (c *Checker) fetch(ctx context.Context, prefix string) ([]uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url+prefix, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "Palisade-WAF")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var out []uint64
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		suffix, count, _ := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		// Padding entries carry a count of 0.
		if len(suffix) != 35 || count == "0" || count == "" {
			continue
		}
		if v, err := strconv.ParseUint(suffix[:16], 16, 64); err == nil {
			out = append(out, v)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	slices.Sort(out)
	return out, nil
}

// warn logs a failed lookup at most once per warnEvery, not per login.
func (c *Checker) warn(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.lastWarn) < warnEvery {
		return
	}
	c.lastWarn = time.Now()
	log.Printf("breach check: lookup failed, logins proceed unchecked: %v", err)
}

// Password returns the password a login request carries: HTTP Basic auth
// first, else the first non-empty field of fields (DefaultFields when empty)
// in a form or JSON body. JSON is searched at any depth, so
// {"user":{"password":"…"}} works.
func Password(r *http.Request, body []byte, fields []string) string {
	if len(fields) == 0 {
		fields = DefaultFields
	}
	if _, pw, ok := r.BasicAuth(); ok && pw != "" {
		return pw
	}
	if len(body) == 0 {
		return ""
	}
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch {
	case mt == "application/x-www-form-urlencoded":
		v, err := url.ParseQuery(string(body))
		if err != nil {
			return ""
		}
		for _, f := range fields {
			if pw := v.Get(f); pw != "" {
				return pw
			}
		}
	case mt == "application/json" || strings.HasSuffix(mt, "+json"):
		var v any
		if json.Unmarshal(body, &v) != nil {
			return ""
		}
		for _, f := range fields {
			if pw := findString(v, f, 0); pw != "" {
				return pw
			}
		}
	}
	return ""
}

func findString(v any, key string, depth int) string {
	if depth > 4 {
		return ""
	}
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if strings.EqualFold(k, key) {
				if s, ok := val.(string); ok && s != "" {
					return s
				}
			}
		}
		for _, val := range t {
			if s := findString(val, key, depth+1); s != "" {
				return s
			}
		}
	}
	return ""
}
