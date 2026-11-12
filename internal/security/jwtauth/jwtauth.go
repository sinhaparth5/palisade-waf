// Package jwtauth verifies bearer JWTs at the edge, per service (issue #279),
// so requests with a missing, forged or expired token never reach a backend
// that authenticates with them.
//
// Only asymmetric algorithms are accepted: keys come from a JWKS URL or a
// static PEM public key, and "none" and the HS* family can't be configured,
// so a public key can never be turned into an HMAC secret.
package jwtauth

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"palisade/internal/security/egress"
)

// SubjectHeader carries the verified "sub" claim to the backend. Client
// copies are always stripped on a service with a JWT policy.
const SubjectHeader = "X-Auth-Subject"

// Leeway is the clock skew allowed on exp, nbf and iat.
const Leeway = time.Minute

// asymmetric lists every algorithm a policy may allow.
var asymmetric = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// Config is one service's policy, as stored in service_jwt.
type Config struct {
	Mode       string   // "log" or "enforce"
	JWKSURL    string   // keys by kid; or
	PublicKey  string   // one PEM public key
	Issuer     string   // required "iss", "" = any
	Audience   string   // required "aud" entry, "" = any
	Algorithms []string // allowed "alg" values, empty = every asymmetric one
	Prefixes   []string // protected paths after the service prefix, empty = all
}

// Verifier checks tokens for one service.
type Verifier struct {
	cfg    Config
	algs   []jose.SignatureAlgorithm
	static any
	jwks   *keySet
}

// New validates cfg and returns its verifier. With a JWKS URL it also starts
// fetching the key set in the background.
func New(cfg Config) (*Verifier, error) {
	v := &Verifier{cfg: cfg}
	for _, a := range cfg.Algorithms {
		alg := jose.SignatureAlgorithm(a)
		ok := false
		for _, allowed := range asymmetric {
			ok = ok || alg == allowed
		}
		if !ok {
			return nil, fmt.Errorf("algorithm %q is not allowed: use RS*, PS*, ES* or EdDSA", a)
		}
		v.algs = append(v.algs, alg)
	}
	if len(v.algs) == 0 {
		v.algs = asymmetric
	}
	for _, p := range cfg.Prefixes {
		if !strings.HasPrefix(p, "/") {
			return nil, fmt.Errorf("protected path %q must start with /", p)
		}
	}
	switch {
	case cfg.JWKSURL != "" && cfg.PublicKey != "":
		return nil, errors.New("set a JWKS URL or a public key, not both")
	case cfg.JWKSURL != "":
		u, err := url.Parse(cfg.JWKSURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return nil, errors.New("the JWKS URL must be an absolute http(s) URL")
		}
		v.jwks = keySetFor(cfg.JWKSURL)
		v.jwks.refresh(false)
	case cfg.PublicKey != "":
		block, _ := pem.Decode([]byte(cfg.PublicKey))
		if block == nil {
			return nil, errors.New("the public key is not PEM")
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("the public key: %w", err)
		}
		v.static = key
	default:
		return nil, errors.New("set a JWKS URL or a public key")
	}
	return v, nil
}

// Enforce reports whether a failed check should answer 401.
func (v *Verifier) Enforce() bool { return v.cfg.Mode == "enforce" }

// Protects reports whether path (service prefix stripped) needs a token.
func (v *Verifier) Protects(path string) bool {
	if len(v.cfg.Prefixes) == 0 {
		return true
	}
	for _, p := range v.cfg.Prefixes {
		if p == "/" || path == p || strings.HasPrefix(path, strings.TrimSuffix(p, "/")+"/") {
			return true
		}
	}
	return false
}

// Verify checks r's bearer token and returns its "sub" claim.
func (v *Verifier) Verify(r *http.Request) (string, error) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || raw == "" {
		return "", errors.New("missing bearer token")
	}
	tok, err := jwt.ParseSigned(strings.TrimSpace(raw), v.algs)
	if err != nil {
		return "", err
	}
	if len(tok.Headers) != 1 {
		return "", errors.New("token must have exactly one signature")
	}
	key := v.static
	if v.jwks != nil {
		k, err := v.jwks.key(tok.Headers[0].KeyID, tok.Headers[0].Algorithm)
		if err != nil {
			return "", err
		}
		key = k
	}
	var c jwt.Claims
	if err := tok.Claims(key, &c); err != nil {
		return "", err
	}
	if c.Expiry == nil {
		return "", errors.New("token has no exp")
	}
	want := jwt.Expected{Issuer: v.cfg.Issuer, Time: time.Now()}
	if v.cfg.Audience != "" {
		want.AnyAudience = jwt.Audience{v.cfg.Audience}
	}
	if err := c.ValidateWithLeeway(want, Leeway); err != nil {
		return "", err
	}
	return c.Subject, nil
}

// ── JWKS cache ──────────────────────────────────────────────────────────────

const (
	jwksTTL      = time.Hour // refetch a key set this old on use
	jwksMaxBytes = 256 << 10
)

// jwksMinGap allows at most one fetch per URL per gap for unknown kids. A
// variable so tests can drop it.
var jwksMinGap = 30 * time.Second

var jwksClient = egress.Client(5 * time.Second)

// keySet is one URL's keys, shared by every service using that URL and kept
// across registry reloads.
type keySet struct {
	url string

	mu       sync.Mutex
	set      *jose.JSONWebKeySet
	fetched  time.Time // last successful fetch
	tried    time.Time // last attempt
	fetching bool
}

var (
	setsMu sync.Mutex
	sets   = map[string]*keySet{}
)

func keySetFor(u string) *keySet {
	setsMu.Lock()
	defer setsMu.Unlock()
	if s, ok := sets[u]; ok {
		return s
	}
	s := &keySet{url: u}
	sets[u] = s
	return s
}

// key returns the public key for kid. It never blocks on the network: a
// missing kid or stale set starts a background fetch (rate-limited) and this
// request fails, so a token with a random kid can't make Palisade hammer the
// issuer.
func (s *keySet) key(kid, alg string) (any, error) {
	s.mu.Lock()
	set, stale := s.set, time.Since(s.fetched) > jwksTTL
	s.mu.Unlock()
	if set != nil {
		for _, k := range set.Keys {
			if k.KeyID == kid && k.IsPublic() && (k.Algorithm == "" || k.Algorithm == alg) && (k.Use == "" || k.Use == "sig") {
				if stale {
					s.refresh(false)
				}
				return k.Key, nil
			}
		}
	}
	s.refresh(true)
	if set == nil {
		return nil, errors.New("JWKS not loaded yet")
	}
	return nil, fmt.Errorf("no key %q in the JWKS", kid)
}

// refresh fetches the set in the background unless one is running or, when
// limited, the last attempt was under jwksMinGap ago.
func (s *keySet) refresh(limited bool) {
	s.mu.Lock()
	if s.fetching || (limited && time.Since(s.tried) < jwksMinGap) {
		s.mu.Unlock()
		return
	}
	s.fetching, s.tried = true, time.Now()
	s.mu.Unlock()
	go func() {
		set, err := fetchJWKS(s.url)
		s.mu.Lock()
		defer s.mu.Unlock()
		s.fetching = false
		if err != nil {
			log.Printf("jwt: fetch %s: %v", s.url, err)
			return
		}
		s.set, s.fetched = set, time.Now()
	}()
}

func fetchJWKS(u string) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := jwksClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxBytes))
	if err != nil {
		return nil, err
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, err
	}
	return &set, nil
}
