package jwtauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sign(t *testing.T, alg jose.SignatureAlgorithm, key any, kid string, c jwt.Claims) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Signed(s).Claims(c).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func req(tok string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	return r
}

func claims(mod func(*jwt.Claims)) jwt.Claims {
	now := time.Now()
	c := jwt.Claims{Subject: "user-1", Issuer: "https://idp.test", Audience: jwt.Audience{"api"},
		Expiry: jwt.NewNumericDate(now.Add(time.Hour)), IssuedAt: jwt.NewNumericDate(now)}
	if mod != nil {
		mod(&c)
	}
	return c
}

func TestStaticKey(t *testing.T) {
	key := newKey(t)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	v, err := New(Config{Mode: "enforce", PublicKey: pemKey, Issuer: "https://idp.test", Audience: "api"})
	if err != nil {
		t.Fatal(err)
	}
	other := newKey(t)
	for name, tc := range map[string]struct {
		tok string
		ok  bool
	}{
		"valid":          {sign(t, jose.ES256, key, "", claims(nil)), true},
		"missing":        {"", false},
		"wrong key":      {sign(t, jose.ES256, other, "", claims(nil)), false},
		"expired":        {sign(t, jose.ES256, key, "", claims(func(c *jwt.Claims) { c.Expiry = jwt.NewNumericDate(time.Now().Add(-2 * Leeway)) })), false},
		"no exp":         {sign(t, jose.ES256, key, "", claims(func(c *jwt.Claims) { c.Expiry = nil })), false},
		"wrong issuer":   {sign(t, jose.ES256, key, "", claims(func(c *jwt.Claims) { c.Issuer = "https://evil.test" })), false},
		"wrong audience": {sign(t, jose.ES256, key, "", claims(func(c *jwt.Claims) { c.Audience = jwt.Audience{"other"} })), false},
		"not yet valid":  {sign(t, jose.ES256, key, "", claims(func(c *jwt.Claims) { c.NotBefore = jwt.NewNumericDate(time.Now().Add(2 * Leeway)) })), false},
		// Algorithm confusion: HS256 keyed with the public key's bytes.
		"hs256 with public key": {sign(t, jose.HS256, []byte(pemKey), "", claims(nil)), false},
		"unsigned":              {"eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.", false},
	} {
		sub, err := v.Verify(req(tc.tok))
		if (err == nil) != tc.ok || (tc.ok && sub != "user-1") {
			t.Errorf("%s: sub=%q err=%v, want ok=%v", name, sub, err, tc.ok)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no key":       {Mode: "enforce"},
		"both keys":    {JWKSURL: "https://idp.test/jwks", PublicKey: "x"},
		"bad pem":      {PublicKey: "not pem"},
		"hs256":        {JWKSURL: "https://idp.test/jwks", Algorithms: []string{"HS256"}},
		"none":         {JWKSURL: "https://idp.test/jwks", Algorithms: []string{"none"}},
		"relative url": {JWKSURL: "/jwks"},
		"bad prefix":   {JWKSURL: "https://idp.test/jwks", Prefixes: []string{"api"}},
		"file scheme":  {JWKSURL: "file:///etc/passwd"},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestProtects(t *testing.T) {
	v := &Verifier{cfg: Config{Prefixes: []string{"/api", "/admin/"}}}
	for path, want := range map[string]bool{
		"/api": true, "/api/x": true, "/apix": false, "/admin/y": true, "/": false, "/public": false,
	} {
		if v.Protects(path) != want {
			t.Errorf("Protects(%q) != %v", path, want)
		}
	}
	if !(&Verifier{}).Protects("/anything") {
		t.Error("no prefixes must protect every path")
	}
}

// TestJWKSRotation: a token with a kid the cached set lacks triggers one
// background refetch; after it lands the new key verifies.
func TestJWKSRotation(t *testing.T) {
	defer func(g time.Duration) { jwksMinGap = g }(jwksMinGap)
	jwksMinGap = 0

	k1, k2 := newKey(t), newKey(t)
	var current atomic.Value
	current.Store([]jose.JSONWebKey{{Key: &k1.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}})
	var fetches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: current.Load().([]jose.JSONWebKey)})
	}))
	defer srv.Close()

	v, err := New(Config{Mode: "enforce", JWKSURL: srv.URL + "/jwks", Algorithms: []string{"ES256"}})
	if err != nil {
		t.Fatal(err)
	}
	eventually := func(tok string) error {
		var err error
		for range 50 {
			if _, err = v.Verify(req(tok)); err == nil {
				return nil
			}
			time.Sleep(20 * time.Millisecond)
		}
		return err
	}
	if err := eventually(sign(t, jose.ES256, k1, "k1", claims(nil))); err != nil {
		t.Fatalf("k1 never verified: %v", err)
	}
	current.Store([]jose.JSONWebKey{{Key: &k2.PublicKey, KeyID: "k2", Algorithm: "ES256", Use: "sig"}})
	if err := eventually(sign(t, jose.ES256, k2, "k2", claims(nil))); err != nil {
		t.Fatalf("rotated key k2 never verified: %v", err)
	}
	if _, err := v.Verify(req(sign(t, jose.ES256, k2, "k1", claims(nil)))); err == nil {
		t.Error("token signed by k2 but naming k1 verified")
	}
	if n := fetches.Load(); n < 2 || n > 60 {
		t.Errorf("fetches = %d", n)
	}
}
