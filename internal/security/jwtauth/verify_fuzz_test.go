package jwtauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// fuzzFamily is one algorithm family with its test key and verifier.
type fuzzFamily struct {
	alg    jose.SignatureAlgorithm // used to sign the seeds
	algs   []string
	priv   crypto.Signer
	pemPub string
	v      *Verifier
}

// FuzzJWTVerify feeds attacker-shaped tokens to Verify (issue #305). Every
// accepted token is re-checked with the standard library, not go-jose: the
// signature is the test key's over header.payload, alg is in the verifier's
// family, exp is present and not past the leeway, and the returned subject
// is the payload's sub. none and HS* can't pass that check.
func FuzzJWTVerify(f *testing.F) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	fams := []*fuzzFamily{
		{alg: jose.RS256, algs: []string{"RS256", "RS384", "RS512"}, priv: rsaKey},
		{alg: jose.PS256, algs: []string{"PS256", "PS384", "PS512"}, priv: rsaKey},
		{alg: jose.ES256, algs: []string{"ES256"}, priv: ecKey},
		{alg: jose.EdDSA, algs: []string{"EdDSA"}, priv: edKey},
	}
	for _, fam := range fams {
		der, err := x509.MarshalPKIXPublicKey(fam.priv.Public())
		if err != nil {
			f.Fatal(err)
		}
		fam.pemPub = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		if fam.v, err = New(Config{Mode: "enforce", PublicKey: fam.pemPub, Algorithms: fam.algs}); err != nil {
			f.Fatal(err)
		}
	}

	now := time.Now()
	seed := func(fam *fuzzFamily, c jwt.Claims) string {
		s, err := jose.NewSigner(jose.SigningKey{Algorithm: fam.alg, Key: fam.priv}, nil)
		if err != nil {
			f.Fatal(err)
		}
		tok, err := jwt.Signed(s).Claims(c).Serialize()
		if err != nil {
			f.Fatal(err)
		}
		return tok
	}
	b64 := base64.RawURLEncoding.EncodeToString
	for i, fam := range fams {
		valid := seed(fam, jwt.Claims{Subject: "user-1", Expiry: jwt.NewNumericDate(now.Add(time.Hour))})
		f.Add(uint8(i), valid)
		f.Add(uint8(i), valid[:len(valid)-5])
		f.Add(uint8(i), seed(fam, jwt.Claims{Subject: "old", Expiry: jwt.NewNumericDate(now.Add(-time.Hour))}))
		f.Add(uint8(i), seed(fam, jwt.Claims{Subject: "no-exp"}))
		payload := b64([]byte(`{"sub":"x","exp":` + big.NewInt(now.Add(time.Hour).Unix()).String() + `}`))
		f.Add(uint8(i), b64([]byte(`{"alg":"none"}`))+"."+payload+".")
		signing := b64([]byte(`{"alg":"HS256"}`)) + "." + payload
		mac := hmac.New(sha256.New, []byte(fam.pemPub)) // the classic key-confusion forgery
		mac.Write([]byte(signing))
		forged := signing + "." + b64(mac.Sum(nil))
		f.Add(uint8(i), forged)

		// The oracle must accept a real token, and Verify must refuse the
		// forgeries, or the target would pass vacuously.
		if sub, err := fam.v.Verify(req(valid)); err != nil || oracle(fam, valid, sub) != "" || sub != "user-1" {
			f.Fatalf("%s: valid token: sub %q, err %v, oracle %q", fam.alg, sub, err, oracle(fam, valid, sub))
		}
		for _, bad := range []string{forged, b64([]byte(`{"alg":"none"}`)) + "." + payload + "."} {
			if _, err := fam.v.Verify(req(bad)); err == nil {
				f.Fatalf("%s: accepted %q", fam.alg, bad)
			}
		}
	}

	f.Fuzz(func(t *testing.T, which uint8, tok string) {
		fam := fams[int(which)%len(fams)]
		sub, err := fam.v.Verify(req(tok))
		if err != nil {
			return
		}
		if why := oracle(fam, strings.TrimSpace(tok), sub); why != "" {
			t.Fatalf("Verify accepted %q (sub %q): %s", tok, sub, why)
		}
	})
}

// oracle independently checks a token Verify accepted, returning why it
// should have been refused ("" when it is genuinely valid).
func oracle(fam *fuzzFamily, tok, sub string) string {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "not three compact parts"
	}
	dec := base64.RawURLEncoding
	hdrJSON, err1 := dec.DecodeString(parts[0])
	payload, err2 := dec.DecodeString(parts[1])
	sig, err3 := dec.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return "not base64url"
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(hdrJSON, &hdr) != nil {
		return "header is not JSON"
	}
	ok := false
	for _, a := range fam.algs {
		ok = ok || hdr.Alg == a
	}
	if !ok {
		return "alg " + hdr.Alg + " outside the family"
	}
	signed := []byte(parts[0] + "." + parts[1])
	hashFor := map[byte]crypto.Hash{'2': crypto.SHA256, '3': crypto.SHA384, '5': crypto.SHA512}
	switch k := fam.priv.Public().(type) {
	case *rsa.PublicKey:
		h := hashFor[hdr.Alg[2]]
		hh := h.New()
		hh.Write(signed)
		if strings.HasPrefix(hdr.Alg, "PS") {
			err1 = rsa.VerifyPSS(k, h, hh.Sum(nil), sig, nil)
		} else {
			err1 = rsa.VerifyPKCS1v15(k, h, hh.Sum(nil), sig)
		}
		if err1 != nil {
			return "bad RSA signature"
		}
	case *ecdsa.PublicKey:
		d := sha256.Sum256(signed)
		if len(sig) != 64 || !ecdsa.Verify(k, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return "bad ECDSA signature"
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(k, signed, sig) {
			return "bad Ed25519 signature"
		}
	}
	var c struct {
		Sub string   `json:"sub"`
		Exp *float64 `json:"exp"`
	}
	if json.Unmarshal(payload, &c) != nil {
		return "payload is not JSON"
	}
	if c.Exp == nil {
		return "no exp"
	}
	if float64(time.Now().Add(-Leeway-time.Second).Unix()) > *c.Exp {
		return "expired"
	}
	if c.Sub != sub {
		return "subject " + sub + " is not the payload's " + c.Sub
	}
	return ""
}
