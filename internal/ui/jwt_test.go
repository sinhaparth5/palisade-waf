package ui

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestSetServiceJWT(t *testing.T) {
	env := newAdminEnv(t)
	svc := env.seedService("api", "api.example.com")
	path := "/admin/services/jwt/" + itoa(svc.ID)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	rec := env.do("POST", path, form("jwt_mode", "enforce", "jwt_public_key", pub, "jwt_algorithms", "ES256",
		"jwt_prefixes", "/api\r\n/admin", "jwt_issuer", "https://idp.test"))
	wantCode(t, "save", rec.Code, 200, rec.Body.String())
	if rec.Header().Get("HX-Trigger") != "jwt-saved" || !strings.Contains(rec.Body.String(), "JWT: enforce") {
		t.Fatalf("no jwt-saved trigger or badge: %s", rec.Body)
	}
	if env.h.registry.JWT(svc.Name) == nil {
		t.Error("registry not reloaded")
	}
	got, _ := env.db.ListServiceJWT()
	if j := got[svc.ID]; j.Prefixes != "/api\n/admin" || j.Algorithms != "ES256" || j.Issuer != "https://idp.test" {
		t.Errorf("stored %+v", j)
	}

	for _, bad := range [][]string{
		{"jwt_public_key", pub, "jwt_algorithms", "HS256"},
		{"jwt_public_key", pub, "jwt_algorithms", "none"},
		{"jwt_public_key", "not a key"},
		{},
		{"jwt_jwks_url", "ftp://idp.test/jwks"},
		{"jwt_public_key", pub, "jwt_prefixes", "api"},
	} {
		rec = env.do("POST", path, form(append([]string{"jwt_mode", "log"}, bad...)...))
		if rec.Header().Get("HX-Retarget") != "#svc-jwt-error" {
			t.Errorf("%v: want inline error, got %s", bad, rec.Body)
		}
	}
	if got, _ = env.db.ListServiceJWT(); got[svc.ID].Mode != "enforce" {
		t.Error("rejected save changed the policy")
	}

	env.do("POST", path, form("jwt_mode", "off"))
	if got, _ = env.db.ListServiceJWT(); len(got) != 0 || env.h.registry.JWT(svc.Name) != nil {
		t.Errorf("off should remove the policy: %+v", got)
	}
}
