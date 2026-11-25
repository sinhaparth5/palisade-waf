package ui

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"
)

func TestSetServiceJWT(t *testing.T) {
	env := newAdminEnv(t)
	svc := env.seedService("api", "api.example.com")
	path := "/admin/api/services/" + itoa(svc.ID) + "/jwt"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	ok := svcJWT{Mode: "enforce", PublicKey: pub, Algorithms: []string{"ES256"}, Prefixes: []string{"/api", " /admin "}, Issuer: "https://idp.test"}
	if rec := env.doJSON(env.session, http.MethodPut, path, ok, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	if env.h.registry.JWT(svc.Name) == nil {
		t.Error("registry not reloaded")
	}
	got, _ := env.db.ListServiceJWT()
	if j := got[svc.ID]; j.Prefixes != "/api\n/admin" || j.Algorithms != "ES256" || j.Issuer != "https://idp.test" {
		t.Errorf("stored %+v", j)
	}

	for _, bad := range []svcJWT{
		{PublicKey: pub, Algorithms: []string{"HS256"}},
		{PublicKey: pub, Algorithms: []string{"none"}},
		{PublicKey: "not a key"},
		{},
		{JWKSURL: "ftp://idp.test/jwks"},
		{PublicKey: pub, Prefixes: []string{"api"}},
	} {
		bad.Mode = "log"
		if rec := env.doJSON(env.session, http.MethodPut, path, bad, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%+v: %d, want 400", bad, rec.Code)
		}
	}
	if got, _ = env.db.ListServiceJWT(); got[svc.ID].Mode != "enforce" {
		t.Error("rejected save changed the policy")
	}

	env.doJSON(env.session, http.MethodPut, path, svcJWT{Mode: "off"}, nil)
	if got, _ = env.db.ListServiceJWT(); len(got) != 0 || env.h.registry.JWT(svc.Name) != nil {
		t.Errorf("off should remove the policy: %+v", got)
	}
}
