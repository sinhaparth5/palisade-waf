package ui

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"palisade/internal/storage"
)

// TestServicesJSONCache: the cache tab saves in one go, and purge needs
// Varnish on and a safe path.
func TestServicesJSONCache(t *testing.T) {
	env := newAdminEnv(t)
	svc := "/admin/api/services/" + itoa(env.seedService("shop", "shop.example.com").ID)
	for _, tc := range []struct {
		body  map[string]any
		field string
	}{
		{map[string]any{"by_session": true}, "session_cookie"},
		{map[string]any{"ttl_floor": -1}, "ttl_floor"},
		{map[string]any{"ttl_floor": 100, "ttl_ceiling": 50}, "ttl_floor"},
		{map[string]any{"rules": "keep /assets/"}, "rules"},
	} {
		var got jsonError
		if rec := env.doJSON(env.session, http.MethodPut, svc+"/cache", tc.body, &got); rec.Code != http.StatusBadRequest || got.Fields[tc.field] == "" {
			t.Errorf("%v: %d %s, want a %s error", tc.body, rec.Code, rec.Body, tc.field)
		}
	}
	ok := map[string]any{"enabled": true, "by_session": true, "session_cookie": " sid ", "ttl_floor": 60, "ttl_ceiling": 600, "grace": 10, "rules": "cache /assets/", "compress": true}
	if rec := env.doJSON(env.session, http.MethodPut, svc+"/cache", ok, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	s := env.services(t, env.session)[0]
	if s.Cache != (svcCache{true, true, "sid", 60, 600, 10, 0, "cache /assets/"}) || !s.Compress {
		t.Errorf("cache = %+v compress %v", s.Cache, s.Compress)
	}

	if rec := env.doJSON(env.session, http.MethodPost, svc+"/purge", map[string]string{}, nil); rec.Code != http.StatusConflict {
		t.Errorf("purge with varnish off: %d", rec.Code)
	}
	var purged string
	varnish := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { purged = r.Header.Get("X-Cache-Purge-Url") }))
	defer varnish.Close()
	if err := env.db.SetVarnishConfig(storage.VarnishConfig{Enabled: true, Addr: strings.TrimPrefix(varnish.URL, "http://")}); err != nil {
		t.Fatal(err)
	}
	var got jsonError
	if rec := env.doJSON(env.session, http.MethodPost, svc+"/purge", map[string]string{"path": "/a && obj.status"}, &got); rec.Code != http.StatusBadRequest || got.Fields["path"] == "" {
		t.Errorf("unsafe purge path: %d %s", rec.Code, rec.Body)
	}
	if rec := env.doJSON(env.session, http.MethodPost, svc+"/purge", map[string]string{"path": "/assets/"}, nil); rec.Code != http.StatusNoContent || purged != "^/assets/" {
		t.Errorf("purge: %d %s, varnish got %q", rec.Code, rec.Body, purged)
	}
	varnish.Close()
	if rec := env.doJSON(env.session, http.MethodPost, svc+"/purge", map[string]string{}, nil); rec.Code != http.StatusBadGateway {
		t.Errorf("purge with varnish down: %d", rec.Code)
	}
}

// TestServicesJSONTLS: pool, upload, auto with the ACME email, clear,
// HTTP/3 and client certificates, all on host-matched services only.
func TestServicesJSONTLS(t *testing.T) {
	t.Chdir(t.TempDir()) // cert files are written relative to the working directory
	env := newAdminEnv(t)
	host := env.seedService("shop", "shop.example.com")
	if err := env.db.AddService("api", "", "/api", env.backend.URL, 0, 0); err != nil {
		t.Fatal(err)
	}
	var prefixID int
	svcs, _ := env.db.ListServices()
	for _, s := range svcs {
		if s.Name == "api" {
			prefixID = s.ID
		}
	}
	svc := "/admin/api/services/" + itoa(host.ID)
	certPEM, keyPEM := testCertPEM(t, "shop.example.com")
	otherCert, otherKey := testCertPEM(t, "other.example.com")
	for _, r := range []certAddRequest{{"shop", certPEM, keyPEM}, {"other", otherCert, otherKey}} {
		if rec := env.doJSON(env.session, http.MethodPost, "/admin/api/certificates", r, nil); rec.Code != http.StatusCreated {
			t.Fatalf("add cert: %d %s", rec.Code, rec.Body)
		}
	}
	certs, _ := env.db.ListCertificates()
	poolID := func(name string) int64 {
		for _, c := range certs {
			if c.Name == name {
				return c.ID
			}
		}
		t.Fatalf("no pool cert %s", name)
		return 0
	}

	for _, p := range []string{"/tls", "/http3", "/mtls"} {
		if rec := env.doJSON(env.session, http.MethodPut, "/admin/api/services/"+itoa(prefixID)+p, map[string]any{"mode": "none"}, nil); rec.Code != http.StatusConflict {
			t.Errorf("prefix service %s: %d", p, rec.Code)
		}
	}
	for _, tc := range []struct {
		body  map[string]any
		field string
	}{
		{map[string]any{"mode": "pool", "cert_id": 99999}, "cert_id"},
		{map[string]any{"mode": "pool", "cert_id": poolID("other")}, "cert_id"},
		{map[string]any{"mode": "custom"}, "cert_pem"},
		{map[string]any{"mode": "custom", "cert_pem": otherCert, "key_pem": otherKey}, "cert_pem"},
		{map[string]any{"mode": "custom", "cert_pem": certPEM, "key_pem": otherKey}, "key_pem"},
		{map[string]any{"mode": "auto"}, "acme_email"},
		{map[string]any{"mode": "auto", "acme_email": "nope"}, "acme_email"},
		{map[string]any{"mode": "sometimes"}, "mode"},
	} {
		var got jsonError
		if rec := env.doJSON(env.session, http.MethodPut, svc+"/tls", tc.body, &got); rec.Code != http.StatusBadRequest || got.Fields[tc.field] == "" {
			t.Errorf("%v: %d %s, want a %s error", tc.body, rec.Code, rec.Body, tc.field)
		}
	}
	tlsNow := func() svcTLS { return env.services(t, env.session)[0].TLS }
	save := func(body map[string]any) {
		t.Helper()
		if rec := env.doJSON(env.session, http.MethodPut, svc+"/tls", body, nil); rec.Code != http.StatusNoContent {
			t.Fatalf("%v: %d %s", body, rec.Code, rec.Body)
		}
	}
	save(map[string]any{"mode": "pool", "cert_id": poolID("shop")})
	if got := tlsNow(); got.CertID != poolID("shop") || got.CertName != "shop" {
		t.Errorf("pool = %+v", got)
	}
	save(map[string]any{"mode": "custom", "cert_pem": certPEM, "key_pem": keyPEM})
	if got := tlsNow(); got.Mode != "custom" || got.CertID != 0 || got.ExpiresAt == "" {
		t.Errorf("custom = %+v", got)
	}
	if _, err := os.Stat(filepath.Join("certs", "services", "by-id", itoa(host.ID), "key.pem")); err != nil {
		t.Errorf("custom cert dir: %v", err)
	}
	save(map[string]any{"mode": "auto", "acme_email": "ops@example.com"})
	if email, _ := env.db.GetAcmeEmail(); email != "ops@example.com" || tlsNow().Mode != "auto" {
		t.Errorf("auto: email %q, tls %+v", email, tlsNow())
	}
	save(map[string]any{"mode": "none"})
	save(map[string]any{"mode": "auto"}) // the stored email is enough now
	save(map[string]any{"mode": "none"})
	if got := tlsNow(); got.Mode != "" {
		t.Errorf("after clear = %+v", got)
	}

	if rec := env.doJSON(env.session, http.MethodPut, svc+"/http3", map[string]bool{"enabled": true}, nil); rec.Code != http.StatusNoContent || !tlsNow().HTTP3 {
		t.Errorf("http3: %d %+v", rec.Code, tlsNow())
	}

	// Client certificates.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	for _, tc := range []struct {
		body  map[string]any
		field string
	}{
		{map[string]any{"mode": "required"}, "ca"},
		{map[string]any{"mode": "required", "ca": certPEM}, "ca"}, // a leaf, not a CA
		{map[string]any{"mode": "always"}, "mode"},
	} {
		var got jsonError
		if rec := env.doJSON(env.session, http.MethodPut, svc+"/mtls", tc.body, &got); rec.Code != http.StatusBadRequest || got.Fields[tc.field] == "" {
			t.Errorf("mtls %v: %d %s, want a %s error", tc.body, rec.Code, rec.Body, tc.field)
		}
	}
	if rec := env.doJSON(env.session, http.MethodPut, svc+"/mtls", map[string]any{"mode": "required", "ca": caPEM, "allow": []string{" svc-a ", "", "svc-b"}}, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("mtls save: %d %s", rec.Code, rec.Body)
	}
	if m := tlsNow().MTLS; m.Mode != "required" || !m.CASet || len(m.Allow) != 2 {
		t.Errorf("mtls = %+v", m)
	}
	if env.h.registry.ClientCAs("shop.example.com") == nil {
		t.Error("registry not reloaded")
	}
	// Off keeps the CA, and an empty CA field keeps it on the way back.
	env.doJSON(env.session, http.MethodPut, svc+"/mtls", map[string]any{"mode": "off"}, nil)
	if env.h.registry.ClientCAs("shop.example.com") != nil {
		t.Error("off still requests client certs")
	}
	if rec := env.doJSON(env.session, http.MethodPut, svc+"/mtls", map[string]any{"mode": "optional"}, nil); rec.Code != http.StatusNoContent || !tlsNow().MTLS.CASet {
		t.Errorf("re-enable without a CA: %d %+v", rec.Code, tlsNow().MTLS)
	}
	env.doJSON(env.session, http.MethodDelete, svc, nil, nil)
	if got, _ := env.db.ListServiceMTLS(); len(got) != 0 {
		t.Errorf("policy outlived its service: %+v", got)
	}
}
