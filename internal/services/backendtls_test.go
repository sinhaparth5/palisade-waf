package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"palisade/internal/storage"
)

// selfSigned returns a non-CA leaf for a name that doesn't match the
// backend's address, like a typical appliance cert reached by IP.
func selfSigned(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pve.local"},
		DNSNames:     []string{"pve.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func tlsBackend(t *testing.T, cert *tls.Certificate) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if cert != nil {
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// TestBackendCA pins issue #313: a self-signed backend works only with its
// certificate pasted, a CA bundle verifies normally, and nothing else passes.
func TestBackendCA(t *testing.T) {
	leaf, leafPEM := selfSigned(t)
	_, otherPEM := selfSigned(t)
	pinned := tlsBackend(t, &leaf)
	caSigned := tlsBackend(t, nil) // httptest's cert: a CA valid for 127.0.0.1
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caSigned.Certificate().Raw}))

	for _, tc := range []struct {
		name, url, ca string
		ok            bool
	}{
		{"self-signed, nothing trusted", pinned.URL, "", false},
		{"self-signed, its cert pinned", pinned.URL, leafPEM, true},
		{"self-signed, another cert pinned", pinned.URL, otherPEM, false},
		{"CA bundle", caSigned.URL, caPEM, true},
		{"CA bundle, wrong backend", pinned.URL, caPEM, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, tc.url, nil)
			resp, err := backendRT(storage.Service{BackendCA: tc.ca}).RoundTrip(req)
			if err == nil {
				resp.Body.Close()
			}
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
		})
	}

	// The add-service probe counts an unverified TLS answer as reachable.
	if err := Probe(pinned.URL); err != nil {
		t.Errorf("Probe(self-signed) = %v, want reachable", err)
	}

	for _, bad := range []string{"not pem", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"} {
		if ValidateBackendCA(bad) == nil {
			t.Errorf("ValidateBackendCA(%q) accepted", bad)
		}
	}
	if err := ValidateBackendCA(leafPEM); err != nil {
		t.Errorf("ValidateBackendCA(leaf) = %v", err)
	}
}
