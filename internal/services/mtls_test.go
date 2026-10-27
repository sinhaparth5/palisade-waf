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
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"palisade/internal/storage"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, cn string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testCA{cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue signs a client certificate for cn (+ DNS SANs).
func (ca testCA) issue(t *testing.T, cn string, dns ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dns,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// mtlsRegistry has "secure.test" (required, client CA ca) and "open.test"
// (no policy).
func mtlsRegistry(t *testing.T, ca testCA, allow string) *Registry {
	t.Helper()
	t.Chdir(t.TempDir())
	db := openTestDB(t)
	for _, h := range []string{"secure", "open"} {
		if err := db.AddService(h, h+".test", "", "http://10.0.0.1", 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	path, err := SaveClientCA("secure", ca.pem)
	if err != nil {
		t.Fatal(err)
	}
	list, _ := db.ListServices()
	if err := db.SetServiceMTLS(list[0].ID, storage.ServiceMTLS{Mode: "required", CAPath: path, Allow: allow}); err != nil {
		t.Fatal(err)
	}
	r, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSaveClientCARejects(t *testing.T) {
	t.Chdir(t.TempDir())
	ca := newTestCA(t, "ca")
	leafPEM := selfSignedPEM(t, "leaf", nil)
	for name, in := range map[string][]byte{
		"empty":   nil,
		"not PEM": []byte("hello"),
		"not CA":  leafPEM,
		"key":     append(append([]byte{}, ca.pem...), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}})...),
	} {
		if _, err := SaveClientCA("svc", in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := SaveClientCA("svc", ca.pem); err != nil {
		t.Fatalf("valid CA rejected: %v", err)
	}
}

func TestCheckClientCert(t *testing.T) {
	ca, rogue := newTestCA(t, "ca"), newTestCA(t, "rogue")
	good := ca.issue(t, "svc-a", "client.a")
	cases := []struct {
		name, allow, host string
		cert              *tls.Certificate
		policy, verified  bool
	}{
		{"no policy on host", "", "open.test", &good, false, false},
		{"no cert", "", "secure.test", nil, true, false},
		{"valid cert", "", "secure.test:443", &good, true, true},
		{"other CA", "", "secure.test", ptr(rogue.issue(t, "svc-a")), true, false},
		{"allow by CN", "other\nSVC-A", "secure.test", &good, true, true},
		{"allow by DNS SAN", "client.a", "secure.test", &good, true, true},
		{"not on allowlist", "other", "secure.test", &good, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := mtlsRegistry(t, ca, tc.allow)
			req, _ := http.NewRequest("GET", "https://"+tc.host+"/", nil)
			req.Header.Set(ClientCertVerifiedHeader, "1")
			req.Header.Set(ClientCertSubjectHeader, "CN=admin")
			if tc.cert != nil {
				req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{tc.cert.Leaf}}
			}
			res, ok := r.CheckClientCert(req)
			if ok != tc.policy || res.Verified != tc.verified {
				t.Fatalf("got policy=%v verified=%v, want %v %v", ok, res.Verified, tc.policy, tc.verified)
			}
			if !ok {
				return
			}
			wantV, wantS := "0", ""
			if tc.verified {
				wantV, wantS = "1", "CN=svc-a"
			}
			if v, s := req.Header.Get(ClientCertVerifiedHeader), req.Header.Get(ClientCertSubjectHeader); v != wantV || s != wantS {
				t.Fatalf("headers verified=%q subject=%q, want %q %q", v, s, wantV, wantS)
			}
			if (tc.cert != nil) != (len(req.Header.Get(ClientCertFingerprintHeader)) == 64) {
				t.Fatalf("fingerprint %q", req.Header.Get(ClientCertFingerprintHeader))
			}
		})
	}
	t.Run("allow by fingerprint with colons", func(t *testing.T) {
		probe := mtlsRegistry(t, ca, "")
		req, _ := http.NewRequest("GET", "https://secure.test/", nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{good.Leaf}}
		fp, _ := probe.CheckClientCert(req)
		var colons []string
		for i := 0; i < len(fp.Fingerprint); i += 2 {
			colons = append(colons, strings.ToUpper(fp.Fingerprint[i:i+2]))
		}
		r := mtlsRegistry(t, ca, strings.Join(colons, ":"))
		if res, _ := r.CheckClientCert(req); !res.Verified {
			t.Fatal("fingerprint allowlist entry not matched")
		}
	})
}

func ptr[T any](v T) *T { return &v }

// TestMTLSHandshake runs a real TLS listener wired like startTLS in main.go:
// the client cert is only requested for SNI names with a policy, the check
// itself follows the Host header, and HTTP/2 and HTTP/3 survive the
// per-SNI config.
func TestMTLSHandshake(t *testing.T) {
	ca, rogue := newTestCA(t, "ca"), newTestCA(t, "rogue")
	r := mtlsRegistry(t, ca, "")
	certPEM, keyPEM := selfSignedPair(t, "secure.test")
	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	base := &tls.Config{Certificates: []tls.Certificate{serverCert}, NextProtos: []string{"h2", "http/1.1"}}
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if cfg := r.MTLSConfig(base, hello.ServerName); cfg != nil {
			return cfg, nil
		}
		return nil, nil
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if res, ok := r.CheckClientCert(req); ok && !res.Verified {
			w.WriteHeader(http.StatusForbidden)
		}
		w.Header().Set("X-Proto", req.Proto)
	})
	srv := &http.Server{TLSConfig: base, ReadHeaderTimeout: 5 * time.Second, Handler: handler}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(tls.NewListener(ln, base)) }()
	t.Cleanup(func() { _ = srv.Close() })

	// HTTP/3 as startHTTP3 builds it: a clone of the same config.
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h3 := &http3.Server{TLSConfig: base.Clone(), QUICConfig: &quic.Config{}, Handler: handler}
	go func() { _ = h3.Serve(udp) }()
	t.Cleanup(func() { _ = h3.Close() })

	for _, proto := range []string{"HTTP/2.0", "HTTP/3.0"} {
		t.Run(proto, func(t *testing.T) {
			get := func(sni, host string, cert *tls.Certificate) *http.Response {
				t.Helper()
				cfg := &tls.Config{ServerName: sni, InsecureSkipVerify: true} //nolint:gosec // throwaway self-signed server cert
				if cert != nil {
					cfg.Certificates = []tls.Certificate{*cert}
				}
				var rt http.RoundTripper = &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}
				addr := ln.Addr().String()
				if proto == "HTTP/3.0" {
					tr := &http3.Transport{TLSClientConfig: cfg}
					defer tr.Close()
					rt, addr = tr, udp.LocalAddr().String()
				}
				req, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
				req.Host = host
				resp, err := rt.RoundTrip(req)
				if err != nil {
					t.Fatalf("request: %v", err)
				}
				resp.Body.Close()
				return resp
			}

			good := ca.issue(t, "svc-a")
			if resp := get("secure.test", "secure.test", &good); resp.StatusCode != 200 || resp.Header.Get("X-Proto") != proto {
				t.Fatalf("valid cert: %d %s, want 200 over %s", resp.StatusCode, resp.Header.Get("X-Proto"), proto)
			}
			if resp := get("secure.test", "secure.test", nil); resp.StatusCode != 403 {
				t.Fatalf("no cert: %d, want 403", resp.StatusCode)
			}
			bad := rogue.issue(t, "svc-a")
			if resp := get("secure.test", "secure.test", &bad); resp.StatusCode != 403 {
				t.Fatalf("other CA: %d, want 403", resp.StatusCode)
			}
			// SNI names a host without a policy, so no cert is requested (and
			// the client sends none) even though it has one; Host must still
			// decide.
			if resp := get("open.test", "secure.test", &good); resp.StatusCode != 403 {
				t.Fatalf("SNI/Host mismatch: %d, want 403", resp.StatusCode)
			}
			if resp := get("open.test", "open.test", nil); resp.StatusCode != 200 || resp.Header.Get("X-Proto") != proto {
				t.Fatalf("host without policy: %d %s, want 200 over %s", resp.StatusCode, resp.Header.Get("X-Proto"), proto)
			}
		})
	}
}
