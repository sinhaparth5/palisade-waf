package services

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"palisade/internal/storage"
)

// Identity headers Palisade sets for mTLS services (issue #191). Client
// copies are always stripped first, so the backend can trust them.
const (
	ClientCertVerifiedHeader    = "X-Client-Cert-Verified"
	ClientCertSubjectHeader     = "X-Client-Cert-Subject"
	ClientCertFingerprintHeader = "X-Client-Cert-Fingerprint"
)

// mtlsPolicy is one service's compiled client-certificate policy.
type mtlsPolicy struct {
	required bool
	pool     *x509.CertPool
	allow    map[string]bool // lowercased CNs/DNS names, and fingerprints without colons
}

// ClientCert is the outcome of checking a request against its host's policy.
type ClientCert struct {
	Required    bool
	Verified    bool
	Subject     string // only when Verified
	Fingerprint string // SHA-256 of the leaf, hex; whenever a cert was sent
}

// SaveClientCA validates a PEM bundle of CA certificates and writes it to
// certs/services/<name>/client-ca.pem, returning the path.
func SaveClientCA(name string, caPEM []byte) (string, error) {
	if _, err := parseClientCAs(caPEM); err != nil {
		return "", err
	}
	dir := certDir(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create cert dir: %w", err)
	}
	path := filepath.Join(dir, "client-ca.pem")
	if err := os.WriteFile(path, caPEM, 0o644); err != nil {
		return "", fmt.Errorf("write client CA: %w", err)
	}
	return path, nil
}

func parseClientCAs(caPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	n := 0
	for rest := caPEM; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("client CA bundle contains a %s block; only certificates are allowed", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse client CA: %w", err)
		}
		if !cert.IsCA {
			return nil, fmt.Errorf("%q is not a CA certificate", cert.Subject.CommonName)
		}
		pool.AddCert(cert)
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("no PEM certificate found in the client CA bundle")
	}
	return pool, nil
}

// loadMTLSPolicies compiles the stored policies keyed by service index. A
// required policy whose CA file can't be read still gets a policy with an
// empty pool, so the service fails closed (403) instead of opening up.
func loadMTLSPolicies(stored map[int]storage.ServiceMTLS, list []storage.Service) map[int]*mtlsPolicy {
	out := make(map[int]*mtlsPolicy)
	for i, s := range list {
		m, ok := stored[s.ID]
		if !ok || m.Mode == "off" || s.Host == "" {
			continue
		}
		p := &mtlsPolicy{required: m.Mode == "required", pool: x509.NewCertPool(), allow: map[string]bool{}}
		if b, err := os.ReadFile(m.CAPath); err != nil {
			log.Printf("mtls: service %q: %v", s.Name, err)
		} else if pool, err := parseClientCAs(b); err != nil {
			log.Printf("mtls: service %q: %v", s.Name, err)
		} else {
			p.pool = pool
		}
		for _, e := range strings.Fields(m.Allow) {
			e = strings.ToLower(e)
			p.allow[e] = true
			p.allow[strings.ReplaceAll(e, ":", "")] = true
		}
		out[i] = p
	}
	return out
}

// check verifies the connection's client certificate against p. It runs per
// request, not at the handshake, so a request whose Host differs from its
// SNI is judged by the Host's policy.
// ponytail: one x509 Verify per request (~50µs); cache per connection if
// mTLS services ever see high request rates.
func (p *mtlsPolicy) check(cs *tls.ConnectionState) ClientCert {
	res := ClientCert{Required: p.required}
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return res
	}
	leaf := cs.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	res.Fingerprint = hex.EncodeToString(sum[:])
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         p.pool,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return res
	}
	if len(p.allow) > 0 && !p.allowed(leaf, res.Fingerprint) {
		return res
	}
	res.Verified = true
	res.Subject = printable(leaf.Subject.String())
	return res
}

func (p *mtlsPolicy) allowed(leaf *x509.Certificate, fp string) bool {
	if p.allow[fp] || p.allow[strings.ToLower(leaf.Subject.CommonName)] {
		return true
	}
	for _, d := range leaf.DNSNames {
		if p.allow[strings.ToLower(d)] {
			return true
		}
	}
	return false
}

// printable drops control characters so a subject can't break a header.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// ClientCAs returns the CA pool to request a client cert with for an SNI
// name, or nil when that host has no mTLS policy.
func (r *Registry) ClientCAs(sni string) *x509.CertPool {
	if r == nil {
		return nil
	}
	host := NormalizeHost(sni)
	r.mu.RLock()
	defer r.mu.RUnlock()
	if i, ok := r.hosts[host]; ok {
		if p := r.mtls[i]; p != nil {
			return p.pool
		}
	}
	return nil
}

// CheckClientCert applies the mTLS policy of r's Host, matched by Host only
// (never Prefix or SNI). For such a host it replaces any client-sent
// X-Client-Cert-* headers with Palisade's own and reports the result; ok is
// false when the host has no policy.
func (r *Registry) CheckClientCert(req *http.Request) (res ClientCert, ok bool) {
	if r == nil {
		return res, false
	}
	host := strings.ToLower(strings.Split(req.Host, ":")[0])
	r.mu.RLock()
	var p *mtlsPolicy
	if i, found := r.hosts[host]; found {
		p = r.mtls[i]
	}
	r.mu.RUnlock()
	if p == nil {
		return res, false
	}
	res = p.check(req.TLS)
	h := req.Header
	h.Del(ClientCertSubjectHeader)
	h.Del(ClientCertFingerprintHeader)
	h.Set(ClientCertVerifiedHeader, "0")
	if res.Verified {
		h.Set(ClientCertVerifiedHeader, "1")
		h.Set(ClientCertSubjectHeader, res.Subject)
	}
	if res.Fingerprint != "" {
		h.Set(ClientCertFingerprintHeader, res.Fingerprint)
	}
	return res, true
}

// MTLSConfig returns a tls.Config.GetConfigForClient helper: for an SNI with
// an mTLS policy it returns a copy of base that asks for a client cert. The
// cert is only requested here (RequestClientCert) and verified per request
// by CheckClientCert, so a missing or bad cert gets a logged 403 rather
// than an opaque handshake failure. Session tickets are off on those hosts
// so every connection presents its cert again.
func (r *Registry) MTLSConfig(base *tls.Config, sni string) *tls.Config {
	pool := r.ClientCAs(sni)
	if pool == nil {
		return nil
	}
	cfg := base.Clone()
	cfg.GetConfigForClient = nil
	cfg.ClientAuth = tls.RequestClientCert
	cfg.ClientCAs = pool
	cfg.SessionTicketsDisabled = true
	return cfg
}
