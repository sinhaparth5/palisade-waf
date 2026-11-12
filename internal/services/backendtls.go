package services

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"palisade/internal/storage"
)

// Trusted backend certificates (issue #313). There is deliberately no
// "skip verification" switch: anyone on the path to the backend could then
// read and rewrite its traffic. The operator pastes what to trust instead:
//
//   - only non-CA certificates (the usual self-signed backend): the backend
//     must present exactly one of them. Exact pinning holds regardless of the
//     name in the cert, so an IP-addressed backend works.
//   - any CA certificate: normal chain and hostname verification, with the
//     pasted certificates as the only roots.

// backendTLSConfig parses a PEM bundle into the tls.Config that verifies a
// backend against it.
func backendTLSConfig(pemData string) (*tls.Config, error) {
	var certs []*x509.Certificate
	anyCA := false
	for rest := []byte(pemData); ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("backend certificate contains a %s block; paste certificates only, never a private key", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse backend certificate: %w", err)
		}
		certs = append(certs, cert)
		anyCA = anyCA || cert.IsCA
	}
	if len(certs) == 0 {
		return nil, errors.New("no PEM certificate found")
	}
	if anyCA {
		roots := x509.NewCertPool()
		for _, c := range certs {
			roots.AddCert(c)
		}
		return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, nil
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Replaced, not skipped: VerifyConnection accepts only a pinned cert.
		InsecureSkipVerify: true, //nolint:gosec // G402: VerifyConnection pins the exact certificate
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) > 0 {
				for _, c := range certs {
					if bytes.Equal(cs.PeerCertificates[0].Raw, c.Raw) {
						return nil
					}
				}
			}
			return errors.New("backend certificate does not match the trusted certificate")
		},
	}, nil
}

// ValidateBackendCA checks a pasted bundle; "" (system roots) is valid.
func ValidateBackendCA(pemData string) error {
	if pemData == "" {
		return nil
	}
	_, err := backendTLSConfig(pemData)
	return err
}

// caTransports holds one transport per trusted bundle, kept across Reload so
// idle backend connections survive a save. Grows only with distinct bundles
// an admin has saved.
var caTransports sync.Map // PEM -> *http.Transport

// backendRT is the transport for a service's backends: the shared one, or a
// clone verifying against the service's BackendCA. An invalid bundle (only
// possible from a hand-edited DB) fails closed on the system roots.
func backendRT(s storage.Service) http.RoundTripper {
	if s.BackendCA == "" {
		return backendTransport
	}
	if t, ok := caTransports.Load(s.BackendCA); ok {
		return t.(*http.Transport)
	}
	cfg, err := backendTLSConfig(s.BackendCA)
	if err != nil {
		return backendTransport
	}
	t := backendTransport.Clone()
	t.TLSClientConfig = cfg
	actual, _ := caTransports.LoadOrStore(s.BackendCA, t)
	return actual.(*http.Transport)
}
