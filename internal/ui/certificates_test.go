package ui

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type certsPage struct {
	Certs     []certView       `json:"certs"`
	Services  []serviceTLSView `json:"services"`
	AcmeEmail bool             `json:"acme_email"`
}

// TestCertificatesAPI covers the pool from the React page: field errors that
// name the field, the name fallback on a clash, the list with each service's
// TLS, and delete resetting the services that served the cert.
func TestCertificatesAPI(t *testing.T) {
	t.Chdir(t.TempDir()) // cert files are written relative to the working directory
	env := newAdminEnv(t)
	shop := env.seedService("shop", "shop.example.com")
	env.seedService("blog", "blog.example.com")
	_ = env.db.AddService("api", "", "/api", env.backend.URL, 0, 0)
	certPEM, keyPEM := testCertPEM(t, "shop.example.com")
	otherCert, otherKey := testCertPEM(t, "other.example.com")

	for _, tc := range []struct {
		req   certAddRequest
		field string
	}{
		{certAddRequest{CertPEM: certPEM, KeyPEM: keyPEM}, "name"},
		{certAddRequest{Name: "  ", CertPEM: certPEM, KeyPEM: keyPEM}, "name"},
		{certAddRequest{Name: "x", KeyPEM: keyPEM}, "cert_pem"},
		{certAddRequest{Name: "x", CertPEM: certPEM}, "key_pem"},
		{certAddRequest{Name: "x", CertPEM: "junk", KeyPEM: keyPEM}, "cert_pem"},
		{certAddRequest{Name: "x", CertPEM: certPEM, KeyPEM: otherKey}, "key_pem"},
	} {
		var got jsonError
		rec := env.doJSON(env.session, http.MethodPost, "/admin/api/certificates", tc.req, &got)
		if rec.Code != http.StatusBadRequest || got.Fields[tc.field] == "" {
			t.Errorf("%+v: %d %s, want a %s error", tc.req, rec.Code, rec.Body, tc.field)
		}
	}
	if n, _ := env.db.ListCertificates(); len(n) != 0 {
		t.Fatalf("a refused upload left %d rows", len(n))
	}
	if rec := env.doJSON(env.session, http.MethodPost, "/admin/api/certificates", "nope", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("non-object body: %d", rec.Code)
	}

	var first, second certView
	if rec := env.doJSON(env.session, http.MethodPost, "/admin/api/certificates", certAddRequest{"cert.pem", certPEM, keyPEM}, &first); rec.Code != http.StatusCreated {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	env.doJSON(env.session, http.MethodPost, "/admin/api/certificates", certAddRequest{"cert.pem", otherCert, otherKey}, &second)
	if first.Name != "cert.pem" || second.Name != "other.example.com" || len(first.Domains) != 1 || first.Domains[0] != "shop.example.com" || first.ExpiresAt == "" {
		t.Fatalf("added %+v and %+v (a clashing name falls back to the domain)", first, second)
	}
	if rows, _ := env.db.ListCertificates(); len(rows) != 2 {
		t.Fatalf("rows = %d", len(rows))
	} else if _, err := os.Stat(rows[0].KeyPath); err != nil {
		t.Errorf("pool key not written: %v", err)
	}

	_ = env.db.SetServiceCertID(shop.ID, first.ID)
	var page certsPage
	if rec := env.doJSON(env.session, http.MethodGet, "/admin/api/certificates", nil, &page); rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	if len(page.Certs) != 2 || strings.Join(page.Certs[0].Services, ",") != "shop" || len(page.Certs[1].Services) != 0 || page.AcmeEmail {
		t.Errorf("certs = %+v acme=%v", page.Certs, page.AcmeEmail)
	}
	modes := map[string]serviceTLSView{}
	for _, s := range page.Services {
		modes[s.Name] = s
	}
	if len(page.Services) != 2 || modes["shop"].Mode != "pool" || modes["shop"].Cert != "cert.pem" || modes["shop"].ExpiresAt == "" || modes["blog"].Mode != "none" {
		t.Errorf("services = %+v (path-prefix services are left out)", page.Services)
	}

	// A viewer reads the list but can't write.
	viewer := env.sessionAs("viewer")
	if rec := env.doJSON(viewer, http.MethodGet, "/admin/api/certificates", nil, nil); rec.Code != http.StatusOK {
		t.Errorf("viewer list: %d", rec.Code)
	}
	if rec := env.doJSON(viewer, http.MethodDelete, "/admin/api/certificates/1", nil, nil); rec.Code != http.StatusForbidden {
		t.Errorf("viewer delete: %d", rec.Code)
	}

	if rec := env.doJSON(env.session, http.MethodDelete, "/admin/api/certificates/x", nil, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete bad id: %d", rec.Code)
	}
	rows, _ := env.db.ListCertificates()
	if rec := env.doJSON(env.session, http.MethodDelete, "/admin/api/certificates/"+itoa(first.ID), nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Dir(rows[0].CertPath)); !os.IsNotExist(err) {
		t.Error("pool cert dir not removed")
	}
	if got, _ := env.db.GetService(shop.ID); got.CertID != 0 || got.TLSMode != "none" {
		t.Errorf("service after delete = %q cert %d", got.TLSMode, got.CertID)
	}
}
