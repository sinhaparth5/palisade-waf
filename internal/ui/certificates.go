package ui

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"palisade/internal/services"
	"palisade/internal/storage"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
)

// ── Certificate Pool ──────────────────────────────────────────────────────────

// certView is a pool certificate as the React Certificates page shows it:
// paths stay server-side, and Services names who serves it.
type certView struct {
	ID        int64    `json:"id"`
	Name      string   `json:"name"`
	Domains   []string `json:"domains"`
	ExpiresAt string   `json:"expires_at"`
	CreatedAt string   `json:"created_at"`
	Services  []string `json:"services"`
}

// serviceTLSView is one host-matched service's TLS: "auto" (Let's
// Encrypt), "pool" (Cert names the pool entry), "custom" (its own upload)
// or "none".
type serviceTLSView struct {
	Name      string `json:"name"`
	Host      string `json:"host"`
	Mode      string `json:"mode"`
	Cert      string `json:"cert,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

func splitDomains(s string) []string {
	out := []string{}
	for d := range strings.SplitSeq(s, ",") {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// ListCertificates answers GET /api/certificates: the pool, every
// host-matched service's TLS, and whether Let's Encrypt has its contact
// email (without it auto TLS can't issue).
func (h *Handler) ListCertificates(c *echo.Context) error {
	certs, err := h.db.ListCertificates()
	if err != nil {
		return err
	}
	svcs, err := h.db.ListServices()
	if err != nil {
		return err
	}
	email, err := h.db.GetAcmeEmail()
	if err != nil {
		return err
	}
	byID := map[int64]*certView{}
	views := make([]certView, len(certs))
	for i, r := range certs {
		views[i] = certView{ID: r.ID, Name: r.Name, Domains: splitDomains(r.Domains), ExpiresAt: r.ExpiresAt, CreatedAt: r.CreatedAt, Services: []string{}}
		byID[r.ID] = &views[i]
	}
	tlsViews := []serviceTLSView{}
	for _, s := range svcs {
		if s.Host == "" {
			continue
		}
		v := serviceTLSView{Name: s.Name, Host: s.Host, Mode: s.TLSMode, ExpiresAt: s.TLSExpiresAt}
		if cv := byID[s.CertID]; s.CertID > 0 && cv != nil {
			v.Mode, v.Cert, v.ExpiresAt = "pool", cv.Name, cv.ExpiresAt
			cv.Services = append(cv.Services, s.Name)
		}
		if v.Mode == "" {
			v.Mode = "none"
		}
		tlsViews = append(tlsViews, v)
	}
	return c.JSON(http.StatusOK, map[string]any{"certs": views, "services": tlsViews, "acme_email": email != ""})
}

type certAddRequest struct {
	Name    string `json:"name"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// AddCertificate uploads a cert+key PEM pair to the shared pool. It parses
// the certificate first to auto-detect covered domains and the expiry date,
// checks the key matches, then saves to disk and records the paths.
func (h *Handler) AddCertificate(c *echo.Context) error {
	var req certAddRequest
	if err := c.Bind(&req); err != nil {
		return &jsonError{Status: http.StatusBadRequest, Code: "invalid", Message: "Send name, cert_pem and key_pem as JSON."}
	}
	name := strings.TrimSpace(req.Name)
	certPEM, keyPEM := []byte(req.CertPEM), []byte(req.KeyPEM)
	switch {
	case name == "":
		return fieldError("name", "Give the certificate a name.")
	case len(certPEM) == 0:
		return fieldError("cert_pem", "Paste or upload the certificate.")
	case len(keyPEM) == 0:
		return fieldError("key_pem", "Paste or upload the private key.")
	}
	domains, expiresAt, err := services.ParseCertInfo(certPEM)
	if err != nil {
		return fieldError("cert_pem", "Not a valid certificate: "+err.Error())
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fieldError("key_pem", "This key doesn't match the certificate, or isn't a PEM private key.")
	}

	// Cert files are commonly saved under generic names (cert.pem/cert.key),
	// and the Name field autofills from the filename, so a second upload
	// would collide with the UNIQUE name column. Prefer a name derived from
	// the cert's own domains over failing.
	existing, err := h.db.ListCertificates()
	if err != nil {
		return err
	}
	name = uniqueCertName(name, domains, existing)

	// Insert first to obtain the row ID used as the on-disk directory name.
	exp := expiresAt.UTC().Format(time.RFC3339)
	id, err := h.db.AddCertificate(name, strings.Join(domains, ", "), exp, "", "")
	if err != nil {
		return err
	}
	certPath, keyPath, err := services.SavePoolCert(id, certPEM, keyPEM)
	if err == nil {
		err = h.db.UpdateCertificatePaths(id, certPath, keyPath)
	}
	if err != nil {
		h.db.DeleteCertificate(id) //nolint:errcheck // best-effort undo; the save error is what matters
		services.DeletePoolCert(id)
		return err
	}
	return c.JSON(http.StatusCreated, certView{ID: id, Name: name, Domains: domains, ExpiresAt: exp, Services: []string{}})
}

// uniqueCertName returns requested if no pool cert already uses it; otherwise
// it falls back to the first non-wildcard domain the cert covers, then to
// requested-2, requested-3, … until a free name is found.
func uniqueCertName(requested string, domains []string, existing []storage.CertRecord) string {
	taken := make(map[string]bool, len(existing))
	for _, c := range existing {
		taken[strings.ToLower(c.Name)] = true
	}
	if !taken[strings.ToLower(requested)] {
		return requested
	}
	for _, d := range domains {
		if !strings.HasPrefix(d, "*") && !taken[strings.ToLower(d)] {
			return d
		}
	}
	for i := 2; ; i++ {
		cand := fmt.Sprintf("%s-%d", requested, i)
		if !taken[strings.ToLower(cand)] {
			return cand
		}
	}
}

// DeleteCertificate removes a cert from the pool. Services that referenced it
// are reset to no-TLS by the DB layer, and the registry is reloaded so they
// stop presenting the cert immediately.
func (h *Handler) DeleteCertificate(c *echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		return &jsonError{Status: http.StatusBadRequest, Code: "invalid", Message: "Invalid certificate id."}
	}
	if err := h.db.DeleteCertificate(id); err != nil {
		return err
	}
	services.DeletePoolCert(id)
	if err := h.registry.Reload(h.db); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// ── Service TLS ───────────────────────────────────────────────────────────────
