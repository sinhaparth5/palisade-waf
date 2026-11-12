package ui

import (
	"fmt"
	"net/http"
	"os"
	"palisade/internal/services"
	"palisade/internal/storage"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
)

// ── Certificate Pool ──────────────────────────────────────────────────────────

func (h *Handler) certError(c *echo.Context, msg string) error {
	c.Response().Header().Set("HX-Retarget", "#cert-error")
	c.Response().Header().Set("HX-Reswap", "innerHTML")
	return c.String(http.StatusOK, msg)
}

func (h *Handler) renderCertRows(c *echo.Context) error {
	certs, _ := h.db.ListCertificates()
	return h.renderPartial(c, "certificates", "cert-rows", map[string]any{
		"Certs":     certs,
		"AdminPath": h.cfg.Admin.Path,
	})
}

func (h *Handler) CertificatesPage(c *echo.Context) error {
	certs, _ := h.db.ListCertificates()
	return h.render(c, "certificates", map[string]any{
		"Certs": certs,
	})
}

// AddCertificate uploads a cert+key PEM pair to the shared pool. It parses
// the certificate first to auto-detect covered domains and the expiry date,
// then saves to disk and records the paths in the database.
func (h *Handler) AddCertificate(c *echo.Context) error {
	name := strings.TrimSpace(c.FormValue("name"))
	certPEM := []byte(c.FormValue("cert_pem"))
	keyPEM := []byte(c.FormValue("key_pem"))

	if name == "" {
		return h.certError(c, "name is required")
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return h.certError(c, "paste both the certificate and private key")
	}

	domains, expiresAt, err := services.ParseCertInfo(certPEM)
	if err != nil {
		return h.certError(c, "invalid certificate: "+err.Error())
	}

	// Cert files are commonly saved under generic names (cert.pem/cert.key),
	// and the Name field autofills from the filename, so a second upload
	// would collide with the UNIQUE name column. Prefer a name derived from
	// the cert's own domains over failing.
	if existing, err := h.db.ListCertificates(); err == nil {
		name = uniqueCertName(name, domains, existing)
	}

	// Insert first to obtain the row ID used as the on-disk directory name.
	id, err := h.db.AddCertificate(name, strings.Join(domains, ", "), expiresAt.UTC().Format(time.RFC3339), "", "")
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return h.certError(c, fmt.Sprintf("a certificate named %q already exists; choose a different name", name))
		}
		return h.certError(c, "save: "+err.Error())
	}

	certPath, keyPath, err := services.SavePoolCert(id, certPEM, keyPEM)
	if err != nil {
		h.db.DeleteCertificate(id) //nolint
		return h.certError(c, err.Error())
	}

	if err := h.db.UpdateCertificatePaths(id, certPath, keyPath); err != nil {
		return h.certError(c, "update paths: "+err.Error())
	}

	return h.renderCertRows(c)
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
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid id")
	}
	if err := h.db.DeleteCertificate(id); err != nil {
		return err
	}
	services.DeletePoolCert(id)
	if err := h.registry.Reload(h.db); err != nil {
		return err
	}
	return h.renderCertRows(c)
}

// AssignPoolCert links an existing pool cert to a host-matched service. After
// this call the registry serves that cert for the service's domain over TLS.
func (h *Handler) AssignPoolCert(c *echo.Context) error {
	serviceID, err := strconv.Atoi(c.FormValue("service_id"))
	if err != nil {
		return h.tlsModalError(c, "invalid service")
	}
	certID, err := strconv.ParseInt(c.FormValue("cert_id"), 10, 64)
	if err != nil || certID <= 0 {
		return h.tlsModalError(c, "select a certificate")
	}
	svc, err := h.db.GetService(serviceID)
	if err != nil {
		return h.tlsModalError(c, "service not found")
	}
	if svc.Host == "" {
		return h.tlsModalError(c, "TLS requires a host-matched service (this one matches by path prefix)")
	}
	poolCert, err := h.db.GetCertificate(certID)
	if err != nil {
		return h.tlsModalError(c, "certificate not found")
	}
	certPEM, err := os.ReadFile(poolCert.CertPath)
	if err != nil {
		return h.tlsModalError(c, "read certificate: "+err.Error())
	}
	// Reject assigning a cert that doesn't cover this service's domain:
	// serving it would fail browser validation and Cloudflare Full (strict).
	if err := services.CertCoversHost(certPEM, svc.Host); err != nil {
		return h.tlsModalError(c, err.Error())
	}
	if err := h.db.SetServiceCertID(serviceID, certID); err != nil {
		return h.tlsModalError(c, err.Error())
	}
	if err := h.registry.Reload(h.db); err != nil {
		return err
	}
	return h.tlsSaved(c)
}

// ── Service TLS ───────────────────────────────────────────────────────────────

// tlsModalError redirects the swap to the TLS modal's own error box instead
// of the services table, mirroring wizardError for the add-service wizard.
func (h *Handler) tlsModalError(c *echo.Context, msg string) error {
	c.Response().Header().Set("HX-Retarget", "#tls-error")
	c.Response().Header().Set("HX-Reswap", "innerHTML")
	return c.String(http.StatusOK, msg)
}

// tlsSaved re-renders the services table after a TLS change, clears any
// stale error in the modal, and fires a "tls-saved" event (via HX-Trigger)
// that the modal listens for to close itself. extraEvents are fired
// alongside it: the header can only be set once, so a caller that also
// needs its own event (SaveAcmeEmail) must pass it here rather than set
// HX-Trigger itself, or it would be silently overwritten.
func (h *Handler) tlsSaved(c *echo.Context, extraEvents ...string) error {
	c.Response().Header().Set("HX-Trigger", strings.Join(append([]string{"tls-saved"}, extraEvents...), ", "))
	w := c.Response()
	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<div id="tls-error" hx-swap-oob="true"></div>`)
	return h.tmpls["services"].ExecuteTemplate(w, "services-rows", h.servicesRowsData(c))
}

// UploadServiceTLS saves an admin-provided cert+key PEM pair for a
// host-matched service. The private key is written to disk, never stored
// in the database (see services.SaveCustomCert).
func (h *Handler) UploadServiceTLS(c *echo.Context) error {
	id, err := strconv.Atoi(c.FormValue("service_id"))
	if err != nil {
		return h.tlsModalError(c, "invalid service")
	}
	svc, err := h.db.GetService(id)
	if err != nil {
		return h.tlsModalError(c, "service not found")
	}
	if svc.Host == "" {
		return h.tlsModalError(c, "TLS requires a host-matched service (this one matches by path prefix)")
	}

	certPEM := []byte(c.FormValue("cert_pem"))
	keyPEM := []byte(c.FormValue("key_pem"))
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return h.tlsModalError(c, "paste both the certificate and the private key")
	}
	if err := services.CertCoversHost(certPEM, svc.Host); err != nil {
		return h.tlsModalError(c, err.Error())
	}

	certPath, keyPath, expiresAt, err := services.SaveCustomCert(svc.Name, certPEM, keyPEM)
	if err != nil {
		return h.tlsModalError(c, err.Error())
	}
	if err := h.db.SetServiceTLS(id, "custom", certPath, keyPath, expiresAt.UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	if err := h.registry.Reload(h.db); err != nil {
		return err
	}
	return h.tlsSaved(c)
}

// EnableServiceAutoTLS marks a service for on-demand Let's Encrypt issuance.
// If no ACME email is stored in the DB yet, it fires a need-acme-email event
// so the UI can prompt the user first; without an email Let's Encrypt
// cannot register an account and cert issuance will always fail.
func (h *Handler) EnableServiceAutoTLS(c *echo.Context) error {
	id, err := strconv.Atoi(c.FormValue("service_id"))
	if err != nil {
		return h.tlsModalError(c, "invalid service")
	}
	svc, err := h.db.GetService(id)
	if err != nil {
		return h.tlsModalError(c, "service not found")
	}
	if svc.Host == "" {
		return h.tlsModalError(c, "TLS requires a host-matched service (this one matches by path prefix)")
	}

	email, err := h.db.GetAcmeEmail()
	if err != nil {
		return err
	}
	if email == "" {
		// No email yet, so ask the UI to collect it first.
		c.Response().Header().Set("HX-Trigger",
			fmt.Sprintf(`{"need-acme-email":{"service_id":%d}}`, id))
		return c.String(http.StatusOK, "")
	}

	if err := h.db.SetServiceTLS(id, "auto", "", "", ""); err != nil {
		return err
	}
	if err := h.registry.Reload(h.db); err != nil {
		return err
	}
	return h.tlsSaved(c)
}

// SaveAcmeEmail stores the Let's Encrypt contact email and, if a service_id
// is provided, immediately enables auto-TLS for that service so the user
// doesn't have to click "Enable" twice after filling in their email.
func (h *Handler) SaveAcmeEmail(c *echo.Context) error {
	email := strings.TrimSpace(c.FormValue("email"))
	if email == "" || !strings.Contains(email, "@") {
		c.Response().Header().Set("HX-Retarget", "#acme-email-error")
		c.Response().Header().Set("HX-Reswap", "innerHTML")
		return c.String(http.StatusOK, "Enter a valid email address.")
	}
	if err := h.db.SetAcmeEmail(email); err != nil {
		return err
	}
	// If the caller passed a service_id, enable auto-TLS for it now.
	if id, err := strconv.Atoi(c.FormValue("service_id")); err == nil && id > 0 {
		if err := h.db.SetServiceTLS(id, "auto", "", "", ""); err != nil {
			return err
		}
	}
	if err := h.registry.Reload(h.db); err != nil {
		return err
	}
	return h.tlsSaved(c, "acme-email-saved")
}

// ClearServiceTLS reverts a service to plain HTTP.
func (h *Handler) ClearServiceTLS(c *echo.Context) error {
	id, err := strconv.Atoi(c.FormValue("service_id"))
	if err != nil {
		return h.tlsModalError(c, "invalid service")
	}
	if err := h.db.ClearServiceTLS(id); err != nil {
		return err
	}
	if err := h.registry.Reload(h.db); err != nil {
		return err
	}
	return h.tlsSaved(c)
}
