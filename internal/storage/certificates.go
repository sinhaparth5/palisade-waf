package storage

// ── Certificate Pool ──────────────────────────────────────────────────────────

// CertRecord is a row in the certificates table. Cert+key files live on disk
// under certs/pool/<id>/; only the paths are stored here.
type CertRecord struct {
	ID        int64
	Name      string
	Domains   string // comma-separated list of covered hostnames, e.g. "example.com, *.example.com"
	ExpiresAt string // RFC3339, or "" if unknown
	CertPath  string
	KeyPath   string
	CreatedAt string
}

// AddCertificate inserts a new certificate pool entry. Cert+key paths may be
// empty initially and updated with UpdateCertificatePaths once files are saved.
func (db *DB) AddCertificate(name, domains, expiresAt, certPath, keyPath string) (int64, error) {
	return db.insertReturningID(
		`INSERT INTO certificates (name, domains, expires_at, cert_path, key_path) VALUES (?, ?, ?, ?, ?)`,
		name, domains, expiresAt, certPath, keyPath,
	)
}

// UpdateCertificatePaths stores the on-disk file paths after the files have
// been written (called immediately after AddCertificate + SavePoolCert).
func (db *DB) UpdateCertificatePaths(id int64, certPath, keyPath string) error {
	_, err := db.exec(
		`UPDATE certificates SET cert_path = ?, key_path = ? WHERE id = ?`,
		certPath, keyPath, id,
	)
	return err
}

func (db *DB) ListCertificates() ([]CertRecord, error) {
	rows, err := db.query(
		`SELECT id, name, domains, expires_at, cert_path, key_path, created_at FROM certificates ORDER BY created_at ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CertRecord
	for rows.Next() {
		var c CertRecord
		if err := rows.Scan(&c.ID, &c.Name, &c.Domains, &c.ExpiresAt, &c.CertPath, &c.KeyPath, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (db *DB) GetCertificate(id int64) (CertRecord, error) {
	var c CertRecord
	err := db.queryRow(
		`SELECT id, name, domains, expires_at, cert_path, key_path, created_at FROM certificates WHERE id = ?`, id,
	).Scan(&c.ID, &c.Name, &c.Domains, &c.ExpiresAt, &c.CertPath, &c.KeyPath, &c.CreatedAt)
	return c, err
}

// DeleteCertificate removes a cert-pool entry. Services that referenced it
// via cert_id are reset to tls_mode='none' so they don't silently lose TLS.
func (db *DB) DeleteCertificate(id int64) error {
	if _, err := db.exec(
		`UPDATE services SET tls_mode = 'none', cert_id = 0, tls_cert_path = '', tls_key_path = '', tls_expires_at = '' WHERE cert_id = ?`,
		id,
	); err != nil {
		return err
	}
	_, err := db.exec(`DELETE FROM certificates WHERE id = ?`, id)
	return err
}
