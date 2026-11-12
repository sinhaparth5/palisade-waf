package storage

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func exportConfig(t *testing.T, db *DB) string {
	t.Helper()
	var buf bytes.Buffer
	mustNoErr(t, db.ExportConfig(&buf))
	return buf.String()
}

func seedConfig(t *testing.T, db *DB) {
	t.Helper()
	mustNoErr(t, db.AddService("api", "api.example.com", "", "http://127.0.0.1:3000", 5, 10))
	mustNoErr(t, db.AddIPRule("", "198.51.100.0/24", "block"))
	mustNoErr(t, db.AddGeoRule("", "CN", "block"))
	mustNoErr(t, db.SetServiceRateRules(1, "POST /reset 5/h 3"))
	mustNoErr(t, db.setSecretMeta("email_token", "tok-secret"))
	mustNoErr(t, db.SetWebhookConfig(WebhookConfig{URL: "https://hooks.example/x", Secret: "hook-secret", Enabled: true}))
	uid, err := db.CreateAdminUser("owner@example.com", "a long enough password", "owner")
	mustNoErr(t, err)
	mustNoErr(t, db.SetPendingTOTPSecret(uid, "JBSWY3DPEHPK3PXP"))
	mustNoErr(t, db.EnableTOTP(uid, nil))
}

// TestConfigExportImport pins issue #263 without a key file: config round
// trips into an empty database, plaintext secrets are left out, and an
// import never overwrites existing config without replace.
func TestConfigExportImport(t *testing.T) {
	src := openTestDB(t)
	seedConfig(t, src)
	file := exportConfig(t, src)
	for _, secret := range []string{"tok-secret", "hook-secret", "JBSWY3DPEHPK3PXP"} {
		if strings.Contains(file, secret) {
			t.Errorf("plaintext secret %q in export", secret)
		}
	}

	dst := openTestDB(t)
	rep, err := dst.ImportConfig(strings.NewReader(file), false)
	mustNoErr(t, err)
	if rep.TotalRows == 0 {
		t.Fatal("nothing imported")
	}
	svcs, _ := dst.ListServices()
	if len(svcs) != 1 || svcs[0].Name != "api" || svcs[0].RateLimitRPS != 5 {
		t.Fatalf("services = %+v", svcs)
	}
	if r, _ := dst.ListServiceRateRules(); r[1] != "POST /reset 5/h 3" {
		t.Errorf("rate rules = %v", r)
	}
	if ips, _ := dst.ListIPRules(); len(ips) != 1 || ips[0].IP != "198.51.100.0/24" || ips[0].CreatedAt.IsZero() {
		t.Errorf("ip rules = %+v", ips)
	}
	if u, err := dst.GetAdminUserByEmail("owner@example.com"); err != nil || u.Role != "owner" {
		t.Errorf("user = %+v, %v", u, err)
	}
	if wh, _ := dst.GetWebhookConfig(); wh.URL != "https://hooks.example/x" || wh.Secret != "" {
		t.Errorf("webhook = %+v", wh)
	}
	// The import added an identity row: the next normal insert must not collide.
	mustNoErr(t, dst.AddService("web", "web.example.com", "", "http://127.0.0.1:3001", 0, 0))

	if _, err := dst.ImportConfig(strings.NewReader(file), false); !errors.Is(err, ErrConfigNotEmpty) {
		t.Fatalf("import over config: %v", err)
	}
	_, err = dst.ImportConfig(strings.NewReader(file), true)
	mustNoErr(t, err)
	if svcs, _ := dst.ListServices(); len(svcs) != 1 {
		t.Fatalf("replace kept %d services", len(svcs))
	}

	for name, bad := range map[string]string{
		"not json":      "nope",
		"wrong format":  `{"format":"other","version":1}`,
		"unknown table": `{"format":"palisade-config","version":1,"tables":{"requests":[]}}`,
		"bad column":    `{"format":"palisade-config","version":1,"tables":{"geo_rules":[{"id":1,"x; DROP TABLE meta":1}]}}`,
	} {
		if _, err := openTestDB(t).ImportConfig(strings.NewReader(bad), false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestConfigExportSealed: with a key file the secrets stay in the export,
// sealed, and come back with the same key; without it the import refuses.
func TestConfigExportSealed(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	src, err := Open(filepath.Join(t.TempDir(), "src.db"))
	mustNoErr(t, err)
	defer src.Close()
	mustNoErr(t, src.EnableSecretEncryption(key))
	seedConfig(t, src)
	file := exportConfig(t, src)
	if strings.Contains(file, "tok-secret") || strings.Count(file, secretPrefix) < 3 {
		t.Fatalf("secrets not sealed in export:\n%s", file)
	}

	if _, err := openTestDB(t).ImportConfig(strings.NewReader(file), false); err == nil {
		t.Fatal("sealed file imported without a key")
	}
	dst, err := Open(filepath.Join(t.TempDir(), "dst.db"))
	mustNoErr(t, err)
	defer dst.Close()
	mustNoErr(t, dst.EnableSecretEncryption(key))
	_, err = dst.ImportConfig(strings.NewReader(file), false)
	mustNoErr(t, err)
	if tok, err := dst.getSecretMeta("email_token"); err != nil || tok != "tok-secret" {
		t.Errorf("email token = %q, %v", tok, err)
	}
	if wh, _ := dst.GetWebhookConfig(); wh.Secret != "hook-secret" {
		t.Errorf("webhook secret = %q", wh.Secret)
	}
	u, _ := dst.GetAdminUserByEmail("owner@example.com")
	if s, err := dst.GetTOTPSecret(u.ID); err != nil || s != "JBSWY3DPEHPK3PXP" {
		t.Errorf("totp = %q, %v", s, err)
	}
}
