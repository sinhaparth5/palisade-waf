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
	"strconv"
	"strings"
	"testing"
	"time"
)

func itoa[T int | int64](n T) string { return strconv.FormatInt(int64(n), 10) }

// testCertPEM returns a self-signed cert+key for the given DNS names.
func testCertPEM(t *testing.T, names ...string) (certPEM, keyPEM string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
}

// TestBackupDownloads: the database and config downloads Settings links to.
func TestBackupDownloads(t *testing.T) {
	env := newAdminEnv(t)

	rec := env.do("POST", "/admin/settings/backup", nil)
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), "SQLite format 3") ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), "palisade-") {
		t.Errorf("backup: %d %q", rec.Code, rec.Header().Get("Content-Disposition"))
	}
	rec = env.do("POST", "/admin/settings/config-export", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"palisade-config"`) ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), "palisade-config-") {
		t.Errorf("config export: %d %q", rec.Code, rec.Header().Get("Content-Disposition"))
	}
}

// TestPasskeyEnrollment: a secure context gets a WebAuthn challenge, a bogus
// attestation spends the pending ceremony, and an expired slot isn't taken.
func TestPasskeyEnrollment(t *testing.T) {
	env := newAdminEnv(t)
	secure := func(method, path, body string) *httptestRecorder {
		r := newReq(env, method, path, body)
		r.Host = "localhost"
		r.Header.Set("Accept", "application/json")
		return serve(env, r)
	}
	rec := secure("POST", "/admin/api/settings/passkeys/begin", `{"name":"YubiKey"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "challenge") {
		t.Fatalf("begin enrollment: %d %s", rec.Code, rec.Body)
	}
	if rec := secure("POST", "/admin/api/settings/passkeys/finish", `{}`); rec.Code != 400 {
		t.Errorf("finish with bogus attestation = %d", rec.Code)
	}
	if rec := secure("POST", "/admin/api/settings/passkeys/finish", `{}`); rec.Code != 409 || !strings.Contains(rec.Body.String(), "expired") {
		t.Errorf("finish without a pending ceremony: %d %s", rec.Code, rec.Body)
	}

	_ = env.db.AddWebAuthnCredential(env.uid, "AQID", "Key", []byte(`{"id":"AQID"}`))
	creds, _ := env.db.ListWebAuthnCredentials(env.uid)
	if rec := env.doJSON(env.session, "DELETE", "/admin/api/settings/passkeys/"+itoa(creds[0].ID), nil, nil); rec.Code != 204 {
		t.Errorf("delete passkey: %d", rec.Code)
	}
	if creds, _ := env.db.ListWebAuthnCredentials(env.uid); len(creds) != 0 {
		t.Error("passkey not deleted")
	}

	env.h.pkEnroll.m[env.uid] = pkEnrollment{name: "x", expires: time.Now().Add(-time.Second)}
	if _, _, ok := env.h.pkEnroll.take(env.uid); ok {
		t.Error("expired enrollment should not be taken")
	}
}

func TestPasskeyLogin(t *testing.T) {
	env := newAdminEnv(t)
	_ = env.db.AddWebAuthnCredential(env.uid, "AQID", "Key", []byte(`{"id":"AQID"}`))

	post := func(path string, cookies ...*http.Cookie) *httptestRecorder {
		r := newReq(env, "POST", path, "{}")
		r.Host = "localhost"
		r.Header.Del("X-CSRF-Token")
		r.Header.Del("Cookie")
		for _, c := range cookies {
			r.AddCookie(c)
		}
		return serve(env, r)
	}
	if rec := post("/admin/login/webauthn/begin"); rec.Code != 400 {
		t.Errorf("begin without pending login = %d", rec.Code)
	}
	if rec := post("/admin/login/webauthn/finish"); rec.Code != 400 {
		t.Errorf("finish without pending login = %d", rec.Code)
	}

	// The password step parks the login because a passkey is registered.
	rec := env.doWith("POST", "/admin/login", form("email", testAdminEmail, "password", testAdminPassword), "")
	pending := cookieByName(rec, twoFACookie)
	if pending == nil {
		t.Fatalf("password step should park the login: %d", rec.Code)
	}
	if rec := post("/admin/login/webauthn/finish", pending); rec.Code != 400 {
		t.Errorf("finish before begin = %d", rec.Code)
	}
	if rec := post("/admin/login/webauthn/begin", pending); rec.Code != 200 || !strings.Contains(rec.Body.String(), "challenge") {
		t.Fatalf("begin: %d %s", rec.Code, rec.Body)
	}
	for range maxLoginFailures {
		post("/admin/login/webauthn/begin", pending)
		post("/admin/login/webauthn/finish", pending)
	}
	if rec := post("/admin/login/webauthn/begin", pending); rec.Code != http.StatusTooManyRequests {
		t.Errorf("begin after lockout = %d", rec.Code)
	}
	if rec := post("/admin/login/webauthn/finish", pending); rec.Code != http.StatusTooManyRequests {
		t.Errorf("finish after lockout = %d", rec.Code)
	}
}
