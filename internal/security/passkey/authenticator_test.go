package passkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/webauthn"
)

// softKey is a minimal ES256 authenticator with "none" attestation, enough
// to drive both ceremonies through the real go-webauthn verification.
type softKey struct {
	t     *testing.T
	key   *ecdsa.PrivateKey
	id    []byte
	count uint32
}

const testOrigin = "http://localhost:8080"

var b64 = base64.RawURLEncoding

func (k *softKey) authData(flags byte, attested []byte) []byte {
	rp := sha256.Sum256([]byte("localhost"))
	var buf bytes.Buffer
	buf.Write(rp[:])
	buf.WriteByte(flags)
	_ = binary.Write(&buf, binary.BigEndian, k.count)
	buf.Write(attested)
	return buf.Bytes()
}

func (k *softKey) request(body any) *http.Request {
	k.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		k.t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
	r.Host = "localhost:8080"
	return r
}

func clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]string{"type": typ, "challenge": challenge, "origin": testOrigin})
	return b
}

// register answers a creation challenge: user present + verified, with an
// attested credential (AAGUID zero, COSE EC2 P-256 key).
func (k *softKey) register(s *webauthn.SessionData) *http.Request {
	k.t.Helper()
	cose, err := webauthncbor.Marshal(map[int]any{
		1: 2, 3: -7, -1: 1,
		-2: k.key.X.FillBytes(make([]byte, 32)),
		-3: k.key.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		k.t.Fatal(err)
	}
	var att bytes.Buffer
	att.Write(make([]byte, 16))
	_ = binary.Write(&att, binary.BigEndian, uint16(len(k.id)))
	att.Write(k.id)
	att.Write(cose)
	obj, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": k.authData(0x45, att.Bytes())})
	if err != nil {
		k.t.Fatal(err)
	}
	return k.request(map[string]any{
		"id": b64.EncodeToString(k.id), "rawId": b64.EncodeToString(k.id), "type": "public-key",
		"response": map[string]string{
			"clientDataJSON":    b64.EncodeToString(clientData("webauthn.create", s.Challenge)),
			"attestationObject": b64.EncodeToString(obj),
		},
	})
}

// assert answers a login challenge, signing authData || SHA-256(clientData).
func (k *softKey) assert(s *webauthn.SessionData, handle []byte) *http.Request {
	k.t.Helper()
	k.count++
	ad := k.authData(0x05, nil)
	cd := clientData("webauthn.get", s.Challenge)
	h := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.key, digest[:])
	if err != nil {
		k.t.Fatal(err)
	}
	return k.request(map[string]any{
		"id": b64.EncodeToString(k.id), "rawId": b64.EncodeToString(k.id), "type": "public-key",
		"response": map[string]string{
			"clientDataJSON":    b64.EncodeToString(cd),
			"authenticatorData": b64.EncodeToString(ad),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(handle),
		},
	})
}

// TestCeremonyRoundTrip registers a passkey and logs in with it, then checks
// the stored sign counter moved, a stale counter is flagged, and a wrong
// challenge or another user is refused.
func TestCeremonyRoundTrip(t *testing.T) {
	m, db, uid := newManager(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k := &softKey{t: t, key: key, id: []byte("soft-key-1")}
	start := httptest.NewRequest(http.MethodPost, "/", nil)
	start.Host = "localhost:8080"

	_, reg, err := m.BeginRegistration(start, uid)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.FinishRegistration(k.register(reg), uid, *reg, ""); err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	rows, err := db.ListWebAuthnCredentials(uid)
	if err != nil || len(rows) != 1 || rows[0].Name != "Passkey" {
		t.Fatalf("stored credentials = %+v, %v", rows, err)
	}
	if ok, _ := m.Enabled(uid); !ok {
		t.Fatal("Enabled() false after registration")
	}

	handle, err := db.GetOrCreateWebAuthnHandle(uid)
	if err != nil {
		t.Fatal(err)
	}
	_, login, err := m.BeginLogin(start, uid)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.FinishLogin(k.assert(login, handle), uid, *login); err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	rows, _ = db.ListWebAuthnCredentials(uid)
	var stored webauthn.Credential
	if err := json.Unmarshal(rows[0].Data, &stored); err != nil || stored.Authenticator.SignCount != 1 {
		t.Fatalf("sign count after login = %d, %v", stored.Authenticator.SignCount, err)
	}

	// A cloned authenticator replaying an old counter still verifies (the
	// signature is valid), but the stored credential is flagged.
	k.count = 0
	_, login, _ = m.BeginLogin(start, uid)
	if err := m.FinishLogin(k.assert(login, handle), uid, *login); err != nil {
		t.Fatalf("FinishLogin with a stale counter: %v", err)
	}
	rows, _ = db.ListWebAuthnCredentials(uid)
	if err := json.Unmarshal(rows[0].Data, &stored); err != nil || !stored.Authenticator.CloneWarning {
		t.Fatalf("stale counter not flagged: clone=%v, %v", stored.Authenticator.CloneWarning, err)
	}

	// A signature over a different challenge is refused.
	_, login, _ = m.BeginLogin(start, uid)
	_, other, _ := m.BeginLogin(start, uid)
	k.count = 5
	if err := m.FinishLogin(k.assert(other, handle), uid, *login); err == nil {
		t.Fatal("FinishLogin accepted an assertion for another challenge")
	}

	// Another admin can't log in with this user's passkey.
	viewer, err := db.CreateAdminUser("viewer@example.com", "pw", "viewer")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.BeginLogin(start, viewer); err == nil {
		t.Fatal("BeginLogin for a user without passkeys succeeded")
	}
}
