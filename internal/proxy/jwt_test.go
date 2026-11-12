package proxy_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/labstack/echo/v5"

	"palisade/internal/services"
	"palisade/internal/storage"
)

// TestEdgeJWT pins issue #279: protected paths need a valid bearer token,
// enforce answers 401, log forwards and tags the row, the verified sub is
// passed as X-Auth-Subject and a client copy never reaches the backend.
func TestEdgeJWT(t *testing.T) {
	var gotSub, gotPath atomic.Value
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSub.Store(r.Header.Get("X-Auth-Subject"))
		gotPath.Store(r.URL.Path)
	}))
	defer backend.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := jwt.Signed(signer).Claims(jwt.Claims{Subject: "user-7", Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour))}).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	h, db, reg := newTestHandlerDB(t, backend)
	logs := make(chan storage.RequestLog, 100)
	db.SetWebhookFn(func(l storage.RequestLog) { logs <- l })
	svc := reg.List()[0]
	if err := db.SetServiceBotMode(svc.ID, "off"); err != nil {
		t.Fatal(err)
	}
	e := echo.New()

	tests := []struct {
		name, mode, path, token, spoof string
		want                           int
		wantAction, wantSub            string
	}{
		{"off", "off", "/api/x", "", "evil", http.StatusOK, "", "evil"},
		{"enforce: missing", "enforce", "/api/x", "", "", http.StatusUnauthorized, "jwt_invalid", ""},
		{"enforce: garbage", "enforce", "/api/x", "abc.def.ghi", "", http.StatusUnauthorized, "jwt_invalid", ""},
		{"enforce: valid", "enforce", "/api/x", valid, "evil", http.StatusOK, "", "user-7"},
		{"enforce: unprotected path", "enforce", "/public", "", "evil", http.StatusOK, "", ""},
		{"enforce: open path", "enforce", "/robots.txt", "", "", http.StatusOK, "", ""},
		{"log: missing", "log", "/api/x", "", "evil", http.StatusOK, "jwt_invalid:log", ""},
		// Issue #310: a non-canonical path must not step around the prefix.
		{"enforce: doubled slash", "enforce", "//api/x", "", "", http.StatusUnauthorized, "jwt_invalid", ""},
		{"enforce: doubled slash, valid", "enforce", "//api//x/", valid, "", http.StatusOK, "", "user-7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := db.SetServiceJWT(svc.ID, storage.ServiceJWT{Mode: tt.mode, PublicKey: pub, Prefixes: "/api"}); err != nil {
				t.Fatal(err)
			}
			if err := reg.Reload(db); err != nil {
				t.Fatal(err)
			}
			gotSub.Store("")
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.RemoteAddr = "203.0.113.9:1234"
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			if tt.spoof != "" {
				req.Header.Set("X-Auth-Subject", tt.spoof)
			}
			rec := httptest.NewRecorder()
			_ = h.Handle(e.NewContext(req, rec))
			if rec.Code != tt.want {
				t.Fatalf("status %d, want %d", rec.Code, tt.want)
			}
			if tt.want == http.StatusOK && gotSub.Load() != tt.wantSub {
				t.Errorf("backend X-Auth-Subject %q, want %q", gotSub.Load(), tt.wantSub)
			}
			if tt.path == "//api//x/" && gotPath.Load() != "/api/x/" {
				t.Errorf("backend path %q, want the canonical /api/x/", gotPath.Load())
			}
			select {
			case l := <-logs:
				if l.Action != tt.wantAction {
					t.Errorf("logged action %q, want %q", l.Action, tt.wantAction)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("no request logged")
			}
		})
	}

	// Trusted IPs skip the WAF but not authentication, so only the canonical
	// path stops a dot segment walking around the prefix (CRS would catch it
	// for anyone else).
	trusted, err := services.ParseTrustedIPs([]string{"203.0.113.9"})
	if err != nil {
		t.Fatal(err)
	}
	reg.SetTrustedIPs(trusted)
	req := httptest.NewRequest(http.MethodGet, "/z/../api/x", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	rec := httptest.NewRecorder()
	_ = h.Handle(e.NewContext(req, rec))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("trusted /z/../api/x: status %d, want 401", rec.Code)
	}
}
