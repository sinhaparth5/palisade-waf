package ui

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"palisade/internal/security/totp"
	"palisade/internal/storage"
)

type accountPage struct {
	Email    string        `json:"email"`
	TOTP     bool          `json:"totp"`
	Secure   bool          `json:"secure_context"`
	Passkeys []passkeyJSON `json:"passkeys"`
	Devices  []deviceJSON  `json:"devices"`
}

// TestAccountTOTP: start, a wrong then a right code, backup codes once, and
// turning it off only with a code.
func TestAccountTOTP(t *testing.T) {
	env := newAdminEnv(t)
	const api = "/admin/api/settings/2fa/"

	if rec := env.doJSON(env.session, http.MethodPost, api+"confirm", codeRequest{Code: "123456"}, nil); rec.Code != http.StatusConflict {
		t.Errorf("confirm without start: %d", rec.Code)
	}
	var start struct{ QR, Key string }
	if rec := env.doJSON(env.session, http.MethodPost, api+"start", map[string]any{}, &start); rec.Code != http.StatusOK || !strings.HasPrefix(start.QR, "data:image/png;base64,") || start.Key == "" {
		t.Fatalf("start: %d %s", rec.Code, rec.Body)
	}
	var bad jsonError
	if rec := env.doJSON(env.session, http.MethodPost, api+"confirm", codeRequest{Code: "000000"}, &bad); rec.Code != http.StatusBadRequest || bad.Fields["code"] == "" {
		t.Errorf("wrong code: %d %s", rec.Code, rec.Body)
	}
	secret, _ := env.db.GetPendingTOTPSecret(env.uid)
	code, _ := totp.Code(secret, time.Now())
	var done struct {
		BackupCodes []string `json:"backup_codes"`
	}
	if rec := env.doJSON(env.session, http.MethodPost, api+"confirm", codeRequest{Code: code}, &done); rec.Code != http.StatusOK || len(done.BackupCodes) != backupCodeCount {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body)
	}
	if rec := env.doJSON(env.session, http.MethodPost, api+"start", map[string]any{}, nil); rec.Code != http.StatusConflict {
		t.Errorf("start while on: %d", rec.Code)
	}

	var page accountPage
	env.doJSON(env.session, http.MethodGet, "/admin/api/settings/account", nil, &page)
	if !page.TOTP || page.Email != testAdminEmail {
		t.Errorf("account = %+v", page)
	}

	for _, c := range []string{"", "nope"} {
		if rec := env.doJSON(env.session, http.MethodPost, api+"disable", codeRequest{Code: c}, &bad); rec.Code != http.StatusBadRequest || bad.Fields["code"] == "" {
			t.Errorf("disable with %q: %d", c, rec.Code)
		}
	}
	if rec := env.doJSON(env.session, http.MethodPost, api+"disable", codeRequest{Code: done.BackupCodes[0]}, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("disable with a backup code: %d %s", rec.Code, rec.Body)
	}
	if on, _ := env.db.TOTPEnabled(env.uid); on {
		t.Error("2FA still on")
	}
}

func TestAccountCredentials(t *testing.T) {
	env := newAdminEnv(t)
	const api = "/admin/api/settings/credentials"
	viewer := env.sessionAs(storage.RoleViewer)
	for _, tc := range []struct {
		req   credentialsRequest
		field string
	}{
		{credentialsRequest{CurrentPassword: "wrong", NewEmail: "x@example.com"}, "current_password"},
		{credentialsRequest{CurrentPassword: testAdminPassword}, "new_email"},
		{credentialsRequest{CurrentPassword: testAdminPassword, NewEmail: "not an email"}, "new_email"},
		{credentialsRequest{CurrentPassword: testAdminPassword, NewEmail: "test-viewer@example.com"}, "new_email"},
		{credentialsRequest{CurrentPassword: testAdminPassword, NewPassword: "a long new password", ConfirmPassword: "different"}, "confirm_password"},
		{credentialsRequest{CurrentPassword: testAdminPassword, NewPassword: "short", ConfirmPassword: "short"}, "new_password"},
		{credentialsRequest{CurrentPassword: testAdminPassword, NewPassword: breachedTestPassword, ConfirmPassword: breachedTestPassword}, "new_password"},
	} {
		var got jsonError
		if rec := env.doJSON(env.session, http.MethodPut, api, tc.req, &got); rec.Code != http.StatusBadRequest || got.Fields[tc.field] == "" {
			t.Errorf("%+v: %d %s, want a %s error", tc.req, rec.Code, rec.Body, tc.field)
		}
	}

	rec := env.doJSON(env.session, http.MethodPut, api, credentialsRequest{CurrentPassword: testAdminPassword, NewEmail: "new@example.com"}, nil)
	if rec.Code != http.StatusNoContent || !strings.Contains(rec.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("change: %d %v", rec.Code, rec.Header())
	}
	if u, _ := env.db.GetAdminUserByEmail("new@example.com"); u == nil {
		t.Error("email not changed")
	}
	if rec := env.doJSON(env.session, http.MethodGet, "/admin/api/settings/account", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("old session still works: %d", rec.Code)
	}
	if rec := env.doJSON(viewer, http.MethodPut, api, credentialsRequest{CurrentPassword: "password-viewer", NewEmail: "v2@example.com"}, nil); rec.Code != http.StatusNoContent {
		t.Errorf("a viewer changes their own email: %d %s", rec.Code, rec.Body)
	}
}

func TestAccountPasskeysAndDevices(t *testing.T) {
	env := newAdminEnv(t)
	var page accountPage
	if rec := env.doJSON(env.session, http.MethodGet, "/admin/api/settings/account", nil, &page); rec.Code != http.StatusOK {
		t.Fatalf("account: %d", rec.Code)
	}
	if page.Secure || len(page.Passkeys) != 0 || len(page.Devices) != 1 || !page.Devices[0].Current || !page.Devices[0].Live {
		t.Errorf("account = %+v", page)
	}

	// The harness talks plain HTTP to example.com, so registration is refused.
	if rec := env.doJSON(env.session, http.MethodPost, "/admin/api/settings/passkeys/begin", map[string]string{"name": "Mac"}, nil); rec.Code != http.StatusConflict {
		t.Errorf("begin over HTTP: %d", rec.Code)
	}
	if rec := env.doJSON(env.session, http.MethodPost, "/admin/api/settings/passkeys/finish", map[string]any{}, nil); rec.Code != http.StatusConflict {
		t.Errorf("finish without begin: %d", rec.Code)
	}
	for path, want := range map[string]int{"x": http.StatusBadRequest, "99": http.StatusNoContent} {
		if rec := env.doJSON(env.session, http.MethodDelete, "/admin/api/settings/passkeys/"+path, nil, nil); rec.Code != want {
			t.Errorf("delete passkey %s: %d", path, rec.Code)
		}
	}

	// A second sign-in revokes the first; the old one is then only history.
	old := env.session
	cur, _ := env.db.CreateSession(env.uid, "198.51.100.7", "Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0", "")
	env.doJSON(cur, http.MethodGet, "/admin/api/settings/account", nil, &page)
	if len(page.Devices) != 2 || !page.Devices[0].Current || page.Devices[1].Live || page.Devices[0].Device != "Firefox on Linux" {
		t.Fatalf("devices = %+v", page.Devices)
	}
	for _, tc := range []struct {
		id   string
		want int
	}{
		{page.Devices[0].ID, http.StatusBadRequest}, // this device
		{"nope", http.StatusNotFound},
		{storage.SessionID(old), http.StatusNoContent},
	} {
		if rec := env.doJSON(cur, http.MethodDelete, "/admin/api/settings/devices/"+tc.id, nil, nil); rec.Code != tc.want {
			t.Errorf("device %s: %d %s, want %d", tc.id, rec.Code, rec.Body, tc.want)
		}
	}
	viewer := env.sessionAs(storage.RoleViewer)
	if rec := env.doJSON(viewer, http.MethodDelete, "/admin/api/settings/devices/"+storage.SessionID(cur), nil, nil); rec.Code != http.StatusNotFound {
		t.Errorf("another user's device: %d", rec.Code)
	}
	if rec := env.doJSON(cur, http.MethodPost, "/admin/api/settings/devices/sign-out-others", map[string]any{}, nil); rec.Code != http.StatusNoContent {
		t.Errorf("sign out others: %d", rec.Code)
	}
	env.doJSON(cur, http.MethodGet, "/admin/api/settings/account", nil, &page)
	if len(page.Devices) != 1 {
		t.Errorf("old device not forgotten: %+v", page.Devices)
	}
}
