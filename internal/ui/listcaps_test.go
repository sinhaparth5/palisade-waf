package ui

import (
	"fmt"
	"strings"
	"testing"
)

// TestListCaps: the honeypot and trusted-IP lists are scanned on every
// proxied request, so an oversized list is refused and nothing is stored.
func TestListCaps(t *testing.T) {
	env := newAdminEnv(t)
	var paths, ips []string
	for i := range honeypotMax + 1 {
		paths = append(paths, fmt.Sprintf("/trap%d", i))
	}
	for i := range trustedIPsMax + 1 {
		ips = append(ips, fmt.Sprintf("10.0.%d.%d", i/250, i%250+1))
	}
	if rec := env.do("POST", "/admin/ip-rules/honeypots", form("honeypot_paths", strings.Join(paths, "\n"))); !strings.Contains(rec.Body.String(), "At most") {
		t.Errorf("honeypots over the cap: %d", rec.Code)
	}
	if rec := env.do("POST", "/admin/settings/trusted-ips", form("trusted_ips", strings.Join(ips, "\n"))); !strings.Contains(rec.Body.String(), "At most") {
		t.Errorf("trusted IPs over the cap: %d", rec.Code)
	}
	if got, _ := env.db.GetHoneypotPaths(); len(got) != 0 {
		t.Errorf("honeypots stored: %d", len(got))
	}
	if got, _ := env.db.GetTrustedIPs(); len(got) != 0 {
		t.Errorf("trusted IPs stored: %d", len(got))
	}
}
