package egress

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestControl(t *testing.T) {
	for addr, blocked := range map[string]bool{
		"169.254.169.254:80":          true, // what a rebound hostname dials
		"169.254.170.2:80":            true, // ECS task metadata
		"[fd00:ec2::254]:80":          true,
		"[fe80::1%eth0]:80":           true,
		"[::ffff:169.254.169.254]:80": true,
		"[64:ff9b::a9fe:a9fe]:80":     true,
		"127.0.0.1:3000":              false,
		"10.0.0.5:443":                false,
		"[::1]:8080":                  false,
		"93.184.216.34:443":           false,
	} {
		err := Control("tcp", addr, nil)
		if errors.Is(err, ErrBlocked) != blocked {
			t.Errorf("Control(%s) = %v, want blocked=%v", addr, err, blocked)
		}
	}
	if Control("tcp", "metadata.google.internal:80", nil) == nil {
		t.Error("unresolved name passed the dial check")
	}
}

// A loopback server is reachable, and its redirect to the metadata address
// is refused at the dial rather than followed.
func TestClientRefusesRedirectToMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redir" {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
		}
	}))
	defer srv.Close()
	c := Client(5 * time.Second)

	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("loopback refused: %v", err)
	}
	resp.Body.Close()

	resp, err = c.Get(srv.URL + "/redir")
	if err == nil {
		resp.Body.Close()
	}
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("redirect to metadata: err = %v, want ErrBlocked", err)
	}
}
