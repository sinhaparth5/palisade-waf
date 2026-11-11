package ui

import (
	"context"
	"testing"

	"palisade/internal/security/breach"
)

func TestValidateAdminPassword(t *testing.T) {
	// Port 1 refuses the connection: the breach lookup fails open while the
	// local rules still apply.
	down := breach.New("http://127.0.0.1:1/")
	for _, tc := range []struct {
		email, password string
		ok              bool
	}{
		{"a@x.test", "twelve-chars", true},
		{"a@x.test", "elevenchars", false},
		{"long-name@x.test", "Long-Name@x.test", false},
		{"long-name@x.test", "long-name@x.test!", true},
	} {
		for _, c := range []*breach.Checker{nil, down} {
			if err := ValidateAdminPassword(context.Background(), c, tc.email, tc.password); (err == nil) != tc.ok {
				t.Errorf("ValidateAdminPassword(%q, %q) = %v, want ok=%v", tc.email, tc.password, err, tc.ok)
			}
		}
	}
}
